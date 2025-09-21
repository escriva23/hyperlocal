-- Function to handle user registration
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO users (id, email, name, role)
    VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'name', NEW.email),
        COALESCE(NEW.raw_user_meta_data->>'role', 'customer')::user_role
    );
    
    -- Create profile
    INSERT INTO profiles (user_id)
    VALUES (NEW.id);
    
    -- Create wallet
    INSERT INTO wallets (user_id)
    VALUES (NEW.id);
    
    -- Create provider profile if role is provider
    IF COALESCE(NEW.raw_user_meta_data->>'role', 'customer') = 'provider' THEN
        INSERT INTO provider_profiles (user_id, business_name)
        VALUES (NEW.id, COALESCE(NEW.raw_user_meta_data->>'business_name', 'New Business'));
        
        INSERT INTO mtaa_shares (user_id)
        VALUES (NEW.id);
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger for new user registration
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION handle_new_user();

-- Function to update provider rating
CREATE OR REPLACE FUNCTION update_provider_rating()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE provider_profiles
    SET 
        average_rating = (
            SELECT ROUND(AVG(rating)::numeric, 2)
            FROM reviews
            WHERE provider_id = NEW.provider_id
        ),
        total_reviews = (
            SELECT COUNT(*)
            FROM reviews
            WHERE provider_id = NEW.provider_id
        )
    WHERE user_id = NEW.provider_id;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to update provider rating when review is added
CREATE TRIGGER update_provider_rating_trigger
    AFTER INSERT OR UPDATE ON reviews
    FOR EACH ROW EXECUTE FUNCTION update_provider_rating();

-- Function to calculate commission
CREATE OR REPLACE FUNCTION calculate_commission()
RETURNS TRIGGER AS $$
BEGIN
    NEW.commission_amount = NEW.price * NEW.commission_rate;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to calculate commission on booking
CREATE TRIGGER calculate_commission_trigger
    BEFORE INSERT OR UPDATE ON bookings
    FOR EACH ROW EXECUTE FUNCTION calculate_commission();

-- Function to update wallet balance
CREATE OR REPLACE FUNCTION update_wallet_balance()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'completed' AND OLD.status != 'completed' THEN
        -- Update customer wallet (deduct payment)
        UPDATE wallets
        SET 
            balance = balance - NEW.amount,
            total_spent = total_spent + NEW.amount
        WHERE user_id = NEW.user_id AND NEW.type = 'payment';
        
        -- Update provider wallet (add earnings minus commission)
        IF NEW.type = 'payment' THEN
            UPDATE wallets
            SET 
                balance = balance + (NEW.amount - (
                    SELECT commission_amount 
                    FROM bookings 
                    WHERE id = NEW.booking_id
                )),
                total_earned = total_earned + (NEW.amount - (
                    SELECT commission_amount 
                    FROM bookings 
                    WHERE id = NEW.booking_id
                ))
            WHERE user_id = (
                SELECT provider_id 
                FROM bookings 
                WHERE id = NEW.booking_id
            );
        END IF;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to update wallet balance
CREATE TRIGGER update_wallet_balance_trigger
    AFTER UPDATE ON transactions
    FOR EACH ROW EXECUTE FUNCTION update_wallet_balance();

-- Function to update booking counts
CREATE OR REPLACE FUNCTION update_booking_counts()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'completed' AND OLD.status != 'completed' THEN
        UPDATE provider_profiles
        SET total_bookings = total_bookings + 1
        WHERE user_id = NEW.provider_id;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to update booking counts
CREATE TRIGGER update_booking_counts_trigger
    AFTER UPDATE ON bookings
    FOR EACH ROW EXECUTE FUNCTION update_booking_counts();

-- Function to update Mtaa Shares
CREATE OR REPLACE FUNCTION update_mtaa_shares()
RETURNS TRIGGER AS $$
DECLARE
    shares_to_add DECIMAL(10,2);
    current_share_value DECIMAL(10,2) := 10.00; -- Base share value
BEGIN
    IF NEW.status = 'completed' AND OLD.status != 'completed' THEN
        -- Calculate shares based on booking value (1% of booking value)
        shares_to_add := NEW.price * 0.01;
        
        UPDATE mtaa_shares
        SET 
            shares_earned = shares_earned + shares_to_add,
            shares_value = shares_value + (shares_to_add * current_share_value),
            total_earnings = total_earnings + (shares_to_add * current_share_value)
        WHERE user_id = NEW.provider_id;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to update Mtaa Shares
CREATE TRIGGER update_mtaa_shares_trigger
    AFTER UPDATE ON bookings
    FOR EACH ROW EXECUTE FUNCTION update_mtaa_shares();

-- Function to create notification
CREATE OR REPLACE FUNCTION create_notification(
    p_user_id UUID,
    p_title TEXT,
    p_message TEXT,
    p_type TEXT,
    p_data JSONB DEFAULT '{}'
)
RETURNS UUID AS $$
DECLARE
    notification_id UUID;
BEGIN
    INSERT INTO notifications (user_id, title, message, type, data)
    VALUES (p_user_id, p_title, p_message, p_type, p_data)
    RETURNING id INTO notification_id;
    
    RETURN notification_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to send booking notifications
CREATE OR REPLACE FUNCTION send_booking_notifications()
RETURNS TRIGGER AS $$
BEGIN
    -- Notify provider of new booking
    IF TG_OP = 'INSERT' THEN
        PERFORM create_notification(
            NEW.provider_id,
            'New Booking Request',
            'You have received a new booking request.',
            'booking_request',
            jsonb_build_object('booking_id', NEW.id)
        );
    END IF;
    
    -- Notify customer of booking status changes
    IF TG_OP = 'UPDATE' AND OLD.status != NEW.status THEN
        PERFORM create_notification(
            NEW.customer_id,
            'Booking Status Updated',
            'Your booking status has been updated to ' || NEW.status || '.',
            'booking_status',
            jsonb_build_object('booking_id', NEW.id, 'status', NEW.status)
        );
        
        -- Also notify provider for certain status changes
        IF NEW.status IN ('confirmed', 'cancelled') THEN
            PERFORM create_notification(
                NEW.provider_id,
                'Booking Status Updated',
                'Booking status has been updated to ' || NEW.status || '.',
                'booking_status',
                jsonb_build_object('booking_id', NEW.id, 'status', NEW.status)
            );
        END IF;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for booking notifications
CREATE TRIGGER send_booking_notifications_trigger
    AFTER INSERT OR UPDATE ON bookings
    FOR EACH ROW EXECUTE FUNCTION send_booking_notifications();

-- Function to get nearby providers
CREATE OR REPLACE FUNCTION get_nearby_providers(
    user_lat DOUBLE PRECISION,
    user_lng DOUBLE PRECISION,
    radius_km INTEGER DEFAULT 10,
    service_category TEXT DEFAULT NULL
)
RETURNS TABLE (
    provider_id UUID,
    business_name TEXT,
    description TEXT,
    average_rating DECIMAL,
    total_reviews INTEGER,
    distance_km DOUBLE PRECISION,
    services JSONB
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        pp.user_id,
        pp.business_name,
        pp.description,
        pp.average_rating,
        pp.total_reviews,
        ST_Distance(
            pp.location::geometry,
            ST_SetSRID(ST_MakePoint(user_lng, user_lat), 4326)::geometry
        ) / 1000 AS distance_km,
        COALESCE(
            jsonb_agg(
                jsonb_build_object(
                    'id', s.id,
                    'name', s.name,
                    'price', s.price,
                    'price_type', s.price_type
                )
            ) FILTER (WHERE s.id IS NOT NULL),
            '[]'::jsonb
        ) AS services
    FROM provider_profiles pp
    LEFT JOIN services s ON s.provider_id = pp.user_id AND s.status = 'active'
    LEFT JOIN service_categories sc ON s.category_id = sc.id
    WHERE 
        pp.verification_status = 'verified'
        AND pp.is_available = true
        AND ST_DWithin(
            pp.location::geometry,
            ST_SetSRID(ST_MakePoint(user_lng, user_lat), 4326)::geometry,
            radius_km * 1000
        )
        AND (service_category IS NULL OR sc.slug = service_category)
    GROUP BY pp.user_id, pp.business_name, pp.description, pp.average_rating, pp.total_reviews, pp.location
    ORDER BY distance_km;
END;
$$ LANGUAGE plpgsql;

-- Function to search services with full-text search
CREATE OR REPLACE FUNCTION search_services(
    search_query TEXT,
    user_lat DOUBLE PRECISION DEFAULT NULL,
    user_lng DOUBLE PRECISION DEFAULT NULL,
    max_distance_km INTEGER DEFAULT 50,
    min_rating DECIMAL DEFAULT 0,
    max_price DECIMAL DEFAULT NULL,
    category_slug TEXT DEFAULT NULL
)
RETURNS TABLE (
    service_id UUID,
    service_name TEXT,
    service_description TEXT,
    price DECIMAL,
    price_type TEXT,
    provider_id UUID,
    business_name TEXT,
    average_rating DECIMAL,
    total_reviews INTEGER,
    distance_km DOUBLE PRECISION,
    relevance_score REAL
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        s.id,
        s.name,
        s.description,
        s.price,
        s.price_type::TEXT,
        pp.user_id,
        pp.business_name,
        pp.average_rating,
        pp.total_reviews,
        CASE 
            WHEN user_lat IS NOT NULL AND user_lng IS NOT NULL THEN
                ST_Distance(
                    pp.location::geometry,
                    ST_SetSRID(ST_MakePoint(user_lng, user_lat), 4326)::geometry
                ) / 1000
            ELSE NULL
        END AS distance_km,
        ts_rank(
            to_tsvector('english', s.name || ' ' || COALESCE(s.description, '') || ' ' || pp.business_name),
            plainto_tsquery('english', search_query)
        ) AS relevance_score
    FROM services s
    JOIN provider_profiles pp ON s.provider_id = pp.user_id
    LEFT JOIN service_categories sc ON s.category_id = sc.id
    WHERE 
        s.status = 'active'
        AND pp.verification_status = 'verified'
        AND pp.is_available = true
        AND (
            to_tsvector('english', s.name || ' ' || COALESCE(s.description, '') || ' ' || pp.business_name) 
            @@ plainto_tsquery('english', search_query)
        )
        AND pp.average_rating >= min_rating
        AND (max_price IS NULL OR s.price <= max_price)
        AND (category_slug IS NULL OR sc.slug = category_slug)
        AND (
            user_lat IS NULL OR user_lng IS NULL OR
            ST_DWithin(
                pp.location::geometry,
                ST_SetSRID(ST_MakePoint(user_lng, user_lat), 4326)::geometry,
                max_distance_km * 1000
            )
        )
    ORDER BY relevance_score DESC, pp.average_rating DESC, distance_km ASC NULLS LAST;
END;
$$ LANGUAGE plpgsql;

-- Function to get dashboard stats for customers
CREATE OR REPLACE FUNCTION get_customer_dashboard_stats(customer_id UUID)
RETURNS JSONB AS $$
DECLARE
    stats JSONB;
BEGIN
    SELECT jsonb_build_object(
        'total_bookings', (
            SELECT COUNT(*) FROM bookings WHERE customer_id = get_customer_dashboard_stats.customer_id
        ),
        'completed_bookings', (
            SELECT COUNT(*) FROM bookings 
            WHERE customer_id = get_customer_dashboard_stats.customer_id AND status = 'completed'
        ),
        'pending_reviews', (
            SELECT COUNT(*) FROM bookings b
            LEFT JOIN reviews r ON b.id = r.booking_id
            WHERE b.customer_id = get_customer_dashboard_stats.customer_id 
            AND b.status = 'completed' 
            AND r.id IS NULL
        ),
        'wallet_balance', (
            SELECT COALESCE(balance, 0) FROM wallets WHERE user_id = get_customer_dashboard_stats.customer_id
        ),
        'total_spent', (
            SELECT COALESCE(total_spent, 0) FROM wallets WHERE user_id = get_customer_dashboard_stats.customer_id
        ),
        'active_bookings', (
            SELECT COUNT(*) FROM bookings 
            WHERE customer_id = get_customer_dashboard_stats.customer_id 
            AND status IN ('pending', 'confirmed', 'in_progress')
        ),
        'unread_notifications', (
            SELECT COUNT(*) FROM notifications 
            WHERE user_id = get_customer_dashboard_stats.customer_id AND is_read = false
        )
    ) INTO stats;
    
    RETURN stats;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to get dashboard stats for providers
CREATE OR REPLACE FUNCTION get_provider_dashboard_stats(provider_id UUID)
RETURNS JSONB AS $$
DECLARE
    stats JSONB;
BEGIN
    SELECT jsonb_build_object(
        'total_services', (
            SELECT COUNT(*) FROM services WHERE provider_id = get_provider_dashboard_stats.provider_id AND status = 'active'
        ),
        'total_bookings', (
            SELECT COUNT(*) FROM bookings WHERE provider_id = get_provider_dashboard_stats.provider_id
        ),
        'completed_bookings', (
            SELECT COUNT(*) FROM bookings 
            WHERE provider_id = get_provider_dashboard_stats.provider_id AND status = 'completed'
        ),
        'monthly_earnings', (
            SELECT COALESCE(SUM(price - commission_amount), 0) FROM bookings 
            WHERE provider_id = get_provider_dashboard_stats.provider_id 
            AND status = 'completed'
            AND DATE_TRUNC('month', created_at) = DATE_TRUNC('month', NOW())
        ),
        'total_earnings', (
            SELECT COALESCE(total_earned, 0) FROM wallets WHERE user_id = get_provider_dashboard_stats.provider_id
        ),
        'average_rating', (
            SELECT COALESCE(average_rating, 0) FROM provider_profiles WHERE user_id = get_provider_dashboard_stats.provider_id
        ),
        'total_reviews', (
            SELECT COALESCE(total_reviews, 0) FROM provider_profiles WHERE user_id = get_provider_dashboard_stats.provider_id
        ),
        'pending_bookings', (
            SELECT COUNT(*) FROM bookings 
            WHERE provider_id = get_provider_dashboard_stats.provider_id AND status = 'pending'
        ),
        'mtaa_shares', (
            SELECT COALESCE(shares_earned, 0) FROM mtaa_shares WHERE user_id = get_provider_dashboard_stats.provider_id
        ),
        'shares_value', (
            SELECT COALESCE(shares_value, 0) FROM mtaa_shares WHERE user_id = get_provider_dashboard_stats.provider_id
        )
    ) INTO stats;
    
    RETURN stats;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
