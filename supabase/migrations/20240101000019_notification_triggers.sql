-- Create notification helper function
CREATE OR REPLACE FUNCTION create_notification(
    p_user_id UUID,
    p_type VARCHAR(50),
    p_title VARCHAR(255),
    p_message TEXT,
    p_priority VARCHAR(10) DEFAULT 'medium',
    p_action_url TEXT DEFAULT NULL,
    p_metadata JSONB DEFAULT '{}'
)
RETURNS UUID AS $$
DECLARE
    notification_id UUID;
BEGIN
    INSERT INTO notifications (user_id, type, title, message, priority, action_url, metadata)
    VALUES (p_user_id, p_type, p_title, p_message, p_priority, p_action_url, p_metadata)
    RETURNING id INTO notification_id;
    
    RETURN notification_id;
END;
$$ LANGUAGE plpgsql;

-- Booking notification triggers
CREATE OR REPLACE FUNCTION handle_booking_notifications()
RETURNS TRIGGER AS $$
DECLARE
    customer_name TEXT;
    provider_name TEXT;
    service_name TEXT;
BEGIN
    -- Get related data
    SELECT u.name INTO customer_name FROM users u WHERE u.id = COALESCE(NEW.customer_id, OLD.customer_id);
    SELECT u.name INTO provider_name FROM users u WHERE u.id = COALESCE(NEW.provider_id, OLD.provider_id);
    service_name := COALESCE(NEW.service_name, OLD.service_name, 'Service');

    -- Handle INSERT (new booking)
    IF TG_OP = 'INSERT' THEN
        -- Notify provider about new booking request
        IF NEW.status = 'pending' THEN
            PERFORM create_notification(
                NEW.provider_id,
                'booking',
                'New Booking Request',
                'You have a new booking request for ' || service_name || ' from ' || COALESCE(customer_name, 'a customer'),
                'high',
                '/provider/bookings/' || NEW.id,
                jsonb_build_object('booking_id', NEW.id, 'customer_name', customer_name, 'service_name', service_name)
            );
        END IF;
        
        -- Notify customer if booking is auto-confirmed
        IF NEW.status = 'confirmed' THEN
            PERFORM create_notification(
                NEW.customer_id,
                'booking',
                'Booking Confirmed',
                'Your ' || service_name || ' booking has been confirmed for ' || TO_CHAR(NEW.scheduled_date, 'Day, Month DD at HH:MI AM'),
                'high',
                '/customer/bookings/' || NEW.id,
                jsonb_build_object('booking_id', NEW.id, 'provider_name', provider_name, 'service_name', service_name)
            );
        END IF;
    END IF;

    -- Handle UPDATE (status changes)
    IF TG_OP = 'UPDATE' AND OLD.status != NEW.status THEN
        CASE NEW.status
            WHEN 'confirmed' THEN
                -- Notify customer about confirmation
                PERFORM create_notification(
                    NEW.customer_id,
                    'booking',
                    'Booking Confirmed',
                    'Your ' || service_name || ' booking has been confirmed for ' || TO_CHAR(NEW.scheduled_date, 'Day, Month DD at HH:MI AM'),
                    'high',
                    '/customer/bookings/' || NEW.id,
                    jsonb_build_object('booking_id', NEW.id, 'provider_name', provider_name, 'service_name', service_name)
                );
                
            WHEN 'cancelled' THEN
                -- Notify both parties about cancellation
                PERFORM create_notification(
                    NEW.customer_id,
                    'booking',
                    'Booking Cancelled',
                    'Your ' || service_name || ' booking has been cancelled',
                    'medium',
                    '/customer/bookings/' || NEW.id,
                    jsonb_build_object('booking_id', NEW.id, 'provider_name', provider_name, 'service_name', service_name)
                );
                
                PERFORM create_notification(
                    NEW.provider_id,
                    'booking',
                    'Booking Cancelled',
                    'The ' || service_name || ' booking with ' || COALESCE(customer_name, 'customer') || ' has been cancelled',
                    'medium',
                    '/provider/bookings/' || NEW.id,
                    jsonb_build_object('booking_id', NEW.id, 'customer_name', customer_name, 'service_name', service_name)
                );
                
            WHEN 'completed' THEN
                -- Notify customer to leave review
                PERFORM create_notification(
                    NEW.customer_id,
                    'review',
                    'Please Rate Your Service',
                    'How was your experience with ' || COALESCE(provider_name, 'the provider') || '? Your feedback helps others.',
                    'low',
                    '/customer/bookings/' || NEW.id || '/review',
                    jsonb_build_object('booking_id', NEW.id, 'provider_name', provider_name, 'service_name', service_name)
                );
                
                -- Notify provider about completion
                PERFORM create_notification(
                    NEW.provider_id,
                    'booking',
                    'Service Completed',
                    'You have successfully completed the ' || service_name || ' service for ' || COALESCE(customer_name, 'customer'),
                    'medium',
                    '/provider/bookings/' || NEW.id,
                    jsonb_build_object('booking_id', NEW.id, 'customer_name', customer_name, 'service_name', service_name)
                );
                
            WHEN 'in_progress' THEN
                -- Notify customer that service has started
                PERFORM create_notification(
                    NEW.customer_id,
                    'booking',
                    'Service Started',
                    'Your ' || service_name || ' service has started',
                    'medium',
                    '/customer/bookings/' || NEW.id,
                    jsonb_build_object('booking_id', NEW.id, 'provider_name', provider_name, 'service_name', service_name)
                );
        END CASE;
    END IF;

    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- Payment notification triggers
CREATE OR REPLACE FUNCTION handle_payment_notifications()
RETURNS TRIGGER AS $$
DECLARE
    customer_name TEXT;
    provider_name TEXT;
    service_name TEXT;
BEGIN
    -- Get related data
    SELECT u.name INTO customer_name FROM users u WHERE u.id = COALESCE(NEW.customer_id, OLD.customer_id);
    SELECT u.name INTO provider_name FROM users u WHERE u.id = COALESCE(NEW.provider_id, OLD.provider_id);
    
    -- Get service name from booking if available
    IF NEW.booking_id IS NOT NULL THEN
        SELECT b.service_name INTO service_name FROM bookings b WHERE b.id = NEW.booking_id;
    END IF;
    service_name := COALESCE(service_name, 'service');

    -- Handle INSERT (new payment)
    IF TG_OP = 'INSERT' THEN
        -- Notify customer about payment processing
        IF NEW.status = 'completed' THEN
            PERFORM create_notification(
                NEW.customer_id,
                'payment',
                'Payment Processed',
                'Payment of $' || NEW.amount || ' has been successfully processed for your ' || service_name,
                'medium',
                '/customer/payments/' || NEW.id,
                jsonb_build_object('payment_id', NEW.id, 'amount', NEW.amount, 'service_name', service_name)
            );
            
            -- Notify provider about payment received
            PERFORM create_notification(
                NEW.provider_id,
                'payment',
                'Payment Received',
                'You received $' || NEW.amount || ' for your ' || service_name,
                'medium',
                '/provider/earnings',
                jsonb_build_object('payment_id', NEW.id, 'amount', NEW.amount, 'service_name', service_name)
            );
        END IF;
        
        -- Notify about failed payment
        IF NEW.status = 'failed' THEN
            PERFORM create_notification(
                NEW.customer_id,
                'payment',
                'Payment Failed',
                'Payment of $' || NEW.amount || ' for your ' || service_name || ' could not be processed. Please update your payment method.',
                'high',
                '/customer/payments/' || NEW.id,
                jsonb_build_object('payment_id', NEW.id, 'amount', NEW.amount, 'service_name', service_name)
            );
        END IF;
    END IF;

    -- Handle UPDATE (status changes)
    IF TG_OP = 'UPDATE' AND OLD.status != NEW.status THEN
        CASE NEW.status
            WHEN 'refunded' THEN
                -- Notify customer about refund
                PERFORM create_notification(
                    NEW.customer_id,
                    'payment',
                    'Refund Issued',
                    'A refund of $' || NEW.amount || ' has been issued for your ' || service_name,
                    'low',
                    '/customer/payments/' || NEW.id,
                    jsonb_build_object('payment_id', NEW.id, 'amount', NEW.amount, 'service_name', service_name)
                );
        END CASE;
    END IF;

    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- Review notification triggers
CREATE OR REPLACE FUNCTION handle_review_notifications()
RETURNS TRIGGER AS $$
DECLARE
    customer_name TEXT;
    provider_name TEXT;
    service_name TEXT;
BEGIN
    -- Get related data
    SELECT u.name INTO customer_name FROM users u WHERE u.id = NEW.customer_id;
    SELECT u.name INTO provider_name FROM users u WHERE u.id = NEW.provider_id;
    
    -- Get service name from booking if available
    IF NEW.booking_id IS NOT NULL THEN
        SELECT b.service_name INTO service_name FROM bookings b WHERE b.id = NEW.booking_id;
    END IF;
    service_name := COALESCE(service_name, 'service');

    -- Handle INSERT (new review)
    IF TG_OP = 'INSERT' THEN
        -- Notify provider about new review
        PERFORM create_notification(
            NEW.provider_id,
            'review',
            CASE 
                WHEN NEW.rating >= 4 THEN 'New ' || NEW.rating || '-Star Review!'
                ELSE 'New Review Received'
            END,
            COALESCE(customer_name, 'A customer') || ' left you a ' || NEW.rating || '-star review' ||
            CASE WHEN NEW.comment IS NOT NULL AND LENGTH(NEW.comment) > 0 
                 THEN ': "' || LEFT(NEW.comment, 100) || '"'
                 ELSE ''
            END,
            CASE WHEN NEW.rating >= 4 THEN 'low' ELSE 'medium' END,
            '/provider/reviews',
            jsonb_build_object('review_id', NEW.id, 'rating', NEW.rating, 'customer_name', customer_name, 'service_name', service_name)
        );
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- User registration/system notification triggers
CREATE OR REPLACE FUNCTION handle_user_notifications()
RETURNS TRIGGER AS $$
BEGIN
    -- Handle INSERT (new user registration)
    IF TG_OP = 'INSERT' THEN
        -- Send welcome notification
        PERFORM create_notification(
            NEW.id,
            'system',
            'Welcome to Hequeendo!',
            'Thank you for joining our platform. ' || 
            CASE NEW.role 
                WHEN 'customer' THEN 'Explore trusted services in your area and book with confidence.'
                WHEN 'provider' THEN 'Start offering your services and grow your business with us.'
                ELSE 'Welcome to the platform!'
            END,
            'low',
            CASE NEW.role 
                WHEN 'customer' THEN '/services'
                WHEN 'provider' THEN '/provider/services'
                ELSE '/'
            END,
            jsonb_build_object('welcome', true, 'user_role', NEW.role)
        );
    END IF;

    -- Handle UPDATE (profile verification, etc.)
    IF TG_OP = 'UPDATE' THEN
        -- Notify about verification completion
        IF OLD.verified = false AND NEW.verified = true THEN
            PERFORM create_notification(
                NEW.id,
                'system',
                'Profile Verification Complete',
                'Your identity verification has been completed successfully. ' ||
                CASE NEW.role 
                    WHEN 'customer' THEN 'You can now book premium services.'
                    WHEN 'provider' THEN 'You can now offer verified services.'
                    ELSE 'Your account is now verified.'
                END,
                'medium',
                CASE NEW.role 
                    WHEN 'customer' THEN '/services'
                    WHEN 'provider' THEN '/provider/services'
                    ELSE '/profile'
                END,
                jsonb_build_object('verification_type', 'identity', 'user_role', NEW.role)
            );
        END IF;
    END IF;

    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- Create triggers (only if tables exist)
-- Booking triggers
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'bookings') THEN
        DROP TRIGGER IF EXISTS booking_notifications_trigger ON bookings;
        CREATE TRIGGER booking_notifications_trigger
            AFTER INSERT OR UPDATE ON bookings
            FOR EACH ROW
            EXECUTE FUNCTION handle_booking_notifications();
    END IF;
END $$;

-- Payment triggers
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'payments') THEN
        DROP TRIGGER IF EXISTS payment_notifications_trigger ON payments;
        CREATE TRIGGER payment_notifications_trigger
            AFTER INSERT OR UPDATE ON payments
            FOR EACH ROW
            EXECUTE FUNCTION handle_payment_notifications();
    END IF;
END $$;

-- Review triggers
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'reviews') THEN
        DROP TRIGGER IF EXISTS review_notifications_trigger ON reviews;
        CREATE TRIGGER review_notifications_trigger
            AFTER INSERT ON reviews
            FOR EACH ROW
            EXECUTE FUNCTION handle_review_notifications();
    END IF;
END $$;

-- User triggers
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'users') THEN
        DROP TRIGGER IF EXISTS user_notifications_trigger ON users;
        CREATE TRIGGER user_notifications_trigger
            AFTER INSERT OR UPDATE ON users
            FOR EACH ROW
            EXECUTE FUNCTION handle_user_notifications();
    END IF;
END $$;
