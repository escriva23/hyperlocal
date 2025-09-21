-- Create missing RPC functions for Mtaa Shares functionality

-- Function to get user's community rank
CREATE OR REPLACE FUNCTION get_user_community_rank(user_id UUID)
RETURNS TABLE (
    rank INTEGER,
    total_users INTEGER,
    percentile DECIMAL(5,2)
) AS $$
DECLARE
    user_rank INTEGER;
    total_count INTEGER;
    user_percentile DECIMAL(5,2);
BEGIN
    -- Get total number of users with shares
    SELECT COUNT(*) INTO total_count
    FROM public.mtaa_shares
    WHERE total_shares > 0;
    
    -- Get user's rank based on total shares
    WITH ranked_users AS (
        SELECT 
            ms.user_id,
            ROW_NUMBER() OVER (ORDER BY ms.total_shares DESC, ms.monthly_earnings DESC) as user_rank
        FROM public.mtaa_shares ms
        WHERE ms.total_shares > 0
    )
    SELECT ru.user_rank INTO user_rank
    FROM ranked_users ru
    WHERE ru.user_id = get_user_community_rank.user_id;
    
    -- Calculate percentile
    IF total_count > 0 AND user_rank IS NOT NULL THEN
        user_percentile := ((total_count - user_rank + 1)::DECIMAL / total_count::DECIMAL) * 100;
    ELSE
        user_percentile := 0.00;
        user_rank := total_count + 1;
    END IF;
    
    RETURN QUERY SELECT user_rank, total_count, user_percentile;
END;
$$ LANGUAGE plpgsql;

-- Function to search services (if missing)
CREATE OR REPLACE FUNCTION search_services(
    search_query TEXT DEFAULT '',
    user_lat DECIMAL DEFAULT NULL,
    user_lng DECIMAL DEFAULT NULL,
    max_distance_km INTEGER DEFAULT 50,
    min_rating DECIMAL DEFAULT NULL,
    max_price DECIMAL DEFAULT NULL,
    category_slug TEXT DEFAULT NULL
)
RETURNS TABLE (
    id UUID,
    title VARCHAR,
    description TEXT,
    price DECIMAL,
    price_type VARCHAR,
    provider_id UUID,
    category_id UUID,
    location_type VARCHAR,
    created_at TIMESTAMPTZ,
    provider_name VARCHAR,
    provider_rating DECIMAL,
    category_name VARCHAR,
    distance_km DECIMAL
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        s.id,
        s.title,
        s.description,
        s.price,
        s.price_type,
        s.provider_id,
        s.category_id,
        s.location_type,
        s.created_at,
        pp.business_name as provider_name,
        pp.average_rating as provider_rating,
        sc.name as category_name,
        0.0 as distance_km -- Placeholder for distance calculation
    FROM services s
    LEFT JOIN provider_profiles pp ON s.provider_id = pp.user_id
    LEFT JOIN service_categories sc ON s.category_id = sc.id
    WHERE 
        s.status = 'active'
        AND (search_query = '' OR s.title ILIKE '%' || search_query || '%' OR s.description ILIKE '%' || search_query || '%')
        AND (category_slug IS NULL OR sc.slug = category_slug)
        AND (max_price IS NULL OR s.price <= max_price)
        AND (min_rating IS NULL OR pp.average_rating >= min_rating)
    ORDER BY s.created_at DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to get nearby providers
CREATE OR REPLACE FUNCTION get_nearby_providers(
    user_lat DECIMAL DEFAULT 0,
    user_lng DECIMAL DEFAULT 0,
    radius_km INTEGER DEFAULT 50,
    service_category TEXT DEFAULT NULL
)
RETURNS TABLE (
    id UUID,
    name VARCHAR,
    description TEXT,
    price DECIMAL,
    price_type VARCHAR,
    provider_profiles JSONB,
    service_categories JSONB
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ps.id,
        ps.title as name,
        ps.description,
        ps.price,
        ps.price_type,
        jsonb_build_object(
            'business_name', pp.business_name,
            'average_rating', pp.average_rating,
            'total_reviews', pp.total_reviews,
            'users', jsonb_build_object('name', u.raw_user_meta_data->>'name')
        ) as provider_profiles,
        jsonb_build_object(
            'name', ps.category,
            'icon', '🔧'
        ) as service_categories
    FROM provider_services ps
    LEFT JOIN provider_profiles pp ON ps.provider_id = pp.user_id
    LEFT JOIN auth.users u ON ps.provider_id = u.id
    WHERE 
        ps.is_active = true
        AND (service_category IS NULL OR ps.category = service_category)
    ORDER BY ps.created_at DESC;
END;
$$ LANGUAGE plpgsql;
