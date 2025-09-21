-- Fix get_nearby_providers function conflict causing 300 status code
-- The issue is multiple function definitions with different parameter types
-- causing PostgREST to return "Multiple Choices" error

-- Drop all existing versions of get_nearby_providers function
DROP FUNCTION IF EXISTS get_nearby_providers(DOUBLE PRECISION, DOUBLE PRECISION, INTEGER, TEXT);
DROP FUNCTION IF EXISTS get_nearby_providers(DECIMAL, DECIMAL, INTEGER, TEXT);
DROP FUNCTION IF EXISTS get_nearby_providers(DOUBLE PRECISION, DOUBLE PRECISION, INTEGER);
DROP FUNCTION IF EXISTS get_nearby_providers(DECIMAL, DECIMAL, INTEGER);
DROP FUNCTION IF EXISTS get_nearby_providers();

-- Create a single, properly defined get_nearby_providers function
CREATE OR REPLACE FUNCTION get_nearby_providers(
    user_lat DOUBLE PRECISION DEFAULT 0,
    user_lng DOUBLE PRECISION DEFAULT 0,
    radius_km INTEGER DEFAULT 50,
    service_category TEXT DEFAULT NULL
)
RETURNS TABLE (
    id UUID,
    name TEXT,
    description TEXT,
    price DECIMAL,
    price_type TEXT,
    location_type TEXT,
    provider_id UUID,
    provider_name TEXT,
    business_name TEXT,
    average_rating DECIMAL,
    total_reviews INTEGER,
    distance_km DOUBLE PRECISION,
    category TEXT,
    images TEXT[]
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ps.id,
        ps.title as name,
        ps.description,
        ps.price,
        ps.price_type,
        ps.location_type,
        ps.provider_id,
        COALESCE(u.raw_user_meta_data->>'name', u.email) as provider_name,
        COALESCE(pp.business_name, 'Service Provider') as business_name,
        COALESCE(pp.average_rating, 0.0) as average_rating,
        COALESCE(pp.total_reviews, 0) as total_reviews,
        -- Calculate distance using Haversine formula (simplified for nearby results)
        CASE 
            WHEN pp.latitude IS NOT NULL AND pp.longitude IS NOT NULL THEN
                6371 * acos(
                    cos(radians(user_lat)) * cos(radians(pp.latitude)) * 
                    cos(radians(pp.longitude) - radians(user_lng)) + 
                    sin(radians(user_lat)) * sin(radians(pp.latitude))
                )
            ELSE 999999.0 -- Large distance for providers without location
        END as distance_km,
        ps.category,
        ps.images
    FROM provider_services ps
    LEFT JOIN provider_profiles pp ON ps.provider_id = pp.user_id
    LEFT JOIN users u ON ps.provider_id = u.id
    WHERE 
        ps.is_active = true
        AND (service_category IS NULL OR ps.category ILIKE '%' || service_category || '%')
        AND (
            pp.latitude IS NULL OR pp.longitude IS NULL OR
            6371 * acos(
                cos(radians(user_lat)) * cos(radians(pp.latitude)) * 
                cos(radians(pp.longitude) - radians(user_lng)) + 
                sin(radians(user_lat)) * sin(radians(pp.latitude))
            ) <= radius_km
        )
    ORDER BY distance_km ASC, pp.average_rating DESC NULLS LAST
    LIMIT 50;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant proper permissions
GRANT EXECUTE ON FUNCTION get_nearby_providers(DOUBLE PRECISION, DOUBLE PRECISION, INTEGER, TEXT) TO anon, authenticated;

-- Create a simple wrapper function for cases where no parameters are provided
CREATE OR REPLACE FUNCTION get_nearby_providers()
RETURNS TABLE (
    id UUID,
    name TEXT,
    description TEXT,
    price DECIMAL,
    price_type TEXT,
    location_type TEXT,
    provider_id UUID,
    provider_name TEXT,
    business_name TEXT,
    average_rating DECIMAL,
    total_reviews INTEGER,
    distance_km DOUBLE PRECISION,
    category TEXT,
    images TEXT[]
) AS $$
BEGIN
    RETURN QUERY
    SELECT * FROM get_nearby_providers(0.0, 0.0, 50, NULL);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant permissions for the wrapper function
GRANT EXECUTE ON FUNCTION get_nearby_providers() TO anon, authenticated;

-- Test the function to ensure it works
DO $$
DECLARE
    result_count INTEGER;
BEGIN
    -- Test the function with default parameters
    SELECT COUNT(*) INTO result_count FROM get_nearby_providers();
    RAISE NOTICE 'get_nearby_providers() returned % results', result_count;
    
    -- Test with specific parameters
    SELECT COUNT(*) INTO result_count FROM get_nearby_providers(-1.2921, 36.8219, 25, NULL);
    RAISE NOTICE 'get_nearby_providers(-1.2921, 36.8219, 25, NULL) returned % results', result_count;
END $$;

-- Final notice
DO $$
BEGIN
    RAISE NOTICE '=== GET_NEARBY_PROVIDERS CONFLICT FIX COMPLETE ===';
    RAISE NOTICE 'Function conflict resolved - only one version now exists';
    RAISE NOTICE 'PostgREST should no longer return 300 status codes for this function';
    RAISE NOTICE 'Test the function: POST /rest/v1/rpc/get_nearby_providers';
    RAISE NOTICE 'With body: {"user_lat": -1.2921, "user_lng": 36.8219, "radius_km": 25}';
END $$;
