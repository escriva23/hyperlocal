-- Fix get_nearby_providers function with correct users table schema
-- The previous version tried to use raw_user_meta_data which doesn't exist
-- Our users table has a 'name' column directly

-- Drop ALL versions of get_nearby_providers by OID to ensure complete removal
DO $$
DECLARE
    func_record RECORD;
BEGIN
    RAISE NOTICE 'Dropping all get_nearby_providers functions...';
    
    FOR func_record IN 
        SELECT 
            p.oid,
            p.proname,
            pg_get_function_identity_arguments(p.oid) as args
        FROM pg_proc p
        JOIN pg_namespace n ON p.pronamespace = n.oid
        WHERE p.proname = 'get_nearby_providers'
        AND n.nspname = 'public'
    LOOP
        RAISE NOTICE 'Dropping function: % with args: %', func_record.proname, func_record.args;
        EXECUTE 'DROP FUNCTION IF EXISTS ' || func_record.oid::regprocedure || ' CASCADE';
    END LOOP;
    
    RAISE NOTICE 'All get_nearby_providers functions dropped.';
END $$;

-- Create the corrected function with proper users table schema
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
        COALESCE(u.name, u.email) as provider_name,  -- Fixed: use u.name instead of raw_user_meta_data
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

-- Test the function to ensure it works
DO $$
DECLARE
    result_count INTEGER;
BEGIN
    -- Test the function with explicit parameters
    SELECT COUNT(*) INTO result_count FROM get_nearby_providers(0.0, 0.0, 50, NULL);
    RAISE NOTICE 'get_nearby_providers(0.0, 0.0, 50, NULL) returned % results', result_count;
    
    -- Test with Nairobi coordinates
    SELECT COUNT(*) INTO result_count FROM get_nearby_providers(-1.2921, 36.8219, 25, NULL);
    RAISE NOTICE 'get_nearby_providers(-1.2921, 36.8219, 25, NULL) returned % results', result_count;
    
    -- Test with a specific category
    SELECT COUNT(*) INTO result_count FROM get_nearby_providers(-1.2921, 36.8219, 25, 'cleaning');
    RAISE NOTICE 'get_nearby_providers(-1.2921, 36.8219, 25, ''cleaning'') returned % results', result_count;
END $$;

-- Final verification and instructions
DO $$
DECLARE
    func_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO func_count
    FROM pg_proc p
    JOIN pg_namespace n ON p.pronamespace = n.oid
    WHERE p.proname = 'get_nearby_providers'
    AND n.nspname = 'public';
    
    RAISE NOTICE '=== GET_NEARBY_PROVIDERS SCHEMA FIX COMPLETE ===';
    RAISE NOTICE 'Number of get_nearby_providers functions: %', func_count;
    RAISE NOTICE 'Fixed to use users.name instead of raw_user_meta_data';
    RAISE NOTICE 'Function should now work without column errors';
    RAISE NOTICE 'Test with: POST /rest/v1/rpc/get_nearby_providers';
    RAISE NOTICE 'Body: {"user_lat": -1.2921, "user_lng": 36.8219, "radius_km": 25}';
END $$;
