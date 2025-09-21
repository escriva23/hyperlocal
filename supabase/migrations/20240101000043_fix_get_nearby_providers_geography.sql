-- Fix get_nearby_providers function to use PostGIS geography column
-- The provider_profiles table uses location GEOGRAPHY(POINT, 4326) instead of separate lat/lng columns

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

-- Create the corrected function using PostGIS geography
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
        COALESCE(u.name, u.email) as provider_name,
        COALESCE(pp.business_name, 'Service Provider') as business_name,
        COALESCE(pp.average_rating, 0.0) as average_rating,
        COALESCE(pp.total_reviews, 0) as total_reviews,
        -- Calculate distance using PostGIS geography functions
        CASE 
            WHEN pp.location IS NOT NULL THEN
                ST_Distance(
                    pp.location,
                    ST_GeogFromText('POINT(' || user_lng || ' ' || user_lat || ')')
                ) / 1000.0  -- Convert meters to kilometers
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
            pp.location IS NULL OR
            ST_DWithin(
                pp.location,
                ST_GeogFromText('POINT(' || user_lng || ' ' || user_lat || ')'),
                radius_km * 1000  -- Convert km to meters for PostGIS
            )
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

-- Create a helper function to add sample provider locations for testing
CREATE OR REPLACE FUNCTION add_sample_provider_locations()
RETURNS void AS $$
BEGIN
    -- Update a few provider profiles with sample Nairobi locations
    UPDATE provider_profiles 
    SET location = ST_GeogFromText('POINT(36.8219 -1.2921)')  -- Nairobi CBD
    WHERE user_id IN (
        SELECT id FROM users WHERE role = 'provider' LIMIT 1
    );
    
    UPDATE provider_profiles 
    SET location = ST_GeogFromText('POINT(36.7965 -1.3032)')  -- Westlands
    WHERE user_id IN (
        SELECT id FROM users WHERE role = 'provider' 
        AND id NOT IN (
            SELECT user_id FROM provider_profiles WHERE location IS NOT NULL
        )
        LIMIT 1
    );
    
    UPDATE provider_profiles 
    SET location = ST_GeogFromText('POINT(36.8906 -1.2634)')  -- Eastlands
    WHERE user_id IN (
        SELECT id FROM users WHERE role = 'provider' 
        AND id NOT IN (
            SELECT user_id FROM provider_profiles WHERE location IS NOT NULL
        )
        LIMIT 1
    );
    
    RAISE NOTICE 'Added sample locations to provider profiles for testing';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Add sample locations if there are providers without locations
DO $$
DECLARE
    providers_without_location INTEGER;
BEGIN
    SELECT COUNT(*) INTO providers_without_location
    FROM provider_profiles pp
    JOIN users u ON pp.user_id = u.id
    WHERE u.role = 'provider' AND pp.location IS NULL;
    
    IF providers_without_location > 0 THEN
        RAISE NOTICE 'Found % providers without location, adding sample locations...', providers_without_location;
        PERFORM add_sample_provider_locations();
    ELSE
        RAISE NOTICE 'All providers already have location data';
    END IF;
END $$;

-- Final verification and instructions
DO $$
DECLARE
    func_count INTEGER;
    providers_with_location INTEGER;
BEGIN
    SELECT COUNT(*) INTO func_count
    FROM pg_proc p
    JOIN pg_namespace n ON p.pronamespace = n.oid
    WHERE p.proname = 'get_nearby_providers'
    AND n.nspname = 'public';
    
    SELECT COUNT(*) INTO providers_with_location
    FROM provider_profiles pp
    JOIN users u ON pp.user_id = u.id
    WHERE u.role = 'provider' AND pp.location IS NOT NULL;
    
    RAISE NOTICE '=== GET_NEARBY_PROVIDERS GEOGRAPHY FIX COMPLETE ===';
    RAISE NOTICE 'Number of get_nearby_providers functions: %', func_count;
    RAISE NOTICE 'Providers with location data: %', providers_with_location;
    RAISE NOTICE 'Fixed to use PostGIS geography column instead of lat/lng columns';
    RAISE NOTICE 'Function should now work without column errors';
    RAISE NOTICE 'Test with: POST /rest/v1/rpc/get_nearby_providers';
    RAISE NOTICE 'Body: {"user_lat": -1.2921, "user_lng": 36.8219, "radius_km": 25}';
END $$;
