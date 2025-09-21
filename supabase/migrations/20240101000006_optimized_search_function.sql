-- Enhanced search function with better performance
-- This function is separated to avoid dependency issues in the performance optimization migration

CREATE OR REPLACE FUNCTION search_services_optimized(
  search_query text DEFAULT '',
  user_lat double precision DEFAULT NULL,
  user_lng double precision DEFAULT NULL,
  max_distance_km double precision DEFAULT 50,
  min_rating double precision DEFAULT 0,
  max_price double precision DEFAULT NULL,
  category_slug text DEFAULT NULL,
  limit_results integer DEFAULT 20
)
RETURNS TABLE (
  service_id uuid,
  service_name text,
  service_description text,
  price numeric,
  price_type text,
  provider_id uuid,
  business_name text,
  average_rating numeric,
  total_reviews integer,
  distance_km double precision,
  relevance_score double precision
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
BEGIN
  -- Handle empty search query
  IF search_query IS NULL OR search_query = '' THEN
    search_query := '';
  END IF;

  RETURN QUERY
  SELECT 
    s.id as service_id,
    s.name as service_name,
    s.description as service_description,
    s.price,
    s.price_type::text,
    pp.user_id as provider_id,
    pp.business_name,
    COALESCE(pp.average_rating, 0.0) as average_rating,
    COALESCE(pp.total_reviews, 0) as total_reviews,
    CASE 
      WHEN user_lat IS NOT NULL AND user_lng IS NOT NULL AND pp.location IS NOT NULL
      THEN ST_Distance(
        ST_GeogFromText('POINT(' || user_lng || ' ' || user_lat || ')'),
        pp.location
      ) / 1000.0
      ELSE NULL
    END as distance_km,
    -- Enhanced relevance scoring
    (
      CASE WHEN search_query = '' THEN 1.0
           WHEN s.name ILIKE '%' || search_query || '%' THEN 3.0 
           ELSE 0.0 END +
      CASE WHEN search_query = '' THEN 0.0
           WHEN s.description ILIKE '%' || search_query || '%' THEN 2.0 
           ELSE 0.0 END +
      CASE WHEN search_query = '' THEN 0.0
           WHEN pp.business_name ILIKE '%' || search_query || '%' THEN 2.5 
           ELSE 0.0 END +
      CASE WHEN pp.average_rating IS NOT NULL THEN pp.average_rating / 5.0 ELSE 0.0 END +
      CASE WHEN pp.total_reviews > 10 THEN 0.5 ELSE 0.0 END
    ) as relevance_score
  FROM services s
  INNER JOIN provider_profiles pp ON s.provider_id = pp.user_id
  LEFT JOIN service_categories sc ON s.category_id = sc.id
  WHERE 
    s.status = 'active'
    AND pp.verification_status = 'verified'
    AND pp.is_available = true
    AND (
      search_query = '' OR
      s.name ILIKE '%' || search_query || '%' 
      OR s.description ILIKE '%' || search_query || '%'
      OR pp.business_name ILIKE '%' || search_query || '%'
    )
    AND (min_rating IS NULL OR COALESCE(pp.average_rating, 0) >= min_rating)
    AND (max_price IS NULL OR s.price <= max_price)
    AND (category_slug IS NULL OR sc.slug = category_slug)
    AND (
      user_lat IS NULL OR user_lng IS NULL OR pp.location IS NULL
      OR ST_DWithin(
        ST_GeogFromText('POINT(' || user_lng || ' ' || user_lat || ')'),
        pp.location,
        max_distance_km * 1000
      )
    )
  ORDER BY relevance_score DESC, COALESCE(pp.average_rating, 0) DESC, distance_km ASC NULLS LAST
  LIMIT limit_results;
END;
$$;

-- Add comment for the function
COMMENT ON FUNCTION search_services_optimized(text, double precision, double precision, double precision, double precision, double precision, text, integer) IS 'Optimized service search with enhanced relevance scoring and geospatial filtering';
