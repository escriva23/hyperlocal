-- Function to get trending services
-- Separated from performance optimizations to avoid dependency issues

CREATE OR REPLACE FUNCTION get_trending_services(
  days_back integer DEFAULT 7,
  limit_results integer DEFAULT 10
)
RETURNS TABLE (
  service_id uuid,
  service_name text,
  provider_name text,
  booking_count bigint,
  average_rating numeric,
  price numeric
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
BEGIN
  RETURN QUERY
  SELECT 
    s.id as service_id,
    s.name as service_name,
    pp.business_name as provider_name,
    COUNT(b.id) as booking_count,
    pp.average_rating,
    s.price
  FROM services s
  INNER JOIN provider_profiles pp ON s.provider_id = pp.user_id
  INNER JOIN bookings b ON s.id = b.service_id
  WHERE 
    s.status = 'active'
    AND pp.verification_status = 'verified'
    AND b.created_at >= NOW() - INTERVAL '1 day' * days_back
    AND b.status IN ('confirmed', 'completed')
  GROUP BY s.id, s.name, pp.business_name, pp.average_rating, s.price
  ORDER BY booking_count DESC, pp.average_rating DESC NULLS LAST
  LIMIT limit_results;
END;
$$;

-- Add comment for the function
COMMENT ON FUNCTION get_trending_services(integer, integer) IS 'Returns trending services based on recent bookings';
