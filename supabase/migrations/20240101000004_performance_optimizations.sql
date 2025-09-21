-- Performance and Security Optimizations

-- Additional indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_bookings_customer_status ON bookings(customer_id, status);
CREATE INDEX IF NOT EXISTS idx_bookings_provider_status ON bookings(provider_id, status);
CREATE INDEX IF NOT EXISTS idx_bookings_booking_time ON bookings(booking_time);
CREATE INDEX IF NOT EXISTS idx_services_category_status ON services(category_id, status);
CREATE INDEX IF NOT EXISTS idx_services_provider_status ON services(provider_id, status);
CREATE INDEX IF NOT EXISTS idx_reviews_provider_rating ON reviews(provider_id, rating);
CREATE INDEX IF NOT EXISTS idx_transactions_user_type ON transactions(user_id, type);
CREATE INDEX IF NOT EXISTS idx_transactions_status_created ON transactions(status, created_at);
CREATE INDEX IF NOT EXISTS idx_notifications_user_read ON notifications(user_id, is_read);
CREATE INDEX IF NOT EXISTS idx_provider_profiles_location ON provider_profiles USING GIST(location);
CREATE INDEX IF NOT EXISTS idx_profiles_location ON profiles USING GIST(location);

-- Composite indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_services_search ON services(status, category_id, price) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_bookings_dashboard ON bookings(customer_id, status, created_at) WHERE status IN ('pending', 'confirmed', 'completed');
CREATE INDEX IF NOT EXISTS idx_provider_availability ON provider_profiles(is_available, verification_status) WHERE is_available = true AND verification_status = 'verified';

-- Partial indexes for better performance on filtered queries
CREATE INDEX IF NOT EXISTS idx_active_services ON services(created_at) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_verified_providers ON provider_profiles(average_rating, total_reviews) WHERE verification_status = 'verified';
CREATE INDEX IF NOT EXISTS idx_unread_notifications ON notifications(created_at) WHERE is_read = false;

-- Function to clean up old notifications (older than 30 days)
CREATE OR REPLACE FUNCTION cleanup_old_notifications()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  DELETE FROM notifications 
  WHERE created_at < NOW() - INTERVAL '30 days' 
  AND is_read = true;
END;
$$;

-- Function to update provider statistics (to be called periodically)
CREATE OR REPLACE FUNCTION update_provider_statistics()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  -- Update provider profiles with latest statistics
  UPDATE provider_profiles 
  SET 
    total_bookings = (
      SELECT COUNT(*) 
      FROM bookings 
      WHERE provider_id = provider_profiles.user_id
    ),
    average_rating = (
      SELECT ROUND(AVG(rating), 2) 
      FROM reviews 
      WHERE provider_id = provider_profiles.user_id
    ),
    total_reviews = (
      SELECT COUNT(*) 
      FROM reviews 
      WHERE provider_id = provider_profiles.user_id
    ),
    updated_at = NOW()
  WHERE EXISTS (
    SELECT 1 FROM bookings WHERE provider_id = provider_profiles.user_id
    OR EXISTS (SELECT 1 FROM reviews WHERE provider_id = provider_profiles.user_id)
  );
END;
$$;

-- Function to archive old completed bookings (older than 1 year)
CREATE OR REPLACE FUNCTION archive_old_bookings()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  -- Create archive table if it doesn't exist
  CREATE TABLE IF NOT EXISTS bookings_archive (LIKE bookings INCLUDING ALL);
  
  -- Move old completed bookings to archive
  WITH old_bookings AS (
    DELETE FROM bookings 
    WHERE status = 'completed' 
    AND actual_end_time < NOW() - INTERVAL '1 year'
    RETURNING *
  )
  INSERT INTO bookings_archive SELECT * FROM old_bookings;
END;
$$;

-- Note: search_services_optimized function moved to separate migration file (20240101000006_optimized_search_function.sql)
-- to avoid dependency issues during migration execution

-- Note: get_trending_services function moved to separate migration file (20240101000007_trending_services_function.sql)
-- to avoid dependency issues during migration execution

-- Create materialized view for dashboard statistics (refresh periodically)
CREATE MATERIALIZED VIEW IF NOT EXISTS dashboard_stats_cache AS
SELECT 
  'customer' as user_type,
  u.id as user_id,
  COUNT(CASE WHEN b.status = 'completed' THEN 1 END)::integer as completed_bookings,
  COUNT(CASE WHEN b.status IN ('pending', 'confirmed') THEN 1 END)::integer as active_bookings,
  COUNT(CASE WHEN b.status = 'completed' AND r.id IS NULL THEN 1 END)::integer as pending_reviews,
  COALESCE(w.balance, 0.00) as wallet_balance
FROM users u
LEFT JOIN bookings b ON u.id = b.customer_id
LEFT JOIN reviews r ON b.id = r.booking_id
LEFT JOIN wallets w ON u.id = w.user_id
WHERE u.role = 'customer'
GROUP BY u.id, w.balance

UNION ALL

SELECT 
  'provider' as user_type,
  u.id as user_id,
  COUNT(CASE WHEN b.status = 'completed' THEN 1 END)::integer as completed_bookings,
  COUNT(CASE WHEN b.status IN ('pending', 'confirmed') THEN 1 END)::integer as active_bookings,
  COUNT(s.id)::integer as total_services,
  COALESCE(w.balance, 0.00) as wallet_balance
FROM users u
LEFT JOIN bookings b ON u.id = b.provider_id
LEFT JOIN services s ON u.id = s.provider_id AND s.status = 'active'
LEFT JOIN wallets w ON u.id = w.user_id
WHERE u.role = 'provider'
GROUP BY u.id, w.balance;

-- Create unique index on materialized view
CREATE UNIQUE INDEX IF NOT EXISTS idx_dashboard_stats_cache_user ON dashboard_stats_cache(user_type, user_id);

-- Function to refresh dashboard stats cache
CREATE OR REPLACE FUNCTION refresh_dashboard_stats_cache()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  REFRESH MATERIALIZED VIEW CONCURRENTLY dashboard_stats_cache;
END;
$$;

-- Note: validate_phone_number function moved to separate migration file (20240101000008_phone_validation_function.sql)
-- to avoid dependency issues during migration execution

-- Note: log_security_event function and security_logs table moved to separate migration file (20240101000009_security_logging_function.sql)
-- to avoid dependency issues during migration execution

-- Comment moved to separate migration file with table definition
COMMENT ON FUNCTION cleanup_old_notifications() IS 'Cleans up read notifications older than 30 days';
COMMENT ON FUNCTION update_provider_statistics() IS 'Updates provider statistics - run periodically';
COMMENT ON FUNCTION archive_old_bookings() IS 'Archives completed bookings older than 1 year';
-- Comment moved to separate migration file with function definition
-- Comment moved to separate migration file with function definition
COMMENT ON MATERIALIZED VIEW dashboard_stats_cache IS 'Cached dashboard statistics for better performance';
-- Comment moved to separate migration file with function definition
-- Comment moved to separate migration file with function definition
