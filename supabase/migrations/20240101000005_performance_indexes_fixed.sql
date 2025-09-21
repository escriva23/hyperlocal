-- Additional Performance Indexes (Non-duplicates only)
-- Note: Basic indexes are already created in the main performance optimization file

-- Additional specialized indexes for advanced queries
CREATE INDEX IF NOT EXISTS idx_bookings_time_range ON bookings(booking_time, status) WHERE status IN ('confirmed', 'in_progress');
CREATE INDEX IF NOT EXISTS idx_services_price_range ON services(price, status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_reviews_recent ON reviews(created_at, rating);
CREATE INDEX IF NOT EXISTS idx_transactions_recent ON transactions(created_at, status, type);
CREATE INDEX IF NOT EXISTS idx_notifications_priority ON notifications(created_at, type) WHERE is_read = false;

-- Indexes for reporting and analytics
CREATE INDEX IF NOT EXISTS idx_bookings_monthly_stats ON bookings(created_at, status, provider_id) WHERE status = 'completed';
CREATE INDEX IF NOT EXISTS idx_provider_performance ON provider_profiles(verification_status, average_rating, total_reviews) WHERE is_available = true;
