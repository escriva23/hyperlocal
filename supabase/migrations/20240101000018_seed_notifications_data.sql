-- Insert sample notifications for existing users
-- Note: Replace with actual user IDs from your auth.users table

-- Sample notifications for customer users
INSERT INTO notifications (user_id, type, title, message, priority, is_read, action_url, metadata) VALUES
-- Booking notifications
('550e8400-e29b-41d4-a716-446655440001', 'booking', 'Booking Confirmed', 'Your house cleaning service has been confirmed for tomorrow at 2:00 PM', 'high', false, '/customer/bookings/1', '{"service_id": "1", "provider_name": "Maria Santos"}'),
('550e8400-e29b-41d4-a716-446655440001', 'booking', 'Service Completed', 'Your plumbing repair service has been completed. Please rate your experience.', 'medium', false, '/customer/bookings/2/review', '{"service_id": "2", "provider_name": "John Smith"}'),

-- Payment notifications
('550e8400-e29b-41d4-a716-446655440001', 'payment', 'Payment Processed', 'Payment of $75.00 has been successfully processed for your cleaning service', 'medium', false, null, '{"amount": 75.00, "service": "House Cleaning"}'),
('550e8400-e29b-41d4-a716-446655440001', 'payment', 'Refund Issued', 'A refund of $25.00 has been issued for your cancelled appointment', 'low', true, null, '{"amount": 25.00, "reason": "Service cancelled"}'),

-- Review notifications
('550e8400-e29b-41d4-a716-446655440001', 'review', 'Please Rate Your Service', 'How was your experience with HandyFix Services? Your feedback helps others.', 'low', true, '/customer/bookings/3/review', '{"service_id": "3", "provider_name": "HandyFix Services"}'),

-- System notifications
('550e8400-e29b-41d4-a716-446655440001', 'system', 'Profile Verification Complete', 'Your identity verification has been completed successfully. You can now book premium services.', 'medium', true, null, '{"verification_type": "identity"}'),
('550e8400-e29b-41d4-a716-446655440001', 'system', 'Welcome to Hequeendo!', 'Thank you for joining our platform. Explore trusted services in your area.', 'low', true, '/services', '{"welcome": true}'),

-- Message notifications
('550e8400-e29b-41d4-a716-446655440001', 'message', 'New Message from Provider', 'John from HandyFix Services sent you a message about your upcoming repair.', 'medium', false, '/messages/john-handyfix', '{"sender": "John Smith", "provider_id": "handyfix-services"}'),

-- Sample notifications for provider users
('550e8400-e29b-41d4-a716-446655440002', 'booking', 'New Booking Request', 'You have a new booking request for house cleaning on Friday at 10:00 AM', 'high', false, '/provider/bookings/pending', '{"customer_name": "Sarah Johnson", "service": "House Cleaning"}'),
('550e8400-e29b-41d4-a716-446655440002', 'booking', 'Booking Cancelled', 'Your Tuesday appointment has been cancelled by the customer', 'medium', false, '/provider/bookings/cancelled', '{"customer_name": "Mike Davis", "reason": "Schedule conflict"}'),

-- Payment notifications for providers
('550e8400-e29b-41d4-a716-446655440002', 'payment', 'Payment Received', 'You received $120.00 for your electrical repair service', 'medium', false, '/provider/earnings', '{"amount": 120.00, "service": "Electrical Repair"}'),
('550e8400-e29b-41d4-a716-446655440002', 'payment', 'Weekly Payout Processed', 'Your weekly earnings of $450.00 have been transferred to your account', 'low', true, '/provider/earnings', '{"amount": 450.00, "period": "week"}'),

-- Review notifications for providers
('550e8400-e29b-41d4-a716-446655440002', 'review', 'New 5-Star Review!', 'Sarah Johnson left you a 5-star review: "Excellent service, very professional!"', 'low', false, '/provider/reviews', '{"rating": 5, "customer": "Sarah Johnson"}'),

-- System notifications for providers
('550e8400-e29b-41d4-a716-446655440002', 'system', 'Service Verification Approved', 'Your plumbing service has been verified and is now live on the platform', 'medium', true, '/provider/services', '{"service": "Plumbing", "status": "approved"}'),
('550e8400-e29b-41d4-a716-446655440002', 'system', 'Monthly Performance Report', 'Your monthly performance report is ready. You completed 15 services this month.', 'low', true, '/provider/analytics', '{"services_completed": 15, "month": "current"}');

-- Create a function to generate notifications for new bookings
CREATE OR REPLACE FUNCTION create_booking_notification()
RETURNS TRIGGER AS $$
BEGIN
    -- Notify customer about booking confirmation
    IF NEW.status = 'confirmed' AND OLD.status != 'confirmed' THEN
        INSERT INTO notifications (user_id, type, title, message, priority, is_read, action_url, metadata)
        VALUES (
            NEW.customer_id,
            'booking',
            'Booking Confirmed',
            'Your service booking has been confirmed for ' || TO_CHAR(NEW.scheduled_date, 'Day, Month DD at HH:MI AM'),
            'high',
            false,
            '/customer/bookings/' || NEW.id,
            jsonb_build_object('booking_id', NEW.id, 'service_name', NEW.service_name)
        );
    END IF;

    -- Notify provider about new booking request
    IF NEW.status = 'pending' AND OLD IS NULL THEN
        INSERT INTO notifications (user_id, type, title, message, priority, is_read, action_url, metadata)
        VALUES (
            NEW.provider_id,
            'booking',
            'New Booking Request',
            'You have a new booking request for ' || NEW.service_name,
            'high',
            false,
            '/provider/bookings/pending',
            jsonb_build_object('booking_id', NEW.id, 'customer_name', NEW.customer_name)
        );
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Note: Uncomment the trigger below if you have a bookings table
-- CREATE TRIGGER booking_notification_trigger
--     AFTER INSERT OR UPDATE ON bookings
--     FOR EACH ROW
--     EXECUTE FUNCTION create_booking_notification();
