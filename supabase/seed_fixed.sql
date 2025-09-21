-- Fixed seed file that works with Supabase authentication
-- This file creates sample data without directly inserting into auth.users
-- Users should be created through the Supabase Auth API or dashboard

-- Insert sample service categories
INSERT INTO service_categories (name, description, icon, slug, is_active, sort_order) VALUES
('Home Cleaning', 'Professional home cleaning services', 'home', 'home-cleaning', true, 1),
('Plumbing', 'Plumbing repairs and installations', 'droplet', 'plumbing', true, 2),
('Electrical', 'Electrical repairs and installations', 'zap', 'electrical', true, 3),
('Gardening', 'Garden maintenance and landscaping', 'leaf', 'gardening', true, 4),
('Carpentry', 'Furniture and woodwork services', 'hammer', 'carpentry', true, 5),
('Painting', 'Interior and exterior painting', 'palette', 'painting', true, 6),
('Tutoring', 'Academic tutoring and lessons', 'book', 'tutoring', true, 7),
('Beauty & Wellness', 'Beauty treatments and wellness services', 'scissors', 'beauty-wellness', true, 8),
('Pet Care', 'Pet grooming and care services', 'heart', 'pet-care', true, 9),
('Delivery', 'Package and food delivery services', 'car', 'delivery', true, 10),
('Photography', 'Professional photography and videography', 'camera', 'photography', true, 11),
('Catering', 'Food preparation and catering services', 'chef-hat', 'catering', true, 12),
('Security', 'Security and protection services', 'shield', 'security', true, 13),
('Tech Support', 'Computer and technology assistance', 'monitor', 'tech-support', true, 14),
('Event Planning', 'Event organization and planning', 'calendar', 'event-planning', true, 15)
ON CONFLICT (slug) DO NOTHING;

-- Insert sample neighborhoods
INSERT INTO neighborhoods (name, description, city, country, center_point, is_active) VALUES
('Westlands', 'Business and residential area in Nairobi', 'Nairobi', 'Kenya', ST_GeogFromText('POINT(36.8097 -1.2676)'), true),
('Karen', 'Upmarket residential area', 'Nairobi', 'Kenya', ST_GeogFromText('POINT(36.6853 -1.3197)'), true),
('Kilimani', 'Mixed residential and commercial area', 'Nairobi', 'Kenya', ST_GeogFromText('POINT(36.7833 -1.2833)'), true),
('Lavington', 'Residential area with shopping centers', 'Nairobi', 'Kenya', ST_GeogFromText('POINT(36.7667 -1.2833)'), true),
('Kileleshwa', 'Residential area near the city center', 'Nairobi', 'Kenya', ST_GeogFromText('POINT(36.7833 -1.2667)'), true)
ON CONFLICT (name, city, country) DO NOTHING;

-- Insert sample FAQs with proper columns
INSERT INTO faqs (question, answer, category, is_published, helpful_count, sort_order) VALUES
('How do I book a service?', 'You can book a service by browsing our categories, selecting a provider, and clicking the "Book Now" button. Follow the prompts to complete your booking.', 'booking', true, 15, 1),
('How do I pay for services?', 'We accept M-Pesa, credit/debit cards, and wallet payments. You can choose your preferred payment method during checkout.', 'payment', true, 12, 2),
('What if I need to cancel my booking?', 'You can cancel your booking up to 2 hours before the scheduled time. Go to "My Bookings" and click "Cancel" on the relevant booking.', 'booking', true, 8, 3),
('How do I become a service provider?', 'Click on "Become a Provider" in the app, complete the registration form, upload required documents, and wait for verification.', 'provider', true, 20, 4),
('What is Mtaa Shares?', 'Mtaa Shares is our equity program where providers earn shares in the platform based on their performance and bookings completed.', 'mtaa-shares', true, 25, 5),
('How do I contact customer support?', 'You can reach our support team through the in-app chat, email at support@hequeendo.com, or phone at +254 700 000 000.', 'support', true, 18, 6),
('What icons are used for services?', 'Each service has a visual icon to help you quickly identify the type of service. Icons are automatically assigned based on service names and categories.', 'general', true, 5, 7),
('Can I filter services by category?', 'Yes, you can browse services by category using the category icons on the main page, or use the search function with filters.', 'search', true, 10, 8)
ON CONFLICT (question) DO NOTHING;

-- Note: To create sample users with services, you need to:
-- 1. Create users through Supabase Auth (signup API or dashboard)
-- 2. Then run additional SQL to create their profiles and services
-- 3. This approach ensures proper authentication integration

-- Create a function to help setup sample data after user creation
CREATE OR REPLACE FUNCTION create_sample_provider_data(
  user_id UUID,
  business_name TEXT,
  description TEXT,
  category_slug TEXT
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  category_id UUID;
BEGIN
  -- Get category ID
  SELECT id INTO category_id FROM service_categories WHERE slug = category_slug;
  
  -- Create provider profile
  INSERT INTO provider_profiles (
    user_id, business_name, description, verification_status, 
    location, is_available
  ) VALUES (
    user_id, business_name, description, 'verified',
    ST_GeogFromText('POINT(36.8219 -1.2921)'), true
  ) ON CONFLICT (user_id) DO NOTHING;
  
  -- Create wallet
  INSERT INTO wallets (user_id, balance) VALUES (user_id, 0.00)
  ON CONFLICT (user_id) DO NOTHING;
  
  -- Create mtaa shares
  INSERT INTO mtaa_shares (user_id, shares_earned, shares_value) VALUES (user_id, 0.00, 0.00)
  ON CONFLICT (user_id) DO NOTHING;
  
END;
$$;

-- Create a function to help setup sample customer data
CREATE OR REPLACE FUNCTION create_sample_customer_data(
  user_id UUID,
  address TEXT DEFAULT 'Nairobi, Kenya',
  initial_balance DECIMAL(10,2) DEFAULT 1000.00
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  -- Create profile
  INSERT INTO profiles (
    user_id, address, city, country, location
  ) VALUES (
    user_id, address, 'Nairobi', 'Kenya',
    ST_GeogFromText('POINT(36.8097 -1.2676)')
  ) ON CONFLICT (user_id) DO NOTHING;
  
  -- Create wallet with initial balance
  INSERT INTO wallets (user_id, balance) VALUES (user_id, initial_balance)
  ON CONFLICT (user_id) DO NOTHING;
  
END;
$$;

COMMENT ON FUNCTION create_sample_provider_data(UUID, TEXT, TEXT, TEXT) IS 'Helper function to create sample provider data after user authentication';
COMMENT ON FUNCTION create_sample_customer_data(UUID, TEXT, DECIMAL) IS 'Helper function to create sample customer data after user authentication';
