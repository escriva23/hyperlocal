-- Create sample users first (providers, customers, and admin)
-- Note: For production, create users through the Supabase Auth system first
-- This approach creates users directly in the auth.users and users tables for development/testing

-- First, create entries in auth.users table (required for foreign key constraint)
INSERT INTO auth.users (id, email, encrypted_password, email_confirmed_at, created_at, updated_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, role, aud) VALUES
('00000000-0000-0000-0000-000000000001', 'cleaner@hequeendo.com', crypt('password123', gen_salt('bf')), NOW(), NOW(), NOW(), '{"provider": "email", "providers": ["email"]}', '{}', false, 'authenticated', 'authenticated'),
('00000000-0000-0000-0000-000000000002', 'plumber@hequeendo.com', crypt('password123', gen_salt('bf')), NOW(), NOW(), NOW(), '{"provider": "email", "providers": ["email"]}', '{}', false, 'authenticated', 'authenticated'),
('00000000-0000-0000-0000-000000000003', 'electrician@hequeendo.com', crypt('password123', gen_salt('bf')), NOW(), NOW(), NOW(), '{"provider": "email", "providers": ["email"]}', '{}', false, 'authenticated', 'authenticated'),
('00000000-0000-0000-0000-000000000004', 'gardener@hequeendo.com', crypt('password123', gen_salt('bf')), NOW(), NOW(), NOW(), '{"provider": "email", "providers": ["email"]}', '{}', false, 'authenticated', 'authenticated'),
('00000000-0000-0000-0000-000000000005', 'carpenter@hequeendo.com', crypt('password123', gen_salt('bf')), NOW(), NOW(), NOW(), '{"provider": "email", "providers": ["email"]}', '{}', false, 'authenticated', 'authenticated'),
('00000000-0000-0000-0000-000000000006', 'painter@hequeendo.com', crypt('password123', gen_salt('bf')), NOW(), NOW(), NOW(), '{"provider": "email", "providers": ["email"]}', '{}', false, 'authenticated', 'authenticated'),
('00000000-0000-0000-0000-000000000007', 'tutor@hequeendo.com', crypt('password123', gen_salt('bf')), NOW(), NOW(), NOW(), '{"provider": "email", "providers": ["email"]}', '{}', false, 'authenticated', 'authenticated'),
('00000000-0000-0000-0000-000000000008', 'beauty@hequeendo.com', crypt('password123', gen_salt('bf')), NOW(), NOW(), NOW(), '{"provider": "email", "providers": ["email"]}', '{}', false, 'authenticated', 'authenticated'),
('00000000-0000-0000-0000-000000000009', 'petcare@hequeendo.com', crypt('password123', gen_salt('bf')), NOW(), NOW(), NOW(), '{"provider": "email", "providers": ["email"]}', '{}', false, 'authenticated', 'authenticated'),
('00000000-0000-0000-0000-000000000010', 'delivery@hequeendo.com', crypt('password123', gen_salt('bf')), NOW(), NOW(), NOW(), '{"provider": "email", "providers": ["email"]}', '{}', false, 'authenticated', 'authenticated'),
('00000000-0000-0000-0000-000000000011', 'photographer@hequeendo.com', crypt('password123', gen_salt('bf')), NOW(), NOW(), NOW(), '{"provider": "email", "providers": ["email"]}', '{}', false, 'authenticated', 'authenticated'),
('00000000-0000-0000-0000-000000000012', 'caterer@hequeendo.com', crypt('password123', gen_salt('bf')), NOW(), NOW(), NOW(), '{"provider": "email", "providers": ["email"]}', '{}', false, 'authenticated', 'authenticated'),
('00000000-0000-0000-0000-000000000013', 'security@hequeendo.com', crypt('password123', gen_salt('bf')), NOW(), NOW(), NOW(), '{"provider": "email", "providers": ["email"]}', '{}', false, 'authenticated', 'authenticated'),
('00000000-0000-0000-0000-000000000014', 'techsupport@hequeendo.com', crypt('password123', gen_salt('bf')), NOW(), NOW(), NOW(), '{"provider": "email", "providers": ["email"]}', '{}', false, 'authenticated', 'authenticated'),
('00000000-0000-0000-0000-000000000015', 'eventplanner@hequeendo.com', crypt('password123', gen_salt('bf')), NOW(), NOW(), NOW(), '{"provider": "email", "providers": ["email"]}', '{}', false, 'authenticated', 'authenticated'),
('00000000-0000-0000-0000-000000000101', 'john.doe@example.com', crypt('password123', gen_salt('bf')), NOW(), NOW(), NOW(), '{"provider": "email", "providers": ["email"]}', '{}', false, 'authenticated', 'authenticated'),
('00000000-0000-0000-0000-000000000102', 'jane.smith@example.com', crypt('password123', gen_salt('bf')), NOW(), NOW(), NOW(), '{"provider": "email", "providers": ["email"]}', '{}', false, 'authenticated', 'authenticated'),
('00000000-0000-0000-0000-000000000103', 'mike.johnson@example.com', crypt('password123', gen_salt('bf')), NOW(), NOW(), NOW(), '{"provider": "email", "providers": ["email"]}', '{}', false, 'authenticated', 'authenticated'),
('00000000-0000-0000-0000-000000000104', 'sarah.wilson@example.com', crypt('password123', gen_salt('bf')), NOW(), NOW(), NOW(), '{"provider": "email", "providers": ["email"]}', '{}', false, 'authenticated', 'authenticated'),
('00000000-0000-0000-0000-000000000105', 'david.brown@example.com', crypt('password123', gen_salt('bf')), NOW(), NOW(), NOW(), '{"provider": "email", "providers": ["email"]}', '{}', false, 'authenticated', 'authenticated'),
('00000000-0000-0000-0000-000000000099', 'admin@hequeendo.com', crypt('password123', gen_salt('bf')), NOW(), NOW(), NOW(), '{"provider": "email", "providers": ["email"]}', '{}', false, 'authenticated', 'authenticated');

-- Now create sample provider users
INSERT INTO users (id, email, name, role, phone, is_verified, is_active) VALUES
('00000000-0000-0000-0000-000000000001', 'cleaner@hequeendo.com', 'Professional Cleaners Ltd', 'provider', '254700000001', true, true),
('00000000-0000-0000-0000-000000000002', 'plumber@hequeendo.com', 'Nairobi Plumbing Services', 'provider', '254700000002', true, true),
('00000000-0000-0000-0000-000000000003', 'electrician@hequeendo.com', 'PowerFix Electrical', 'provider', '254700000003', true, true),
('00000000-0000-0000-0000-000000000004', 'gardener@hequeendo.com', 'Green Thumb Gardens', 'provider', '254700000004', true, true),
('00000000-0000-0000-0000-000000000005', 'carpenter@hequeendo.com', 'Master Carpentry Works', 'provider', '254700000005', true, true),
('00000000-0000-0000-0000-000000000006', 'painter@hequeendo.com', 'Color Perfect Painting', 'provider', '254700000006', true, true),
('00000000-0000-0000-0000-000000000007', 'tutor@hequeendo.com', 'Academic Excellence Tutors', 'provider', '254700000007', true, true),
('00000000-0000-0000-0000-000000000008', 'beauty@hequeendo.com', 'Beauty & Wellness Hub', 'provider', '254700000008', true, true),
('00000000-0000-0000-0000-000000000009', 'petcare@hequeendo.com', 'Happy Pets Care', 'provider', '254700000009', true, true),
('00000000-0000-0000-0000-000000000010', 'delivery@hequeendo.com', 'Swift Delivery Services', 'provider', '254700000010', true, true),
('00000000-0000-0000-0000-000000000011', 'photographer@hequeendo.com', 'Capture Moments Photography', 'provider', '254700000011', true, true),
('00000000-0000-0000-0000-000000000012', 'caterer@hequeendo.com', 'Delicious Catering Co', 'provider', '254700000012', true, true),
('00000000-0000-0000-0000-000000000013', 'security@hequeendo.com', 'SecureGuard Services', 'provider', '254700000013', true, true),
('00000000-0000-0000-0000-000000000014', 'techsupport@hequeendo.com', 'TechFix Solutions', 'provider', '254700000014', true, true),
('00000000-0000-0000-0000-000000000015', 'eventplanner@hequeendo.com', 'Perfect Events Planning', 'provider', '254700000015', true, true);

-- Create sample customer users
INSERT INTO users (id, email, name, role, phone, is_verified, is_active) VALUES
('00000000-0000-0000-0000-000000000101', 'john.doe@example.com', 'John Doe', 'customer', '254700000101', true, true),
('00000000-0000-0000-0000-000000000102', 'jane.smith@example.com', 'Jane Smith', 'customer', '254700000102', true, true),
('00000000-0000-0000-0000-000000000103', 'mike.johnson@example.com', 'Mike Johnson', 'customer', '254700000103', true, true),
('00000000-0000-0000-0000-000000000104', 'sarah.wilson@example.com', 'Sarah Wilson', 'customer', '254700000104', true, true),
('00000000-0000-0000-0000-000000000105', 'david.brown@example.com', 'David Brown', 'customer', '254700000105', true, true);

-- Create admin user
INSERT INTO users (id, email, name, role, phone, is_verified, is_active) VALUES
('00000000-0000-0000-0000-000000000099', 'admin@hequeendo.com', 'Admin User', 'admin', '254700000099', true, true);

-- Create provider profiles for all providers
INSERT INTO provider_profiles (user_id, business_name, description, verification_status, location, is_available) VALUES
('00000000-0000-0000-0000-000000000001', 'Professional Cleaners Ltd', 'Expert cleaning services for homes and offices', 'verified', ST_GeogFromText('POINT(36.8219 -1.2921)'), true),
('00000000-0000-0000-0000-000000000002', 'Nairobi Plumbing Services', 'Reliable plumbing repairs and installations', 'verified', ST_GeogFromText('POINT(36.8219 -1.2921)'), true),
('00000000-0000-0000-0000-000000000003', 'PowerFix Electrical', 'Licensed electrical contractors', 'verified', ST_GeogFromText('POINT(36.8219 -1.2921)'), true),
('00000000-0000-0000-0000-000000000004', 'Green Thumb Gardens', 'Professional landscaping and garden maintenance', 'verified', ST_GeogFromText('POINT(36.8219 -1.2921)'), true),
('00000000-0000-0000-0000-000000000005', 'Master Carpentry Works', 'Custom furniture and carpentry services', 'verified', ST_GeogFromText('POINT(36.8219 -1.2921)'), true),
('00000000-0000-0000-0000-000000000006', 'Color Perfect Painting', 'Interior and exterior painting specialists', 'verified', ST_GeogFromText('POINT(36.8219 -1.2921)'), true),
('00000000-0000-0000-0000-000000000007', 'Academic Excellence Tutors', 'Qualified tutors for all subjects', 'verified', ST_GeogFromText('POINT(36.8219 -1.2921)'), true),
('00000000-0000-0000-0000-000000000008', 'Beauty & Wellness Hub', 'Professional beauty and wellness services', 'verified', ST_GeogFromText('POINT(36.8219 -1.2921)'), true),
('00000000-0000-0000-0000-000000000009', 'Happy Pets Care', 'Loving care for your pets', 'verified', ST_GeogFromText('POINT(36.8219 -1.2921)'), true),
('00000000-0000-0000-0000-000000000010', 'Swift Delivery Services', 'Fast and reliable delivery', 'verified', ST_GeogFromText('POINT(36.8219 -1.2921)'), true),
('00000000-0000-0000-0000-000000000011', 'Capture Moments Photography', 'Professional photography services', 'verified', ST_GeogFromText('POINT(36.8219 -1.2921)'), true),
('00000000-0000-0000-0000-000000000012', 'Delicious Catering Co', 'Catering for all occasions', 'verified', ST_GeogFromText('POINT(36.8219 -1.2921)'), true),
('00000000-0000-0000-0000-000000000013', 'SecureGuard Services', 'Professional security services', 'verified', ST_GeogFromText('POINT(36.8219 -1.2921)'), true),
('00000000-0000-0000-0000-000000000014', 'TechFix Solutions', 'Computer and network support', 'verified', ST_GeogFromText('POINT(36.8219 -1.2921)'), true),
('00000000-0000-0000-0000-000000000015', 'Perfect Events Planning', 'Complete event planning services', 'verified', ST_GeogFromText('POINT(36.8219 -1.2921)'), true);

-- Create profiles for customers
INSERT INTO profiles (user_id, address, city, country, location) VALUES
('00000000-0000-0000-0000-000000000101', 'Westlands, Nairobi', 'Nairobi', 'Kenya', ST_GeogFromText('POINT(36.8097 -1.2676)')),
('00000000-0000-0000-0000-000000000102', 'Karen, Nairobi', 'Nairobi', 'Kenya', ST_GeogFromText('POINT(36.6853 -1.3197)')),
('00000000-0000-0000-0000-000000000103', 'Kilimani, Nairobi', 'Nairobi', 'Kenya', ST_GeogFromText('POINT(36.7833 -1.2833)')),
('00000000-0000-0000-0000-000000000104', 'Lavington, Nairobi', 'Nairobi', 'Kenya', ST_GeogFromText('POINT(36.7667 -1.2833)')),
('00000000-0000-0000-0000-000000000105', 'Kileleshwa, Nairobi', 'Nairobi', 'Kenya', ST_GeogFromText('POINT(36.7833 -1.2667)'));

-- Create wallets for all users
INSERT INTO wallets (user_id, balance) VALUES
('00000000-0000-0000-0000-000000000001', 0.00),
('00000000-0000-0000-0000-000000000002', 0.00),
('00000000-0000-0000-0000-000000000003', 0.00),
('00000000-0000-0000-0000-000000000004', 0.00),
('00000000-0000-0000-0000-000000000005', 0.00),
('00000000-0000-0000-0000-000000000006', 0.00),
('00000000-0000-0000-0000-000000000007', 0.00),
('00000000-0000-0000-0000-000000000008', 0.00),
('00000000-0000-0000-0000-000000000009', 0.00),
('00000000-0000-0000-0000-000000000010', 0.00),
('00000000-0000-0000-0000-000000000011', 0.00),
('00000000-0000-0000-0000-000000000012', 0.00),
('00000000-0000-0000-0000-000000000013', 0.00),
('00000000-0000-0000-0000-000000000014', 0.00),
('00000000-0000-0000-0000-000000000015', 0.00),
('00000000-0000-0000-0000-000000000101', 1000.00),
('00000000-0000-0000-0000-000000000102', 1500.00),
('00000000-0000-0000-0000-000000000103', 800.00),
('00000000-0000-0000-0000-000000000104', 2000.00),
('00000000-0000-0000-0000-000000000105', 500.00),
('00000000-0000-0000-0000-000000000099', 0.00);

-- Create Mtaa Shares for providers
INSERT INTO mtaa_shares (user_id, shares_earned, shares_value) VALUES
('00000000-0000-0000-0000-000000000001', 0.00, 0.00),
('00000000-0000-0000-0000-000000000002', 0.00, 0.00),
('00000000-0000-0000-0000-000000000003', 0.00, 0.00),
('00000000-0000-0000-0000-000000000004', 0.00, 0.00),
('00000000-0000-0000-0000-000000000005', 0.00, 0.00),
('00000000-0000-0000-0000-000000000006', 0.00, 0.00),
('00000000-0000-0000-0000-000000000007', 0.00, 0.00),
('00000000-0000-0000-0000-000000000008', 0.00, 0.00),
('00000000-0000-0000-0000-000000000009', 0.00, 0.00),
('00000000-0000-0000-0000-000000000010', 0.00, 0.00),
('00000000-0000-0000-0000-000000000011', 0.00, 0.00),
('00000000-0000-0000-0000-000000000012', 0.00, 0.00),
('00000000-0000-0000-0000-000000000013', 0.00, 0.00),
('00000000-0000-0000-0000-000000000014', 0.00, 0.00),
('00000000-0000-0000-0000-000000000015', 0.00, 0.00);

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
('Event Planning', 'Event organization and planning', 'calendar', 'event-planning', true, 15);

-- Insert sample neighborhoods
INSERT INTO neighborhoods (name, description, city, country, center_point, is_active) VALUES
('Westlands', 'Business and residential area in Nairobi', 'Nairobi', 'Kenya', ST_GeogFromText('POINT(36.8097 -1.2676)'), true),
('Karen', 'Upmarket residential area', 'Nairobi', 'Kenya', ST_GeogFromText('POINT(36.6853 -1.3197)'), true),
('Kilimani', 'Mixed residential and commercial area', 'Nairobi', 'Kenya', ST_GeogFromText('POINT(36.7833 -1.2833)'), true),
('Lavington', 'Residential area with shopping centers', 'Nairobi', 'Kenya', ST_GeogFromText('POINT(36.7667 -1.2833)'), true),
('Kileleshwa', 'Residential area near the city center', 'Nairobi', 'Kenya', ST_GeogFromText('POINT(36.7833 -1.2667)'), true);

-- Insert sample services with icons
INSERT INTO services (provider_id, category_id, name, description, price, price_type, icon, status, images, requirements) VALUES
-- Note: These will use placeholder provider_ids - update with actual provider IDs after user registration
('00000000-0000-0000-0000-000000000001', (SELECT id FROM service_categories WHERE slug = 'home-cleaning'), 'Deep House Cleaning', 'Complete deep cleaning service for your home including all rooms, kitchen, and bathrooms', 5000, 'fixed', 'home', 'active', '["cleaning1.jpg", "cleaning2.jpg"]', 'Access to all rooms, cleaning supplies provided'),
('00000000-0000-0000-0000-000000000001', (SELECT id FROM service_categories WHERE slug = 'home-cleaning'), 'Office Cleaning', 'Professional office cleaning service for businesses', 3000, 'fixed', 'building', 'active', '["office1.jpg"]', 'After hours access preferred'),
('00000000-0000-0000-0000-000000000002', (SELECT id FROM service_categories WHERE slug = 'plumbing'), 'Pipe Repair & Installation', 'Expert plumbing services for pipe repairs and new installations', 2500, 'hourly', 'droplet', 'active', '["plumbing1.jpg", "plumbing2.jpg"]', 'Access to water mains, materials extra'),
('00000000-0000-0000-0000-000000000002', (SELECT id FROM service_categories WHERE slug = 'plumbing'), 'Drain Cleaning', 'Professional drain cleaning and unblocking service', 1500, 'fixed', 'droplet', 'active', '["drain1.jpg"]', 'Access to affected drains'),
('00000000-0000-0000-0000-000000000003', (SELECT id FROM service_categories WHERE slug = 'electrical'), 'House Wiring', 'Complete electrical wiring for new constructions and renovations', 8000, 'negotiable', 'zap', 'active', '["wiring1.jpg", "wiring2.jpg"]', 'Electrical plans, permits required'),
('00000000-0000-0000-0000-000000000003', (SELECT id FROM service_categories WHERE slug = 'electrical'), 'Light Installation', 'Installation of lights, fans, and electrical fixtures', 1000, 'fixed', 'lightbulb', 'active', '["lights1.jpg"]', 'Fixtures to be provided by client'),
('00000000-0000-0000-0000-000000000004', (SELECT id FROM service_categories WHERE slug = 'gardening'), 'Garden Design & Landscaping', 'Complete garden design and landscaping service', 15000, 'negotiable', 'leaf', 'active', '["garden1.jpg", "garden2.jpg"]', 'Site survey required, plants extra'),
('00000000-0000-0000-0000-000000000004', (SELECT id FROM service_categories WHERE slug = 'gardening'), 'Lawn Maintenance', 'Regular lawn mowing and garden maintenance', 2000, 'fixed', 'scissors', 'active', '["lawn1.jpg"]', 'Weekly or bi-weekly service'),
('00000000-0000-0000-0000-000000000005', (SELECT id FROM service_categories WHERE slug = 'carpentry'), 'Custom Furniture', 'Handcrafted custom furniture design and creation', 25000, 'negotiable', 'hammer', 'active', '["furniture1.jpg", "furniture2.jpg"]', 'Design consultation, materials extra'),
('00000000-0000-0000-0000-000000000005', (SELECT id FROM service_categories WHERE slug = 'carpentry'), 'Door & Window Installation', 'Professional door and window installation service', 5000, 'fixed', 'square', 'active', '["doors1.jpg"]', 'Doors/windows to be provided'),
('00000000-0000-0000-0000-000000000006', (SELECT id FROM service_categories WHERE slug = 'painting'), 'Interior Painting', 'Professional interior wall painting service', 3000, 'hourly', 'palette', 'active', '["paint1.jpg", "paint2.jpg"]', 'Paint and materials included'),
('00000000-0000-0000-0000-000000000006', (SELECT id FROM service_categories WHERE slug = 'painting'), 'Exterior Painting', 'Weather-resistant exterior painting service', 5000, 'hourly', 'home', 'active', '["exterior1.jpg"]', 'Weather dependent, scaffolding extra'),
('00000000-0000-0000-0000-000000000007', (SELECT id FROM service_categories WHERE slug = 'tutoring'), 'Mathematics Tutoring', 'Expert mathematics tutoring for all levels', 1500, 'hourly', 'calculator', 'active', '["math1.jpg"]', 'Study materials provided'),
('00000000-0000-0000-0000-000000000007', (SELECT id FROM service_categories WHERE slug = 'tutoring'), 'English Language Lessons', 'Comprehensive English language tutoring', 1200, 'hourly', 'book-open', 'active', '["english1.jpg"]', 'All ages welcome'),
('00000000-0000-0000-0000-000000000008', (SELECT id FROM service_categories WHERE slug = 'beauty-wellness'), 'Hair Styling & Cut', 'Professional hair styling and cutting service', 2000, 'fixed', 'scissors', 'active', '["hair1.jpg", "hair2.jpg"]', 'Home service available'),
('00000000-0000-0000-0000-000000000008', (SELECT id FROM service_categories WHERE slug = 'beauty-wellness'), 'Manicure & Pedicure', 'Complete nail care and beauty service', 1500, 'fixed', 'hand', 'active', '["nails1.jpg"]', 'All tools sanitized'),
('00000000-0000-0000-0000-000000000009', (SELECT id FROM service_categories WHERE slug = 'pet-care'), 'Dog Walking', 'Professional dog walking and exercise service', 800, 'hourly', 'heart', 'active', '["dog1.jpg"]', 'Vaccinated dogs only'),
('00000000-0000-0000-0000-000000000009', (SELECT id FROM service_categories WHERE slug = 'pet-care'), 'Pet Grooming', 'Complete pet grooming and bathing service', 2500, 'fixed', 'scissors', 'active', '["grooming1.jpg"]', 'All pet types welcome'),
('00000000-0000-0000-0000-000000000010', (SELECT id FROM service_categories WHERE slug = 'delivery'), 'Package Delivery', 'Fast and reliable package delivery service', 500, 'fixed', 'package', 'active', '["delivery1.jpg"]', 'Same day delivery available'),
('00000000-0000-0000-0000-000000000010', (SELECT id FROM service_categories WHERE slug = 'delivery'), 'Food Delivery', 'Hot food delivery from restaurants', 300, 'fixed', 'utensils', 'active', '["food1.jpg"]', 'Insulated delivery bags used'),
('00000000-0000-0000-0000-000000000011', (SELECT id FROM service_categories WHERE slug = 'photography'), 'Wedding Photography', 'Professional wedding photography and videography', 50000, 'negotiable', 'camera', 'active', '["wedding1.jpg", "wedding2.jpg"]', 'Full day coverage, edited photos included'),
('00000000-0000-0000-0000-000000000011', (SELECT id FROM service_categories WHERE slug = 'photography'), 'Portrait Photography', 'Professional portrait and headshot photography', 8000, 'fixed', 'user', 'active', '["portrait1.jpg"]', 'Studio or location shoot'),
('00000000-0000-0000-0000-000000000012', (SELECT id FROM service_categories WHERE slug = 'catering'), 'Event Catering', 'Full-service catering for events and parties', 2000, 'hourly', 'chef-hat', 'active', '["catering1.jpg", "catering2.jpg"]', 'Minimum 20 people, menu planning included'),
('00000000-0000-0000-0000-000000000012', (SELECT id FROM service_categories WHERE slug = 'catering'), 'Home Cooking', 'Personal chef service for home-cooked meals', 3000, 'fixed', 'utensils', 'active', '["cooking1.jpg"]', 'Ingredients provided by client'),
('00000000-0000-0000-0000-000000000013', (SELECT id FROM service_categories WHERE slug = 'security'), 'Event Security', 'Professional security services for events', 2500, 'hourly', 'shield', 'active', '["security1.jpg"]', 'Licensed security personnel'),
('00000000-0000-0000-0000-000000000013', (SELECT id FROM service_categories WHERE slug = 'security'), 'Home Security Installation', 'CCTV and alarm system installation', 15000, 'negotiable', 'shield-check', 'active', '["cctv1.jpg"]', 'Equipment and monitoring setup'),
('00000000-0000-0000-0000-000000000014', (SELECT id FROM service_categories WHERE slug = 'tech-support'), 'Computer Repair', 'Hardware and software computer repair service', 2000, 'hourly', 'monitor', 'active', '["computer1.jpg"]', 'Diagnosis included, parts extra'),
('00000000-0000-0000-0000-000000000014', (SELECT id FROM service_categories WHERE slug = 'tech-support'), 'Network Setup', 'Home and office network installation', 5000, 'fixed', 'wifi', 'active', '["network1.jpg"]', 'Router and cables included'),
('00000000-0000-0000-0000-000000000015', (SELECT id FROM service_categories WHERE slug = 'event-planning'), 'Wedding Planning', 'Complete wedding planning and coordination', 100000, 'negotiable', 'heart', 'active', '["wedding-plan1.jpg"]', 'Full service planning, vendor coordination'),
('00000000-0000-0000-0000-000000000015', (SELECT id FROM service_categories WHERE slug = 'event-planning'), 'Birthday Party Planning', 'Fun and memorable birthday party planning', 15000, 'fixed', 'gift', 'active', '["party1.jpg"]', 'Decorations and entertainment included');

-- Insert sample FAQs
INSERT INTO faqs (question, answer, category, is_active, sort_order) VALUES
('How do I book a service?', 'You can book a service by browsing our categories, selecting a provider, and clicking the "Book Now" button. Follow the prompts to complete your booking.', 'booking', true, 1),
('How do I pay for services?', 'We accept M-Pesa, credit/debit cards, and wallet payments. You can choose your preferred payment method during checkout.', 'payment', true, 2),
('What if I need to cancel my booking?', 'You can cancel your booking up to 2 hours before the scheduled time. Go to "My Bookings" and click "Cancel" on the relevant booking.', 'booking', true, 3),
('How do I become a service provider?', 'Click on "Become a Provider" in the app, complete the registration form, upload required documents, and wait for verification.', 'provider', true, 4),
('What is Mtaa Shares?', 'Mtaa Shares is our equity program where providers earn shares in the platform based on their performance and bookings completed.', 'mtaa-shares', true, 5),
('How do I contact customer support?', 'You can reach our support team through the in-app chat, email at support@hequeendo.com, or phone at +254 700 000 000.', 'support', true, 6),
('What icons are used for services?', 'Each service has a visual icon to help you quickly identify the type of service. Icons are automatically assigned based on service names and categories.', 'general', true, 7),
('Can I filter services by category?', 'Yes, you can browse services by category using the category icons on the main page, or use the search function with filters.', 'search', true, 8);

