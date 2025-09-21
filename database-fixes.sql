-- Run this SQL in your Supabase SQL Editor to fix the API errors

-- 1. Fix FAQs table - add missing columns
ALTER TABLE faqs ADD COLUMN IF NOT EXISTS is_published BOOLEAN DEFAULT TRUE;
ALTER TABLE faqs ADD COLUMN IF NOT EXISTS helpful_count INTEGER DEFAULT 0;

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_faqs_is_published ON faqs(is_published);
CREATE INDEX IF NOT EXISTS idx_faqs_helpful_count ON faqs(helpful_count);
CREATE INDEX IF NOT EXISTS idx_faqs_category ON faqs(category);

-- Update existing FAQs
UPDATE faqs SET is_published = TRUE WHERE is_published IS NULL;
UPDATE faqs SET helpful_count = 0 WHERE helpful_count IS NULL;

-- 2. Insert sample service categories (if not exists)
INSERT INTO service_categories (name, description, icon, slug, is_active, sort_order) 
SELECT 'Home Cleaning', 'Professional home cleaning services', 'home', 'home-cleaning', true, 1
WHERE NOT EXISTS (SELECT 1 FROM service_categories WHERE slug = 'home-cleaning')
UNION ALL
SELECT 'Plumbing', 'Plumbing repairs and installations', 'droplet', 'plumbing', true, 2
WHERE NOT EXISTS (SELECT 1 FROM service_categories WHERE slug = 'plumbing')
UNION ALL
SELECT 'Electrical', 'Electrical repairs and installations', 'zap', 'electrical', true, 3
WHERE NOT EXISTS (SELECT 1 FROM service_categories WHERE slug = 'electrical')
UNION ALL
SELECT 'Gardening', 'Garden maintenance and landscaping', 'leaf', 'gardening', true, 4
WHERE NOT EXISTS (SELECT 1 FROM service_categories WHERE slug = 'gardening')
UNION ALL
SELECT 'Carpentry', 'Furniture and woodwork services', 'hammer', 'carpentry', true, 5
WHERE NOT EXISTS (SELECT 1 FROM service_categories WHERE slug = 'carpentry')
UNION ALL
SELECT 'Painting', 'Interior and exterior painting', 'palette', 'painting', true, 6
WHERE NOT EXISTS (SELECT 1 FROM service_categories WHERE slug = 'painting')
UNION ALL
SELECT 'Tutoring', 'Academic tutoring and lessons', 'book', 'tutoring', true, 7
WHERE NOT EXISTS (SELECT 1 FROM service_categories WHERE slug = 'tutoring')
UNION ALL
SELECT 'Beauty & Wellness', 'Beauty treatments and wellness services', 'scissors', 'beauty-wellness', true, 8
WHERE NOT EXISTS (SELECT 1 FROM service_categories WHERE slug = 'beauty-wellness')
UNION ALL
SELECT 'Pet Care', 'Pet grooming and care services', 'heart', 'pet-care', true, 9
WHERE NOT EXISTS (SELECT 1 FROM service_categories WHERE slug = 'pet-care')
UNION ALL
SELECT 'Delivery', 'Package and food delivery services', 'car', 'delivery', true, 10
WHERE NOT EXISTS (SELECT 1 FROM service_categories WHERE slug = 'delivery')
UNION ALL
SELECT 'Photography', 'Professional photography and videography', 'camera', 'photography', true, 11
WHERE NOT EXISTS (SELECT 1 FROM service_categories WHERE slug = 'photography')
UNION ALL
SELECT 'Catering', 'Food preparation and catering services', 'chef-hat', 'catering', true, 12
WHERE NOT EXISTS (SELECT 1 FROM service_categories WHERE slug = 'catering')
UNION ALL
SELECT 'Security', 'Security and protection services', 'shield', 'security', true, 13
WHERE NOT EXISTS (SELECT 1 FROM service_categories WHERE slug = 'security')
UNION ALL
SELECT 'Tech Support', 'Computer and technology assistance', 'monitor', 'tech-support', true, 14
WHERE NOT EXISTS (SELECT 1 FROM service_categories WHERE slug = 'tech-support')
UNION ALL
SELECT 'Event Planning', 'Event organization and planning', 'calendar', 'event-planning', true, 15
WHERE NOT EXISTS (SELECT 1 FROM service_categories WHERE slug = 'event-planning');

-- 3. Insert sample FAQs with proper columns
INSERT INTO faqs (question, answer, category, is_published, helpful_count, sort_order)
SELECT 'How do I book a service?', 'You can book a service by browsing our categories, selecting a provider, and clicking the "Book Now" button. Follow the prompts to complete your booking.', 'booking', true, 15, 1
WHERE NOT EXISTS (SELECT 1 FROM faqs WHERE question = 'How do I book a service?')
UNION ALL
SELECT 'How do I pay for services?', 'We accept M-Pesa, credit/debit cards, and wallet payments. You can choose your preferred payment method during checkout.', 'payment', true, 12, 2
WHERE NOT EXISTS (SELECT 1 FROM faqs WHERE question = 'How do I pay for services?')
UNION ALL
SELECT 'What if I need to cancel my booking?', 'You can cancel your booking up to 2 hours before the scheduled time. Go to "My Bookings" and click "Cancel" on the relevant booking.', 'booking', true, 8, 3
WHERE NOT EXISTS (SELECT 1 FROM faqs WHERE question = 'What if I need to cancel my booking?')
UNION ALL
SELECT 'How do I become a service provider?', 'Click on "Become a Provider" in the app, complete the registration form, upload required documents, and wait for verification.', 'provider', true, 20, 4
WHERE NOT EXISTS (SELECT 1 FROM faqs WHERE question = 'How do I become a service provider?')
UNION ALL
SELECT 'What is Mtaa Shares?', 'Mtaa Shares is our equity program where providers earn shares in the platform based on their performance and bookings completed.', 'mtaa-shares', true, 25, 5
WHERE NOT EXISTS (SELECT 1 FROM faqs WHERE question = 'What is Mtaa Shares?')
UNION ALL
SELECT 'How do I contact customer support?', 'You can reach our support team through the in-app chat, email at support@hequeendo.com, or phone at +254 700 000 000.', 'support', true, 18, 6
WHERE NOT EXISTS (SELECT 1 FROM faqs WHERE question = 'How do I contact customer support?');
