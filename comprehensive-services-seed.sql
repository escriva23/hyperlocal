-- =================================================================
-- Hequeendo Platform: Comprehensive Service Categories Seed Data
-- Version: 2.0
-- Description: Populates service_categories with icons and comprehensive services
-- =================================================================

-- Step 1: Clear existing data
TRUNCATE TABLE public.service_categories RESTART IDENTITY CASCADE;

-- Step 2: Insert comprehensive service categories with icons
INSERT INTO public.service_categories (name, slug, description, icon, is_active, sort_order, created_at, updated_at) VALUES

-- Home & Maintenance Services
('Plumbing Services', 'plumbing-services', 'Professional plumbers for leaking pipes, blocked drains, toilet repairs, and installation of sanitary ware.', 'droplet', true, 1, NOW(), NOW()),
('Electrical Services', 'electrical-services', 'Certified electricians for wiring, fixture installation, power issues, and electrical repairs.', 'zap', true, 2, NOW(), NOW()),
('Mama Fua (Laundry Services)', 'mama-fua-laundry', 'Reliable and thorough laundry services, ironing, and home cleaning by experienced mama fuas.', 'shirt', true, 3, NOW(), NOW()),
('General House Cleaning', 'general-cleaning', 'Deep cleaning for homes, apartments, and offices including mopping, dusting, and sanitizing.', 'home', true, 4, NOW(), NOW()),
('Carpentry & Furniture Repair', 'carpentry-furniture', 'Skilled carpenters for custom furniture, repairs, installations, and woodwork projects.', 'hammer', true, 5, NOW(), NOW()),
('Painting & Decorating', 'painting-decorating', 'Professional painters for interior and exterior projects, wall decorating, and color consultation.', 'palette', true, 6, NOW(), NOW()),
('Gardening & Landscaping', 'gardening-landscaping', 'Garden maintenance, lawn mowing, landscaping, tree trimming, and outdoor beautification.', 'leaf', true, 7, NOW(), NOW()),
('Pest Control & Fumigation', 'pest-control', 'Effective pest control solutions for cockroaches, rats, termites, and other household pests.', 'bug', true, 8, NOW(), NOW()),
('Appliance Repair', 'appliance-repair', 'Expert technicians for refrigerators, washing machines, ovens, microwaves, and other appliances.', 'settings', true, 9, NOW(), NOW()),
('Movers & Relocation', 'movers-relocation', 'Professional moving services for homes and offices, packing, and furniture transportation.', 'truck', true, 10, NOW(), NOW()),

-- Professional & Business Services
('IT & Computer Support', 'it-computer-support', 'Tech support for computer repairs, software installation, network setup, and troubleshooting.', 'monitor', true, 11, NOW(), NOW()),
('Tutoring & Education', 'tutoring-education', 'Private tutors for all subjects and levels, from primary school to university and professional courses.', 'book', true, 12, NOW(), NOW()),
('Accounting & Bookkeeping', 'accounting-bookkeeping', 'Financial services for individuals and small businesses, tax preparation, and financial planning.', 'calculator', true, 13, NOW(), NOW()),
('Graphic Design', 'graphic-design', 'Creative designers for logos, branding, marketing materials, and digital design projects.', 'image', true, 14, NOW(), NOW()),
('Web Development', 'web-development', 'Professional developers for websites, web applications, e-commerce, and digital solutions.', 'code', true, 15, NOW(), NOW()),
('Legal Services', 'legal-services', 'Qualified lawyers for legal consultation, document preparation, and legal representation.', 'scale', true, 16, NOW(), NOW()),
('Translation Services', 'translation-services', 'Professional translators for documents, interpretation, and language services.', 'languages', true, 17, NOW(), NOW()),

-- Beauty, Health & Wellness
('Hairstyling & Barber Services', 'hairstyling-barber', 'Professional hairstylists and barbers available for home visits, cuts, styling, and treatments.', 'scissors', true, 18, NOW(), NOW()),
('Makeup Artistry', 'makeup-artistry', 'Expert makeup artists for weddings, events, photoshoots, and special occasions.', 'sparkles', true, 19, NOW(), NOW()),
('Nail Care Services', 'nail-care', 'Professional manicures, pedicures, nail art, and nail treatments by certified technicians.', 'hand', true, 20, NOW(), NOW()),
('Massage Therapy', 'massage-therapy', 'Certified massage therapists for relaxation, therapeutic, and sports massage treatments.', 'heart', true, 21, NOW(), NOW()),
('Personal Fitness Training', 'fitness-training', 'Personal trainers for customized workout plans, fitness coaching, and health guidance.', 'dumbbell', true, 22, NOW(), NOW()),
('Yoga & Meditation', 'yoga-meditation', 'Certified yoga instructors and meditation coaches for wellness and mindfulness sessions.', 'lotus', true, 23, NOW(), NOW()),

-- Events & Entertainment
('Event Planning', 'event-planning', 'Professional event planners for weddings, corporate events, parties, and celebrations.', 'calendar', true, 24, NOW(), NOW()),
('Catering Services', 'catering-services', 'Professional chefs and catering companies for events, parties, and special occasions.', 'chef-hat', true, 25, NOW(), NOW()),
('Photography & Videography', 'photography-videography', 'Professional photographers and videographers for weddings, events, portraits, and commercial work.', 'camera', true, 26, NOW(), NOW()),
('DJ & Entertainment', 'dj-entertainment', 'DJs, MCs, and entertainers for parties, weddings, corporate functions, and celebrations.', 'music', true, 27, NOW(), NOW()),
('Sound & Lighting Equipment', 'sound-lighting', 'Professional sound systems, lighting, and AV equipment rental with setup services.', 'speaker', true, 28, NOW(), NOW()),

-- Transportation & Delivery
('Boda Boda Services', 'boda-boda', 'Reliable boda boda riders for quick transport, package delivery, and errands around the city.', 'bike', true, 29, NOW(), NOW()),
('Taxi & Ride Services', 'taxi-ride', 'Professional taxi drivers and ride services for comfortable and safe transportation.', 'car', true, 30, NOW(), NOW()),
('Delivery Services', 'delivery-services', 'Package delivery, food delivery, and courier services for businesses and individuals.', 'package', true, 31, NOW(), NOW()),
('Moving & Logistics', 'moving-logistics', 'Professional moving trucks, logistics coordination, and freight services.', 'truck', true, 32, NOW(), NOW()),

-- Automotive Services
('Car Wash & Detailing', 'car-wash-detailing', 'Mobile car wash and professional auto detailing services at your location.', 'car-wash', true, 33, NOW(), NOW()),
('Auto Mechanics', 'auto-mechanics', 'Mobile mechanics for car repairs, maintenance, diagnostics, and emergency roadside assistance.', 'wrench', true, 34, NOW(), NOW()),
('Tire Services', 'tire-services', 'Tire installation, repair, balancing, and mobile tire services for all vehicle types.', 'tire', true, 35, NOW(), NOW()),

-- Artisans & Crafts
('Tailoring & Alterations', 'tailoring-alterations', 'Skilled tailors for custom clothing, alterations, repairs, and fashion design.', 'needle', true, 36, NOW(), NOW()),
('Shoe Repair & Cobbling', 'shoe-repair', 'Expert cobblers for shoe repair, resoling, polishing, and leather goods restoration.', 'shoe', true, 37, NOW(), NOW()),
('Jewelry Making & Repair', 'jewelry-repair', 'Professional jewelers for custom jewelry, repairs, and precious metal work.', 'gem', true, 38, NOW(), NOW()),
('Arts & Crafts', 'arts-crafts', 'Artists and craftspeople for custom artwork, handicrafts, and creative projects.', 'paintbrush', true, 39, NOW(), NOW()),

-- Family & Personal Care
('Childcare & Nanny Services', 'childcare-nanny', 'Vetted and experienced nannies, babysitters, and childcare providers.', 'baby', true, 40, NOW(), NOW()),
('Elderly Care', 'elderly-care', 'Compassionate caregivers and companions for senior family members and elderly care.', 'heart-handshake', true, 41, NOW(), NOW()),
('Pet Care & Grooming', 'pet-care', 'Professional pet sitters, dog walkers, groomers, and veterinary assistants.', 'dog', true, 42, NOW(), NOW()),
('House Sitting', 'house-sitting', 'Reliable house sitters to watch your home, plants, and property while you are away.', 'home-heart', true, 43, NOW(), NOW()),

-- Food & Hospitality
('Personal Chef Services', 'personal-chef', 'Professional chefs for meal preparation, cooking lessons, and personalized dining experiences.', 'chef-hat', true, 44, NOW(), NOW()),
('Baking & Pastry', 'baking-pastry', 'Expert bakers for custom cakes, pastries, bread, and special occasion desserts.', 'cake', true, 45, NOW(), NOW()),
('Bartending Services', 'bartending', 'Professional bartenders for events, parties, and cocktail service.', 'wine', true, 46, NOW(), NOW()),
('Food Delivery', 'food-delivery', 'Restaurant food delivery, grocery shopping, and meal delivery services.', 'utensils', true, 47, NOW(), NOW()),

-- Security & Safety
('Security Services', 'security-services', 'Professional security guards, watchmen, and security consultation services.', 'shield', true, 48, NOW(), NOW()),
('CCTV Installation', 'cctv-installation', 'Security camera installation, monitoring systems, and surveillance setup.', 'video', true, 49, NOW(), NOW()),
('Locksmith Services', 'locksmith', 'Professional locksmiths for lock installation, repair, key cutting, and emergency lockout services.', 'key', true, 50, NOW(), NOW()),

-- Specialized Services
('Solar Installation', 'solar-installation', 'Solar panel installation, maintenance, and renewable energy solutions.', 'sun', true, 51, NOW(), NOW()),
('Water Tank Cleaning', 'water-tank-cleaning', 'Professional water tank cleaning, disinfection, and water system maintenance.', 'droplets', true, 52, NOW(), NOW()),
('Septic Tank Services', 'septic-services', 'Septic tank cleaning, pumping, and waste management services.', 'recycle', true, 53, NOW(), NOW()),
('Generator Services', 'generator-services', 'Generator installation, repair, maintenance, and backup power solutions.', 'battery', true, 54, NOW(), NOW()),
('Satellite & TV Installation', 'satellite-tv', 'Satellite dish installation, TV mounting, and entertainment system setup.', 'tv', true, 55, NOW(), NOW()),

-- Emergency Services
('Emergency Repairs', 'emergency-repairs', '24/7 emergency repair services for urgent home and business maintenance issues.', 'alert-triangle', true, 56, NOW(), NOW()),
('Cleaning After Events', 'post-event-cleaning', 'Specialized cleaning services after parties, events, and gatherings.', 'broom', true, 57, NOW(), NOW()),

-- Business Support
('Virtual Assistant', 'virtual-assistant', 'Professional virtual assistants for administrative tasks, scheduling, and business support.', 'user-check', true, 58, NOW(), NOW()),
('Data Entry Services', 'data-entry', 'Accurate data entry, document digitization, and database management services.', 'database', true, 59, NOW(), NOW()),
('Social Media Management', 'social-media', 'Social media managers for content creation, posting, and digital marketing.', 'share-2', true, 60, NOW(), NOW());

-- End of comprehensive service categories seed data
