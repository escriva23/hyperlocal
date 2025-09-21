-- Create provider_services table to match frontend expectations
CREATE TABLE provider_services (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    provider_id UUID REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT,
    category TEXT NOT NULL,
    price DECIMAL(10,2) DEFAULT 0.00,
    price_type price_type DEFAULT 'fixed',
    duration INTEGER DEFAULT 60, -- duration in minutes
    location_type TEXT DEFAULT 'customer_location',
    requirements TEXT[] DEFAULT '{}',
    images TEXT[] DEFAULT '{}',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX idx_provider_services_provider_id ON provider_services(provider_id);
CREATE INDEX idx_provider_services_category ON provider_services(category);
CREATE INDEX idx_provider_services_is_active ON provider_services(is_active);

-- Full-text search index
CREATE INDEX idx_provider_services_search ON provider_services USING GIN(to_tsvector('english', title || ' ' || COALESCE(description, '')));

-- Add updated_at trigger
CREATE TRIGGER update_provider_services_updated_at 
    BEFORE UPDATE ON provider_services 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Insert some sample service categories if they don't exist
INSERT INTO service_categories (name, description, slug, icon) VALUES
('Home Cleaning', 'Professional home cleaning services', 'home-cleaning', 'home'),
('Plumbing', 'Plumbing repair and installation services', 'plumbing', 'wrench'),
('Electrical', 'Electrical repair and installation services', 'electrical', 'zap'),
('Gardening', 'Garden maintenance and landscaping', 'gardening', 'leaf'),
('Painting', 'Interior and exterior painting services', 'painting', 'brush'),
('Carpentry', 'Wood work and furniture repair', 'carpentry', 'hammer'),
('Tutoring', 'Educational tutoring services', 'tutoring', 'book'),
('Pet Care', 'Pet sitting and grooming services', 'pet-care', 'heart')
ON CONFLICT (slug) DO NOTHING;
