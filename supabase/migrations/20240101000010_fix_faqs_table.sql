-- Fix FAQs table to add missing columns referenced by API
ALTER TABLE faqs ADD COLUMN IF NOT EXISTS is_published BOOLEAN DEFAULT TRUE;
ALTER TABLE faqs ADD COLUMN IF NOT EXISTS helpful_count INTEGER DEFAULT 0;

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_faqs_is_published ON faqs(is_published);
CREATE INDEX IF NOT EXISTS idx_faqs_helpful_count ON faqs(helpful_count);
CREATE INDEX IF NOT EXISTS idx_faqs_category ON faqs(category);

-- Update existing FAQs to be published by default
UPDATE faqs SET is_published = TRUE WHERE is_published IS NULL;
UPDATE faqs SET helpful_count = 0 WHERE helpful_count IS NULL;

COMMENT ON COLUMN faqs.is_published IS 'Whether the FAQ is published and visible to users';
COMMENT ON COLUMN faqs.helpful_count IS 'Number of times users marked this FAQ as helpful';
