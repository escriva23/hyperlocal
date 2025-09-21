-- Add icon field to services table for better UI visibility
ALTER TABLE services ADD COLUMN IF NOT EXISTS icon text;

-- Add index for icon field (useful for filtering by icon type)
CREATE INDEX IF NOT EXISTS idx_services_icon ON services(icon) WHERE icon IS NOT NULL;

-- Update existing services to have default icons based on common service types
UPDATE services SET icon = 'wrench' WHERE icon IS NULL AND (name ILIKE '%repair%' OR name ILIKE '%fix%');
UPDATE services SET icon = 'home' WHERE icon IS NULL AND (name ILIKE '%clean%' OR name ILIKE '%house%');
UPDATE services SET icon = 'car' WHERE icon IS NULL AND (name ILIKE '%transport%' OR name ILIKE '%delivery%');
UPDATE services SET icon = 'scissors' WHERE icon IS NULL AND (name ILIKE '%hair%' OR name ILIKE '%beauty%');
UPDATE services SET icon = 'book' WHERE icon IS NULL AND (name ILIKE '%tutor%' OR name ILIKE '%teach%');
UPDATE services SET icon = 'hammer' WHERE icon IS NULL AND (name ILIKE '%construct%' OR name ILIKE '%build%');
UPDATE services SET icon = 'leaf' WHERE icon IS NULL AND (name ILIKE '%garden%' OR name ILIKE '%plant%');
UPDATE services SET icon = 'zap' WHERE icon IS NULL AND (name ILIKE '%electric%' OR name ILIKE '%wire%');
UPDATE services SET icon = 'droplet' WHERE icon IS NULL AND (name ILIKE '%plumb%' OR name ILIKE '%water%');
UPDATE services SET icon = 'palette' WHERE icon IS NULL AND (name ILIKE '%paint%' OR name ILIKE '%color%');

-- Set default icon for any remaining services without icons
UPDATE services SET icon = 'tool' WHERE icon IS NULL;

-- Add comment explaining icon usage
COMMENT ON COLUMN services.icon IS 'Icon identifier for UI display (e.g., lucide-react icon names, font-awesome classes, or custom icon identifiers)';

-- Create a function to suggest icons based on service name and category
CREATE OR REPLACE FUNCTION suggest_service_icon(
  service_name text,
  category_name text DEFAULT NULL
)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
AS $$
BEGIN
  -- Priority matching based on service name keywords
  IF service_name ILIKE ANY(ARRAY['%clean%', '%house%', '%home%', '%domestic%']) THEN
    RETURN 'home';
  ELSIF service_name ILIKE ANY(ARRAY['%repair%', '%fix%', '%maintenance%']) THEN
    RETURN 'wrench';
  ELSIF service_name ILIKE ANY(ARRAY['%hair%', '%beauty%', '%makeup%', '%nail%']) THEN
    RETURN 'scissors';
  ELSIF service_name ILIKE ANY(ARRAY['%transport%', '%delivery%', '%drive%', '%taxi%']) THEN
    RETURN 'car';
  ELSIF service_name ILIKE ANY(ARRAY['%tutor%', '%teach%', '%lesson%', '%education%']) THEN
    RETURN 'book';
  ELSIF service_name ILIKE ANY(ARRAY['%construct%', '%build%', '%carpenter%', '%wood%']) THEN
    RETURN 'hammer';
  ELSIF service_name ILIKE ANY(ARRAY['%garden%', '%plant%', '%landscape%', '%lawn%']) THEN
    RETURN 'leaf';
  ELSIF service_name ILIKE ANY(ARRAY['%electric%', '%wire%', '%power%', '%light%']) THEN
    RETURN 'zap';
  ELSIF service_name ILIKE ANY(ARRAY['%plumb%', '%water%', '%pipe%', '%drain%']) THEN
    RETURN 'droplet';
  ELSIF service_name ILIKE ANY(ARRAY['%paint%', '%color%', '%wall%', '%decor%']) THEN
    RETURN 'palette';
  ELSIF service_name ILIKE ANY(ARRAY['%cook%', '%chef%', '%food%', '%catering%']) THEN
    RETURN 'chef-hat';
  ELSIF service_name ILIKE ANY(ARRAY['%photo%', '%camera%', '%video%', '%film%']) THEN
    RETURN 'camera';
  ELSIF service_name ILIKE ANY(ARRAY['%music%', '%sound%', '%dj%', '%audio%']) THEN
    RETURN 'music';
  ELSIF service_name ILIKE ANY(ARRAY['%pet%', '%dog%', '%cat%', '%animal%']) THEN
    RETURN 'heart';
  ELSIF service_name ILIKE ANY(ARRAY['%security%', '%guard%', '%protect%', '%watch%']) THEN
    RETURN 'shield';
  ELSIF service_name ILIKE ANY(ARRAY['%massage%', '%therapy%', '%wellness%', '%spa%']) THEN
    RETURN 'heart-handshake';
  ELSIF service_name ILIKE ANY(ARRAY['%computer%', '%tech%', '%software%', '%IT%']) THEN
    RETURN 'monitor';
  ELSIF service_name ILIKE ANY(ARRAY['%event%', '%party%', '%wedding%', '%celebration%']) THEN
    RETURN 'calendar';
  -- Fallback to category-based matching
  ELSIF category_name ILIKE '%clean%' THEN
    RETURN 'home';
  ELSIF category_name ILIKE '%plumb%' THEN
    RETURN 'droplet';
  ELSIF category_name ILIKE '%electric%' THEN
    RETURN 'zap';
  ELSIF category_name ILIKE '%garden%' THEN
    RETURN 'leaf';
  ELSIF category_name ILIKE '%carpenter%' THEN
    RETURN 'hammer';
  ELSIF category_name ILIKE '%paint%' THEN
    RETURN 'palette';
  ELSIF category_name ILIKE '%tutor%' THEN
    RETURN 'book';
  ELSIF category_name ILIKE '%beauty%' THEN
    RETURN 'scissors';
  ELSIF category_name ILIKE '%pet%' THEN
    RETURN 'heart';
  ELSIF category_name ILIKE '%delivery%' THEN
    RETURN 'car';
  ELSE
    RETURN 'tool';
  END IF;
END;
$$;

-- Create trigger to automatically set icon for new services if not provided
CREATE OR REPLACE FUNCTION auto_set_service_icon()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  category_name text;
BEGIN
  -- Only set icon if it's not already provided
  IF NEW.icon IS NULL OR NEW.icon = '' THEN
    -- Get category name for better icon suggestion
    SELECT name INTO category_name
    FROM service_categories
    WHERE id = NEW.category_id;
    
    -- Set suggested icon
    NEW.icon := suggest_service_icon(NEW.name, category_name);
  END IF;
  
  RETURN NEW;
END;
$$;

-- Create trigger
DROP TRIGGER IF EXISTS trigger_auto_set_service_icon ON services;
CREATE TRIGGER trigger_auto_set_service_icon
  BEFORE INSERT OR UPDATE ON services
  FOR EACH ROW
  EXECUTE FUNCTION auto_set_service_icon();

COMMENT ON FUNCTION suggest_service_icon(text, text) IS 'Suggests appropriate icon based on service name and category';
COMMENT ON FUNCTION auto_set_service_icon() IS 'Automatically sets service icon if not provided during insert/update';
