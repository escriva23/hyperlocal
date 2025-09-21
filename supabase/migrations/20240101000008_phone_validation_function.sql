-- Function to validate phone numbers
-- Separated from performance optimizations to avoid dependency issues

CREATE OR REPLACE FUNCTION validate_phone_number(phone_number text)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
BEGIN
  -- Kenyan phone number validation (254XXXXXXXXX format)
  RETURN phone_number ~ '^254[0-9]{9}$';
END;
$$;

-- Add check constraint for phone number validation (only if constraint doesn't exist)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints 
        WHERE constraint_name = 'check_phone_format' 
        AND table_name = 'users'
    ) THEN
        ALTER TABLE users 
        ADD CONSTRAINT check_phone_format 
        CHECK (phone IS NULL OR validate_phone_number(phone));
    END IF;
END $$;

-- Add comment for the function
COMMENT ON FUNCTION validate_phone_number(text) IS 'Validates Kenyan phone number format';
