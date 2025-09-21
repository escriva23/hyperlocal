-- Create customer_profiles table
CREATE TABLE IF NOT EXISTS customer_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    address TEXT,
    city TEXT,
    date_of_birth DATE,
    emergency_contact_name TEXT,
    emergency_contact_phone TEXT,
    preferences JSONB DEFAULT '{
        "notifications": true,
        "sms_updates": true,
        "email_updates": true,
        "preferred_language": "en"
    }'::jsonb,
    verification_status TEXT DEFAULT 'pending' CHECK (verification_status IN ('pending', 'verified', 'rejected')),
    total_bookings INTEGER DEFAULT 0,
    total_spent DECIMAL(10,2) DEFAULT 0.00,
    location TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id)
);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_customer_profiles_user_id ON customer_profiles(user_id);

-- Create trigger to automatically create customer profile when user is created
CREATE OR REPLACE FUNCTION create_customer_profile()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.role = 'customer' THEN
        INSERT INTO customer_profiles (user_id)
        VALUES (NEW.id)
        ON CONFLICT (user_id) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create trigger
DROP TRIGGER IF EXISTS trigger_create_customer_profile ON users;
CREATE TRIGGER trigger_create_customer_profile
    AFTER INSERT ON users
    FOR EACH ROW
    EXECUTE FUNCTION create_customer_profile();

-- Create profiles for existing customer users
INSERT INTO customer_profiles (user_id)
SELECT id FROM users 
WHERE role = 'customer' 
AND id NOT IN (SELECT user_id FROM customer_profiles WHERE user_id IS NOT NULL)
ON CONFLICT (user_id) DO NOTHING;

-- Enable RLS
ALTER TABLE customer_profiles ENABLE ROW LEVEL SECURITY;

-- Create RLS policies
CREATE POLICY "Users can view own customer profile" ON customer_profiles
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can update own customer profile" ON customer_profiles
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own customer profile" ON customer_profiles
    FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_customer_profiles_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for updated_at
DROP TRIGGER IF EXISTS trigger_update_customer_profiles_updated_at ON customer_profiles;
CREATE TRIGGER trigger_update_customer_profiles_updated_at
    BEFORE UPDATE ON customer_profiles
    FOR EACH ROW
    EXECUTE FUNCTION update_customer_profiles_updated_at();
