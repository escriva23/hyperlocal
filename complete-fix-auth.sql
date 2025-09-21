-- Complete fix for auth trigger - create everything from scratch

-- 1. First, let's create the enum type with a different approach
DROP TYPE IF EXISTS user_role CASCADE;
CREATE TYPE user_role AS ENUM ('customer', 'provider', 'admin');

-- 2. Drop existing users table if it exists (to recreate with correct type)
DROP TABLE IF EXISTS public.users CASCADE;

-- 3. Create users table with correct enum type
CREATE TABLE public.users (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    role user_role NOT NULL DEFAULT 'customer',
    phone TEXT,
    avatar_url TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Create profiles table if it doesn't exist
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    bio TEXT,
    location TEXT,
    date_of_birth DATE,
    gender TEXT,
    preferences JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 5. Create wallets table if it doesn't exist
CREATE TABLE IF NOT EXISTS public.wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    balance DECIMAL(10,2) DEFAULT 0,
    total_earned DECIMAL(10,2) DEFAULT 0,
    total_spent DECIMAL(10,2) DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 6. Create provider_profiles table if it doesn't exist
CREATE TABLE IF NOT EXISTS public.provider_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    business_name TEXT NOT NULL,
    description TEXT,
    verification_status TEXT DEFAULT 'pending',
    is_available BOOLEAN DEFAULT TRUE,
    average_rating DECIMAL(3,2) DEFAULT 0,
    total_reviews INTEGER DEFAULT 0,
    total_bookings INTEGER DEFAULT 0,
    location GEOGRAPHY(POINT, 4326),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 7. Create mtaa_shares table if it doesn't exist
CREATE TABLE IF NOT EXISTS public.mtaa_shares (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    shares_earned DECIMAL(10,2) DEFAULT 0,
    shares_value DECIMAL(10,2) DEFAULT 0,
    total_earnings DECIMAL(10,2) DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 8. Disable RLS on all tables
ALTER TABLE public.users DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.profiles DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.wallets DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.provider_profiles DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.mtaa_shares DISABLE ROW LEVEL SECURITY;

-- 9. Drop and recreate the trigger function
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
DROP FUNCTION IF EXISTS handle_new_user();

-- 10. Create the trigger function
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS TRIGGER AS $$
DECLARE
    user_role_val user_role;
    user_name_val text;
BEGIN
    -- Get values with defaults
    user_role_val := COALESCE(NEW.raw_user_meta_data->>'role', 'customer')::user_role;
    user_name_val := COALESCE(NEW.raw_user_meta_data->>'name', split_part(NEW.email, '@', 1));
    
    -- Insert into users table
    INSERT INTO public.users (id, email, name, role, created_at, updated_at)
    VALUES (
        NEW.id,
        NEW.email,
        user_name_val,
        user_role_val,
        NOW(),
        NOW()
    );
    
    -- Create basic profile
    INSERT INTO public.profiles (user_id, created_at, updated_at)
    VALUES (NEW.id, NOW(), NOW());
    
    -- Create wallet
    INSERT INTO public.wallets (user_id, balance, total_earned, total_spent, created_at, updated_at)
    VALUES (NEW.id, 0, 0, 0, NOW(), NOW());
    
    -- Create provider-specific records if needed
    IF user_role_val = 'provider' THEN
        INSERT INTO public.provider_profiles (
            user_id, 
            business_name, 
            verification_status, 
            is_available,
            average_rating,
            total_reviews,
            total_bookings,
            created_at, 
            updated_at
        )
        VALUES (
            NEW.id, 
            COALESCE(NEW.raw_user_meta_data->>'business_name', user_name_val || '''s Business'), 
            'pending',
            true,
            0,
            0,
            0,
            NOW(), 
            NOW()
        );
        
        INSERT INTO public.mtaa_shares (
            user_id, 
            shares_earned, 
            shares_value, 
            total_earnings,
            created_at, 
            updated_at
        )
        VALUES (NEW.id, 0, 0, 0, NOW(), NOW());
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 11. Create the trigger
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION handle_new_user();

-- 12. Grant permissions
GRANT EXECUTE ON FUNCTION handle_new_user() TO postgres, service_role;
GRANT ALL ON ALL TABLES IN SCHEMA public TO postgres, service_role;
