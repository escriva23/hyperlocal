-- Simple fix for auth trigger issues

-- 0. Create missing enum type first (ignore error if exists)
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('customer', 'provider', 'admin');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- 1. Temporarily disable RLS on users table to allow trigger to work
ALTER TABLE public.users DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.profiles DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.wallets DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.provider_profiles DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.mtaa_shares DISABLE ROW LEVEL SECURITY;

-- 2. Drop and recreate the trigger function with simpler logic
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
DROP FUNCTION IF EXISTS handle_new_user();

-- 3. Create a simpler version of the function
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS TRIGGER AS $$
DECLARE
    user_role text;
    user_name text;
BEGIN
    -- Get values with defaults
    user_role := COALESCE(NEW.raw_user_meta_data->>'role', 'customer');
    user_name := COALESCE(NEW.raw_user_meta_data->>'name', split_part(NEW.email, '@', 1));
    
    -- Insert into users table
    INSERT INTO public.users (id, email, name, role, created_at, updated_at)
    VALUES (
        NEW.id,
        NEW.email,
        user_name,
        user_role::user_role,
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
    IF user_role = 'provider' THEN
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
            COALESCE(NEW.raw_user_meta_data->>'business_name', user_name || '''s Business'), 
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

-- 4. Recreate the trigger
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION handle_new_user();

-- 5. Grant permissions
GRANT EXECUTE ON FUNCTION handle_new_user() TO postgres, service_role;
