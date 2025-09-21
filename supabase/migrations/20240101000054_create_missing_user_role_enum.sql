-- Create the missing user_role enum type that's causing the 500 error
-- This is the root cause of "Database error saving new user"

-- First check if the enum already exists, if not create it
DO $$ 
BEGIN
    -- Check if user_role type exists
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_role') THEN
        -- Create the user_role enum
        CREATE TYPE user_role AS ENUM ('customer', 'provider', 'admin');
        RAISE NOTICE 'Created user_role enum type';
    ELSE
        RAISE NOTICE 'user_role enum type already exists';
    END IF;
END $$;

-- Also check and create other enum types that might be missing
DO $$ 
BEGIN
    -- Check if verification_status type exists
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'verification_status') THEN
        CREATE TYPE verification_status AS ENUM ('pending', 'verified', 'rejected');
        RAISE NOTICE 'Created verification_status enum type';
    END IF;
    
    -- Check if booking_status type exists
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'booking_status') THEN
        CREATE TYPE booking_status AS ENUM ('pending', 'confirmed', 'in_progress', 'completed', 'cancelled');
        RAISE NOTICE 'Created booking_status enum type';
    END IF;
    
    -- Check if service_status type exists
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'service_status') THEN
        CREATE TYPE service_status AS ENUM ('active', 'inactive', 'pending');
        RAISE NOTICE 'Created service_status enum type';
    END IF;
END $$;

-- Now let's clean up our diagnostic trigger since we found the issue
DROP TRIGGER IF EXISTS safe_diagnostic_auth_user_created ON auth.users;
DROP FUNCTION IF EXISTS safe_diagnostic_auth_user() CASCADE;

-- Create a simple, working trigger now that we have the enum
CREATE OR REPLACE FUNCTION handle_new_user_simple()
RETURNS TRIGGER AS $$
BEGIN
    -- Insert into users table with the now-existing user_role enum
    INSERT INTO public.users (id, email, name, role)
    VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'name', split_part(NEW.email, '@', 1)),
        COALESCE(NEW.raw_user_meta_data->>'role', 'customer')::user_role
    );
    
    -- Create user wallet
    INSERT INTO public.user_wallets (user_id)
    VALUES (NEW.id)
    ON CONFLICT (user_id) DO NOTHING;
    
    -- Create user preferences
    INSERT INTO public.user_preferences (user_id)
    VALUES (NEW.id)
    ON CONFLICT (user_id) DO NOTHING;
    
    -- Create basic profile
    INSERT INTO public.profiles (user_id)
    VALUES (NEW.id)
    ON CONFLICT DO NOTHING;
    
    -- Create provider-specific records if provider
    IF COALESCE(NEW.raw_user_meta_data->>'role', 'customer') = 'provider' THEN
        INSERT INTO public.provider_profiles (user_id, business_name)
        VALUES (NEW.id, COALESCE(NEW.raw_user_meta_data->>'business_name', 'New Business'))
        ON CONFLICT DO NOTHING;
        
        INSERT INTO public.mtaa_shares (user_id)
        VALUES (NEW.id)
        ON CONFLICT (user_id) DO NOTHING;
    END IF;
    
    RETURN NEW;
EXCEPTION
    WHEN OTHERS THEN
        -- Log the error but don't prevent user creation
        RAISE LOG 'Error in handle_new_user_simple: % - SQLSTATE: %', SQLERRM, SQLSTATE;
        RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create the working trigger
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION handle_new_user_simple();

-- Grant permissions
GRANT EXECUTE ON FUNCTION handle_new_user_simple() TO authenticated;
GRANT EXECUTE ON FUNCTION handle_new_user_simple() TO anon;
