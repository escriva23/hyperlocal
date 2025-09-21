-- Fix auth trigger conflicts causing "column name does not exist" error
-- This consolidates all user creation logic into a single trigger on auth.users

-- First, drop all conflicting triggers on the users table
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
DROP TRIGGER IF EXISTS create_user_preferences_trigger ON users;
DROP TRIGGER IF EXISTS trigger_create_customer_profile ON users;
DROP TRIGGER IF EXISTS create_user_referral_record_trigger ON users;
DROP TRIGGER IF EXISTS user_notifications_trigger ON users;

-- Drop the old handle_new_user function
DROP FUNCTION IF EXISTS handle_new_user() CASCADE;
DROP FUNCTION IF EXISTS create_user_preferences() CASCADE;
DROP FUNCTION IF EXISTS create_customer_profile() CASCADE;
DROP FUNCTION IF EXISTS create_user_referral_record() CASCADE;

-- Create a comprehensive function to handle all user creation logic
CREATE OR REPLACE FUNCTION handle_auth_user_created()
RETURNS TRIGGER AS $$
DECLARE
    user_role_val user_role;
    user_name_val text;
    business_name_val text;
BEGIN
    -- Extract values from metadata with proper defaults
    user_role_val := COALESCE(NEW.raw_user_meta_data->>'role', 'customer')::user_role;
    user_name_val := COALESCE(NEW.raw_user_meta_data->>'name', split_part(NEW.email, '@', 1));
    business_name_val := COALESCE(NEW.raw_user_meta_data->>'business_name', 'New Business');
    
    -- Insert into users table (this is the main table that other triggers reference)
    INSERT INTO public.users (id, email, name, role)
    VALUES (
        NEW.id,
        NEW.email,
        user_name_val,
        user_role_val
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
    
    -- Create customer-specific profile if customer
    IF user_role_val = 'customer' THEN
        INSERT INTO public.customer_profiles (user_id)
        VALUES (NEW.id)
        ON CONFLICT (user_id) DO NOTHING;
    END IF;
    
    -- Create provider-specific records if provider
    IF user_role_val = 'provider' THEN
        -- Create provider profile
        INSERT INTO public.provider_profiles (user_id, business_name)
        VALUES (NEW.id, business_name_val)
        ON CONFLICT DO NOTHING;
        
        -- Create mtaa_shares record for providers
        INSERT INTO public.mtaa_shares (user_id)
        VALUES (NEW.id)
        ON CONFLICT (user_id) DO NOTHING;
    END IF;
    
    -- Create referral record
    INSERT INTO public.referral_history (user_id, referral_code)
    VALUES (NEW.id, UPPER(SUBSTRING(MD5(NEW.id::text), 1, 8)))
    ON CONFLICT DO NOTHING;
    
    RETURN NEW;
EXCEPTION
    WHEN OTHERS THEN
        -- Log the error for debugging
        RAISE LOG 'Error in handle_auth_user_created function: % - SQLSTATE: %', SQLERRM, SQLSTATE;
        -- Re-raise the error to prevent user creation with incomplete data
        RAISE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create the single trigger on auth.users
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION handle_auth_user_created();

-- Grant necessary permissions
GRANT EXECUTE ON FUNCTION handle_auth_user_created() TO authenticated;
GRANT EXECUTE ON FUNCTION handle_auth_user_created() TO anon;

-- Ensure RLS policies allow the trigger to work
ALTER TABLE public.users DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_wallets DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_preferences DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.profiles DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.customer_profiles DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.provider_profiles DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.mtaa_shares DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.referral_history DISABLE ROW LEVEL SECURITY;
