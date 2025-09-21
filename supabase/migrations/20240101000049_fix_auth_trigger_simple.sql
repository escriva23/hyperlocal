-- Simplified auth trigger that only uses existing tables
-- This fixes the 500 error by avoiding references to non-existent tables

-- Drop all existing triggers and functions
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
DROP FUNCTION IF EXISTS handle_auth_user_created() CASCADE;
DROP FUNCTION IF EXISTS handle_new_user() CASCADE;

-- Create a simple, robust function that only uses confirmed existing tables
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
    
    -- Insert into users table (this is the main table)
    INSERT INTO public.users (id, email, name, role)
    VALUES (
        NEW.id,
        NEW.email,
        user_name_val,
        user_role_val
    );
    
    -- Create user wallet (confirmed exists)
    INSERT INTO public.user_wallets (user_id)
    VALUES (NEW.id)
    ON CONFLICT (user_id) DO NOTHING;
    
    -- Create user preferences (confirmed exists)
    INSERT INTO public.user_preferences (user_id)
    VALUES (NEW.id)
    ON CONFLICT (user_id) DO NOTHING;
    
    -- Create basic profile (confirmed exists)
    INSERT INTO public.profiles (user_id)
    VALUES (NEW.id)
    ON CONFLICT DO NOTHING;
    
    -- Only create provider-specific records if provider and tables exist
    IF user_role_val = 'provider' THEN
        -- Create provider profile (confirmed exists)
        INSERT INTO public.provider_profiles (user_id, business_name)
        VALUES (NEW.id, business_name_val)
        ON CONFLICT DO NOTHING;
        
        -- Create mtaa_shares record (confirmed exists)
        INSERT INTO public.mtaa_shares (user_id)
        VALUES (NEW.id)
        ON CONFLICT (user_id) DO NOTHING;
    END IF;
    
    RETURN NEW;
EXCEPTION
    WHEN OTHERS THEN
        -- Log the error for debugging
        RAISE LOG 'Error in handle_auth_user_created function: % - SQLSTATE: %', SQLERRM, SQLSTATE;
        -- Re-raise the error to prevent user creation with incomplete data
        RAISE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create the trigger on auth.users
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION handle_auth_user_created();

-- Grant necessary permissions
GRANT EXECUTE ON FUNCTION handle_auth_user_created() TO authenticated;
GRANT EXECUTE ON FUNCTION handle_auth_user_created() TO anon;
