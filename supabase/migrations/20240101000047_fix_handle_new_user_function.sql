-- Fix handle_new_user function to use correct table names
-- This fixes the 500 "Database error saving new user" issue during signup

-- Drop and recreate the handle_new_user function with correct table references
DROP FUNCTION IF EXISTS handle_new_user() CASCADE;

CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    -- Insert into users table
    INSERT INTO users (id, email, name, role)
    VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'name', NEW.email),
        COALESCE(NEW.raw_user_meta_data->>'role', 'customer')::user_role
    );
    
    -- Create profile for all users
    INSERT INTO profiles (user_id)
    VALUES (NEW.id);
    
    -- Create wallet (using correct table name: user_wallets)
    INSERT INTO user_wallets (user_id)
    VALUES (NEW.id);
    
    -- Create provider-specific records if role is provider
    IF COALESCE(NEW.raw_user_meta_data->>'role', 'customer') = 'provider' THEN
        -- Create provider profile
        INSERT INTO provider_profiles (user_id, business_name)
        VALUES (NEW.id, COALESCE(NEW.raw_user_meta_data->>'business_name', 'New Business'));
        
        -- Create mtaa_shares record for providers
        INSERT INTO mtaa_shares (user_id)
        VALUES (NEW.id);
    END IF;
    
    -- Create user preferences for all users
    INSERT INTO user_preferences (user_id)
    VALUES (NEW.id)
    ON CONFLICT (user_id) DO NOTHING;
    
    RETURN NEW;
EXCEPTION
    WHEN OTHERS THEN
        -- Log the error for debugging
        RAISE LOG 'Error in handle_new_user function: %', SQLERRM;
        -- Re-raise the error to prevent user creation
        RAISE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Recreate the trigger
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION handle_new_user();

-- Grant necessary permissions
GRANT EXECUTE ON FUNCTION handle_new_user() TO authenticated;
GRANT EXECUTE ON FUNCTION handle_new_user() TO anon;
