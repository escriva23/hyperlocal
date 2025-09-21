-- Restore proper authentication flow with email confirmation and onboarding
-- This fixes the auth flow while keeping the enum types that resolved the 500 error

-- First, let's modify our trigger to only create minimal records for unconfirmed users
-- Full records will be created after email confirmation

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
DROP FUNCTION IF EXISTS handle_new_user_simple() CASCADE;

-- Create a minimal trigger for initial signup (before email confirmation)
CREATE OR REPLACE FUNCTION handle_auth_signup()
RETURNS TRIGGER AS $$
BEGIN
    -- Only create minimal user record for tracking
    -- Full setup happens after email confirmation
    INSERT INTO public.users (id, email, name, role, onboarding_completed)
    VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'name', split_part(NEW.email, '@', 1)),
        COALESCE(NEW.raw_user_meta_data->>'role', 'customer')::user_role,
        FALSE  -- Always false for new signups
    )
    ON CONFLICT (id) DO NOTHING;
    
    RETURN NEW;
EXCEPTION
    WHEN OTHERS THEN
        -- Log error but don't prevent signup
        RAISE LOG 'Error in handle_auth_signup: % - SQLSTATE: %', SQLERRM, SQLSTATE;
        RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create trigger for initial signup
CREATE TRIGGER on_auth_user_signup
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION handle_auth_signup();

-- Create a function to handle email confirmation and full user setup
CREATE OR REPLACE FUNCTION handle_email_confirmation()
RETURNS TRIGGER AS $$
BEGIN
    -- Only proceed if email was just confirmed (email_confirmed_at changed from NULL to a timestamp)
    IF OLD.email_confirmed_at IS NULL AND NEW.email_confirmed_at IS NOT NULL THEN
        
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
        
        -- Get user role from users table
        DECLARE
            user_role_val user_role;
        BEGIN
            SELECT role INTO user_role_val FROM public.users WHERE id = NEW.id;
            
            -- Create role-specific records
            IF user_role_val = 'provider' THEN
                -- Create provider profile
                INSERT INTO public.provider_profiles (user_id, business_name)
                VALUES (NEW.id, COALESCE(NEW.raw_user_meta_data->>'business_name', 'New Business'))
                ON CONFLICT DO NOTHING;
                
                -- Create mtaa_shares record for providers
                INSERT INTO public.mtaa_shares (user_id)
                VALUES (NEW.id)
                ON CONFLICT (user_id) DO NOTHING;
            END IF;
            
            -- Update user to indicate setup is complete but onboarding is still needed
            UPDATE public.users 
            SET onboarding_completed = FALSE,
                updated_at = NOW()
            WHERE id = NEW.id;
            
        END;
    END IF;
    
    RETURN NEW;
EXCEPTION
    WHEN OTHERS THEN
        -- Log error but don't prevent confirmation
        RAISE LOG 'Error in handle_email_confirmation: % - SQLSTATE: %', SQLERRM, SQLSTATE;
        RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create trigger for email confirmation
CREATE TRIGGER on_email_confirmed
    AFTER UPDATE ON auth.users
    FOR EACH ROW EXECUTE FUNCTION handle_email_confirmation();

-- Restore other important triggers that we might have disabled
-- Re-enable wallet creation trigger if it exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.triggers 
        WHERE trigger_name = 'create_wallet_on_user_signup' 
        AND event_object_table = 'users'
    ) THEN
        ALTER TABLE auth.users ENABLE TRIGGER create_wallet_on_user_signup;
    END IF;
END $$;

-- Create a function to check if user needs onboarding
CREATE OR REPLACE FUNCTION needs_onboarding(user_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
    user_record RECORD;
BEGIN
    SELECT onboarding_completed, email_confirmed_at 
    INTO user_record 
    FROM auth.users au
    JOIN public.users pu ON au.id = pu.id
    WHERE au.id = user_id;
    
    -- User needs onboarding if email is confirmed but onboarding is not completed
    RETURN (user_record.email_confirmed_at IS NOT NULL AND NOT COALESCE(user_record.onboarding_completed, FALSE));
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create a function to complete onboarding
CREATE OR REPLACE FUNCTION complete_onboarding(user_id UUID)
RETURNS VOID AS $$
BEGIN
    UPDATE public.users 
    SET onboarding_completed = TRUE,
        updated_at = NOW()
    WHERE id = user_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant necessary permissions
GRANT EXECUTE ON FUNCTION handle_auth_signup() TO authenticated, anon;
GRANT EXECUTE ON FUNCTION handle_email_confirmation() TO authenticated, anon;
GRANT EXECUTE ON FUNCTION needs_onboarding(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION complete_onboarding(UUID) TO authenticated;

-- Create RPC functions for frontend to use
CREATE OR REPLACE FUNCTION check_onboarding_status()
RETURNS JSON AS $$
DECLARE
    current_user_id UUID;
    user_record RECORD;
    result JSON;
BEGIN
    -- Get current user ID
    current_user_id := auth.uid();
    
    IF current_user_id IS NULL THEN
        RETURN json_build_object('error', 'Not authenticated');
    END IF;
    
    -- Get user information
    SELECT 
        pu.onboarding_completed,
        pu.role,
        au.email_confirmed_at IS NOT NULL as email_confirmed
    INTO user_record
    FROM public.users pu
    JOIN auth.users au ON pu.id = au.id
    WHERE pu.id = current_user_id;
    
    -- Build response
    result := json_build_object(
        'needs_onboarding', (user_record.email_confirmed AND NOT COALESCE(user_record.onboarding_completed, FALSE)),
        'email_confirmed', user_record.email_confirmed,
        'onboarding_completed', COALESCE(user_record.onboarding_completed, FALSE),
        'role', user_record.role
    );
    
    RETURN result;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

GRANT EXECUTE ON FUNCTION check_onboarding_status() TO authenticated;
