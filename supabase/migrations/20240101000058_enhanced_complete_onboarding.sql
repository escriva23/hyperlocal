-- Enhanced complete_onboarding function that handles both customer and provider roles
-- This replaces the simple version with proper role-specific handling

-- Drop the existing function if it exists
DROP FUNCTION IF EXISTS complete_onboarding(UUID);

-- Create enhanced complete_onboarding function
CREATE OR REPLACE FUNCTION complete_onboarding(user_id UUID)
RETURNS JSON AS $$
DECLARE
    user_record RECORD;
    result JSON;
BEGIN
    -- Get user information including role
    SELECT 
        u.id,
        u.role,
        u.email,
        u.name,
        au.email_confirmed_at IS NOT NULL as email_confirmed
    INTO user_record
    FROM public.users u
    JOIN auth.users au ON u.id = au.id
    WHERE u.id = user_id;
    
    -- Check if user exists
    IF NOT FOUND THEN
        RETURN json_build_object('error', 'User not found');
    END IF;
    
    -- Check if email is confirmed
    IF NOT user_record.email_confirmed THEN
        RETURN json_build_object('error', 'Email not confirmed');
    END IF;
    
    -- Ensure all required records exist for the user's role
    BEGIN
        -- Basic records for all users
        INSERT INTO public.user_wallets (user_id) VALUES (user_id) ON CONFLICT (user_id) DO NOTHING;
        INSERT INTO public.user_preferences (user_id) VALUES (user_id) ON CONFLICT (user_id) DO NOTHING;
        INSERT INTO public.profiles (user_id) VALUES (user_id) ON CONFLICT DO NOTHING;
        
        -- Role-specific records
        IF user_record.role = 'provider' THEN
            -- Ensure provider has provider_profiles record
            INSERT INTO public.provider_profiles (user_id, business_name)
            VALUES (user_id, COALESCE(user_record.name || '''s Business', 'New Business'))
            ON CONFLICT (user_id) DO NOTHING;
            
            -- Ensure provider has mtaa_shares record
            INSERT INTO public.mtaa_shares (user_id)
            VALUES (user_id)
            ON CONFLICT (user_id) DO NOTHING;
            
            RAISE LOG 'Created provider-specific records for user: %', user_id;
        END IF;
        
        -- Mark onboarding as completed
        UPDATE public.users 
        SET onboarding_completed = TRUE,
            updated_at = NOW()
        WHERE id = user_id;
        
        -- Build success response
        result := json_build_object(
            'success', true,
            'message', 'Onboarding completed successfully',
            'user_id', user_id,
            'role', user_record.role,
            'redirect_path', 
            CASE 
                WHEN user_record.role = 'provider' THEN '/provider/dashboard'
                ELSE '/customer/dashboard'
            END
        );
        
        RAISE LOG 'Onboarding completed for user: % (role: %)', user_id, user_record.role;
        
        RETURN result;
        
    EXCEPTION
        WHEN OTHERS THEN
            -- Log the error but return a user-friendly message
            RAISE LOG 'Error completing onboarding for user %: % - SQLSTATE: %', user_id, SQLERRM, SQLSTATE;
            RETURN json_build_object(
                'error', 'Failed to complete onboarding',
                'details', SQLERRM
            );
    END;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create a simpler version that just marks onboarding complete (for backward compatibility)
CREATE OR REPLACE FUNCTION mark_onboarding_complete(user_id UUID)
RETURNS VOID AS $$
BEGIN
    UPDATE public.users 
    SET onboarding_completed = TRUE,
        updated_at = NOW()
    WHERE id = user_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to check what records exist for a user (for debugging)
CREATE OR REPLACE FUNCTION check_user_records(user_id UUID)
RETURNS JSON AS $$
DECLARE
    result JSON;
    user_role user_role;
BEGIN
    -- Get user role
    SELECT role INTO user_role FROM public.users WHERE id = user_id;
    
    -- Build comprehensive status
    SELECT json_build_object(
        'user_id', user_id,
        'role', user_role,
        'records', json_build_object(
            'users', (SELECT COUNT(*) FROM public.users WHERE id = user_id),
            'user_wallets', (SELECT COUNT(*) FROM public.user_wallets WHERE user_id = check_user_records.user_id),
            'user_preferences', (SELECT COUNT(*) FROM public.user_preferences WHERE user_id = check_user_records.user_id),
            'profiles', (SELECT COUNT(*) FROM public.profiles WHERE user_id = check_user_records.user_id),
            'provider_profiles', (SELECT COUNT(*) FROM public.provider_profiles WHERE user_id = check_user_records.user_id),
            'mtaa_shares', (SELECT COUNT(*) FROM public.mtaa_shares WHERE user_id = check_user_records.user_id)
        ),
        'onboarding_completed', (SELECT onboarding_completed FROM public.users WHERE id = user_id),
        'email_confirmed', (SELECT email_confirmed_at IS NOT NULL FROM auth.users WHERE id = user_id)
    ) INTO result;
    
    RETURN result;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant necessary permissions
GRANT EXECUTE ON FUNCTION complete_onboarding(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION mark_onboarding_complete(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION check_user_records(UUID) TO authenticated;
