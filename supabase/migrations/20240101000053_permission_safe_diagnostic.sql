-- Permission-safe diagnostic that works within Supabase constraints
-- This will help us see exactly what's failing during signup without touching auth.users permissions

-- Create a simple diagnostic function that only logs (no trigger disabling)
CREATE OR REPLACE FUNCTION safe_diagnostic_auth_user()
RETURNS TRIGGER AS $$
BEGIN
    -- Log to PostgreSQL logs (this always works)
    RAISE NOTICE 'SAFE DIAGNOSTIC - AUTH USER CREATED - ID: %, Email: %', NEW.id, NEW.email;
    
    -- Test basic table access
    BEGIN
        PERFORM 1 FROM public.users LIMIT 1;
        RAISE NOTICE 'SUCCESS: users table accessible';
    EXCEPTION
        WHEN OTHERS THEN
            RAISE NOTICE 'ERROR: users table failed - % (SQLSTATE: %)', SQLERRM, SQLSTATE;
    END;
    
    BEGIN
        PERFORM 1 FROM public.user_wallets LIMIT 1;
        RAISE NOTICE 'SUCCESS: user_wallets table accessible';
    EXCEPTION
        WHEN OTHERS THEN
            RAISE NOTICE 'ERROR: user_wallets table failed - % (SQLSTATE: %)', SQLERRM, SQLSTATE;
    END;
    
    BEGIN
        PERFORM 1 FROM public.user_preferences LIMIT 1;
        RAISE NOTICE 'SUCCESS: user_preferences table accessible';
    EXCEPTION
        WHEN OTHERS THEN
            RAISE NOTICE 'ERROR: user_preferences table failed - % (SQLSTATE: %)', SQLERRM, SQLSTATE;
    END;
    
    -- Test user_role enum casting
    BEGIN
        PERFORM COALESCE(NEW.raw_user_meta_data->>'role', 'customer')::user_role;
        RAISE NOTICE 'SUCCESS: user_role casting works';
    EXCEPTION
        WHEN OTHERS THEN
            RAISE NOTICE 'ERROR: user_role casting failed - % (SQLSTATE: %)', SQLERRM, SQLSTATE;
    END;
    
    -- Test the actual insertions that might be failing
    BEGIN
        INSERT INTO public.users (id, email, name, role)
        VALUES (
            NEW.id,
            NEW.email,
            COALESCE(NEW.raw_user_meta_data->>'name', split_part(NEW.email, '@', 1)),
            COALESCE(NEW.raw_user_meta_data->>'role', 'customer')::user_role
        );
        RAISE NOTICE 'SUCCESS: users table insert worked';
    EXCEPTION
        WHEN OTHERS THEN
            RAISE NOTICE 'ERROR: users table insert failed - % (SQLSTATE: %)', SQLERRM, SQLSTATE;
            -- Don't let this prevent user creation - just log and continue
    END;
    
    BEGIN
        INSERT INTO public.user_wallets (user_id)
        VALUES (NEW.id)
        ON CONFLICT (user_id) DO NOTHING;
        RAISE NOTICE 'SUCCESS: user_wallets insert worked';
    EXCEPTION
        WHEN OTHERS THEN
            RAISE NOTICE 'ERROR: user_wallets insert failed - % (SQLSTATE: %)', SQLERRM, SQLSTATE;
    END;
    
    BEGIN
        INSERT INTO public.user_preferences (user_id)
        VALUES (NEW.id)
        ON CONFLICT (user_id) DO NOTHING;
        RAISE NOTICE 'SUCCESS: user_preferences insert worked';
    EXCEPTION
        WHEN OTHERS THEN
            RAISE NOTICE 'ERROR: user_preferences insert failed - % (SQLSTATE: %)', SQLERRM, SQLSTATE;
    END;
    
    RAISE NOTICE 'SAFE DIAGNOSTIC COMPLETED FOR USER: %', NEW.id;
    RETURN NEW;
EXCEPTION
    WHEN OTHERS THEN
        RAISE NOTICE 'CRITICAL ERROR in safe_diagnostic_auth_user: % (SQLSTATE: %)', SQLERRM, SQLSTATE;
        -- Don't prevent user creation
        RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Replace any existing diagnostic trigger with our safe version
DROP TRIGGER IF EXISTS diagnostic_auth_user_created ON auth.users;
DROP TRIGGER IF EXISTS simple_diagnostic_auth_user_created ON auth.users;

-- Create the safe diagnostic trigger that runs FIRST (BEFORE)
CREATE TRIGGER safe_diagnostic_auth_user_created
    BEFORE INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION safe_diagnostic_auth_user();

-- Grant permissions
GRANT EXECUTE ON FUNCTION safe_diagnostic_auth_user() TO authenticated;
GRANT EXECUTE ON FUNCTION safe_diagnostic_auth_user() TO anon;

-- Create a simple query to check results after testing
-- Run this after attempting signup:
-- SELECT id, email, created_at FROM auth.users ORDER BY created_at DESC LIMIT 5;
