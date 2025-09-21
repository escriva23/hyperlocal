-- Simple diagnostic that logs to PostgreSQL logs (always works)
-- This will help us see exactly what's failing during signup

-- First, let's temporarily disable the problematic triggers
ALTER TABLE auth.users DISABLE TRIGGER on_auth_user_created;
ALTER TABLE auth.users DISABLE TRIGGER create_wallet_on_user_signup;

-- Create a minimal diagnostic function that only logs
CREATE OR REPLACE FUNCTION simple_diagnostic_auth_user()
RETURNS TRIGGER AS $$
BEGIN
    -- Log to PostgreSQL logs (this always works)
    RAISE NOTICE 'AUTH USER CREATED - ID: %, Email: %', NEW.id, NEW.email;
    
    -- Test basic table access
    BEGIN
        PERFORM 1 FROM public.users LIMIT 1;
        RAISE NOTICE 'SUCCESS: users table accessible';
    EXCEPTION
        WHEN OTHERS THEN
            RAISE NOTICE 'ERROR: users table failed - %', SQLERRM;
    END;
    
    BEGIN
        PERFORM 1 FROM public.user_wallets LIMIT 1;
        RAISE NOTICE 'SUCCESS: user_wallets table accessible';
    EXCEPTION
        WHEN OTHERS THEN
            RAISE NOTICE 'ERROR: user_wallets table failed - %', SQLERRM;
    END;
    
    BEGIN
        PERFORM 1 FROM public.user_preferences LIMIT 1;
        RAISE NOTICE 'SUCCESS: user_preferences table accessible';
    EXCEPTION
        WHEN OTHERS THEN
            RAISE NOTICE 'ERROR: user_preferences table failed - %', SQLERRM;
    END;
    
    -- Test the actual insertions that are failing
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
    
    RAISE NOTICE 'DIAGNOSTIC COMPLETED FOR USER: %', NEW.id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Replace the diagnostic trigger
DROP TRIGGER IF EXISTS diagnostic_auth_user_created ON auth.users;
CREATE TRIGGER simple_diagnostic_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION simple_diagnostic_auth_user();

GRANT EXECUTE ON FUNCTION simple_diagnostic_auth_user() TO authenticated;
GRANT EXECUTE ON FUNCTION simple_diagnostic_auth_user() TO anon;
