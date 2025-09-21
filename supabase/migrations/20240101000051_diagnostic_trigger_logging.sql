-- Diagnostic script to identify which triggers are causing signup errors
-- This adds comprehensive logging to existing triggers without dropping them

-- First, let's create a logging table to track trigger execution
CREATE TABLE IF NOT EXISTS public.trigger_debug_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trigger_name TEXT NOT NULL,
    table_name TEXT NOT NULL,
    operation TEXT NOT NULL,
    user_id UUID,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    error_sqlstate TEXT,
    execution_time_ms INTEGER,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create a helper function for logging trigger execution
CREATE OR REPLACE FUNCTION log_trigger_execution(
    p_trigger_name TEXT,
    p_table_name TEXT,
    p_operation TEXT,
    p_user_id UUID DEFAULT NULL,
    p_success BOOLEAN DEFAULT TRUE,
    p_error_message TEXT DEFAULT NULL,
    p_error_sqlstate TEXT DEFAULT NULL,
    p_execution_time_ms INTEGER DEFAULT NULL
)
RETURNS VOID AS $$
BEGIN
    INSERT INTO public.trigger_debug_log (
        trigger_name, table_name, operation, user_id, success, 
        error_message, error_sqlstate, execution_time_ms
    )
    VALUES (
        p_trigger_name, p_table_name, p_operation, p_user_id, p_success,
        p_error_message, p_error_sqlstate, p_execution_time_ms
    );
EXCEPTION
    WHEN OTHERS THEN
        -- Don't let logging errors break the main operation
        NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create a comprehensive diagnostic trigger that runs BEFORE all other triggers
CREATE OR REPLACE FUNCTION diagnostic_auth_user_created()
RETURNS TRIGGER AS $$
DECLARE
    start_time TIMESTAMPTZ;
    end_time TIMESTAMPTZ;
    execution_time INTEGER;
    error_occurred BOOLEAN := FALSE;
    error_msg TEXT;
    error_state TEXT;
BEGIN
    start_time := clock_timestamp();
    
    -- Log the start of user creation
    PERFORM log_trigger_execution(
        'diagnostic_auth_user_created',
        'auth.users',
        'INSERT',
        NEW.id,
        TRUE,
        'User creation started - ID: ' || NEW.id || ', Email: ' || NEW.email,
        NULL,
        NULL
    );
    
    -- Test each table insertion individually to identify which one fails
    
    -- Test 1: Check if users table insertion would work
    BEGIN
        -- Just test the query without actually inserting
        PERFORM 1 FROM public.users WHERE id = NEW.id LIMIT 1;
        PERFORM log_trigger_execution(
            'diagnostic_test_users_table',
            'users',
            'TEST',
            NEW.id,
            TRUE,
            'Users table access test passed',
            NULL,
            NULL
        );
    EXCEPTION
        WHEN OTHERS THEN
            PERFORM log_trigger_execution(
                'diagnostic_test_users_table',
                'users',
                'TEST',
                NEW.id,
                FALSE,
                'Users table access failed: ' || SQLERRM,
                SQLSTATE,
                NULL
            );
    END;
    
    -- Test 2: Check if user_wallets table exists and is accessible
    BEGIN
        PERFORM 1 FROM public.user_wallets WHERE user_id = NEW.id LIMIT 1;
        PERFORM log_trigger_execution(
            'diagnostic_test_user_wallets_table',
            'user_wallets',
            'TEST',
            NEW.id,
            TRUE,
            'User_wallets table access test passed',
            NULL,
            NULL
        );
    EXCEPTION
        WHEN OTHERS THEN
            PERFORM log_trigger_execution(
                'diagnostic_test_user_wallets_table',
                'user_wallets',
                'TEST',
                NEW.id,
                FALSE,
                'User_wallets table access failed: ' || SQLERRM,
                SQLSTATE,
                NULL
            );
    END;
    
    -- Test 3: Check if user_preferences table exists and is accessible
    BEGIN
        PERFORM 1 FROM public.user_preferences WHERE user_id = NEW.id LIMIT 1;
        PERFORM log_trigger_execution(
            'diagnostic_test_user_preferences_table',
            'user_preferences',
            'TEST',
            NEW.id,
            TRUE,
            'User_preferences table access test passed',
            NULL,
            NULL
        );
    EXCEPTION
        WHEN OTHERS THEN
            PERFORM log_trigger_execution(
                'diagnostic_test_user_preferences_table',
                'user_preferences',
                'TEST',
                NEW.id,
                FALSE,
                'User_preferences table access failed: ' || SQLERRM,
                SQLSTATE,
                NULL
            );
    END;
    
    -- Test 4: Check if profiles table exists and is accessible
    BEGIN
        PERFORM 1 FROM public.profiles WHERE user_id = NEW.id LIMIT 1;
        PERFORM log_trigger_execution(
            'diagnostic_test_profiles_table',
            'profiles',
            'TEST',
            NEW.id,
            TRUE,
            'Profiles table access test passed',
            NULL,
            NULL
        );
    EXCEPTION
        WHEN OTHERS THEN
            PERFORM log_trigger_execution(
                'diagnostic_test_profiles_table',
                'profiles',
                'TEST',
                NEW.id,
                FALSE,
                'Profiles table access failed: ' || SQLERRM,
                SQLSTATE,
                NULL
            );
    END;
    
    -- Test 5: Check user_role enum casting
    BEGIN
        PERFORM COALESCE(NEW.raw_user_meta_data->>'role', 'customer')::user_role;
        PERFORM log_trigger_execution(
            'diagnostic_test_user_role_cast',
            'auth.users',
            'TEST',
            NEW.id,
            TRUE,
            'User role casting test passed',
            NULL,
            NULL
        );
    EXCEPTION
        WHEN OTHERS THEN
            PERFORM log_trigger_execution(
                'diagnostic_test_user_role_cast',
                'auth.users',
                'TEST',
                NEW.id,
                FALSE,
                'User role casting failed: ' || SQLERRM,
                SQLSTATE,
                NULL
            );
    END;
    
    end_time := clock_timestamp();
    execution_time := EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER;
    
    -- Log completion
    PERFORM log_trigger_execution(
        'diagnostic_auth_user_created',
        'auth.users',
        'INSERT',
        NEW.id,
        NOT error_occurred,
        'Diagnostic completed',
        error_state,
        execution_time
    );
    
    RETURN NEW;
EXCEPTION
    WHEN OTHERS THEN
        end_time := clock_timestamp();
        execution_time := EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER;
        
        PERFORM log_trigger_execution(
            'diagnostic_auth_user_created',
            'auth.users',
            'INSERT',
            NEW.id,
            FALSE,
            'Diagnostic trigger failed: ' || SQLERRM,
            SQLSTATE,
            execution_time
        );
        
        -- Don't prevent user creation - just log and continue
        RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create the diagnostic trigger with high priority (runs first)
DROP TRIGGER IF EXISTS diagnostic_auth_user_created ON auth.users;
CREATE TRIGGER diagnostic_auth_user_created
    BEFORE INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION diagnostic_auth_user_created();

-- Grant permissions
GRANT EXECUTE ON FUNCTION diagnostic_auth_user_created() TO authenticated;
GRANT EXECUTE ON FUNCTION diagnostic_auth_user_created() TO anon;
GRANT EXECUTE ON FUNCTION log_trigger_execution(TEXT, TEXT, TEXT, UUID, BOOLEAN, TEXT, TEXT, INTEGER) TO authenticated;
GRANT EXECUTE ON FUNCTION log_trigger_execution(TEXT, TEXT, TEXT, UUID, BOOLEAN, TEXT, TEXT, INTEGER) TO anon;

-- Create a view to easily see the diagnostic results
CREATE OR REPLACE VIEW trigger_diagnostic_summary AS
SELECT 
    trigger_name,
    table_name,
    operation,
    user_id,
    success,
    error_message,
    error_sqlstate,
    execution_time_ms,
    created_at
FROM public.trigger_debug_log
ORDER BY created_at DESC;

-- Query to run after testing signup to see results
-- SELECT * FROM trigger_diagnostic_summary WHERE user_id = 'YOUR_USER_ID_HERE';
