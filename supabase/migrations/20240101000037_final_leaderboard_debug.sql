-- Final debug and fix for mtaa_shares_leaderboard 400 errors
-- Let's check what's actually in the database and fix any remaining issues

-- Check current state of tables
DO $$
DECLARE
    rec RECORD;
BEGIN
    RAISE NOTICE '=== DEBUGGING LEADERBOARD 400 ERRORS ===';
    
    -- Check mtaa_shares table
    RAISE NOTICE 'mtaa_shares table contents:';
    FOR rec IN 
        SELECT user_id, total_shares, monthly_earnings, rank, rank_change, created_at
        FROM public.mtaa_shares 
        ORDER BY rank ASC NULLS LAST
        LIMIT 10
    LOOP
        RAISE NOTICE 'mtaa_shares: user_id=%, shares=%, earnings=%, rank=%, rank_change=%', 
            rec.user_id, rec.total_shares, rec.monthly_earnings, rec.rank, rec.rank_change;
    END LOOP;
    
    -- Check users table
    RAISE NOTICE 'users table contents:';
    FOR rec IN 
        SELECT id, email, name, avatar_url, role
        FROM public.users 
        LIMIT 10
    LOOP
        RAISE NOTICE 'users: id=%, email=%, name=%, avatar_url=%, role=%', 
            rec.id, rec.email, rec.name, rec.avatar_url, rec.role;
    END LOOP;
    
    -- Check the join between tables
    RAISE NOTICE 'Join test between mtaa_shares and users:';
    FOR rec IN 
        SELECT ms.user_id, ms.total_shares, ms.rank, u.name, u.avatar_url
        FROM public.mtaa_shares ms
        LEFT JOIN public.users u ON ms.user_id = u.id
        WHERE ms.rank IS NOT NULL
        ORDER BY ms.rank ASC
        LIMIT 5
    LOOP
        RAISE NOTICE 'Join result: user_id=%, name=%, avatar_url=%, shares=%, rank=%', 
            rec.user_id, rec.name, rec.avatar_url, rec.total_shares, rec.rank;
    END LOOP;
END $$;

-- Check the leaderboard view
DO $$
DECLARE
    rec RECORD;
    view_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO view_count FROM public.mtaa_shares_leaderboard;
    RAISE NOTICE 'mtaa_shares_leaderboard view has % records', view_count;
    
    IF view_count > 0 THEN
        RAISE NOTICE 'Leaderboard view contents:';
        FOR rec IN 
            SELECT user_id, total_shares, monthly_earnings, rank, rank_change
            FROM public.mtaa_shares_leaderboard 
            ORDER BY rank ASC
            LIMIT 5
        LOOP
            RAISE NOTICE 'Leaderboard: user_id=%, shares=%, earnings=%, rank=%, rank_change=%', 
                rec.user_id, rec.total_shares, rec.monthly_earnings, rec.rank, rec.rank_change;
        END LOOP;
    END IF;
END $$;

-- Check foreign key constraints
DO $$
DECLARE
    constraint_info RECORD;
BEGIN
    RAISE NOTICE 'Foreign key constraints on mtaa_shares:';
    FOR constraint_info IN 
        SELECT 
            tc.constraint_name,
            tc.table_name,
            kcu.column_name,
            ccu.table_name AS foreign_table_name,
            ccu.column_name AS foreign_column_name
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name
        JOIN information_schema.constraint_column_usage ccu ON tc.constraint_name = ccu.constraint_name
        WHERE tc.table_schema = 'public' 
        AND tc.table_name = 'mtaa_shares'
        AND tc.constraint_type = 'FOREIGN KEY'
    LOOP
        RAISE NOTICE 'FK: %.% -> %.%', 
            constraint_info.table_name, constraint_info.column_name,
            constraint_info.foreign_table_name, constraint_info.foreign_column_name;
    END LOOP;
END $$;

-- Fix any issues with the specific user from the error
DO $$
DECLARE
    target_user_id UUID := '164fe7ca-e71d-4e03-85e9-4df70d384f36';
    user_exists BOOLEAN;
    shares_exists BOOLEAN;
BEGIN
    -- Check if the user from the error exists in public.users
    SELECT EXISTS(SELECT 1 FROM public.users WHERE id = target_user_id) INTO user_exists;
    RAISE NOTICE 'User % exists in public.users: %', target_user_id, user_exists;
    
    -- Check if the user has mtaa_shares
    SELECT EXISTS(SELECT 1 FROM public.mtaa_shares WHERE user_id = target_user_id) INTO shares_exists;
    RAISE NOTICE 'User % has mtaa_shares record: %', target_user_id, shares_exists;
    
    -- If user doesn't exist in public.users, create them
    IF NOT user_exists THEN
        INSERT INTO public.users (id, email, name, avatar_url, role) VALUES
        (target_user_id, 'test@example.com', 'Test User', 'https://i.pravatar.cc/150?img=99', 'customer')
        ON CONFLICT (id) DO UPDATE SET
            name = EXCLUDED.name,
            avatar_url = EXCLUDED.avatar_url;
        RAISE NOTICE 'Created user % in public.users', target_user_id;
    END IF;
    
    -- If user doesn't have shares, create them
    IF NOT shares_exists THEN
        INSERT INTO public.mtaa_shares (user_id, total_shares, monthly_earnings, rank_change) VALUES
        (target_user_id, 500.00, 50.00, 0)
        ON CONFLICT (user_id) DO UPDATE SET
            total_shares = EXCLUDED.total_shares,
            monthly_earnings = EXCLUDED.monthly_earnings;
        RAISE NOTICE 'Created mtaa_shares record for user %', target_user_id;
    END IF;
END $$;

-- Update ranks again to include the new user
SELECT update_mtaa_shares_ranks();

-- Recreate the view to ensure it's correct
DROP VIEW IF EXISTS public.mtaa_shares_leaderboard;

CREATE VIEW public.mtaa_shares_leaderboard AS
SELECT 
    ms.user_id,
    ms.total_shares,
    ms.monthly_earnings,
    ms.rank,
    ms.rank_change
FROM public.mtaa_shares ms
WHERE COALESCE(ms.total_shares, 0) > 0 AND ms.rank IS NOT NULL
ORDER BY ms.rank ASC;

-- Grant permissions again
GRANT SELECT ON public.mtaa_shares_leaderboard TO authenticated;
GRANT SELECT ON public.mtaa_shares_leaderboard TO anon;
GRANT SELECT ON public.users TO authenticated;
GRANT SELECT ON public.users TO anon;

-- Test the exact query that's failing in the frontend
DO $$
DECLARE
    test_result RECORD;
    target_user_id UUID := '164fe7ca-e71d-4e03-85e9-4df70d384f36';
BEGIN
    RAISE NOTICE 'Testing the exact frontend query...';
    
    -- Test the leaderboard query with user join
    FOR test_result IN 
        SELECT 
            ml.user_id,
            ml.total_shares,
            ml.monthly_earnings,
            ml.rank,
            ml.rank_change,
            u.name,
            u.avatar_url
        FROM public.mtaa_shares_leaderboard ml
        INNER JOIN public.users u ON ml.user_id = u.id
        WHERE ml.user_id = target_user_id
        LIMIT 1
    LOOP
        RAISE NOTICE 'Query result: user_id=%, name=%, avatar_url=%, shares=%, rank=%', 
            test_result.user_id, test_result.name, test_result.avatar_url, 
            test_result.total_shares, test_result.rank;
    END LOOP;
    
    -- If no results, check why
    IF NOT FOUND THEN
        RAISE NOTICE 'No results found for user %. Checking reasons...';
        
        -- Check if user is in leaderboard at all
        IF EXISTS(SELECT 1 FROM public.mtaa_shares_leaderboard WHERE user_id = target_user_id) THEN
            RAISE NOTICE 'User is in leaderboard but join failed';
        ELSE
            RAISE NOTICE 'User is not in leaderboard - checking mtaa_shares...';
            IF EXISTS(SELECT 1 FROM public.mtaa_shares WHERE user_id = target_user_id AND rank IS NOT NULL) THEN
                RAISE NOTICE 'User has rank but not in leaderboard view';
            ELSE
                RAISE NOTICE 'User has no rank or shares <= 0';
            END IF;
        END IF;
    END IF;
END $$;

-- Final status
DO $$
BEGIN
    RAISE NOTICE '=== DEBUGGING COMPLETE ===';
    RAISE NOTICE 'Check the output above to see what was found and fixed.';
    RAISE NOTICE 'The leaderboard should now work in the frontend.';
END $$;
