-- Diagnose and fix mtaa_shares table issues
-- The update_mtaa_shares_ranks() function returned empty, let's check why

-- First, let's check what's in the mtaa_shares table
DO $$
DECLARE
    table_count INTEGER;
    shares_count INTEGER;
    users_count INTEGER;
BEGIN
    -- Check if mtaa_shares table exists and has data
    SELECT COUNT(*) INTO table_count FROM public.mtaa_shares;
    RAISE NOTICE 'Total records in mtaa_shares: %', table_count;
    
    -- Check how many have shares > 0
    SELECT COUNT(*) INTO shares_count FROM public.mtaa_shares WHERE COALESCE(total_shares, 0) > 0;
    RAISE NOTICE 'Records with total_shares > 0: %', shares_count;
    
    -- Check how many users exist in public.users
    SELECT COUNT(*) INTO users_count FROM public.users;
    RAISE NOTICE 'Total users in public.users: %', users_count;
    
    -- Show sample data from mtaa_shares
    IF table_count > 0 THEN
        RAISE NOTICE 'Sample mtaa_shares data:';
        FOR rec IN 
            SELECT user_id, total_shares, monthly_earnings, rank, rank_change 
            FROM public.mtaa_shares 
            LIMIT 5
        LOOP
            RAISE NOTICE 'User: %, Shares: %, Earnings: %, Rank: %, RankChange: %', 
                rec.user_id, rec.total_shares, rec.monthly_earnings, rec.rank, rec.rank_change;
        END LOOP;
    END IF;
END $$;

-- Check table structure
DO $$
DECLARE
    col_record RECORD;
BEGIN
    RAISE NOTICE 'mtaa_shares table structure:';
    FOR col_record IN 
        SELECT column_name, data_type, is_nullable, column_default
        FROM information_schema.columns 
        WHERE table_schema = 'public' 
        AND table_name = 'mtaa_shares'
        ORDER BY ordinal_position
    LOOP
        RAISE NOTICE 'Column: % | Type: % | Nullable: % | Default: %', 
            col_record.column_name, col_record.data_type, col_record.is_nullable, col_record.column_default;
    END LOOP;
END $$;

-- If table is empty or has no meaningful data, let's populate it
DO $$
DECLARE
    user_record RECORD;
    shares_count INTEGER;
BEGIN
    -- Check if we need to create sample data
    SELECT COUNT(*) INTO shares_count FROM public.mtaa_shares WHERE COALESCE(total_shares, 0) > 0;
    
    IF shares_count = 0 THEN
        RAISE NOTICE 'No users with shares found, creating sample data...';
        
        -- First, ensure we have some users in public.users
        INSERT INTO public.users (id, email, name, avatar_url, role) VALUES
        ('550e8400-e29b-41d4-a716-446655440001', 'alice@example.com', 'Alice Johnson', 'https://i.pravatar.cc/150?img=1', 'customer'),
        ('550e8400-e29b-41d4-a716-446655440002', 'bob@example.com', 'Bob Smith', 'https://i.pravatar.cc/150?img=2', 'customer'),
        ('550e8400-e29b-41d4-a716-446655440003', 'carol@example.com', 'Carol Davis', 'https://i.pravatar.cc/150?img=3', 'provider'),
        ('550e8400-e29b-41d4-a716-446655440004', 'david@example.com', 'David Wilson', 'https://i.pravatar.cc/150?img=4', 'customer'),
        ('550e8400-e29b-41d4-a716-446655440005', 'eve@example.com', 'Eve Brown', 'https://i.pravatar.cc/150?img=5', 'provider')
        ON CONFLICT (id) DO UPDATE SET
            name = EXCLUDED.name,
            avatar_url = EXCLUDED.avatar_url;
        
        -- Now create mtaa_shares records for these users
        INSERT INTO public.mtaa_shares (user_id, total_shares, monthly_earnings, rank_change) VALUES
        ('550e8400-e29b-41d4-a716-446655440001', 1250.50, 125.75, 2),
        ('550e8400-e29b-41d4-a716-446655440002', 980.25, 98.50, -1),
        ('550e8400-e29b-41d4-a716-446655440003', 1450.00, 145.25, 1),
        ('550e8400-e29b-41d4-a716-446655440004', 750.75, 75.00, 0),
        ('550e8400-e29b-41d4-a716-446655440005', 1100.00, 110.50, 3)
        ON CONFLICT (user_id) DO UPDATE SET
            total_shares = EXCLUDED.total_shares,
            monthly_earnings = EXCLUDED.monthly_earnings,
            rank_change = EXCLUDED.rank_change;
        
        RAISE NOTICE 'Created sample mtaa_shares data for 5 users';
    ELSE
        RAISE NOTICE 'Found % users with shares, no need to create sample data', shares_count;
    END IF;
END $$;

-- Now update the ranks with better logging
CREATE OR REPLACE FUNCTION update_mtaa_shares_ranks()
RETURNS TABLE(updated_count INTEGER) AS $$
DECLARE
    total_updated INTEGER := 0;
    total_nullified INTEGER := 0;
BEGIN
    RAISE NOTICE 'Starting rank update process...';
    
    -- Update ranks based on total_shares and monthly_earnings
    WITH ranked_users AS (
        SELECT 
            user_id,
            total_shares,
            monthly_earnings,
            ROW_NUMBER() OVER (ORDER BY 
                COALESCE(total_shares, 0) DESC, 
                COALESCE(monthly_earnings, 0) DESC,
                user_id ASC  -- tie-breaker for consistent ordering
            ) as new_rank
        FROM public.mtaa_shares
        WHERE COALESCE(total_shares, 0) > 0
    )
    UPDATE public.mtaa_shares 
    SET rank = ranked_users.new_rank
    FROM ranked_users
    WHERE public.mtaa_shares.user_id = ranked_users.user_id;
    
    GET DIAGNOSTICS total_updated = ROW_COUNT;
    RAISE NOTICE 'Updated ranks for % users with shares > 0', total_updated;
    
    -- Set rank to NULL for users with 0 or NULL shares
    UPDATE public.mtaa_shares 
    SET rank = NULL 
    WHERE COALESCE(total_shares, 0) = 0;
    
    GET DIAGNOSTICS total_nullified = ROW_COUNT;
    RAISE NOTICE 'Set rank to NULL for % users with zero shares', total_nullified;
    
    RETURN QUERY SELECT total_updated;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Run the updated function
SELECT * FROM update_mtaa_shares_ranks();

-- Check the results
DO $$
DECLARE
    rec RECORD;
BEGIN
    RAISE NOTICE 'Updated mtaa_shares data with ranks:';
    FOR rec IN 
        SELECT ms.user_id, u.name, ms.total_shares, ms.monthly_earnings, ms.rank, ms.rank_change
        FROM public.mtaa_shares ms
        LEFT JOIN public.users u ON ms.user_id = u.id
        WHERE ms.rank IS NOT NULL
        ORDER BY ms.rank ASC
        LIMIT 10
    LOOP
        RAISE NOTICE 'Rank %: % (%) - Shares: %, Earnings: %', 
            rec.rank, COALESCE(rec.name, 'Unknown'), rec.user_id, rec.total_shares, rec.monthly_earnings;
    END LOOP;
END $$;

-- Test the leaderboard view
DO $$
DECLARE
    view_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO view_count FROM public.mtaa_shares_leaderboard;
    RAISE NOTICE 'mtaa_shares_leaderboard view has % records', view_count;
    
    IF view_count > 0 THEN
        RAISE NOTICE 'Leaderboard is working! Frontend should now be able to query it.';
    ELSE
        RAISE NOTICE 'Leaderboard view is empty - there may still be an issue.';
    END IF;
END $$;

-- Final status
DO $$
BEGIN
    RAISE NOTICE '=== DIAGNOSTIC COMPLETE ===';
    RAISE NOTICE 'If you see ranks above, the leaderboard should work now!';
    RAISE NOTICE 'Try the frontend again - the 400 errors should be resolved.';
END $$;
