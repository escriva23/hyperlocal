-- Fix infinite recursion in mtaa_shares trigger
-- The trigger was calling update_mtaa_shares_ranks() which updates the table, causing infinite recursion

-- First, drop the problematic trigger that's causing the stack overflow
DROP TRIGGER IF EXISTS update_ranks_trigger ON public.mtaa_shares;

-- Drop the trigger function as well
DROP FUNCTION IF EXISTS trigger_update_mtaa_shares_ranks();

-- Recreate the update_mtaa_shares_ranks function with better error handling
CREATE OR REPLACE FUNCTION update_mtaa_shares_ranks()
RETURNS void AS $$
BEGIN
    -- Use a more efficient approach that doesn't trigger recursion
    -- Update ranks based on total_shares and monthly_earnings
    WITH ranked_users AS (
        SELECT 
            user_id,
            ROW_NUMBER() OVER (ORDER BY 
                COALESCE(total_shares, 0) DESC, 
                COALESCE(monthly_earnings, 0) DESC,
                created_at ASC  -- tie-breaker for consistent ordering
            ) as new_rank
        FROM public.mtaa_shares
        WHERE COALESCE(total_shares, 0) > 0
    )
    UPDATE public.mtaa_shares 
    SET rank = ranked_users.new_rank
    FROM ranked_users
    WHERE public.mtaa_shares.user_id = ranked_users.user_id;
    
    -- Set rank to NULL for users with 0 or NULL shares
    UPDATE public.mtaa_shares 
    SET rank = NULL 
    WHERE COALESCE(total_shares, 0) = 0;
    
    RAISE NOTICE 'Updated ranks for % users', (SELECT COUNT(*) FROM public.mtaa_shares WHERE rank IS NOT NULL);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create a safer trigger that only updates ranks when shares or earnings change
-- This trigger will NOT call update_mtaa_shares_ranks to avoid recursion
CREATE OR REPLACE FUNCTION trigger_rank_change_only()
RETURNS TRIGGER AS $$
BEGIN
    -- Only update the rank if total_shares or monthly_earnings changed
    -- Don't call the full rank update function to avoid recursion
    IF TG_OP = 'UPDATE' THEN
        -- Check if the values that affect ranking have changed
        IF (OLD.total_shares IS DISTINCT FROM NEW.total_shares) OR 
           (OLD.monthly_earnings IS DISTINCT FROM NEW.monthly_earnings) THEN
            -- Mark that ranks need to be recalculated (we'll do this manually or via cron)
            -- For now, just log the change
            RAISE NOTICE 'Rank-affecting data changed for user %', NEW.user_id;
        END IF;
    END IF;
    
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create a trigger that only logs changes, doesn't update ranks automatically
CREATE TRIGGER mtaa_shares_change_trigger
    AFTER INSERT OR UPDATE ON public.mtaa_shares
    FOR EACH ROW
    EXECUTE FUNCTION trigger_rank_change_only();

-- Now manually update the ranks once (this won't trigger recursion)
SELECT update_mtaa_shares_ranks();

-- Create the leaderboard view (recreate to ensure it works)
DROP VIEW IF EXISTS public.mtaa_shares_leaderboard;

CREATE VIEW public.mtaa_shares_leaderboard AS
SELECT 
    user_id,
    total_shares,
    monthly_earnings,
    rank,
    rank_change
FROM public.mtaa_shares
WHERE COALESCE(total_shares, 0) > 0 AND rank IS NOT NULL
ORDER BY rank ASC;

-- Grant permissions
GRANT SELECT ON public.mtaa_shares_leaderboard TO authenticated;
GRANT SELECT ON public.mtaa_shares_leaderboard TO anon;
GRANT EXECUTE ON FUNCTION update_mtaa_shares_ranks() TO service_role;

-- Create a function that can be called manually to update ranks when needed
CREATE OR REPLACE FUNCTION refresh_mtaa_shares_ranks()
RETURNS TABLE(updated_users INTEGER) AS $$
DECLARE
    user_count INTEGER;
BEGIN
    -- Temporarily disable the trigger to avoid any issues
    ALTER TABLE public.mtaa_shares DISABLE TRIGGER mtaa_shares_change_trigger;
    
    -- Update ranks
    PERFORM update_mtaa_shares_ranks();
    
    -- Re-enable the trigger
    ALTER TABLE public.mtaa_shares ENABLE TRIGGER mtaa_shares_change_trigger;
    
    -- Return count of users with ranks
    SELECT COUNT(*) INTO user_count FROM public.mtaa_shares WHERE rank IS NOT NULL;
    
    RETURN QUERY SELECT user_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant permission to call the refresh function
GRANT EXECUTE ON FUNCTION refresh_mtaa_shares_ranks() TO authenticated;
GRANT EXECUTE ON FUNCTION refresh_mtaa_shares_ranks() TO service_role;

-- Final completion notice
DO $$
BEGIN
    RAISE NOTICE 'Fixed infinite recursion in mtaa_shares trigger';
    RAISE NOTICE 'Ranks can now be updated manually using: SELECT refresh_mtaa_shares_ranks()';
    RAISE NOTICE 'Leaderboard view recreated and should work without 400 errors';
END $$;
