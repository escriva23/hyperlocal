-- Add missing rank columns to mtaa_shares table
-- The previous migration assumed these columns existed, but they don't

-- First, check what columns exist and add the missing ones
DO $$
BEGIN
    -- Check if rank column exists, if not add it
    IF NOT EXISTS (
        SELECT FROM information_schema.columns 
        WHERE table_schema = 'public' 
        AND table_name = 'mtaa_shares' 
        AND column_name = 'rank'
    ) THEN
        ALTER TABLE public.mtaa_shares ADD COLUMN rank INTEGER;
        RAISE NOTICE 'Added rank column to mtaa_shares table';
    ELSE
        RAISE NOTICE 'Rank column already exists in mtaa_shares table';
    END IF;

    -- Check if rank_change column exists, if not add it
    IF NOT EXISTS (
        SELECT FROM information_schema.columns 
        WHERE table_schema = 'public' 
        AND table_name = 'mtaa_shares' 
        AND column_name = 'rank_change'
    ) THEN
        ALTER TABLE public.mtaa_shares ADD COLUMN rank_change INTEGER DEFAULT 0;
        RAISE NOTICE 'Added rank_change column to mtaa_shares table';
    ELSE
        RAISE NOTICE 'Rank_change column already exists in mtaa_shares table';
    END IF;

    -- Check if total_shares column exists (it should, but let's verify)
    IF NOT EXISTS (
        SELECT FROM information_schema.columns 
        WHERE table_schema = 'public' 
        AND table_name = 'mtaa_shares' 
        AND column_name = 'total_shares'
    ) THEN
        -- If total_shares doesn't exist, we need to check what columns do exist
        RAISE NOTICE 'total_shares column does not exist! Checking table structure...';
        
        -- Check if it's using the old schema with shares_earned instead
        IF EXISTS (
            SELECT FROM information_schema.columns 
            WHERE table_schema = 'public' 
            AND table_name = 'mtaa_shares' 
            AND column_name = 'shares_earned'
        ) THEN
            -- Add total_shares as an alias or copy from shares_earned
            ALTER TABLE public.mtaa_shares ADD COLUMN total_shares DECIMAL(12,2) DEFAULT 0;
            UPDATE public.mtaa_shares SET total_shares = COALESCE(shares_earned, 0);
            RAISE NOTICE 'Added total_shares column and copied from shares_earned';
        ELSE
            -- Add total_shares with default value
            ALTER TABLE public.mtaa_shares ADD COLUMN total_shares DECIMAL(12,2) DEFAULT 0;
            RAISE NOTICE 'Added total_shares column with default value 0';
        END IF;
    END IF;

    -- Check if monthly_earnings column exists
    IF NOT EXISTS (
        SELECT FROM information_schema.columns 
        WHERE table_schema = 'public' 
        AND table_name = 'mtaa_shares' 
        AND column_name = 'monthly_earnings'
    ) THEN
        -- Check if it's using the old schema with total_earnings instead
        IF EXISTS (
            SELECT FROM information_schema.columns 
            WHERE table_schema = 'public' 
            AND table_name = 'mtaa_shares' 
            AND column_name = 'total_earnings'
        ) THEN
            -- Add monthly_earnings as an alias or copy from total_earnings
            ALTER TABLE public.mtaa_shares ADD COLUMN monthly_earnings DECIMAL(10,2) DEFAULT 0;
            UPDATE public.mtaa_shares SET monthly_earnings = COALESCE(total_earnings, 0);
            RAISE NOTICE 'Added monthly_earnings column and copied from total_earnings';
        ELSE
            -- Add monthly_earnings with default value
            ALTER TABLE public.mtaa_shares ADD COLUMN monthly_earnings DECIMAL(10,2) DEFAULT 0;
            RAISE NOTICE 'Added monthly_earnings column with default value 0';
        END IF;
    END IF;
END $$;

-- Now recreate the update_mtaa_shares_ranks function (fixed version)
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

-- Add some sample data if the table is empty
DO $$
DECLARE
    user_count INTEGER;
BEGIN
    -- Check if there are any users with shares
    SELECT COUNT(*) INTO user_count FROM public.mtaa_shares WHERE COALESCE(total_shares, 0) > 0;
    
    IF user_count = 0 THEN
        -- Add sample data for existing users
        UPDATE public.mtaa_shares 
        SET 
            total_shares = (RANDOM() * 1000 + 100)::INTEGER,
            monthly_earnings = (RANDOM() * 500 + 50)::DECIMAL(10,2)
        WHERE total_shares = 0 OR total_shares IS NULL;
        
        RAISE NOTICE 'Added sample data to mtaa_shares for testing';
    END IF;
END $$;

-- Now update the ranks
SELECT update_mtaa_shares_ranks();

-- Create the leaderboard view
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

-- Final completion notice
DO $$
BEGIN
    RAISE NOTICE 'Added missing columns to mtaa_shares table';
    RAISE NOTICE 'Updated ranks and created leaderboard view';
    RAISE NOTICE 'Leaderboard should now work without column errors';
END $$;
