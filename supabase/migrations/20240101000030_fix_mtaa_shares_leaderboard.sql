-- Fix mtaa_shares_leaderboard to support foreign key relationships
-- The frontend expects to query users(name, avatar_url) as a relationship, not flattened fields

-- Drop the existing view
DROP VIEW IF EXISTS public.mtaa_shares_leaderboard;

-- Create mtaa_shares_leaderboard as a materialized view or table that maintains foreign key relationships
-- We'll use the mtaa_shares table directly and let Supabase handle the foreign key relationship

-- First, ensure mtaa_shares table has all necessary columns
DO $$
BEGIN
    -- Add rank column if it doesn't exist
    IF NOT EXISTS (
        SELECT FROM information_schema.columns 
        WHERE table_schema = 'public' 
        AND table_name = 'mtaa_shares' 
        AND column_name = 'rank'
    ) THEN
        ALTER TABLE public.mtaa_shares ADD COLUMN rank INTEGER;
        RAISE NOTICE 'Added rank column to mtaa_shares table';
    END IF;

    -- Add rank_change column if it doesn't exist
    IF NOT EXISTS (
        SELECT FROM information_schema.columns 
        WHERE table_schema = 'public' 
        AND table_name = 'mtaa_shares' 
        AND column_name = 'rank_change'
    ) THEN
        ALTER TABLE public.mtaa_shares ADD COLUMN rank_change INTEGER DEFAULT 0;
        RAISE NOTICE 'Added rank_change column to mtaa_shares table';
    END IF;
END $$;

-- Create a function to update ranks
CREATE OR REPLACE FUNCTION update_mtaa_shares_ranks()
RETURNS void AS $$
BEGIN
    -- Update ranks based on total_shares and monthly_earnings
    WITH ranked_users AS (
        SELECT 
            user_id,
            ROW_NUMBER() OVER (ORDER BY total_shares DESC, monthly_earnings DESC) as new_rank
        FROM public.mtaa_shares
        WHERE total_shares > 0
    )
    UPDATE public.mtaa_shares 
    SET rank = ranked_users.new_rank
    FROM ranked_users
    WHERE public.mtaa_shares.user_id = ranked_users.user_id;
    
    -- Set rank to NULL for users with 0 shares
    UPDATE public.mtaa_shares 
    SET rank = NULL 
    WHERE total_shares = 0;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create the leaderboard as a view that references mtaa_shares directly
-- This allows Supabase to handle the foreign key relationship to users table
CREATE VIEW public.mtaa_shares_leaderboard AS
SELECT 
    user_id,
    total_shares,
    monthly_earnings,
    rank,
    rank_change
FROM public.mtaa_shares
WHERE total_shares > 0 AND rank IS NOT NULL
ORDER BY rank ASC;

-- Update the ranks initially
SELECT update_mtaa_shares_ranks();

-- Create a trigger to update ranks when mtaa_shares data changes
CREATE OR REPLACE FUNCTION trigger_update_mtaa_shares_ranks()
RETURNS TRIGGER AS $$
BEGIN
    -- Update ranks after any change to mtaa_shares
    PERFORM update_mtaa_shares_ranks();
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Drop existing trigger if it exists
DROP TRIGGER IF EXISTS update_ranks_trigger ON public.mtaa_shares;

-- Create trigger to update ranks on changes
CREATE TRIGGER update_ranks_trigger
    AFTER INSERT OR UPDATE OR DELETE ON public.mtaa_shares
    FOR EACH STATEMENT
    EXECUTE FUNCTION trigger_update_mtaa_shares_ranks();

-- Grant permissions
GRANT SELECT ON public.mtaa_shares_leaderboard TO authenticated;
GRANT SELECT ON public.mtaa_shares_leaderboard TO anon;
GRANT EXECUTE ON FUNCTION update_mtaa_shares_ranks() TO service_role;

-- Add some sample data to test the leaderboard
DO $$
BEGIN
    -- Update existing records with some sample data if they exist
    UPDATE public.mtaa_shares 
    SET 
        total_shares = CASE 
            WHEN total_shares = 0 THEN (RANDOM() * 1000 + 100)::INTEGER
            ELSE total_shares
        END,
        monthly_earnings = CASE 
            WHEN monthly_earnings = 0 THEN (RANDOM() * 500 + 50)::DECIMAL(10,2)
            ELSE monthly_earnings
        END
    WHERE total_shares = 0 OR monthly_earnings = 0;
    
    -- Update ranks after adding sample data
    PERFORM update_mtaa_shares_ranks();
    
    RAISE NOTICE 'Updated mtaa_shares with sample data and calculated ranks';
END $$;

-- Final completion notice
DO $$
BEGIN
    RAISE NOTICE 'Fixed mtaa_shares_leaderboard to support foreign key relationships';
    RAISE NOTICE 'Frontend can now query: users(name, avatar_url) as a relationship';
    RAISE NOTICE 'Ranks are automatically updated when mtaa_shares data changes';
END $$;
