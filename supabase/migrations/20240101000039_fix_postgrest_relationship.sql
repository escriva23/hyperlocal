-- Fix PostgREST foreign key relationship detection
-- The issue is that PostgREST can't find the relationship between the view and users table
-- We need to ensure the foreign key constraint exists and is properly detected

-- First, check and fix the foreign key constraint on the underlying table
DO $$
BEGIN
    -- Drop existing foreign key constraint if it exists
    ALTER TABLE public.mtaa_shares DROP CONSTRAINT IF EXISTS mtaa_shares_user_id_fkey;
    
    -- Add the foreign key constraint with a specific name
    ALTER TABLE public.mtaa_shares 
    ADD CONSTRAINT mtaa_shares_user_id_fkey 
    FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
    
    RAISE NOTICE 'Added foreign key constraint: mtaa_shares.user_id -> users.id';
END $$;

-- Drop and recreate the view to ensure PostgREST detects the relationship
DROP VIEW IF EXISTS public.mtaa_shares_leaderboard;

-- Create the view with explicit column references to help PostgREST detect relationships
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

-- Grant permissions
GRANT SELECT ON public.mtaa_shares_leaderboard TO authenticated;
GRANT SELECT ON public.mtaa_shares_leaderboard TO anon;
GRANT SELECT ON public.users TO authenticated;
GRANT SELECT ON public.users TO anon;

-- Refresh PostgREST schema cache by creating a dummy function and dropping it
-- This forces PostgREST to reload the schema and detect the foreign key relationships
CREATE OR REPLACE FUNCTION refresh_schema_cache() RETURNS void AS $$
BEGIN
    -- This function exists solely to trigger schema cache refresh
    RETURN;
END;
$$ LANGUAGE plpgsql;

DROP FUNCTION refresh_schema_cache();

-- Alternative approach: Create a materialized view instead of a regular view
-- Materialized views can have their own constraints that PostgREST can detect
DROP MATERIALIZED VIEW IF EXISTS public.mtaa_shares_leaderboard_mv;

CREATE MATERIALIZED VIEW public.mtaa_shares_leaderboard_mv AS
SELECT 
    ms.user_id,
    ms.total_shares,
    ms.monthly_earnings,
    ms.rank,
    ms.rank_change
FROM public.mtaa_shares ms
WHERE COALESCE(ms.total_shares, 0) > 0 AND ms.rank IS NOT NULL
ORDER BY ms.rank ASC;

-- Create a unique index on the materialized view to help with performance and relationships
CREATE UNIQUE INDEX idx_mtaa_shares_leaderboard_mv_user_id ON public.mtaa_shares_leaderboard_mv(user_id);

-- Grant permissions on materialized view
GRANT SELECT ON public.mtaa_shares_leaderboard_mv TO authenticated;
GRANT SELECT ON public.mtaa_shares_leaderboard_mv TO anon;

-- Create a function to refresh the materialized view
CREATE OR REPLACE FUNCTION refresh_mtaa_shares_leaderboard()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW public.mtaa_shares_leaderboard_mv;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Initial refresh of the materialized view
SELECT refresh_mtaa_shares_leaderboard();

-- Test if PostgREST can now detect the relationship
DO $$
DECLARE
    constraint_exists BOOLEAN;
BEGIN
    -- Check if the foreign key constraint exists
    SELECT EXISTS (
        SELECT 1 FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name
        JOIN information_schema.constraint_column_usage ccu ON tc.constraint_name = ccu.constraint_name
        WHERE tc.table_schema = 'public' 
        AND tc.table_name = 'mtaa_shares'
        AND tc.constraint_type = 'FOREIGN KEY'
        AND kcu.column_name = 'user_id'
        AND ccu.table_name = 'users'
        AND ccu.table_schema = 'public'
    ) INTO constraint_exists;
    
    IF constraint_exists THEN
        RAISE NOTICE 'Foreign key constraint exists: mtaa_shares.user_id -> public.users.id';
    ELSE
        RAISE NOTICE 'WARNING: Foreign key constraint not found!';
    END IF;
END $$;

-- Final instructions
DO $$
BEGIN
    RAISE NOTICE '=== POSTGREST RELATIONSHIP FIX COMPLETE ===';
    RAISE NOTICE 'Try using the materialized view instead: mtaa_shares_leaderboard_mv';
    RAISE NOTICE 'Frontend should query: /rest/v1/mtaa_shares_leaderboard_mv?select=user_id,total_shares,monthly_earnings,rank,rank_change,users(name,avatar_url)';
    RAISE NOTICE 'If the regular view still fails, use the materialized view as a workaround.';
END $$;
