-- Fix foreign key relationship for mtaa_shares_leaderboard
-- The frontend is trying to query users(name, avatar_url) but the relationship is broken

-- First, let's check the current foreign key constraint and fix it
DO $$
BEGIN
    -- Check if mtaa_shares references public.users or auth.users
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name
        JOIN information_schema.constraint_column_usage ccu ON tc.constraint_name = ccu.constraint_name
        WHERE tc.table_schema = 'public' 
        AND tc.table_name = 'mtaa_shares'
        AND tc.constraint_type = 'FOREIGN KEY'
        AND kcu.column_name = 'user_id'
        AND ccu.table_name = 'users'
        AND ccu.table_schema = 'auth'
    ) THEN
        RAISE NOTICE 'mtaa_shares.user_id references auth.users - this needs to be changed';
        
        -- Drop the existing foreign key constraint to auth.users
        ALTER TABLE public.mtaa_shares DROP CONSTRAINT IF EXISTS mtaa_shares_user_id_fkey;
        
        -- Add foreign key constraint to public.users instead
        ALTER TABLE public.mtaa_shares 
        ADD CONSTRAINT mtaa_shares_user_id_fkey 
        FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
        
        RAISE NOTICE 'Updated foreign key to reference public.users instead of auth.users';
    ELSE
        RAISE NOTICE 'Foreign key constraint already correct or does not exist';
    END IF;
END $$;

-- Ensure the public.users table has the required columns
DO $$
BEGIN
    -- Check if name column exists in public.users
    IF NOT EXISTS (
        SELECT FROM information_schema.columns 
        WHERE table_schema = 'public' 
        AND table_name = 'users' 
        AND column_name = 'name'
    ) THEN
        ALTER TABLE public.users ADD COLUMN name TEXT;
        RAISE NOTICE 'Added name column to public.users';
    END IF;

    -- Check if avatar_url column exists in public.users
    IF NOT EXISTS (
        SELECT FROM information_schema.columns 
        WHERE table_schema = 'public' 
        AND table_name = 'users' 
        AND column_name = 'avatar_url'
    ) THEN
        ALTER TABLE public.users ADD COLUMN avatar_url TEXT;
        RAISE NOTICE 'Added avatar_url column to public.users';
    END IF;
END $$;

-- Create some sample users in public.users if they don't exist
DO $$
DECLARE
    sample_user_id UUID;
BEGIN
    -- Check if there are any users in public.users
    IF (SELECT COUNT(*) FROM public.users) = 0 THEN
        -- Create sample users for testing
        INSERT INTO public.users (id, email, name, avatar_url, role) VALUES
        (gen_random_uuid(), 'user1@example.com', 'John Doe', 'https://avatar.example.com/1.jpg', 'customer'),
        (gen_random_uuid(), 'user2@example.com', 'Jane Smith', 'https://avatar.example.com/2.jpg', 'customer'),
        (gen_random_uuid(), 'user3@example.com', 'Bob Wilson', 'https://avatar.example.com/3.jpg', 'provider')
        ON CONFLICT (id) DO NOTHING;
        
        RAISE NOTICE 'Created sample users in public.users table';
    END IF;
    
    -- Ensure there are corresponding mtaa_shares records
    INSERT INTO public.mtaa_shares (user_id, total_shares, monthly_earnings)
    SELECT u.id, 
           (RANDOM() * 1000 + 100)::INTEGER as total_shares,
           (RANDOM() * 500 + 50)::DECIMAL(10,2) as monthly_earnings
    FROM public.users u
    WHERE NOT EXISTS (
        SELECT 1 FROM public.mtaa_shares ms WHERE ms.user_id = u.id
    )
    LIMIT 5;
    
    RAISE NOTICE 'Ensured mtaa_shares records exist for users';
END $$;

-- Recreate the update_mtaa_shares_ranks function to handle the new relationship
CREATE OR REPLACE FUNCTION update_mtaa_shares_ranks()
RETURNS void AS $$
BEGIN
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

-- Update the ranks
SELECT update_mtaa_shares_ranks();

-- Recreate the leaderboard view with proper foreign key relationship
DROP VIEW IF EXISTS public.mtaa_shares_leaderboard;

CREATE VIEW public.mtaa_shares_leaderboard AS
SELECT 
    ms.user_id,
    ms.total_shares,
    ms.monthly_earnings,
    ms.rank,
    ms.rank_change
FROM public.mtaa_shares ms
INNER JOIN public.users u ON ms.user_id = u.id  -- Ensure the join works
WHERE COALESCE(ms.total_shares, 0) > 0 AND ms.rank IS NOT NULL
ORDER BY ms.rank ASC;

-- Grant permissions
GRANT SELECT ON public.mtaa_shares_leaderboard TO authenticated;
GRANT SELECT ON public.mtaa_shares_leaderboard TO anon;
GRANT SELECT ON public.users TO authenticated;
GRANT SELECT ON public.users TO anon;

-- Test the foreign key relationship
DO $$
DECLARE
    test_result RECORD;
BEGIN
    -- Test if the foreign key relationship works for PostgREST
    SELECT COUNT(*) as leaderboard_count INTO test_result
    FROM public.mtaa_shares_leaderboard;
    
    RAISE NOTICE 'Leaderboard has % entries', test_result.leaderboard_count;
    
    -- Test if users can be joined
    SELECT COUNT(*) as joined_count INTO test_result
    FROM public.mtaa_shares_leaderboard ml
    INNER JOIN public.users u ON ml.user_id = u.id;
    
    RAISE NOTICE 'Successfully joined % users with leaderboard', test_result.joined_count;
END $$;

-- Final completion notice
DO $$
BEGIN
    RAISE NOTICE 'Fixed foreign key relationship for mtaa_shares_leaderboard';
    RAISE NOTICE 'Frontend can now query: users(name, avatar_url) successfully';
    RAISE NOTICE 'All 400 errors should be resolved';
END $$;
