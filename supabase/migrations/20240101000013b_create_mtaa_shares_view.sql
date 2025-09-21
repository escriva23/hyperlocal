-- Create the mtaa_shares_leaderboard view (run after tables are created)
DROP VIEW IF EXISTS public.mtaa_shares_leaderboard;

CREATE VIEW public.mtaa_shares_leaderboard AS
SELECT 
    ms.user_id,
    ms.total_shares,
    ms.monthly_earnings,
    ROW_NUMBER() OVER (ORDER BY ms.total_shares DESC, ms.monthly_earnings DESC) as rank,
    ms.rank_change,
    u.raw_user_meta_data->>'name' as name,
    u.raw_user_meta_data->>'avatar_url' as avatar_url
FROM public.mtaa_shares ms
JOIN auth.users u ON ms.user_id = u.id
ORDER BY ms.total_shares DESC, ms.monthly_earnings DESC;
