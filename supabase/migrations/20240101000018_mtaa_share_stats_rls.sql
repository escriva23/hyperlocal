-- Enable RLS on mtaa_share_stats table
ALTER TABLE public.mtaa_share_stats ENABLE ROW LEVEL SECURITY;

-- Policy: Anyone can read share stats (public information)
CREATE POLICY "Anyone can read share stats" ON public.mtaa_share_stats
    FOR SELECT USING (true);

-- Policy: Only authenticated users can insert/update stats (for system functions)
CREATE POLICY "System can manage share stats" ON public.mtaa_share_stats
    FOR ALL USING (auth.role() = 'service_role');

-- Grant necessary permissions
GRANT SELECT ON public.mtaa_share_stats TO anon, authenticated;
GRANT ALL ON public.mtaa_share_stats TO service_role;

-- Grant execute permissions on functions
GRANT EXECUTE ON FUNCTION get_current_share_stats() TO anon, authenticated;
GRANT EXECUTE ON FUNCTION update_share_stats() TO service_role;
GRANT EXECUTE ON FUNCTION get_user_community_rank(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION search_services(TEXT, DECIMAL, DECIMAL, INTEGER, DECIMAL, DECIMAL, TEXT) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION get_nearby_providers(DECIMAL, DECIMAL, INTEGER, TEXT) TO anon, authenticated;
