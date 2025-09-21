-- Enable RLS on all Mtaa Shares tables
ALTER TABLE public.mtaa_share_activities ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mtaa_shares ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.referral_history ENABLE ROW LEVEL SECURITY;

-- Policies for mtaa_share_activities table
CREATE POLICY "Users can view their own share activities" ON public.mtaa_share_activities
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own share activities" ON public.mtaa_share_activities
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Service role can manage all share activities" ON public.mtaa_share_activities
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');

-- Policies for mtaa_shares table
CREATE POLICY "Users can view their own shares" ON public.mtaa_shares
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own shares record" ON public.mtaa_shares
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own shares" ON public.mtaa_shares
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Service role can manage all shares" ON public.mtaa_shares
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');

-- Policies for referral_history table
CREATE POLICY "Users can view referrals they made" ON public.referral_history
    FOR SELECT USING (auth.uid() = referrer_id);

CREATE POLICY "Users can view referrals where they were referred" ON public.referral_history
    FOR SELECT USING (auth.uid() = referred_user_id);

CREATE POLICY "Users can insert referrals they made" ON public.referral_history
    FOR INSERT WITH CHECK (auth.uid() = referrer_id);

CREATE POLICY "Service role can manage all referrals" ON public.referral_history
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');

-- Grant permissions to authenticated users
GRANT SELECT, INSERT, UPDATE ON public.mtaa_share_activities TO authenticated;
GRANT SELECT, INSERT, UPDATE ON public.mtaa_shares TO authenticated;
GRANT SELECT, INSERT ON public.referral_history TO authenticated;

-- Grant permissions on the leaderboard view
GRANT SELECT ON public.mtaa_shares_leaderboard TO authenticated;
GRANT SELECT ON public.mtaa_shares_leaderboard TO anon;
