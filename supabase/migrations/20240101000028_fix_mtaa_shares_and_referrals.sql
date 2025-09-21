-- Fix missing database structures for Mtaa Shares and Referrals
-- This addresses 400/404/406 errors for mtaa_shares, user_referrals, and referral_history

-- Create user_referrals table (missing table causing 404 errors)
CREATE TABLE IF NOT EXISTS public.user_referrals (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    referral_code VARCHAR(20) NOT NULL UNIQUE,
    total_referrals INTEGER DEFAULT 0,
    successful_referrals INTEGER DEFAULT 0,
    total_earnings DECIMAL(10,2) DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id)
);

-- Create indexes for user_referrals
CREATE INDEX IF NOT EXISTS idx_user_referrals_user_id ON public.user_referrals(user_id);
CREATE INDEX IF NOT EXISTS idx_user_referrals_code ON public.user_referrals(referral_code);

-- Fix the mtaa_shares_leaderboard view to use public.users instead of auth.users
DROP VIEW IF EXISTS public.mtaa_shares_leaderboard;

CREATE VIEW public.mtaa_shares_leaderboard AS
SELECT 
    ms.user_id,
    ms.total_shares,
    ms.monthly_earnings,
    ROW_NUMBER() OVER (ORDER BY ms.total_shares DESC, ms.monthly_earnings DESC) as rank,
    ms.rank_change,
    u.name,
    u.avatar_url
FROM public.mtaa_shares ms
JOIN public.users u ON ms.user_id = u.id
WHERE ms.total_shares > 0
ORDER BY ms.total_shares DESC, ms.monthly_earnings DESC;

-- Enable RLS on all tables (ignore errors if already enabled)
DO $$
BEGIN
    BEGIN
        ALTER TABLE public.user_referrals ENABLE ROW LEVEL SECURITY;
    EXCEPTION
        WHEN OTHERS THEN NULL;
    END;
    
    BEGIN
        ALTER TABLE public.mtaa_shares ENABLE ROW LEVEL SECURITY;
    EXCEPTION
        WHEN OTHERS THEN NULL;
    END;
    
    BEGIN
        ALTER TABLE public.mtaa_share_activities ENABLE ROW LEVEL SECURITY;
    EXCEPTION
        WHEN OTHERS THEN NULL;
    END;
    
    BEGIN
        ALTER TABLE public.referral_history ENABLE ROW LEVEL SECURITY;
    EXCEPTION
        WHEN OTHERS THEN NULL;
    END;
END $$;

-- Drop existing policies to avoid conflicts
DROP POLICY IF EXISTS "Users can view their own referrals" ON public.user_referrals;
DROP POLICY IF EXISTS "Users can insert their own referrals" ON public.user_referrals;
DROP POLICY IF EXISTS "Users can update their own referrals" ON public.user_referrals;
DROP POLICY IF EXISTS "Users can view their own shares" ON public.mtaa_shares;
DROP POLICY IF EXISTS "Users can insert their own shares" ON public.mtaa_shares;
DROP POLICY IF EXISTS "Users can update their own shares" ON public.mtaa_shares;
DROP POLICY IF EXISTS "Users can view their own share activities" ON public.mtaa_share_activities;
DROP POLICY IF EXISTS "Users can insert their own share activities" ON public.mtaa_share_activities;
DROP POLICY IF EXISTS "Users can view referrals they made" ON public.referral_history;
DROP POLICY IF EXISTS "Users can view referrals they received" ON public.referral_history;
DROP POLICY IF EXISTS "Users can insert referral history" ON public.referral_history;
DROP POLICY IF EXISTS "Anyone can view leaderboard" ON public.mtaa_shares;
DROP POLICY IF EXISTS "Service role can manage user_referrals" ON public.user_referrals;
DROP POLICY IF EXISTS "Service role can manage mtaa_shares" ON public.mtaa_shares;
DROP POLICY IF EXISTS "Service role can manage share activities" ON public.mtaa_share_activities;
DROP POLICY IF EXISTS "Service role can manage referral history" ON public.referral_history;

-- RLS Policies for user_referrals
CREATE POLICY "Users can view their own referrals" ON public.user_referrals
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own referrals" ON public.user_referrals
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own referrals" ON public.user_referrals
    FOR UPDATE USING (auth.uid() = user_id);

-- RLS Policies for mtaa_shares
CREATE POLICY "Users can view their own shares" ON public.mtaa_shares
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own shares" ON public.mtaa_shares
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own shares" ON public.mtaa_shares
    FOR UPDATE USING (auth.uid() = user_id);

-- Allow public read access to leaderboard view (separate policy)
CREATE POLICY "Anyone can view leaderboard" ON public.mtaa_shares
    FOR SELECT USING (true);

-- RLS Policies for mtaa_share_activities
CREATE POLICY "Users can view their own share activities" ON public.mtaa_share_activities
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own share activities" ON public.mtaa_share_activities
    FOR INSERT WITH CHECK (auth.uid() = user_id);

-- RLS Policies for referral_history
CREATE POLICY "Users can view referrals they made" ON public.referral_history
    FOR SELECT USING (auth.uid() = referrer_id);

CREATE POLICY "Users can view referrals they received" ON public.referral_history
    FOR SELECT USING (auth.uid() = referred_user_id);

CREATE POLICY "Users can insert referral history" ON public.referral_history
    FOR INSERT WITH CHECK (auth.uid() = referrer_id OR auth.uid() = referred_user_id);

-- Service role can manage all data
CREATE POLICY "Service role can manage user_referrals" ON public.user_referrals
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');

CREATE POLICY "Service role can manage mtaa_shares" ON public.mtaa_shares
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');

CREATE POLICY "Service role can manage share activities" ON public.mtaa_share_activities
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');

CREATE POLICY "Service role can manage referral history" ON public.referral_history
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');

-- Grant permissions (ignore errors if already granted)
DO $$
BEGIN
    BEGIN
        GRANT ALL ON public.user_referrals TO authenticated;
    EXCEPTION
        WHEN OTHERS THEN NULL;
    END;
    
    BEGIN
        GRANT ALL ON public.user_referrals TO service_role;
    EXCEPTION
        WHEN OTHERS THEN NULL;
    END;
    
    BEGIN
        GRANT SELECT ON public.mtaa_shares_leaderboard TO authenticated;
    EXCEPTION
        WHEN OTHERS THEN NULL;
    END;
    
    BEGIN
        GRANT SELECT ON public.mtaa_shares_leaderboard TO anon;
    EXCEPTION
        WHEN OTHERS THEN NULL;
    END;
END $$;

-- Create function to initialize user referrals
CREATE OR REPLACE FUNCTION create_user_referral_record()
RETURNS TRIGGER AS $$
BEGIN
    -- Generate a unique referral code
    INSERT INTO public.user_referrals (user_id, referral_code)
    VALUES (
        NEW.id, 
        UPPER(SUBSTRING(MD5(NEW.id::text || NOW()::text) FROM 1 FOR 8))
    )
    ON CONFLICT (user_id) DO NOTHING;
    
    -- Initialize mtaa_shares record
    INSERT INTO public.mtaa_shares (user_id)
    VALUES (NEW.id)
    ON CONFLICT (user_id) DO NOTHING;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create trigger to auto-create referral records
DROP TRIGGER IF EXISTS create_user_referral_record_trigger ON public.users;
CREATE TRIGGER create_user_referral_record_trigger
    AFTER INSERT ON public.users
    FOR EACH ROW
    EXECUTE FUNCTION create_user_referral_record();

-- Create referral records for existing users
INSERT INTO public.user_referrals (user_id, referral_code)
SELECT 
    u.id,
    UPPER(SUBSTRING(MD5(u.id::text || NOW()::text || RANDOM()::text) FROM 1 FOR 8))
FROM public.users u
LEFT JOIN public.user_referrals ur ON u.id = ur.user_id
WHERE ur.user_id IS NULL
ON CONFLICT (user_id) DO NOTHING;

-- Create mtaa_shares records for existing users
INSERT INTO public.mtaa_shares (user_id)
SELECT u.id
FROM public.users u
LEFT JOIN public.mtaa_shares ms ON u.id = ms.user_id
WHERE ms.user_id IS NULL
ON CONFLICT (user_id) DO NOTHING;

-- Completion notice
DO $$
BEGIN
    RAISE NOTICE 'Created missing tables: user_referrals';
    RAISE NOTICE 'Fixed mtaa_shares_leaderboard view to use public.users';
    RAISE NOTICE 'Added RLS policies for all mtaa_shares and referral tables';
    RAISE NOTICE 'Created auto-initialization triggers for new users';
END $$;
