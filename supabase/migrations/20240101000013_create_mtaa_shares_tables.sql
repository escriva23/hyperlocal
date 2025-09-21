-- Drop existing tables if they exist to avoid conflicts
DROP TABLE IF EXISTS public.mtaa_share_activities CASCADE;
DROP TABLE IF EXISTS public.mtaa_shares CASCADE;
DROP TABLE IF EXISTS public.referral_history CASCADE;

-- Create mtaa_share_activities table
CREATE TABLE public.mtaa_share_activities (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    activity_type VARCHAR(50) NOT NULL, -- 'earned', 'redeemed', 'bonus', 'referral'
    shares_amount DECIMAL(10,2) NOT NULL DEFAULT 0,
    description TEXT,
    reference_id UUID, -- Can reference bookings, referrals, etc.
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create mtaa_shares table (main shares balance)
CREATE TABLE public.mtaa_shares (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE UNIQUE,
    total_shares DECIMAL(12,2) NOT NULL DEFAULT 0,
    available_shares DECIMAL(12,2) NOT NULL DEFAULT 0,
    locked_shares DECIMAL(12,2) NOT NULL DEFAULT 0,
    lifetime_earned DECIMAL(12,2) NOT NULL DEFAULT 0,
    monthly_earnings DECIMAL(10,2) NOT NULL DEFAULT 0,
    current_rank INTEGER DEFAULT NULL,
    rank_change INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create referral_history table
CREATE TABLE public.referral_history (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    referrer_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    referred_user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    referral_code VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- 'pending', 'completed', 'cancelled'
    shares_earned DECIMAL(10,2) DEFAULT 0,
    bonus_earned DECIMAL(10,2) DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(referred_user_id) -- Each user can only be referred once
);

-- Create indexes for better performance
CREATE INDEX idx_mtaa_share_activities_user_id ON public.mtaa_share_activities(user_id);
CREATE INDEX idx_mtaa_share_activities_created_at ON public.mtaa_share_activities(created_at DESC);
CREATE INDEX idx_mtaa_shares_user_id ON public.mtaa_shares(user_id);
CREATE INDEX idx_mtaa_shares_total_shares ON public.mtaa_shares(total_shares DESC);
CREATE INDEX idx_referral_history_referrer_id ON public.referral_history(referrer_id);
CREATE INDEX idx_referral_history_referred_user_id ON public.referral_history(referred_user_id);

-- Create trigger function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers
CREATE TRIGGER update_mtaa_share_activities_updated_at 
    BEFORE UPDATE ON public.mtaa_share_activities 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_mtaa_shares_updated_at 
    BEFORE UPDATE ON public.mtaa_shares 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_referral_history_updated_at 
    BEFORE UPDATE ON public.referral_history 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
