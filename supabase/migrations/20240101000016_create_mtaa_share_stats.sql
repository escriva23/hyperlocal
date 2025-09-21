-- Create mtaa_share_stats table for tracking share value and community statistics
CREATE TABLE public.mtaa_share_stats (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    current_value DECIMAL(10,4) NOT NULL DEFAULT 1.0000, -- Current value per share in KES
    total_shares_issued DECIMAL(15,2) NOT NULL DEFAULT 0,
    total_community_value DECIMAL(15,2) NOT NULL DEFAULT 0,
    active_users INTEGER NOT NULL DEFAULT 0,
    monthly_transactions INTEGER NOT NULL DEFAULT 0,
    growth_rate DECIMAL(5,2) NOT NULL DEFAULT 0.00, -- Percentage growth
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create index for performance
CREATE INDEX idx_mtaa_share_stats_created_at ON public.mtaa_share_stats(created_at DESC);

-- Create trigger for updated_at
CREATE TRIGGER update_mtaa_share_stats_updated_at 
    BEFORE UPDATE ON public.mtaa_share_stats 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert initial stats data
INSERT INTO public.mtaa_share_stats (
    current_value,
    total_shares_issued,
    total_community_value,
    active_users,
    monthly_transactions,
    growth_rate
) VALUES (
    1.0000,  -- Starting value of 1 KES per share
    0,       -- No shares issued yet
    0,       -- No community value yet
    0,       -- No active users yet
    0,       -- No transactions yet
    0.00     -- No growth yet
);

-- Create function to get current share stats
CREATE OR REPLACE FUNCTION get_current_share_stats()
RETURNS TABLE (
    current_value DECIMAL(10,4),
    total_shares_issued DECIMAL(15,2),
    total_community_value DECIMAL(15,2),
    active_users INTEGER,
    monthly_transactions INTEGER,
    growth_rate DECIMAL(5,2)
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        mss.current_value,
        mss.total_shares_issued,
        mss.total_community_value,
        mss.active_users,
        mss.monthly_transactions,
        mss.growth_rate
    FROM public.mtaa_share_stats mss
    ORDER BY mss.created_at DESC
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;

-- Create function to update share stats (can be called periodically)
CREATE OR REPLACE FUNCTION update_share_stats()
RETURNS void AS $$
DECLARE
    total_shares DECIMAL(15,2);
    user_count INTEGER;
    transaction_count INTEGER;
    new_value DECIMAL(10,4);
BEGIN
    -- Calculate total shares issued
    SELECT COALESCE(SUM(total_shares), 0) INTO total_shares
    FROM public.mtaa_shares;
    
    -- Count active users (users with shares)
    SELECT COUNT(*) INTO user_count
    FROM public.mtaa_shares
    WHERE total_shares > 0;
    
    -- Count monthly transactions
    SELECT COUNT(*) INTO transaction_count
    FROM public.mtaa_share_activities
    WHERE created_at >= DATE_TRUNC('month', NOW());
    
    -- Calculate new share value (simple growth model)
    -- Value increases based on community activity and total value
    new_value := 1.0000 + (total_shares * 0.0001) + (user_count * 0.001);
    
    -- Insert new stats record
    INSERT INTO public.mtaa_share_stats (
        current_value,
        total_shares_issued,
        total_community_value,
        active_users,
        monthly_transactions,
        growth_rate
    ) VALUES (
        new_value,
        total_shares,
        total_shares * new_value,
        user_count,
        transaction_count,
        CASE 
            WHEN total_shares > 0 THEN ((new_value - 1.0000) / 1.0000) * 100
            ELSE 0.00
        END
    );
END;
$$ LANGUAGE plpgsql;
