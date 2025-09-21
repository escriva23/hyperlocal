-- Create wallet tables for user balance and transaction management

-- Create user_wallets table
CREATE TABLE IF NOT EXISTS public.user_wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    balance DECIMAL(10,2) DEFAULT 0.00 NOT NULL,
    currency VARCHAR(3) DEFAULT 'KES' NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    
    CONSTRAINT user_wallets_balance_positive CHECK (balance >= 0),
    CONSTRAINT user_wallets_user_id_unique UNIQUE (user_id)
);

-- Create wallet_transactions table
CREATE TABLE IF NOT EXISTS public.wallet_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    wallet_id UUID NOT NULL REFERENCES public.user_wallets(id) ON DELETE CASCADE,
    type VARCHAR(20) NOT NULL CHECK (type IN ('deposit', 'withdrawal', 'payment', 'refund', 'bonus', 'commission')),
    amount DECIMAL(10,2) NOT NULL,
    currency VARCHAR(3) DEFAULT 'KES' NOT NULL,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'failed', 'cancelled')),
    reference VARCHAR(100),
    description TEXT,
    metadata JSONB DEFAULT '{}',
    booking_id UUID REFERENCES public.bookings(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    
    CONSTRAINT wallet_transactions_amount_positive CHECK (amount > 0)
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_user_wallets_user_id ON public.user_wallets(user_id);
CREATE INDEX IF NOT EXISTS idx_wallet_transactions_user_id ON public.wallet_transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_wallet_transactions_wallet_id ON public.wallet_transactions(wallet_id);
CREATE INDEX IF NOT EXISTS idx_wallet_transactions_status ON public.wallet_transactions(status);
CREATE INDEX IF NOT EXISTS idx_wallet_transactions_type ON public.wallet_transactions(type);
CREATE INDEX IF NOT EXISTS idx_wallet_transactions_created_at ON public.wallet_transactions(created_at DESC);

-- Enable RLS
ALTER TABLE public.user_wallets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.wallet_transactions ENABLE ROW LEVEL SECURITY;

-- RLS Policies for user_wallets
CREATE POLICY "Users can view their own wallet" ON public.user_wallets
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can update their own wallet" ON public.user_wallets
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "System can insert wallets" ON public.user_wallets
    FOR INSERT WITH CHECK (true);

-- RLS Policies for wallet_transactions
CREATE POLICY "Users can view their own transactions" ON public.wallet_transactions
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "System can insert transactions" ON public.wallet_transactions
    FOR INSERT WITH CHECK (true);

CREATE POLICY "System can update transactions" ON public.wallet_transactions
    FOR UPDATE USING (true);

-- Function to create wallet for new users
CREATE OR REPLACE FUNCTION create_user_wallet()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.user_wallets (user_id, balance, currency)
    VALUES (NEW.id, 0.00, 'KES');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger to automatically create wallet for new users
DROP TRIGGER IF EXISTS create_wallet_on_user_signup ON auth.users;
CREATE TRIGGER create_wallet_on_user_signup
    AFTER INSERT ON auth.users
    FOR EACH ROW
    EXECUTE FUNCTION create_user_wallet();

-- Function to update wallet balance after transaction
CREATE OR REPLACE FUNCTION update_wallet_balance()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'completed' AND (OLD.status IS NULL OR OLD.status != 'completed') THEN
        -- Update wallet balance based on transaction type
        IF NEW.type IN ('deposit', 'refund', 'bonus', 'commission') THEN
            UPDATE public.user_wallets 
            SET balance = balance + NEW.amount, updated_at = NOW()
            WHERE id = NEW.wallet_id;
        ELSIF NEW.type IN ('withdrawal', 'payment') THEN
            UPDATE public.user_wallets 
            SET balance = balance - NEW.amount, updated_at = NOW()
            WHERE id = NEW.wallet_id AND balance >= NEW.amount;
        END IF;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger to update wallet balance on transaction completion
DROP TRIGGER IF EXISTS update_balance_on_transaction ON public.wallet_transactions;
CREATE TRIGGER update_balance_on_transaction
    AFTER INSERT OR UPDATE ON public.wallet_transactions
    FOR EACH ROW
    EXECUTE FUNCTION update_wallet_balance();

-- Grant permissions
GRANT SELECT, INSERT, UPDATE ON public.user_wallets TO authenticated;
GRANT SELECT, INSERT, UPDATE ON public.wallet_transactions TO authenticated;

-- Create wallets for existing users
INSERT INTO public.user_wallets (user_id, balance, currency)
SELECT id, 0.00, 'KES'
FROM auth.users
WHERE id NOT IN (SELECT user_id FROM public.user_wallets)
ON CONFLICT (user_id) DO NOTHING;

-- Completion notice
DO $$
BEGIN
    RAISE NOTICE 'Wallet tables created successfully with RLS policies and triggers';
END $$;
