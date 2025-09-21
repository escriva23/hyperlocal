-- Create secure wallet system with transaction codes
-- This migration implements the bank-vault level security system

-- System state table to track transaction codes
CREATE TABLE IF NOT EXISTS system_state (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    last_tx_code BIGINT NOT NULL DEFAULT 0,
    last_tx_hash TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert initial system state
INSERT INTO system_state (last_tx_code, last_tx_hash) VALUES (0, '') ON CONFLICT DO NOTHING;

-- Enhanced wallets table with available and locked balances
DROP TABLE IF EXISTS wallets CASCADE;
CREATE TABLE wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    available_balance DECIMAL(12,2) NOT NULL DEFAULT 0.00,
    locked_balance DECIMAL(12,2) NOT NULL DEFAULT 0.00,
    total_earned DECIMAL(12,2) NOT NULL DEFAULT 0.00,
    total_spent DECIMAL(12,2) NOT NULL DEFAULT 0.00,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id),
    CONSTRAINT positive_balances CHECK (available_balance >= 0 AND locked_balance >= 0)
);

-- Enhanced transactions table with system-generated transaction codes
DROP TABLE IF EXISTS transactions CASCADE;
CREATE TABLE transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tx_code TEXT NOT NULL UNIQUE, -- System-generated sequential transaction code
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    booking_id UUID REFERENCES bookings(id) ON DELETE SET NULL,
    amount DECIMAL(12,2) NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('deposit', 'withdraw', 'lock', 'release', 'commission', 'transfer_send', 'transfer_receive', 'referral_credit', 'escrow_hold', 'escrow_release')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'succeeded', 'failed', 'flagged')),
    balance_before DECIMAL(12,2) NOT NULL,
    balance_after DECIMAL(12,2) NOT NULL,
    counterparty_id UUID REFERENCES users(id) ON DELETE SET NULL, -- For transfers
    payment_method TEXT,
    reference TEXT,
    description TEXT,
    metadata JSONB DEFAULT '{}',
    is_flagged BOOLEAN DEFAULT FALSE,
    processed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- PIN secrets table for secure PIN storage
CREATE TABLE IF NOT EXISTS pin_secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    pin_hash TEXT NOT NULL, -- bcrypt/argon2 hash
    pin_salt TEXT NOT NULL,
    pin_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id)
);

-- QR codes table for payment QR codes
CREATE TABLE IF NOT EXISTS qr_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    qr_id TEXT NOT NULL UNIQUE, -- Public QR identifier
    owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_string TEXT NOT NULL UNIQUE, -- Token for QR
    amount DECIMAL(12,2), -- NULL for dynamic QR
    type TEXT NOT NULL DEFAULT 'static' CHECK (type IN ('static', 'dynamic')),
    expires_at TIMESTAMPTZ,
    redeemed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    redeemed_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Flags table for suspicious transactions
CREATE TABLE IF NOT EXISTS transaction_flags (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tx_id UUID NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    flagged_by TEXT DEFAULT 'system', -- 'system' or admin user ID
    resolved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at TIMESTAMPTZ,
    resolution_notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Audit log for sensitive operations
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    old_values JSONB,
    new_values JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Referrals table for referral rewards
CREATE TABLE IF NOT EXISTS referrals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    referrer_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    referred_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reward_type TEXT NOT NULL CHECK (reward_type IN ('credit', 'discount', 'points')),
    reward_amount DECIMAL(12,2),
    reward_discount_percent INTEGER,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'unlocked', 'paid', 'expired')),
    unlock_condition TEXT, -- e.g., 'first_paid_job'
    unlock_condition_met_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(referrer_id, referred_id)
);

-- Mtaashhare Points (MPs) ledger
CREATE TABLE IF NOT EXISTS mps_points (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    points INTEGER NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('job', 'rating', 'referral', 'bonus', 'manual')),
    source_id UUID, -- booking_id, referral_id, etc.
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Provider tiers based on MPs
CREATE TABLE IF NOT EXISTS provider_tiers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tier_name TEXT NOT NULL,
    from_points INTEGER NOT NULL,
    to_points INTEGER,
    effective_since TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(provider_id)
);

-- Equity pools for Mtaa Shares
CREATE TABLE IF NOT EXISTS equity_pools (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phase TEXT NOT NULL CHECK (phase IN ('Nairobi', 'Africa', 'Global')),
    total_allocated_percent DECIMAL(5,2) NOT NULL,
    distributed_percent DECIMAL(5,2) DEFAULT 0.00,
    distributed_points BIGINT DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert initial equity pools
INSERT INTO equity_pools (phase, total_allocated_percent) VALUES 
('Nairobi', 30.00),
('Africa', 40.00),
('Global', 30.00)
ON CONFLICT DO NOTHING;

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_wallets_user_id ON wallets(user_id);
CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_transactions_tx_code ON transactions(tx_code);
CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_transactions_type ON transactions(type);
CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pin_secrets_user_id ON pin_secrets(user_id);
CREATE INDEX IF NOT EXISTS idx_qr_codes_owner_user_id ON qr_codes(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_qr_codes_code_string ON qr_codes(code_string);
CREATE INDEX IF NOT EXISTS idx_transaction_flags_tx_id ON transaction_flags(tx_id);
CREATE INDEX IF NOT EXISTS idx_referrals_referrer_id ON referrals(referrer_id);
CREATE INDEX IF NOT EXISTS idx_referrals_referred_id ON referrals(referred_id);
CREATE INDEX IF NOT EXISTS idx_mps_points_provider_id ON mps_points(provider_id);
CREATE INDEX IF NOT EXISTS idx_provider_tiers_provider_id ON provider_tiers(provider_id);

-- Enable RLS
ALTER TABLE wallets ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE pin_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE qr_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE transaction_flags ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE referrals ENABLE ROW LEVEL SECURITY;
ALTER TABLE mps_points ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_tiers ENABLE ROW LEVEL SECURITY;
ALTER TABLE equity_pools ENABLE ROW LEVEL SECURITY;
