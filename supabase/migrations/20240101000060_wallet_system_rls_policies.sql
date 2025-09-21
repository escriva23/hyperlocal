-- RLS Policies for Secure Wallet System

-- Wallets policies
CREATE POLICY "Users can view own wallet" ON wallets
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "System can manage wallets" ON wallets
    FOR ALL USING (
        auth.jwt() ->> 'role' = 'service_role' OR
        auth.uid() IN (SELECT id FROM users WHERE role = 'admin')
    );

-- Transactions policies
CREATE POLICY "Users can view own transactions" ON transactions
    FOR SELECT USING (
        auth.uid() = user_id OR 
        auth.uid() = counterparty_id OR
        auth.uid() IN (SELECT id FROM users WHERE role = 'admin')
    );

CREATE POLICY "System can manage transactions" ON transactions
    FOR ALL USING (
        auth.jwt() ->> 'role' = 'service_role' OR
        auth.uid() IN (SELECT id FROM users WHERE role = 'admin')
    );

-- PIN secrets policies (very restrictive)
CREATE POLICY "System only access to PIN secrets" ON pin_secrets
    FOR ALL USING (
        auth.jwt() ->> 'role' = 'service_role'
    );

-- QR codes policies
CREATE POLICY "Users can view own QR codes" ON qr_codes
    FOR SELECT USING (auth.uid() = owner_user_id);

CREATE POLICY "Users can create own QR codes" ON qr_codes
    FOR INSERT WITH CHECK (auth.uid() = owner_user_id);

CREATE POLICY "Users can update own QR codes" ON qr_codes
    FOR UPDATE USING (auth.uid() = owner_user_id);

CREATE POLICY "System can manage QR codes" ON qr_codes
    FOR ALL USING (
        auth.jwt() ->> 'role' = 'service_role' OR
        auth.uid() IN (SELECT id FROM users WHERE role = 'admin')
    );

-- Transaction flags policies
CREATE POLICY "Admins can view all flags" ON transaction_flags
    FOR SELECT USING (
        auth.uid() IN (SELECT id FROM users WHERE role = 'admin')
    );

CREATE POLICY "System can manage flags" ON transaction_flags
    FOR ALL USING (
        auth.jwt() ->> 'role' = 'service_role' OR
        auth.uid() IN (SELECT id FROM users WHERE role = 'admin')
    );

-- Audit log policies
CREATE POLICY "Admins can view audit log" ON audit_log
    FOR SELECT USING (
        auth.uid() IN (SELECT id FROM users WHERE role = 'admin')
    );

CREATE POLICY "System can write audit log" ON audit_log
    FOR INSERT WITH CHECK (
        auth.jwt() ->> 'role' = 'service_role' OR
        auth.uid() IN (SELECT id FROM users WHERE role = 'admin')
    );

-- Referrals policies
CREATE POLICY "Users can view own referrals" ON referrals
    FOR SELECT USING (
        auth.uid() = referrer_id OR 
        auth.uid() = referred_id OR
        auth.uid() IN (SELECT id FROM users WHERE role = 'admin')
    );

CREATE POLICY "System can manage referrals" ON referrals
    FOR ALL USING (
        auth.jwt() ->> 'role' = 'service_role' OR
        auth.uid() IN (SELECT id FROM users WHERE role = 'admin')
    );

-- MPs points policies
CREATE POLICY "Providers can view own points" ON mps_points
    FOR SELECT USING (
        auth.uid() = provider_id OR
        auth.uid() IN (SELECT id FROM users WHERE role = 'admin')
    );

CREATE POLICY "System can manage points" ON mps_points
    FOR ALL USING (
        auth.jwt() ->> 'role' = 'service_role' OR
        auth.uid() IN (SELECT id FROM users WHERE role = 'admin')
    );

-- Provider tiers policies
CREATE POLICY "Providers can view own tier" ON provider_tiers
    FOR SELECT USING (
        auth.uid() = provider_id OR
        auth.uid() IN (SELECT id FROM users WHERE role = 'admin')
    );

CREATE POLICY "System can manage tiers" ON provider_tiers
    FOR ALL USING (
        auth.jwt() ->> 'role' = 'service_role' OR
        auth.uid() IN (SELECT id FROM users WHERE role = 'admin')
    );

-- Equity pools policies
CREATE POLICY "Everyone can view equity pools" ON equity_pools
    FOR SELECT USING (true);

CREATE POLICY "Admins can manage equity pools" ON equity_pools
    FOR ALL USING (
        auth.jwt() ->> 'role' = 'service_role' OR
        auth.uid() IN (SELECT id FROM users WHERE role = 'admin')
    );
