-- Core Wallet System Functions with Transaction Code Security

-- Function to generate next transaction code
CREATE OR REPLACE FUNCTION generate_transaction_code()
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    next_code BIGINT;
    tx_code TEXT;
    timestamp_part TEXT;
    checksum TEXT;
BEGIN
    -- Get and increment the transaction code
    UPDATE system_state 
    SET last_tx_code = last_tx_code + 1,
        updated_at = NOW()
    RETURNING last_tx_code INTO next_code;
    
    -- Generate timestamp part (YYYYMMDDHHMMSS)
    timestamp_part := to_char(NOW(), 'YYYYMMDDHH24MISS');
    
    -- Generate checksum using HMAC (simplified version)
    checksum := encode(digest(next_code::text || timestamp_part || 'hequeendo_secret', 'sha256'), 'hex');
    checksum := substring(checksum, 1, 8); -- Take first 8 characters
    
    -- Format: TX-YYYYMMDDHHMMSS-NNNNNN-CHECKSUM
    tx_code := 'TX-' || timestamp_part || '-' || lpad(next_code::text, 6, '0') || '-' || upper(checksum);
    
    -- Update system state with new hash
    UPDATE system_state 
    SET last_tx_hash = checksum;
    
    RETURN tx_code;
END;
$$;

-- Function to validate transaction code sequence
CREATE OR REPLACE FUNCTION validate_transaction_code(tx_code TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    code_exists BOOLEAN;
BEGIN
    -- Check if transaction code already exists
    SELECT EXISTS(
        SELECT 1 FROM transactions WHERE transactions.tx_code = validate_transaction_code.tx_code
    ) INTO code_exists;
    
    -- If code exists, it's invalid (replay attempt)
    IF code_exists THEN
        -- Log suspicious activity
        INSERT INTO transaction_flags (tx_id, reason, flagged_by)
        SELECT id, 'Duplicate transaction code attempted', 'system'
        FROM transactions 
        WHERE transactions.tx_code = validate_transaction_code.tx_code
        LIMIT 1;
        
        RETURN FALSE;
    END IF;
    
    RETURN TRUE;
END;
$$;

-- Function to create wallet for new user
CREATE OR REPLACE FUNCTION create_user_wallet(user_id UUID)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    wallet_id UUID;
BEGIN
    INSERT INTO wallets (user_id, available_balance, locked_balance)
    VALUES (user_id, 0.00, 0.00)
    RETURNING id INTO wallet_id;
    
    -- Log wallet creation
    INSERT INTO audit_log (user_id, action, resource_type, resource_id, new_values)
    VALUES (user_id, 'CREATE', 'wallet', wallet_id::text, jsonb_build_object('initial_balance', 0.00));
    
    RETURN wallet_id;
END;
$$;

-- Function to lock funds in escrow (booking)
CREATE OR REPLACE FUNCTION lock_funds_escrow(
    customer_id UUID,
    booking_id UUID,
    amount DECIMAL(12,2),
    description TEXT DEFAULT 'Escrow for booking'
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    tx_code TEXT;
    current_balance DECIMAL(12,2);
    wallet_record RECORD;
    transaction_id UUID;
BEGIN
    -- Generate transaction code
    tx_code := generate_transaction_code();
    
    -- Validate transaction code
    IF NOT validate_transaction_code(tx_code) THEN
        RETURN jsonb_build_object('success', false, 'error', 'Invalid transaction code');
    END IF;
    
    -- Get current wallet state with row lock
    SELECT * FROM wallets WHERE user_id = customer_id FOR UPDATE INTO wallet_record;
    
    IF NOT FOUND THEN
        RETURN jsonb_build_object('success', false, 'error', 'Wallet not found');
    END IF;
    
    -- Check sufficient balance
    IF wallet_record.available_balance < amount THEN
        RETURN jsonb_build_object('success', false, 'error', 'Insufficient balance');
    END IF;
    
    -- Update wallet balances
    UPDATE wallets 
    SET available_balance = available_balance - amount,
        locked_balance = locked_balance + amount,
        updated_at = NOW()
    WHERE user_id = customer_id;
    
    -- Create transaction record
    INSERT INTO transactions (
        tx_code, user_id, booking_id, amount, type, status,
        balance_before, balance_after, description, metadata
    ) VALUES (
        tx_code, customer_id, booking_id, amount, 'lock', 'succeeded',
        wallet_record.available_balance, wallet_record.available_balance - amount,
        description, jsonb_build_object('escrow_amount', amount)
    ) RETURNING id INTO transaction_id;
    
    -- Log audit trail
    INSERT INTO audit_log (user_id, action, resource_type, resource_id, new_values)
    VALUES (customer_id, 'LOCK_FUNDS', 'transaction', transaction_id::text, 
            jsonb_build_object('amount', amount, 'booking_id', booking_id));
    
    RETURN jsonb_build_object('success', true, 'tx_code', tx_code, 'transaction_id', transaction_id);
END;
$$;

-- Function to release escrow funds (job completion)
CREATE OR REPLACE FUNCTION release_escrow_funds(
    booking_id UUID,
    commission_rate DECIMAL(5,2) DEFAULT 15.00
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    tx_code_customer TEXT;
    tx_code_provider TEXT;
    tx_code_commission TEXT;
    booking_record RECORD;
    customer_wallet RECORD;
    provider_wallet RECORD;
    provider_amount DECIMAL(12,2);
    commission_amount DECIMAL(12,2);
    transaction_ids UUID[];
BEGIN
    -- Get booking details
    SELECT * FROM bookings WHERE id = booking_id INTO booking_record;
    
    IF NOT FOUND THEN
        RETURN jsonb_build_object('success', false, 'error', 'Booking not found');
    END IF;
    
    -- Calculate amounts
    commission_amount := booking_record.price * (commission_rate / 100);
    provider_amount := booking_record.price - commission_amount;
    
    -- Generate transaction codes
    tx_code_customer := generate_transaction_code();
    tx_code_provider := generate_transaction_code();
    tx_code_commission := generate_transaction_code();
    
    -- Get wallet states with locks
    SELECT * FROM wallets WHERE user_id = booking_record.customer_id FOR UPDATE INTO customer_wallet;
    SELECT * FROM wallets WHERE user_id = booking_record.provider_id FOR UPDATE INTO provider_wallet;
    
    -- Release customer's locked funds
    UPDATE wallets 
    SET locked_balance = locked_balance - booking_record.price,
        total_spent = total_spent + booking_record.price,
        updated_at = NOW()
    WHERE user_id = booking_record.customer_id;
    
    -- Credit provider
    UPDATE wallets 
    SET available_balance = available_balance + provider_amount,
        total_earned = total_earned + provider_amount,
        updated_at = NOW()
    WHERE user_id = booking_record.provider_id;
    
    -- Create transaction records
    INSERT INTO transactions (
        tx_code, user_id, booking_id, amount, type, status,
        balance_before, balance_after, counterparty_id, description
    ) VALUES 
    (tx_code_customer, booking_record.customer_id, booking_id, -booking_record.price, 'release', 'succeeded',
     customer_wallet.locked_balance, customer_wallet.locked_balance - booking_record.price, 
     booking_record.provider_id, 'Escrow release for completed job'),
    (tx_code_provider, booking_record.provider_id, booking_id, provider_amount, 'commission', 'succeeded',
     provider_wallet.available_balance, provider_wallet.available_balance + provider_amount,
     booking_record.customer_id, 'Payment for completed job'),
    (tx_code_commission, booking_record.provider_id, booking_id, commission_amount, 'commission', 'succeeded',
     0, commission_amount, NULL, 'Platform commission')
    RETURNING ARRAY[id] INTO transaction_ids;
    
    -- Award MPs to provider
    INSERT INTO mps_points (provider_id, points, source, source_id)
    VALUES (booking_record.provider_id, 1, 'job', booking_id);
    
    -- Update booking status
    UPDATE bookings SET status = 'completed', updated_at = NOW() WHERE id = booking_id;
    
    RETURN jsonb_build_object('success', true, 'provider_amount', provider_amount, 'commission_amount', commission_amount);
END;
$$;

-- Function for internal wallet transfers with PIN verification
CREATE OR REPLACE FUNCTION transfer_funds(
    sender_id UUID,
    recipient_id UUID,
    amount DECIMAL(12,2),
    pin_hash TEXT,
    description TEXT DEFAULT 'Wallet transfer'
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    tx_code_send TEXT;
    tx_code_receive TEXT;
    sender_wallet RECORD;
    recipient_wallet RECORD;
    stored_pin_hash TEXT;
    pin_attempts INTEGER;
    locked_until TIMESTAMPTZ;
BEGIN
    -- Validate PIN
    SELECT pin_secrets.pin_hash, pin_secrets.pin_attempts, pin_secrets.locked_until 
    FROM pin_secrets WHERE user_id = sender_id 
    INTO stored_pin_hash, pin_attempts, locked_until;
    
    -- Check if account is locked
    IF locked_until IS NOT NULL AND locked_until > NOW() THEN
        RETURN jsonb_build_object('success', false, 'error', 'Account temporarily locked due to failed PIN attempts');
    END IF;
    
    -- Verify PIN (simplified - in production use proper bcrypt/argon2)
    IF stored_pin_hash != pin_hash THEN
        -- Increment failed attempts
        UPDATE pin_secrets 
        SET pin_attempts = pin_attempts + 1,
            locked_until = CASE WHEN pin_attempts >= 4 THEN NOW() + INTERVAL '15 minutes' ELSE NULL END
        WHERE user_id = sender_id;
        
        RETURN jsonb_build_object('success', false, 'error', 'Invalid PIN');
    END IF;
    
    -- Reset PIN attempts on successful verification
    UPDATE pin_secrets SET pin_attempts = 0, locked_until = NULL WHERE user_id = sender_id;
    
    -- Generate transaction codes
    tx_code_send := generate_transaction_code();
    tx_code_receive := generate_transaction_code();
    
    -- Get wallet states with locks
    SELECT * FROM wallets WHERE user_id = sender_id FOR UPDATE INTO sender_wallet;
    SELECT * FROM wallets WHERE user_id = recipient_id FOR UPDATE INTO recipient_wallet;
    
    -- Check sufficient balance
    IF sender_wallet.available_balance < amount THEN
        RETURN jsonb_build_object('success', false, 'error', 'Insufficient balance');
    END IF;
    
    -- Update balances
    UPDATE wallets 
    SET available_balance = available_balance - amount,
        total_spent = total_spent + amount,
        updated_at = NOW()
    WHERE user_id = sender_id;
    
    UPDATE wallets 
    SET available_balance = available_balance + amount,
        total_earned = total_earned + amount,
        updated_at = NOW()
    WHERE user_id = recipient_id;
    
    -- Create transaction records
    INSERT INTO transactions (
        tx_code, user_id, amount, type, status,
        balance_before, balance_after, counterparty_id, description
    ) VALUES 
    (tx_code_send, sender_id, -amount, 'transfer_send', 'succeeded',
     sender_wallet.available_balance, sender_wallet.available_balance - amount, recipient_id, description),
    (tx_code_receive, recipient_id, amount, 'transfer_receive', 'succeeded',
     recipient_wallet.available_balance, recipient_wallet.available_balance + amount, sender_id, description);
    
    RETURN jsonb_build_object('success', true, 'tx_code_send', tx_code_send, 'tx_code_receive', tx_code_receive);
END;
$$;

-- Function to create static QR code for user
CREATE OR REPLACE FUNCTION create_static_qr(user_id UUID)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    qr_id TEXT;
    code_string TEXT;
    qr_record_id UUID;
BEGIN
    -- Generate unique QR ID and code string
    qr_id := 'QR-' || encode(gen_random_bytes(8), 'hex');
    code_string := encode(gen_random_bytes(16), 'base64');
    
    -- Create QR code record
    INSERT INTO qr_codes (qr_id, owner_user_id, code_string, type, amount)
    VALUES (qr_id, user_id, code_string, 'static', NULL)
    RETURNING id INTO qr_record_id;
    
    RETURN jsonb_build_object('success', true, 'qr_id', qr_id, 'code_string', code_string);
END;
$$;

-- Function to create dynamic QR code for specific amount
CREATE OR REPLACE FUNCTION create_dynamic_qr(
    user_id UUID,
    amount DECIMAL(12,2),
    expires_in_minutes INTEGER DEFAULT 30
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    qr_id TEXT;
    code_string TEXT;
    expires_at TIMESTAMPTZ;
BEGIN
    -- Generate unique QR ID and code string
    qr_id := 'QR-' || encode(gen_random_bytes(8), 'hex');
    code_string := encode(gen_random_bytes(16), 'base64');
    expires_at := NOW() + (expires_in_minutes || ' minutes')::INTERVAL;
    
    -- Create QR code record
    INSERT INTO qr_codes (qr_id, owner_user_id, code_string, type, amount, expires_at)
    VALUES (qr_id, user_id, code_string, 'dynamic', amount, expires_at);
    
    RETURN jsonb_build_object('success', true, 'qr_id', qr_id, 'code_string', code_string, 'expires_at', expires_at);
END;
$$;

-- Trigger to create wallet when user is created
CREATE OR REPLACE FUNCTION trigger_create_user_wallet()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    PERFORM create_user_wallet(NEW.id);
    RETURN NEW;
END;
$$;

-- Create trigger
DROP TRIGGER IF EXISTS create_wallet_on_user_insert ON users;
CREATE TRIGGER create_wallet_on_user_insert
    AFTER INSERT ON users
    FOR EACH ROW
    EXECUTE FUNCTION trigger_create_user_wallet();
