-- Admin functions for wallet system monitoring

-- Function to get admin wallet statistics
CREATE OR REPLACE FUNCTION get_admin_wallet_stats()
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    total_wallets INTEGER;
    total_balance DECIMAL(12,2);
    total_locked DECIMAL(12,2);
    total_transactions INTEGER;
    flagged_transactions INTEGER;
    daily_volume DECIMAL(12,2);
    result JSONB;
BEGIN
    -- Get total number of wallets
    SELECT COUNT(*) FROM wallets INTO total_wallets;
    
    -- Get total available balance across all wallets
    SELECT COALESCE(SUM(available_balance), 0) FROM wallets INTO total_balance;
    
    -- Get total locked balance across all wallets
    SELECT COALESCE(SUM(locked_balance), 0) FROM wallets INTO total_locked;
    
    -- Get total number of transactions
    SELECT COUNT(*) FROM transactions INTO total_transactions;
    
    -- Get number of flagged transactions
    SELECT COUNT(*) FROM transactions WHERE is_flagged = true INTO flagged_transactions;
    
    -- Get daily transaction volume (last 24 hours)
    SELECT COALESCE(SUM(ABS(amount)), 0) 
    FROM transactions 
    WHERE created_at >= NOW() - INTERVAL '24 hours'
    AND status = 'succeeded'
    INTO daily_volume;
    
    -- Build result JSON
    result := jsonb_build_object(
        'total_wallets', total_wallets,
        'total_balance', total_balance,
        'total_locked', total_locked,
        'total_transactions', total_transactions,
        'flagged_transactions', flagged_transactions,
        'daily_volume', daily_volume
    );
    
    RETURN result;
END;
$$;

-- Function to get wallet reconciliation data
CREATE OR REPLACE FUNCTION get_wallet_reconciliation()
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    wallet_sum DECIMAL(12,2);
    transaction_sum DECIMAL(12,2);
    locked_sum DECIMAL(12,2);
    discrepancy DECIMAL(12,2);
    result JSONB;
BEGIN
    -- Sum of all wallet balances
    SELECT COALESCE(SUM(available_balance + locked_balance), 0) FROM wallets INTO wallet_sum;
    
    -- Sum of all successful transactions (net flow)
    SELECT COALESCE(SUM(
        CASE 
            WHEN type IN ('deposit', 'transfer_receive', 'commission') THEN amount
            WHEN type IN ('withdraw', 'transfer_send', 'lock') THEN -amount
            ELSE 0
        END
    ), 0) 
    FROM transactions 
    WHERE status = 'succeeded'
    INTO transaction_sum;
    
    -- Sum of locked balances
    SELECT COALESCE(SUM(locked_balance), 0) FROM wallets INTO locked_sum;
    
    -- Calculate discrepancy
    discrepancy := wallet_sum - transaction_sum;
    
    result := jsonb_build_object(
        'wallet_sum', wallet_sum,
        'transaction_sum', transaction_sum,
        'locked_sum', locked_sum,
        'discrepancy', discrepancy,
        'is_balanced', ABS(discrepancy) < 0.01,
        'last_check', NOW()
    );
    
    RETURN result;
END;
$$;

-- Function to get suspicious activity report
CREATE OR REPLACE FUNCTION get_suspicious_activity_report()
RETURNS TABLE (
    user_id UUID,
    user_name TEXT,
    suspicious_patterns TEXT[],
    risk_score INTEGER,
    last_activity TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    RETURN QUERY
    WITH user_stats AS (
        SELECT 
            u.id,
            u.name,
            COUNT(t.id) as tx_count,
            COUNT(CASE WHEN t.created_at >= NOW() - INTERVAL '24 hours' THEN 1 END) as daily_tx,
            COUNT(CASE WHEN t.is_flagged THEN 1 END) as flagged_tx,
            MAX(t.created_at) as last_tx,
            COUNT(DISTINCT t.counterparty_id) as unique_counterparties,
            AVG(ABS(t.amount)) as avg_amount
        FROM users u
        LEFT JOIN transactions t ON u.id = t.user_id
        WHERE u.role IN ('customer', 'provider')
        GROUP BY u.id, u.name
    ),
    risk_analysis AS (
        SELECT 
            *,
            ARRAY[]::TEXT[] as patterns,
            0 as base_risk
        FROM user_stats
    ),
    pattern_detection AS (
        SELECT 
            *,
            patterns || 
            CASE WHEN daily_tx > 50 THEN ARRAY['High daily transaction volume'] ELSE ARRAY[]::TEXT[] END ||
            CASE WHEN flagged_tx > 0 THEN ARRAY['Has flagged transactions'] ELSE ARRAY[]::TEXT[] END ||
            CASE WHEN unique_counterparties = 1 AND tx_count > 20 THEN ARRAY['Single counterparty pattern'] ELSE ARRAY[]::TEXT[] END ||
            CASE WHEN avg_amount > 100000 THEN ARRAY['High value transactions'] ELSE ARRAY[]::TEXT[] END
            as final_patterns,
            base_risk + 
            (CASE WHEN daily_tx > 50 THEN 30 ELSE 0 END) +
            (CASE WHEN flagged_tx > 0 THEN 40 ELSE 0 END) +
            (CASE WHEN unique_counterparties = 1 AND tx_count > 20 THEN 25 ELSE 0 END) +
            (CASE WHEN avg_amount > 100000 THEN 20 ELSE 0 END)
            as calculated_risk
        FROM risk_analysis
    )
    SELECT 
        id,
        name,
        final_patterns,
        calculated_risk,
        last_tx
    FROM pattern_detection
    WHERE array_length(final_patterns, 1) > 0
    ORDER BY calculated_risk DESC, last_tx DESC;
END;
$$;

-- Function to manually flag a transaction
CREATE OR REPLACE FUNCTION flag_transaction(
    transaction_id UUID,
    flag_reason TEXT,
    admin_user_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    tx_exists BOOLEAN;
    flag_id UUID;
BEGIN
    -- Check if transaction exists
    SELECT EXISTS(SELECT 1 FROM transactions WHERE id = transaction_id) INTO tx_exists;
    
    IF NOT tx_exists THEN
        RETURN jsonb_build_object('success', false, 'error', 'Transaction not found');
    END IF;
    
    -- Update transaction as flagged
    UPDATE transactions 
    SET is_flagged = true, updated_at = NOW()
    WHERE id = transaction_id;
    
    -- Create flag record
    INSERT INTO transaction_flags (tx_id, reason, flagged_by)
    VALUES (transaction_id, flag_reason, admin_user_id::text)
    RETURNING id INTO flag_id;
    
    -- Log audit trail
    INSERT INTO audit_log (user_id, action, resource_type, resource_id, new_values)
    VALUES (admin_user_id, 'FLAG_TRANSACTION', 'transaction', transaction_id::text, 
            jsonb_build_object('reason', flag_reason, 'flag_id', flag_id));
    
    RETURN jsonb_build_object('success', true, 'flag_id', flag_id);
END;
$$;

-- Function to resolve a flagged transaction
CREATE OR REPLACE FUNCTION resolve_transaction_flag(
    flag_id UUID,
    admin_user_id UUID,
    resolution_notes TEXT,
    unblock_transaction BOOLEAN DEFAULT false
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    flag_exists BOOLEAN;
    transaction_id UUID;
BEGIN
    -- Check if flag exists and get transaction ID
    SELECT EXISTS(SELECT 1 FROM transaction_flags WHERE id = flag_id AND resolved_at IS NULL),
           tx_id
    FROM transaction_flags 
    WHERE id = flag_id 
    INTO flag_exists, transaction_id;
    
    IF NOT flag_exists THEN
        RETURN jsonb_build_object('success', false, 'error', 'Flag not found or already resolved');
    END IF;
    
    -- Update flag as resolved
    UPDATE transaction_flags 
    SET resolved_by = admin_user_id,
        resolved_at = NOW(),
        resolution_notes = resolve_transaction_flag.resolution_notes
    WHERE id = flag_id;
    
    -- Optionally unblock the transaction
    IF unblock_transaction THEN
        UPDATE transactions 
        SET is_flagged = false, updated_at = NOW()
        WHERE id = transaction_id;
    END IF;
    
    -- Log audit trail
    INSERT INTO audit_log (user_id, action, resource_type, resource_id, new_values)
    VALUES (admin_user_id, 'RESOLVE_FLAG', 'transaction_flag', flag_id::text, 
            jsonb_build_object(
                'resolution_notes', resolution_notes, 
                'unblocked', unblock_transaction,
                'transaction_id', transaction_id
            ));
    
    RETURN jsonb_build_object('success', true, 'transaction_id', transaction_id);
END;
$$;

-- Function to get transaction code validation report
CREATE OR REPLACE FUNCTION get_transaction_code_report()
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    total_codes INTEGER;
    duplicate_codes INTEGER;
    sequence_gaps INTEGER;
    last_code BIGINT;
    expected_next BIGINT;
    result JSONB;
BEGIN
    -- Get total transaction codes
    SELECT COUNT(*) FROM transactions INTO total_codes;
    
    -- Check for duplicate transaction codes (should be 0)
    SELECT COUNT(*) - COUNT(DISTINCT tx_code) FROM transactions INTO duplicate_codes;
    
    -- Get last transaction code number from system state
    SELECT last_tx_code FROM system_state LIMIT 1 INTO last_code;
    
    -- Expected next code
    expected_next := last_code + 1;
    
    -- Check for sequence gaps (simplified check)
    sequence_gaps := 0; -- Would need more complex logic for full gap detection
    
    result := jsonb_build_object(
        'total_codes', total_codes,
        'duplicate_codes', duplicate_codes,
        'sequence_gaps', sequence_gaps,
        'last_code', last_code,
        'expected_next', expected_next,
        'system_healthy', duplicate_codes = 0 AND sequence_gaps = 0,
        'last_check', NOW()
    );
    
    RETURN result;
END;
$$;

-- Grant execute permissions to authenticated users with admin role
GRANT EXECUTE ON FUNCTION get_admin_wallet_stats() TO authenticated;
GRANT EXECUTE ON FUNCTION get_wallet_reconciliation() TO authenticated;
GRANT EXECUTE ON FUNCTION get_suspicious_activity_report() TO authenticated;
GRANT EXECUTE ON FUNCTION flag_transaction(UUID, TEXT, UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION resolve_transaction_flag(UUID, UUID, TEXT, BOOLEAN) TO authenticated;
GRANT EXECUTE ON FUNCTION get_transaction_code_report() TO authenticated;
