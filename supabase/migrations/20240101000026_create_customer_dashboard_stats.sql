-- Create get_customer_dashboard_stats function to fix dashboard loading errors
-- This addresses the 400 Bad Request on get_customer_dashboard_stats RPC call

-- Drop existing functions first to avoid return type conflicts
DROP FUNCTION IF EXISTS get_customer_dashboard_stats(UUID);
DROP FUNCTION IF EXISTS get_provider_dashboard_stats(UUID);

-- Create function to get customer dashboard statistics
CREATE OR REPLACE FUNCTION get_customer_dashboard_stats(customer_id UUID)
RETURNS JSON AS $$
DECLARE
    stats JSON;
    total_bookings INTEGER := 0;
    completed_bookings INTEGER := 0;
    pending_bookings INTEGER := 0;
    cancelled_bookings INTEGER := 0;
    pending_reviews INTEGER := 0;
    wallet_balance DECIMAL(10,2) := 0.00;
    total_spent DECIMAL(10,2) := 0.00;
    favorite_category TEXT := 'general';
    recent_activity JSON;
BEGIN
    -- Get booking statistics
    SELECT 
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE status = 'completed') as completed,
        COUNT(*) FILTER (WHERE status = 'pending') as pending,
        COUNT(*) FILTER (WHERE status = 'cancelled') as cancelled
    INTO total_bookings, completed_bookings, pending_bookings, cancelled_bookings
    FROM public.bookings 
    WHERE customer_id = get_customer_dashboard_stats.customer_id;

    -- Get pending reviews count
    SELECT COUNT(*)
    INTO pending_reviews
    FROM public.bookings b
    LEFT JOIN public.reviews r ON b.id = r.booking_id
    WHERE b.customer_id = get_customer_dashboard_stats.customer_id 
      AND b.status = 'completed'
      AND r.id IS NULL;

    -- Get wallet balance
    SELECT COALESCE(balance, 0.00)
    INTO wallet_balance
    FROM public.user_wallets 
    WHERE user_id = get_customer_dashboard_stats.customer_id;

    -- Get total spent (completed bookings)
    SELECT COALESCE(SUM(total_amount), 0.00)
    INTO total_spent
    FROM public.bookings 
    WHERE customer_id = get_customer_dashboard_stats.customer_id 
      AND status = 'completed';

    -- Get favorite category (most booked category)
    SELECT COALESCE(
        (SELECT ps.category 
         FROM public.bookings b
         JOIN public.provider_services ps ON b.service_id = ps.id
         WHERE b.customer_id = get_customer_dashboard_stats.customer_id
         GROUP BY ps.category
         ORDER BY COUNT(*) DESC
         LIMIT 1),
        'general'
    ) INTO favorite_category;

    -- Get recent activity (last 5 bookings with details)
    SELECT COALESCE(
        json_agg(
            json_build_object(
                'id', b.id,
                'service_title', ps.title,
                'provider_name', u.name,
                'status', b.status,
                'total_amount', b.total_amount,
                'scheduled_date', b.scheduled_date,
                'created_at', b.created_at
            ) ORDER BY b.created_at DESC
        ),
        '[]'::json
    )
    INTO recent_activity
    FROM (
        SELECT * FROM public.bookings 
        WHERE customer_id = get_customer_dashboard_stats.customer_id
        ORDER BY created_at DESC 
        LIMIT 5
    ) b
    LEFT JOIN public.provider_services ps ON b.service_id = ps.id
    LEFT JOIN public.users u ON b.provider_id = u.id;

    -- Build the final stats object
    stats := json_build_object(
        'total_bookings', total_bookings,
        'completed_bookings', completed_bookings,
        'pending_bookings', pending_bookings,
        'cancelled_bookings', cancelled_bookings,
        'pending_reviews', pending_reviews,
        'wallet_balance', wallet_balance,
        'total_spent', total_spent,
        'favorite_category', favorite_category,
        'recent_activity', recent_activity,
        'success_rate', CASE 
            WHEN total_bookings > 0 THEN 
                ROUND((completed_bookings::DECIMAL / total_bookings::DECIMAL) * 100, 1)
            ELSE 0 
        END,
        'generated_at', NOW()
    );

    RETURN stats;
EXCEPTION
    WHEN OTHERS THEN
        -- Return basic stats if there's an error
        RETURN json_build_object(
            'total_bookings', 0,
            'completed_bookings', 0,
            'pending_bookings', 0,
            'cancelled_bookings', 0,
            'pending_reviews', 0,
            'wallet_balance', 0.00,
            'total_spent', 0.00,
            'favorite_category', 'general',
            'recent_activity', '[]'::json,
            'success_rate', 0,
            'generated_at', NOW(),
            'error', SQLERRM
        );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to get provider dashboard statistics as well
CREATE OR REPLACE FUNCTION get_provider_dashboard_stats(provider_id UUID)
RETURNS JSON AS $$
DECLARE
    stats JSON;
    total_bookings INTEGER := 0;
    completed_bookings INTEGER := 0;
    pending_bookings INTEGER := 0;
    cancelled_bookings INTEGER := 0;
    total_earnings DECIMAL(10,2) := 0.00;
    monthly_earnings DECIMAL(10,2) := 0.00;
    wallet_balance DECIMAL(10,2) := 0.00;
    average_rating DECIMAL(3,2) := 0.00;
    total_services INTEGER := 0;
    active_services INTEGER := 0;
    recent_activity JSON;
BEGIN
    -- Get booking statistics
    SELECT 
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE status = 'completed') as completed,
        COUNT(*) FILTER (WHERE status = 'pending') as pending,
        COUNT(*) FILTER (WHERE status = 'cancelled') as cancelled
    INTO total_bookings, completed_bookings, pending_bookings, cancelled_bookings
    FROM public.bookings 
    WHERE provider_id = get_provider_dashboard_stats.provider_id;

    -- Get earnings
    SELECT COALESCE(SUM(total_amount), 0.00)
    INTO total_earnings
    FROM public.bookings 
    WHERE provider_id = get_provider_dashboard_stats.provider_id 
      AND status = 'completed';

    -- Get monthly earnings (current month)
    SELECT COALESCE(SUM(total_amount), 0.00)
    INTO monthly_earnings
    FROM public.bookings 
    WHERE provider_id = get_provider_dashboard_stats.provider_id 
      AND status = 'completed'
      AND DATE_TRUNC('month', created_at) = DATE_TRUNC('month', NOW());

    -- Get wallet balance
    SELECT COALESCE(balance, 0.00)
    INTO wallet_balance
    FROM public.user_wallets 
    WHERE user_id = get_provider_dashboard_stats.provider_id;

    -- Get average rating
    SELECT COALESCE(AVG(rating), 0.00)
    INTO average_rating
    FROM public.reviews r
    JOIN public.bookings b ON r.booking_id = b.id
    WHERE b.provider_id = get_provider_dashboard_stats.provider_id;

    -- Get service counts
    SELECT 
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE is_active = true) as active
    INTO total_services, active_services
    FROM public.provider_services 
    WHERE provider_id = get_provider_dashboard_stats.provider_id;

    -- Get recent activity (last 5 bookings with details)
    SELECT COALESCE(
        json_agg(
            json_build_object(
                'id', b.id,
                'service_title', ps.title,
                'customer_name', u.name,
                'status', b.status,
                'total_amount', b.total_amount,
                'scheduled_date', b.scheduled_date,
                'created_at', b.created_at
            ) ORDER BY b.created_at DESC
        ),
        '[]'::json
    )
    INTO recent_activity
    FROM (
        SELECT * FROM public.bookings 
        WHERE provider_id = get_provider_dashboard_stats.provider_id
        ORDER BY created_at DESC 
        LIMIT 5
    ) b
    LEFT JOIN public.provider_services ps ON b.service_id = ps.id
    LEFT JOIN public.users u ON b.customer_id = u.id;

    -- Build the final stats object
    stats := json_build_object(
        'total_bookings', total_bookings,
        'completed_bookings', completed_bookings,
        'pending_bookings', pending_bookings,
        'cancelled_bookings', cancelled_bookings,
        'total_earnings', total_earnings,
        'monthly_earnings', monthly_earnings,
        'wallet_balance', wallet_balance,
        'average_rating', average_rating,
        'total_services', total_services,
        'active_services', active_services,
        'recent_activity', recent_activity,
        'success_rate', CASE 
            WHEN total_bookings > 0 THEN 
                ROUND((completed_bookings::DECIMAL / total_bookings::DECIMAL) * 100, 1)
            ELSE 0 
        END,
        'generated_at', NOW()
    );

    RETURN stats;
EXCEPTION
    WHEN OTHERS THEN
        -- Return basic stats if there's an error
        RETURN json_build_object(
            'total_bookings', 0,
            'completed_bookings', 0,
            'pending_bookings', 0,
            'cancelled_bookings', 0,
            'total_earnings', 0.00,
            'monthly_earnings', 0.00,
            'wallet_balance', 0.00,
            'average_rating', 0.00,
            'total_services', 0,
            'active_services', 0,
            'recent_activity', '[]'::json,
            'success_rate', 0,
            'generated_at', NOW(),
            'error', SQLERRM
        );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant execute permissions
GRANT EXECUTE ON FUNCTION get_customer_dashboard_stats(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION get_provider_dashboard_stats(UUID) TO authenticated;

-- Completion notice
DO $$
BEGIN
    RAISE NOTICE 'Dashboard stats functions created successfully for both customers and providers';
END $$;
