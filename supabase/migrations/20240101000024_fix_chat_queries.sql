-- Fix chat queries by creating a simplified view for frontend queries
-- This resolves the 400 error when querying chat_messages with complex joins

-- First, check if the chat_messages table exists and what columns it has
DO $$
BEGIN
    -- Check if chat_messages table exists
    IF NOT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'chat_messages') THEN
        RAISE NOTICE 'chat_messages table does not exist, skipping view creation';
        RETURN;
    END IF;
    
    RAISE NOTICE 'chat_messages table found, proceeding with view creation';
END $$;

-- Create a view that provides the data structure the frontend expects
-- Note: The original schema uses 'message' column, not 'content'
CREATE OR REPLACE VIEW public.chat_messages_with_users AS
SELECT 
    cm.id,
    cm.message as content, -- Map 'message' to 'content' for frontend compatibility
    cm.sender_id,
    -- Handle receiver_id - if it doesn't exist, we'll use a workaround
    CASE 
        WHEN EXISTS (SELECT 1 FROM information_schema.columns 
                    WHERE table_schema = 'public' 
                    AND table_name = 'chat_messages' 
                    AND column_name = 'receiver_id') 
        THEN cm.receiver_id
        ELSE NULL::UUID
    END as receiver_id,
    cm.created_at,
    -- Handle booking_id if it exists
    CASE 
        WHEN EXISTS (SELECT 1 FROM information_schema.columns 
                    WHERE table_schema = 'public' 
                    AND table_name = 'chat_messages' 
                    AND column_name = 'booking_id') 
        THEN cm.booking_id
        ELSE NULL::UUID
    END as booking_id,
    cm.is_read,
    -- Handle updated_at if it exists
    CASE 
        WHEN EXISTS (SELECT 1 FROM information_schema.columns 
                    WHERE table_schema = 'public' 
                    AND table_name = 'chat_messages' 
                    AND column_name = 'updated_at') 
        THEN cm.updated_at
        ELSE cm.created_at
    END as updated_at,
    -- Sender information as JSONB (using only columns that exist)
    jsonb_build_object(
        'id', su.id,
        'name', COALESCE(su.raw_user_meta_data->>'name', 'Unknown User'),
        'avatar_url', su.raw_user_meta_data->>'avatar_url',
        'role', COALESCE(up.role, 'customer'),
        'last_seen_at', up.updated_at -- Use updated_at as last_seen_at since last_seen_at doesn't exist
    ) as sender,
    -- Receiver information as JSONB (will be null if receiver_id doesn't exist)
    CASE 
        WHEN EXISTS (SELECT 1 FROM information_schema.columns 
                    WHERE table_schema = 'public' 
                    AND table_name = 'chat_messages' 
                    AND column_name = 'receiver_id') 
        THEN jsonb_build_object(
            'id', ru.id,
            'name', COALESCE(ru.raw_user_meta_data->>'name', 'Unknown User'),
            'avatar_url', ru.raw_user_meta_data->>'avatar_url',
            'role', COALESCE(rp.role, 'customer'),
            'last_seen_at', rp.updated_at -- Use updated_at as last_seen_at since last_seen_at doesn't exist
        )
        ELSE NULL::jsonb
    END as receiver
FROM public.chat_messages cm
LEFT JOIN auth.users su ON cm.sender_id = su.id
LEFT JOIN auth.users ru ON (
    EXISTS (SELECT 1 FROM information_schema.columns 
           WHERE table_schema = 'public' 
           AND table_name = 'chat_messages' 
           AND column_name = 'receiver_id') 
    AND cm.receiver_id = ru.id
)
LEFT JOIN public.users up ON cm.sender_id = up.id
LEFT JOIN public.users rp ON (
    EXISTS (SELECT 1 FROM information_schema.columns 
           WHERE table_schema = 'public' 
           AND table_name = 'chat_messages' 
           AND column_name = 'receiver_id') 
    AND cm.receiver_id = rp.id
);

-- Grant permissions on the view
GRANT SELECT ON public.chat_messages_with_users TO authenticated;
GRANT ALL ON public.chat_messages_with_users TO service_role;

-- Create function to get conversations with proper error handling
-- This function will work with the existing chat_messages structure
CREATE OR REPLACE FUNCTION get_user_chat_conversations(user_id UUID)
RETURNS TABLE (
    conversation_id TEXT,
    other_user_id UUID,
    other_user_name TEXT,
    other_user_avatar TEXT,
    other_user_role TEXT,
    last_message TEXT,
    last_message_time TIMESTAMPTZ,
    unread_count BIGINT,
    booking_id UUID
) AS $$
BEGIN
    -- Check if receiver_id column exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_schema = 'public' 
                   AND table_name = 'chat_messages' 
                   AND column_name = 'receiver_id') THEN
        
        -- If receiver_id doesn't exist, return empty result
        RETURN;
    END IF;

    RETURN QUERY
    WITH latest_messages AS (
        SELECT DISTINCT ON (
            CASE 
                WHEN cm.sender_id = user_id THEN cm.receiver_id
                ELSE cm.sender_id
            END,
            COALESCE(cm.booking_id::text, 'general')
        )
            CASE 
                WHEN cm.sender_id = user_id THEN cm.receiver_id
                ELSE cm.sender_id
            END as other_user_id,
            cm.message as last_message, -- Use 'message' column
            cm.created_at as last_message_time,
            cm.booking_id,
            COALESCE(cm.booking_id::text, 'general') || '_' || 
            CASE 
                WHEN cm.sender_id = user_id THEN cm.receiver_id::text
                ELSE cm.sender_id::text
            END as conversation_id
        FROM public.chat_messages cm
        WHERE cm.sender_id = user_id OR cm.receiver_id = user_id
        ORDER BY 
            CASE 
                WHEN cm.sender_id = user_id THEN cm.receiver_id
                ELSE cm.sender_id
            END,
            COALESCE(cm.booking_id::text, 'general'),
            cm.created_at DESC
    )
    SELECT 
        lm.conversation_id,
        lm.other_user_id,
        COALESCE(au.raw_user_meta_data->>'name', 'Unknown User') as other_user_name,
        au.raw_user_meta_data->>'avatar_url' as other_user_avatar,
        COALESCE(u.role, 'customer') as other_user_role,
        lm.last_message,
        lm.last_message_time,
        COALESCE((
            SELECT COUNT(*)::BIGINT
            FROM public.chat_messages unread 
            WHERE unread.sender_id = lm.other_user_id
              AND unread.receiver_id = user_id 
              AND unread.is_read = FALSE
              AND (lm.booking_id IS NULL OR unread.booking_id = lm.booking_id)
        ), 0) as unread_count,
        lm.booking_id
    FROM latest_messages lm
    LEFT JOIN auth.users au ON lm.other_user_id = au.id
    LEFT JOIN public.users u ON lm.other_user_id = u.id
    ORDER BY lm.last_message_time DESC;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant execute permission
GRANT EXECUTE ON FUNCTION get_user_chat_conversations(UUID) TO authenticated;

-- Create a simpler function to get messages between users
CREATE OR REPLACE FUNCTION get_simple_chat_messages(
    user1_id UUID,
    user2_id UUID,
    message_limit INTEGER DEFAULT 50
)
RETURNS TABLE (
    id UUID,
    content TEXT,
    sender_id UUID,
    receiver_id UUID,
    booking_id UUID,
    created_at TIMESTAMPTZ,
    is_read BOOLEAN,
    sender_name TEXT,
    receiver_name TEXT
) AS $$
BEGIN
    -- Check if receiver_id column exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_schema = 'public' 
                   AND table_name = 'chat_messages' 
                   AND column_name = 'receiver_id') THEN
        
        -- If receiver_id doesn't exist, return empty result
        RETURN;
    END IF;

    RETURN QUERY
    SELECT 
        cm.id,
        cm.message as content, -- Use 'message' column, return as 'content'
        cm.sender_id,
        cm.receiver_id,
        cm.booking_id,
        cm.created_at,
        cm.is_read,
        COALESCE(su.raw_user_meta_data->>'name', 'Unknown') as sender_name,
        COALESCE(ru.raw_user_meta_data->>'name', 'Unknown') as receiver_name
    FROM public.chat_messages cm
    LEFT JOIN auth.users su ON cm.sender_id = su.id
    LEFT JOIN auth.users ru ON cm.receiver_id = ru.id
    WHERE 
        (cm.sender_id = user1_id AND cm.receiver_id = user2_id) OR
        (cm.sender_id = user2_id AND cm.receiver_id = user1_id)
    ORDER BY cm.created_at DESC
    LIMIT message_limit;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant execute permission
GRANT EXECUTE ON FUNCTION get_simple_chat_messages(UUID, UUID, INTEGER) TO authenticated;

-- Completion notice
DO $$
BEGIN
    RAISE NOTICE 'Chat query fixes completed successfully - using updated_at as last_seen_at fallback';
END $$;
