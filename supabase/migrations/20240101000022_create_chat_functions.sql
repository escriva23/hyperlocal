-- Create chat functions after table structure is properly set up

-- Create or replace function to get chat messages between two users
CREATE OR REPLACE FUNCTION get_chat_messages(
    user1_id UUID,
    user2_id UUID,
    booking_id_filter UUID DEFAULT NULL
)
RETURNS TABLE (
    id UUID,
    content TEXT,
    sender_id UUID,
    receiver_id UUID,
    booking_id UUID,
    created_at TIMESTAMPTZ,
    sender JSONB,
    receiver JSONB
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        cm.id,
        cm.content,
        cm.sender_id,
        cm.receiver_id,
        cm.booking_id,
        cm.created_at,
        jsonb_build_object(
            'id', su.id,
            'name', su.raw_user_meta_data->>'name',
            'avatar_url', su.raw_user_meta_data->>'avatar_url',
            'role', COALESCE(up.role, 'customer'),
            'last_seen_at', up.last_seen_at
        ) as sender,
        jsonb_build_object(
            'id', ru.id,
            'name', ru.raw_user_meta_data->>'name',
            'avatar_url', ru.raw_user_meta_data->>'avatar_url',
            'role', COALESCE(rp.role, 'customer'),
            'last_seen_at', rp.last_seen_at
        ) as receiver
    FROM public.chat_messages cm
    LEFT JOIN auth.users su ON cm.sender_id = su.id
    LEFT JOIN auth.users ru ON cm.receiver_id = ru.id
    LEFT JOIN public.users up ON cm.sender_id = up.id
    LEFT JOIN public.users rp ON cm.receiver_id = rp.id
    WHERE 
        ((cm.sender_id = user1_id AND cm.receiver_id = user2_id) OR
         (cm.sender_id = user2_id AND cm.receiver_id = user1_id))
        AND (booking_id_filter IS NULL OR cm.booking_id = booking_id_filter)
    ORDER BY cm.created_at ASC;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant execute permission
GRANT EXECUTE ON FUNCTION get_chat_messages(UUID, UUID, UUID) TO authenticated;

-- Create or replace function to mark messages as read
CREATE OR REPLACE FUNCTION mark_messages_as_read(
    sender_user_id UUID,
    receiver_user_id UUID
)
RETURNS INTEGER AS $$
DECLARE
    updated_count INTEGER;
BEGIN
    UPDATE public.chat_messages 
    SET is_read = TRUE, updated_at = NOW()
    WHERE sender_id = sender_user_id 
      AND receiver_id = receiver_user_id 
      AND is_read = FALSE;
    
    GET DIAGNOSTICS updated_count = ROW_COUNT;
    RETURN updated_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant execute permission
GRANT EXECUTE ON FUNCTION mark_messages_as_read(UUID, UUID) TO authenticated;

-- Create function to get conversation list for a user
CREATE OR REPLACE FUNCTION get_user_conversations(user_id UUID)
RETURNS TABLE (
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
    RETURN QUERY
    WITH conversation_messages AS (
        SELECT DISTINCT
            CASE 
                WHEN cm.sender_id = user_id THEN cm.receiver_id
                ELSE cm.sender_id
            END as other_user_id,
            cm.booking_id,
            ROW_NUMBER() OVER (
                PARTITION BY 
                    CASE WHEN cm.sender_id = user_id THEN cm.receiver_id ELSE cm.sender_id END,
                    cm.booking_id
                ORDER BY cm.created_at DESC
            ) as rn,
            cm.content as last_message,
            cm.created_at as last_message_time,
            (SELECT COUNT(*) 
             FROM public.chat_messages unread 
             WHERE unread.sender_id = CASE WHEN cm.sender_id = user_id THEN cm.receiver_id ELSE cm.sender_id END
               AND unread.receiver_id = user_id 
               AND unread.is_read = FALSE
               AND (cm.booking_id IS NULL OR unread.booking_id = cm.booking_id)
            ) as unread_count
        FROM public.chat_messages cm
        WHERE cm.sender_id = user_id OR cm.receiver_id = user_id
    )
    SELECT 
        conv.other_user_id,
        COALESCE(au.raw_user_meta_data->>'name', 'Unknown User') as other_user_name,
        au.raw_user_meta_data->>'avatar_url' as other_user_avatar,
        COALESCE(u.role, 'customer') as other_user_role,
        conv.last_message,
        conv.last_message_time,
        conv.unread_count,
        conv.booking_id
    FROM conversation_messages conv
    LEFT JOIN auth.users au ON conv.other_user_id = au.id
    LEFT JOIN public.users u ON conv.other_user_id = u.id
    WHERE conv.rn = 1
    ORDER BY conv.last_message_time DESC;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant execute permission
GRANT EXECUTE ON FUNCTION get_user_conversations(UUID) TO authenticated;

-- Final completion notice
DO $$
BEGIN
    RAISE NOTICE 'Chat functions created successfully';
END $$;
