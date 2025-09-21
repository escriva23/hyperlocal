-- Safe migration for chat_messages table - checks for existing objects
-- Create chat_messages table only if it doesn't exist
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'chat_messages') THEN
        CREATE TABLE public.chat_messages (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            sender_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
            receiver_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
            booking_id UUID REFERENCES public.bookings(id) ON DELETE CASCADE,
            content TEXT NOT NULL,
            message_type VARCHAR(20) DEFAULT 'text', -- 'text', 'image', 'file', 'system'
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        RAISE NOTICE 'Created chat_messages table';
    ELSE
        RAISE NOTICE 'chat_messages table already exists, skipping creation';
    END IF;
END $$;

-- Create indexes only if they don't exist
DO $$
BEGIN
    -- Check and create idx_chat_messages_sender_id
    IF NOT EXISTS (SELECT FROM pg_indexes WHERE tablename = 'chat_messages' AND indexname = 'idx_chat_messages_sender_id') THEN
        CREATE INDEX idx_chat_messages_sender_id ON public.chat_messages(sender_id);
        RAISE NOTICE 'Created index idx_chat_messages_sender_id';
    END IF;

    -- Check and create idx_chat_messages_receiver_id
    IF NOT EXISTS (SELECT FROM pg_indexes WHERE tablename = 'chat_messages' AND indexname = 'idx_chat_messages_receiver_id') THEN
        CREATE INDEX idx_chat_messages_receiver_id ON public.chat_messages(receiver_id);
        RAISE NOTICE 'Created index idx_chat_messages_receiver_id';
    END IF;

    -- Check and create idx_chat_messages_booking_id
    IF NOT EXISTS (SELECT FROM pg_indexes WHERE tablename = 'chat_messages' AND indexname = 'idx_chat_messages_booking_id') THEN
        CREATE INDEX idx_chat_messages_booking_id ON public.chat_messages(booking_id);
        RAISE NOTICE 'Created index idx_chat_messages_booking_id';
    END IF;

    -- Check and create idx_chat_messages_created_at
    IF NOT EXISTS (SELECT FROM pg_indexes WHERE tablename = 'chat_messages' AND indexname = 'idx_chat_messages_created_at') THEN
        CREATE INDEX idx_chat_messages_created_at ON public.chat_messages(created_at DESC);
        RAISE NOTICE 'Created index idx_chat_messages_created_at';
    END IF;

    -- Check and create idx_chat_messages_conversation
    IF NOT EXISTS (SELECT FROM pg_indexes WHERE tablename = 'chat_messages' AND indexname = 'idx_chat_messages_conversation') THEN
        CREATE INDEX idx_chat_messages_conversation ON public.chat_messages(sender_id, receiver_id, created_at DESC);
        RAISE NOTICE 'Created index idx_chat_messages_conversation';
    END IF;
END $$;

-- Create trigger only if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM information_schema.triggers WHERE trigger_name = 'update_chat_messages_updated_at' AND event_object_table = 'chat_messages') THEN
        CREATE TRIGGER update_chat_messages_updated_at 
            BEFORE UPDATE ON public.chat_messages 
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        RAISE NOTICE 'Created trigger update_chat_messages_updated_at';
    ELSE
        RAISE NOTICE 'Trigger update_chat_messages_updated_at already exists';
    END IF;
END $$;

-- Enable RLS (safe to run multiple times)
ALTER TABLE public.chat_messages ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if they exist and recreate them
DO $$
BEGIN
    -- Drop existing policies
    DROP POLICY IF EXISTS "Users can view their own messages" ON public.chat_messages;
    DROP POLICY IF EXISTS "Users can insert their own messages" ON public.chat_messages;
    DROP POLICY IF EXISTS "Users can update their own messages" ON public.chat_messages;
    
    -- Create policies
    CREATE POLICY "Users can view their own messages" ON public.chat_messages
        FOR SELECT USING (
            auth.uid() = sender_id OR 
            auth.uid() = receiver_id OR
            auth.role() = 'service_role'
        );

    CREATE POLICY "Users can insert their own messages" ON public.chat_messages
        FOR INSERT WITH CHECK (
            auth.uid() = sender_id
        );

    CREATE POLICY "Users can update their own messages" ON public.chat_messages
        FOR UPDATE USING (
            auth.uid() = sender_id OR 
            auth.uid() = receiver_id
        );
    
    RAISE NOTICE 'Created RLS policies for chat_messages';
END $$;

-- Grant permissions (safe to run multiple times)
GRANT SELECT, INSERT, UPDATE ON public.chat_messages TO authenticated;
GRANT ALL ON public.chat_messages TO service_role;

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
    RAISE NOTICE 'Chat messages migration completed successfully';
END $$;
