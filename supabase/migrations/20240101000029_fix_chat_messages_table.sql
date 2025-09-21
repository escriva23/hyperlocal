-- Fix chat_messages table structure - ensure content column exists
-- This addresses the "column cm.content does not exist" error

-- Check if chat_messages table exists and add missing columns
DO $$
BEGIN
    -- Check if the table exists
    IF EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'chat_messages') THEN
        -- Check if content column exists, if not add it
        IF NOT EXISTS (
            SELECT FROM information_schema.columns 
            WHERE table_schema = 'public' 
            AND table_name = 'chat_messages' 
            AND column_name = 'content'
        ) THEN
            ALTER TABLE public.chat_messages ADD COLUMN content TEXT NOT NULL DEFAULT '';
            RAISE NOTICE 'Added content column to chat_messages table';
        ELSE
            RAISE NOTICE 'Content column already exists in chat_messages table';
        END IF;

        -- Check if message_type column exists, if not add it
        IF NOT EXISTS (
            SELECT FROM information_schema.columns 
            WHERE table_schema = 'public' 
            AND table_name = 'chat_messages' 
            AND column_name = 'message_type'
        ) THEN
            ALTER TABLE public.chat_messages ADD COLUMN message_type VARCHAR(20) DEFAULT 'text';
            RAISE NOTICE 'Added message_type column to chat_messages table';
        END IF;

        -- Check if is_read column exists, if not add it
        IF NOT EXISTS (
            SELECT FROM information_schema.columns 
            WHERE table_schema = 'public' 
            AND table_name = 'chat_messages' 
            AND column_name = 'is_read'
        ) THEN
            ALTER TABLE public.chat_messages ADD COLUMN is_read BOOLEAN DEFAULT FALSE;
            RAISE NOTICE 'Added is_read column to chat_messages table';
        END IF;

        -- Check if updated_at column exists, if not add it
        IF NOT EXISTS (
            SELECT FROM information_schema.columns 
            WHERE table_schema = 'public' 
            AND table_name = 'chat_messages' 
            AND column_name = 'updated_at'
        ) THEN
            ALTER TABLE public.chat_messages ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();
            RAISE NOTICE 'Added updated_at column to chat_messages table';
        END IF;

    ELSE
        -- Create the table if it doesn't exist
        CREATE TABLE public.chat_messages (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            sender_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
            receiver_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
            booking_id UUID REFERENCES public.bookings(id) ON DELETE CASCADE,
            content TEXT NOT NULL,
            message_type VARCHAR(20) DEFAULT 'text',
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        RAISE NOTICE 'Created chat_messages table with all required columns';
    END IF;
END $$;

-- Create indexes if they don't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_indexes WHERE tablename = 'chat_messages' AND indexname = 'idx_chat_messages_sender_id') THEN
        CREATE INDEX idx_chat_messages_sender_id ON public.chat_messages(sender_id);
    END IF;

    IF NOT EXISTS (SELECT FROM pg_indexes WHERE tablename = 'chat_messages' AND indexname = 'idx_chat_messages_receiver_id') THEN
        CREATE INDEX idx_chat_messages_receiver_id ON public.chat_messages(receiver_id);
    END IF;

    IF NOT EXISTS (SELECT FROM pg_indexes WHERE tablename = 'chat_messages' AND indexname = 'idx_chat_messages_created_at') THEN
        CREATE INDEX idx_chat_messages_created_at ON public.chat_messages(created_at DESC);
    END IF;

    IF NOT EXISTS (SELECT FROM pg_indexes WHERE tablename = 'chat_messages' AND indexname = 'idx_chat_messages_conversation') THEN
        CREATE INDEX idx_chat_messages_conversation ON public.chat_messages(sender_id, receiver_id, created_at DESC);
    END IF;
END $$;

-- Enable RLS
ALTER TABLE public.chat_messages ENABLE ROW LEVEL SECURITY;

-- Drop and recreate RLS policies
DROP POLICY IF EXISTS "Users can view their own messages" ON public.chat_messages;
DROP POLICY IF EXISTS "Users can insert their own messages" ON public.chat_messages;
DROP POLICY IF EXISTS "Users can update their own messages" ON public.chat_messages;

CREATE POLICY "Users can view their own messages" ON public.chat_messages
    FOR SELECT USING (
        auth.uid() = sender_id OR 
        auth.uid() = receiver_id
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

-- Grant permissions
GRANT SELECT, INSERT, UPDATE ON public.chat_messages TO authenticated;
GRANT ALL ON public.chat_messages TO service_role;

-- Update the get_user_conversations function to handle missing data gracefully
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
            COALESCE(cm.content, 'No message content') as last_message,
            cm.created_at as last_message_time,
            (SELECT COUNT(*) 
             FROM public.chat_messages unread 
             WHERE unread.sender_id = CASE WHEN cm.sender_id = user_id THEN cm.receiver_id ELSE cm.sender_id END
               AND unread.receiver_id = user_id 
               AND COALESCE(unread.is_read, FALSE) = FALSE
               AND (cm.booking_id IS NULL OR unread.booking_id = cm.booking_id)
            ) as unread_count
        FROM public.chat_messages cm
        WHERE cm.sender_id = user_id OR cm.receiver_id = user_id
    )
    SELECT 
        conv.other_user_id,
        COALESCE(u.name, au.raw_user_meta_data->>'name', 'Unknown User') as other_user_name,
        COALESCE(u.avatar_url, au.raw_user_meta_data->>'avatar_url') as other_user_avatar,
        COALESCE(u.role::TEXT, 'customer') as other_user_role,
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

-- Completion notice
DO $$
BEGIN
    RAISE NOTICE 'Fixed chat_messages table structure and updated get_user_conversations function';
END $$;
