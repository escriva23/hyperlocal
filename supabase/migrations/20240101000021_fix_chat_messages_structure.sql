-- Fix chat_messages table structure - add missing columns if they don't exist
DO $$ 
BEGIN
    -- Check if receiver_id column exists, if not add it
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_schema = 'public' 
                   AND table_name = 'chat_messages' 
                   AND column_name = 'receiver_id') THEN
        ALTER TABLE public.chat_messages ADD COLUMN receiver_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE;
        RAISE NOTICE 'Added receiver_id column to chat_messages table';
    ELSE
        RAISE NOTICE 'receiver_id column already exists in chat_messages table';
    END IF;

    -- Check if booking_id column exists, if not add it
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_schema = 'public' 
                   AND table_name = 'chat_messages' 
                   AND column_name = 'booking_id') THEN
        ALTER TABLE public.chat_messages ADD COLUMN booking_id UUID REFERENCES public.bookings(id) ON DELETE CASCADE;
        RAISE NOTICE 'Added booking_id column to chat_messages table';
    ELSE
        RAISE NOTICE 'booking_id column already exists in chat_messages table';
    END IF;

    -- Check if message_type column exists, if not add it
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_schema = 'public' 
                   AND table_name = 'chat_messages' 
                   AND column_name = 'message_type') THEN
        ALTER TABLE public.chat_messages ADD COLUMN message_type VARCHAR(20) DEFAULT 'text';
        RAISE NOTICE 'Added message_type column to chat_messages table';
    ELSE
        RAISE NOTICE 'message_type column already exists in chat_messages table';
    END IF;

    -- Check if is_read column exists, if not add it
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_schema = 'public' 
                   AND table_name = 'chat_messages' 
                   AND column_name = 'is_read') THEN
        ALTER TABLE public.chat_messages ADD COLUMN is_read BOOLEAN DEFAULT FALSE;
        RAISE NOTICE 'Added is_read column to chat_messages table';
    ELSE
        RAISE NOTICE 'is_read column already exists in chat_messages table';
    END IF;

    -- Check if updated_at column exists, if not add it
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_schema = 'public' 
                   AND table_name = 'chat_messages' 
                   AND column_name = 'updated_at') THEN
        ALTER TABLE public.chat_messages ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();
        RAISE NOTICE 'Added updated_at column to chat_messages table';
    ELSE
        RAISE NOTICE 'updated_at column already exists in chat_messages table';
    END IF;
END $$;

-- Now create indexes only if they don't exist and columns exist
DO $$
BEGIN
    -- Check if receiver_id column exists before creating index
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_schema = 'public' 
               AND table_name = 'chat_messages' 
               AND column_name = 'receiver_id') THEN
        
        IF NOT EXISTS (SELECT FROM pg_indexes WHERE tablename = 'chat_messages' AND indexname = 'idx_chat_messages_receiver_id') THEN
            CREATE INDEX idx_chat_messages_receiver_id ON public.chat_messages(receiver_id);
            RAISE NOTICE 'Created index idx_chat_messages_receiver_id';
        END IF;
    END IF;

    -- Check if sender_id column exists before creating index
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_schema = 'public' 
               AND table_name = 'chat_messages' 
               AND column_name = 'sender_id') THEN
        
        IF NOT EXISTS (SELECT FROM pg_indexes WHERE tablename = 'chat_messages' AND indexname = 'idx_chat_messages_sender_id') THEN
            CREATE INDEX idx_chat_messages_sender_id ON public.chat_messages(sender_id);
            RAISE NOTICE 'Created index idx_chat_messages_sender_id';
        END IF;
    END IF;

    -- Check if booking_id column exists before creating index
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_schema = 'public' 
               AND table_name = 'chat_messages' 
               AND column_name = 'booking_id') THEN
        
        IF NOT EXISTS (SELECT FROM pg_indexes WHERE tablename = 'chat_messages' AND indexname = 'idx_chat_messages_booking_id') THEN
            CREATE INDEX idx_chat_messages_booking_id ON public.chat_messages(booking_id);
            RAISE NOTICE 'Created index idx_chat_messages_booking_id';
        END IF;
    END IF;

    -- Check if created_at column exists before creating index
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_schema = 'public' 
               AND table_name = 'chat_messages' 
               AND column_name = 'created_at') THEN
        
        IF NOT EXISTS (SELECT FROM pg_indexes WHERE tablename = 'chat_messages' AND indexname = 'idx_chat_messages_created_at') THEN
            CREATE INDEX idx_chat_messages_created_at ON public.chat_messages(created_at DESC);
            RAISE NOTICE 'Created index idx_chat_messages_created_at';
        END IF;
    END IF;

    -- Create conversation index if both sender_id and receiver_id exist
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_schema = 'public' 
               AND table_name = 'chat_messages' 
               AND column_name = 'sender_id') 
       AND EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_schema = 'public' 
                   AND table_name = 'chat_messages' 
                   AND column_name = 'receiver_id') THEN
        
        IF NOT EXISTS (SELECT FROM pg_indexes WHERE tablename = 'chat_messages' AND indexname = 'idx_chat_messages_conversation') THEN
            CREATE INDEX idx_chat_messages_conversation ON public.chat_messages(sender_id, receiver_id, created_at DESC);
            RAISE NOTICE 'Created index idx_chat_messages_conversation';
        END IF;
    END IF;
END $$;

-- Create trigger only if it doesn't exist and updated_at column exists
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_schema = 'public' 
               AND table_name = 'chat_messages' 
               AND column_name = 'updated_at') THEN
        
        IF NOT EXISTS (SELECT FROM information_schema.triggers WHERE trigger_name = 'update_chat_messages_updated_at' AND event_object_table = 'chat_messages') THEN
            CREATE TRIGGER update_chat_messages_updated_at 
                BEFORE UPDATE ON public.chat_messages 
                FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
            RAISE NOTICE 'Created trigger update_chat_messages_updated_at';
        ELSE
            RAISE NOTICE 'Trigger update_chat_messages_updated_at already exists';
        END IF;
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
    
    -- Create policies only if required columns exist
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_schema = 'public' 
               AND table_name = 'chat_messages' 
               AND column_name = 'sender_id') 
       AND EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_schema = 'public' 
                   AND table_name = 'chat_messages' 
                   AND column_name = 'receiver_id') THEN
        
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
    ELSE
        RAISE NOTICE 'Cannot create RLS policies - missing required columns';
    END IF;
END $$;

-- Grant permissions (safe to run multiple times)
GRANT SELECT, INSERT, UPDATE ON public.chat_messages TO authenticated;
GRANT ALL ON public.chat_messages TO service_role;

-- Final completion notice
DO $$
BEGIN
    RAISE NOTICE 'Chat messages structure fix completed successfully';
END $$;
