-- Create user_preferences table to fix customer onboarding issues
-- This addresses the 404 Not Found error when POST /user_preferences is called

-- Create user_preferences table
CREATE TABLE IF NOT EXISTS public.user_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    
    -- Notification preferences
    email_notifications BOOLEAN DEFAULT true,
    sms_notifications BOOLEAN DEFAULT true,
    push_notifications BOOLEAN DEFAULT true,
    marketing_emails BOOLEAN DEFAULT false,
    
    -- Service preferences
    preferred_categories TEXT[] DEFAULT '{}',
    preferred_location_radius INTEGER DEFAULT 10, -- in kilometers
    preferred_price_range_min DECIMAL(10,2) DEFAULT 0,
    preferred_price_range_max DECIMAL(10,2) DEFAULT 10000,
    
    -- Communication preferences
    preferred_language VARCHAR(10) DEFAULT 'en',
    timezone VARCHAR(50) DEFAULT 'Africa/Nairobi',
    
    -- Privacy preferences
    profile_visibility VARCHAR(20) DEFAULT 'public' CHECK (profile_visibility IN ('public', 'private', 'contacts_only')),
    show_location BOOLEAN DEFAULT true,
    show_phone BOOLEAN DEFAULT true,
    
    -- Booking preferences
    auto_accept_bookings BOOLEAN DEFAULT false,
    require_advance_payment BOOLEAN DEFAULT false,
    booking_buffer_time INTEGER DEFAULT 30, -- minutes between bookings
    
    -- Other preferences
    dark_mode BOOLEAN DEFAULT false,
    compact_view BOOLEAN DEFAULT false,
    
    -- Metadata
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    
    -- Ensure one preference record per user
    UNIQUE(user_id)
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_user_preferences_user_id ON public.user_preferences(user_id);
CREATE INDEX IF NOT EXISTS idx_user_preferences_categories ON public.user_preferences USING GIN(preferred_categories);

-- Enable RLS
ALTER TABLE public.user_preferences ENABLE ROW LEVEL SECURITY;

-- RLS Policies
CREATE POLICY "Users can view their own preferences" ON public.user_preferences
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own preferences" ON public.user_preferences
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own preferences" ON public.user_preferences
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own preferences" ON public.user_preferences
    FOR DELETE USING (auth.uid() = user_id);

-- Service role can manage all preferences
CREATE POLICY "Service role can manage all preferences" ON public.user_preferences
    FOR ALL USING (auth.jwt() ->> 'role' = 'service_role');

-- Create function to automatically create user preferences on user creation
CREATE OR REPLACE FUNCTION create_user_preferences()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.user_preferences (user_id)
    VALUES (NEW.id)
    ON CONFLICT (user_id) DO NOTHING;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create trigger to auto-create preferences
DROP TRIGGER IF EXISTS create_user_preferences_trigger ON public.users;
CREATE TRIGGER create_user_preferences_trigger
    AFTER INSERT ON public.users
    FOR EACH ROW
    EXECUTE FUNCTION create_user_preferences();

-- Update function to handle updated_at
CREATE OR REPLACE FUNCTION update_user_preferences_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for updated_at
DROP TRIGGER IF EXISTS update_user_preferences_updated_at_trigger ON public.user_preferences;
CREATE TRIGGER update_user_preferences_updated_at_trigger
    BEFORE UPDATE ON public.user_preferences
    FOR EACH ROW
    EXECUTE FUNCTION update_user_preferences_updated_at();

-- Grant permissions
GRANT ALL ON public.user_preferences TO authenticated;
GRANT ALL ON public.user_preferences TO service_role;

-- Create default preferences for existing users who don't have them
INSERT INTO public.user_preferences (user_id)
SELECT u.id
FROM public.users u
LEFT JOIN public.user_preferences up ON u.id = up.user_id
WHERE up.user_id IS NULL
ON CONFLICT (user_id) DO NOTHING;

-- Completion notice
DO $$
BEGIN
    RAISE NOTICE 'User preferences table created successfully with RLS policies and triggers';
END $$;
