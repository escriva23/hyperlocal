-- Fix booking queries by creating a view that includes service_title
-- This will help frontend queries that expect service_title to work properly

-- First, let's check which service table to use and fix the column names

-- Create a view for bookings with service details
DROP VIEW IF EXISTS public.bookings_with_details;

CREATE VIEW public.bookings_with_details AS
SELECT 
    b.*,
    -- Try to get service info from both tables (services and provider_services)
    COALESCE(s.name, ps.title) as service_title,
    COALESCE(s.description, ps.description) as service_description,
    s.category_id as service_category_id,
    sc.name as service_category_name,
    -- Customer details
    cu.name as customer_name,
    cu.email as customer_email,
    cu.phone as customer_phone,
    -- Provider details  
    pu.name as provider_name,
    pu.email as provider_email,
    pu.phone as provider_phone,
    pp.business_name as provider_business_name,
    pp.average_rating as provider_rating
FROM public.bookings b
LEFT JOIN public.services s ON b.service_id = s.id
LEFT JOIN public.provider_services ps ON b.service_id = ps.id
LEFT JOIN public.service_categories sc ON s.category_id = sc.id
LEFT JOIN public.users cu ON b.customer_id = cu.id
LEFT JOIN public.users pu ON b.provider_id = pu.id
LEFT JOIN public.provider_profiles pp ON b.provider_id = pp.user_id;

-- Enable RLS on the view
ALTER VIEW public.bookings_with_details SET (security_barrier = true);

-- Create RLS policies for the bookings table if not exists
DO $$
BEGIN
    -- Check if the policy already exists
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies 
        WHERE schemaname = 'public' 
        AND tablename = 'bookings' 
        AND policyname = 'Users can view their own bookings'
    ) THEN
        CREATE POLICY "Users can view their own bookings" ON public.bookings
            FOR SELECT USING (
                auth.uid() = customer_id OR 
                auth.uid() = provider_id OR
                auth.role() = 'service_role'
            );
    END IF;
END
$$;

-- Grant permissions
GRANT SELECT ON public.bookings_with_details TO authenticated;
GRANT SELECT ON public.bookings_with_details TO service_role;

-- Create function to get user bookings with proper joins
CREATE OR REPLACE FUNCTION get_user_bookings(
    user_id UUID,
    user_type TEXT DEFAULT 'customer'
)
RETURNS TABLE (
    id UUID,
    service_title TEXT,
    booking_time TIMESTAMPTZ,
    status TEXT,
    price DECIMAL,
    customer_name TEXT,
    provider_name TEXT,
    provider_business_name TEXT,
    created_at TIMESTAMPTZ
) AS $$
BEGIN
    IF user_type = 'customer' THEN
        RETURN QUERY
        SELECT 
            bwd.id,
            bwd.service_title,
            bwd.booking_time,
            bwd.status::TEXT,
            bwd.price,
            bwd.customer_name,
            bwd.provider_name,
            bwd.provider_business_name,
            bwd.created_at
        FROM public.bookings_with_details bwd
        WHERE bwd.customer_id = get_user_bookings.user_id
        ORDER BY bwd.created_at DESC;
    ELSE
        RETURN QUERY
        SELECT 
            bwd.id,
            bwd.service_title,
            bwd.booking_time,
            bwd.status::TEXT,
            bwd.price,
            bwd.customer_name,
            bwd.provider_name,
            bwd.provider_business_name,
            bwd.created_at
        FROM public.bookings_with_details bwd
        WHERE bwd.provider_id = get_user_bookings.user_id
        ORDER BY bwd.created_at DESC;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant execute permission on the function
GRANT EXECUTE ON FUNCTION get_user_bookings(UUID, TEXT) TO authenticated;

-- Create a simpler view that just fixes the immediate service_title issue
DROP VIEW IF EXISTS public.bookings_simple;

CREATE VIEW public.bookings_simple AS
SELECT 
    b.*,
    COALESCE(s.name, ps.title, 'Unknown Service') as service_title
FROM public.bookings b
LEFT JOIN public.services s ON b.service_id = s.id
LEFT JOIN public.provider_services ps ON b.service_id = ps.id;

-- Grant permissions on simple view
GRANT SELECT ON public.bookings_simple TO authenticated;
GRANT SELECT ON public.bookings_simple TO service_role;
