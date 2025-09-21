-- Enable RLS on provider_services table
ALTER TABLE provider_services ENABLE ROW LEVEL SECURITY;

-- Policy: Providers can view their own services
CREATE POLICY "Providers can view own services" ON provider_services
    FOR SELECT USING (
        auth.uid() = provider_id
    );

-- Policy: Providers can insert their own services
CREATE POLICY "Providers can insert own services" ON provider_services
    FOR INSERT WITH CHECK (
        auth.uid() = provider_id
    );

-- Policy: Providers can update their own services
CREATE POLICY "Providers can update own services" ON provider_services
    FOR UPDATE USING (
        auth.uid() = provider_id
    ) WITH CHECK (
        auth.uid() = provider_id
    );

-- Policy: Providers can delete their own services
CREATE POLICY "Providers can delete own services" ON provider_services
    FOR DELETE USING (
        auth.uid() = provider_id
    );

-- Policy: Customers can view active services
CREATE POLICY "Customers can view active services" ON provider_services
    FOR SELECT USING (
        is_active = true
    );

-- Policy: Admins can view all services
CREATE POLICY "Admins can view all services" ON provider_services
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM users 
            WHERE users.id = auth.uid() 
            AND users.role = 'admin'
        )
    );

-- Policy: Admins can update all services
CREATE POLICY "Admins can update all services" ON provider_services
    FOR UPDATE USING (
        EXISTS (
            SELECT 1 FROM users 
            WHERE users.id = auth.uid() 
            AND users.role = 'admin'
        )
    );

-- Policy: Admins can delete all services
CREATE POLICY "Admins can delete all services" ON provider_services
    FOR DELETE USING (
        EXISTS (
            SELECT 1 FROM users 
            WHERE users.id = auth.uid() 
            AND users.role = 'admin'
        )
    );
