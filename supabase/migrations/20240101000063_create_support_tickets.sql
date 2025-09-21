-- Create support tickets table for admin issues page

CREATE TABLE IF NOT EXISTS support_tickets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject TEXT NOT NULL,
    message TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'other' CHECK (category IN ('technical', 'billing', 'account', 'service', 'other')),
    priority TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('low', 'medium', 'high', 'urgent')),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'resolved', 'closed')),
    reported_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    assigned_to UUID REFERENCES users(id) ON DELETE SET NULL,
    resolution_notes TEXT,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_support_tickets_reported_by ON support_tickets(reported_by);
CREATE INDEX IF NOT EXISTS idx_support_tickets_assigned_to ON support_tickets(assigned_to);
CREATE INDEX IF NOT EXISTS idx_support_tickets_status ON support_tickets(status);
CREATE INDEX IF NOT EXISTS idx_support_tickets_priority ON support_tickets(priority);
CREATE INDEX IF NOT EXISTS idx_support_tickets_created_at ON support_tickets(created_at DESC);

-- Enable RLS
ALTER TABLE support_tickets ENABLE ROW LEVEL SECURITY;

-- RLS Policies
CREATE POLICY "Users can view own tickets" ON support_tickets
    FOR SELECT USING (auth.uid() = reported_by);

CREATE POLICY "Users can create own tickets" ON support_tickets
    FOR INSERT WITH CHECK (auth.uid() = reported_by);

CREATE POLICY "Admins can view all tickets" ON support_tickets
    FOR SELECT USING (
        auth.uid() IN (SELECT id FROM users WHERE role = 'admin')
    );

CREATE POLICY "Admins can update all tickets" ON support_tickets
    FOR UPDATE USING (
        auth.uid() IN (SELECT id FROM users WHERE role = 'admin')
    );

-- Insert some sample data
INSERT INTO support_tickets (subject, message, category, priority, reported_by) 
SELECT 
    'Sample Support Ticket',
    'This is a sample support ticket for testing purposes.',
    'technical',
    'medium',
    id
FROM users 
WHERE role = 'customer' 
LIMIT 1
ON CONFLICT DO NOTHING;
