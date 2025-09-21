-- Security logging function and table
-- Separated from performance optimizations to avoid dependency issues

-- Create security logs table
CREATE TABLE IF NOT EXISTS security_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type text NOT NULL,
  user_id uuid REFERENCES users(id),
  details jsonb DEFAULT '{}'::jsonb,
  created_at timestamp with time zone DEFAULT NOW()
);

-- Create indexes on security logs
CREATE INDEX IF NOT EXISTS idx_security_logs_created ON security_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_security_logs_type ON security_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_security_logs_user ON security_logs(user_id);

-- Enable RLS on security logs
ALTER TABLE security_logs ENABLE ROW LEVEL SECURITY;

-- Only admins can view security logs
CREATE POLICY security_logs_admin_only ON security_logs
  FOR ALL
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM users 
      WHERE users.id = auth.uid() 
      AND users.role = 'admin'
    )
  );

-- Create function to log security events
CREATE OR REPLACE FUNCTION log_security_event(
  event_type text,
  user_id uuid DEFAULT NULL,
  details jsonb DEFAULT '{}'::jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  INSERT INTO security_logs (event_type, user_id, details, created_at)
  VALUES (event_type, user_id, details, NOW());
EXCEPTION
  WHEN OTHERS THEN
    -- Fail silently to not break application flow
    NULL;
END;
$$;

-- Add comments
COMMENT ON TABLE security_logs IS 'Security event logging table for audit purposes';
COMMENT ON FUNCTION log_security_event(text, uuid, jsonb) IS 'Logs security events for audit purposes';
