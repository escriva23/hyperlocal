-- Check current database structure to understand the issue

-- 1. Check if user_role enum exists
SELECT typname, typtype FROM pg_type WHERE typname = 'user_role';

-- 2. Check users table structure
SELECT column_name, data_type, is_nullable 
FROM information_schema.columns 
WHERE table_schema = 'public' AND table_name = 'users';

-- 3. Check if users table exists at all
SELECT table_name FROM information_schema.tables 
WHERE table_schema = 'public' AND table_name = 'users';

-- 4. Check existing triggers
SELECT tgname, tgfoid::regproc FROM pg_trigger WHERE tgname = 'on_auth_user_created';

-- 5. Check if handle_new_user function exists
SELECT proname FROM pg_proc WHERE proname = 'handle_new_user';
