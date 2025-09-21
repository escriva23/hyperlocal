-- Final comprehensive fix for auth trigger

-- Step 1: Remove all existing triggers and functions
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
DROP FUNCTION IF EXISTS handle_new_user() CASCADE;

-- Step 2: Create enum type (force creation)
DROP TYPE IF EXISTS user_role CASCADE;
CREATE TYPE user_role AS ENUM ('customer', 'provider', 'admin');

-- Step 3: Recreate users table with correct structure
DROP TABLE IF EXISTS public.users CASCADE;
CREATE TABLE public.users (
    id UUID PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    role user_role NOT NULL DEFAULT 'customer',
    phone TEXT,
    avatar_url TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT users_id_fkey FOREIGN KEY (id) REFERENCES auth.users(id) ON DELETE CASCADE
);

-- Step 4: Disable RLS on all tables
ALTER TABLE public.users DISABLE ROW LEVEL SECURITY;

-- Step 5: Create simple trigger function without enum casting issues
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    -- Insert into users table with simple text casting
    INSERT INTO public.users (id, email, name, role, created_at, updated_at)
    VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'name', split_part(NEW.email, '@', 1)),
        CASE 
            WHEN NEW.raw_user_meta_data->>'role' = 'provider' THEN 'provider'::user_role
            WHEN NEW.raw_user_meta_data->>'role' = 'admin' THEN 'admin'::user_role
            ELSE 'customer'::user_role
        END,
        NOW(),
        NOW()
    );
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Step 6: Create the trigger
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION handle_new_user();

-- Step 7: Grant permissions
GRANT EXECUTE ON FUNCTION handle_new_user() TO postgres, service_role;
GRANT ALL ON public.users TO postgres, service_role;
