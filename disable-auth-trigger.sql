-- Disable the problematic auth trigger without affecting existing data

-- Simply disable the trigger that's causing issues
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;

-- Optionally drop the function too if you want to clean up
DROP FUNCTION IF EXISTS handle_new_user();
