"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthService = void 0;
class AuthService {
    constructor(supabase) {
        this.supabase = supabase;
    }
    /**
     * Register a new user
     */
    async signUp(data) {
        try {
            const { email, password, name, role = 'customer', phone } = data;
            // First, create the auth user without metadata to avoid trigger issues
            const { data: authData, error: authError } = await this.supabase.auth.signUp({
                email,
                password
            });
            if (authError)
                throw authError;
            if (!authData.user) {
                return { data: null, error: 'User creation failed', success: false };
            }
            // Manually create the user profile after auth user is created
            const userInsert = {
                id: authData.user.id,
                email,
                name,
                role,
                phone: phone || null
            };
            const { data: userData, error: userError } = await this.supabase
                .from('users')
                .insert(userInsert)
                .select()
                .single();
            if (userError) {
                // If user creation fails, clean up the auth user
                await this.supabase.auth.admin.deleteUser(authData.user.id);
                return { data: null, error: 'Failed to create user profile', success: false };
            }
            // Create additional profiles based on role
            const profileInsert = { user_id: authData.user.id };
            const walletInsert = { user_id: authData.user.id };
            await Promise.all([
                this.supabase.from('profiles').insert(profileInsert),
                this.supabase.from('wallets').insert(walletInsert)
            ]);
            if (role === 'provider') {
                const providerProfileInsert = {
                    user_id: authData.user.id,
                    business_name: `${name}'s Business`
                };
                const mtaaSharesInsert = { user_id: authData.user.id };
                await Promise.all([
                    this.supabase.from('provider_profiles').insert(providerProfileInsert),
                    this.supabase.from('mtaa_shares').insert(mtaaSharesInsert)
                ]);
            }
            return { data: userData, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Registration failed', success: false };
        }
    }
    /**
     * Sign in user
     */
    async signIn(credentials) {
        try {
            const { email, password } = credentials;
            const { data: authData, error: authError } = await this.supabase.auth.signInWithPassword({
                email,
                password
            });
            if (authError) {
                return { data: null, error: authError.message, success: false };
            }
            if (!authData.user) {
                return { data: null, error: 'Login failed', success: false };
            }
            // Get user data
            const { data: userData, error: userError } = await this.supabase
                .from('users')
                .select('*')
                .eq('id', authData.user.id)
                .single();
            if (userError) {
                return { data: null, error: userError.message, success: false };
            }
            return { data: userData, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Login failed', success: false };
        }
    }
    /**
     * Sign out user
     */
    async signOut() {
        try {
            const { error } = await this.supabase.auth.signOut();
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data: null, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Logout failed', success: false };
        }
    }
    /**
     * Reset password
     */
    async resetPassword(data) {
        try {
            const { email } = data;
            const baseUrl = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000';
            const { error } = await this.supabase.auth.resetPasswordForEmail(email, {
                redirectTo: `${baseUrl}/auth/reset-password`
            });
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data: null, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Password reset failed', success: false };
        }
    }
    /**
     * Update password
     */
    async updatePassword(data) {
        try {
            const { password } = data;
            const { error } = await this.supabase.auth.updateUser({ password });
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data: null, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Password update failed', success: false };
        }
    }
    /**
     * Get current user
     */
    async getCurrentUser() {
        try {
            const { data: authData, error: authError } = await this.supabase.auth.getUser();
            if (authError || !authData.user) {
                return { data: null, error: 'No authenticated user', success: false };
            }
            const { data: userData, error: userError } = await this.supabase
                .from('users')
                .select('*')
                .eq('id', authData.user.id)
                .single();
            if (userError) {
                return { data: null, error: userError.message, success: false };
            }
            return { data: userData, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to get current user', success: false };
        }
    }
    /**
     * Update user profile
     */
    async updateUser(updates) {
        try {
            const { data: authData } = await this.supabase.auth.getUser();
            if (!authData.user) {
                return { data: null, error: 'No authenticated user', success: false };
            }
            const { data, error } = await this.supabase
                .from('users')
                .update({ ...updates, updated_at: new Date().toISOString() })
                .eq('id', authData.user.id)
                .select()
                .single();
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to update user', success: false };
        }
    }
    /**
     * Subscribe to auth state changes
     */
    onAuthStateChange(callback) {
        return this.supabase.auth.onAuthStateChange(async (event, session) => {
            if (session?.user) {
                const { data } = await this.getCurrentUser();
                callback(data);
            }
            else {
                callback(null);
            }
        });
    }
}
exports.AuthService = AuthService;
