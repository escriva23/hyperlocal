import { SupabaseClient } from '@supabase/supabase-js';
import { ApiResponse, LoginCredentials, RegisterData } from '../types/api.types';
import { User } from '../types/database.types';
export declare class AuthService {
    private supabase;
    constructor(supabase: SupabaseClient);
    /**
     * Register a new user
     */
    signUp(data: RegisterData): Promise<ApiResponse<User>>;
    /**
     * Sign in user
     */
    signIn(credentials: LoginCredentials): Promise<ApiResponse<User>>;
    /**
     * Sign out user
     */
    signOut(): Promise<ApiResponse<null>>;
    /**
     * Reset password
     */
    resetPassword(data: {
        email: string;
    }): Promise<ApiResponse<null>>;
    /**
     * Update password
     */
    updatePassword(data: {
        password: string;
    }): Promise<ApiResponse<null>>;
    /**
     * Get current user
     */
    getCurrentUser(): Promise<ApiResponse<User>>;
    /**
     * Update user profile
     */
    updateUser(updates: Partial<User>): Promise<ApiResponse<User>>;
    /**
     * Subscribe to auth state changes
     */
    onAuthStateChange(callback: (user: User | null) => void): {
        data: {
            subscription: import("@supabase/supabase-js").Subscription;
        };
    };
}
