import { SupabaseClient } from '@supabase/supabase-js'
import {
    ApiResponse,
    AuthUser,
    LoginCredentials,
    RegisterData
} from '../types/api.types'
import {
    User,
    UserInsert,
    ProfileInsert,
    ProviderProfileInsert,
    WalletInsert,
    MtaaShareInsert
} from '../types/database.types'

export class AuthService {
    constructor(private supabase: SupabaseClient) { }

    /**
     * Register a new user
     */
    async signUp(data: RegisterData): Promise<ApiResponse<User>> {
        try {
            const { email, password, name, role = 'customer', phone } = data

            // First, create the auth user without metadata to avoid trigger issues
            const { data: authData, error: authError } = await this.supabase.auth.signUp({
                email,
                password
            })

            if (authError) throw authError

            if (!authData.user) {
                return { data: null, error: 'User creation failed', success: false }
            }

            // Manually create the user profile after auth user is created
            const userInsert: UserInsert = {
                id: authData.user.id,
                email,
                name,
                role,
                phone: phone || null
            }

            const { data: userData, error: userError } = await this.supabase
                .from('users')
                .insert(userInsert)
                .select()
                .single()

            if (userError) {
                // If user creation fails, clean up the auth user
                await this.supabase.auth.admin.deleteUser(authData.user.id)
                return { data: null, error: 'Failed to create user profile', success: false }
            }

            // Create additional profiles based on role
            const profileInsert: ProfileInsert = { user_id: authData.user.id }
            const walletInsert: WalletInsert = { user_id: authData.user.id }

            await Promise.all([
                this.supabase.from('profiles').insert(profileInsert),
                this.supabase.from('wallets').insert(walletInsert)
            ])

            if (role === 'provider') {
                const providerProfileInsert: ProviderProfileInsert = {
                    user_id: authData.user.id,
                    business_name: `${name}'s Business`
                }
                const mtaaSharesInsert: MtaaShareInsert = { user_id: authData.user.id }

                await Promise.all([
                    this.supabase.from('provider_profiles').insert(providerProfileInsert),
                    this.supabase.from('mtaa_shares').insert(mtaaSharesInsert)
                ])
            }

            return { data: userData, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Registration failed', success: false }
        }
    }

    /**
     * Sign in user
     */
    async signIn(credentials: LoginCredentials): Promise<ApiResponse<User>> {
        try {
            const { email, password } = credentials

            const { data: authData, error: authError } = await this.supabase.auth.signInWithPassword({
                email,
                password
            })

            if (authError) {
                return { data: null, error: authError.message, success: false }
            }

            if (!authData.user) {
                return { data: null, error: 'Login failed', success: false }
            }

            // Get user data
            const { data: userData, error: userError } = await this.supabase
                .from('users')
                .select('*')
                .eq('id', authData.user.id)
                .single()

            if (userError) {
                return { data: null, error: userError.message, success: false }
            }

            return { data: userData, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Login failed', success: false }
        }
    }

    /**
     * Sign out user
     */
    async signOut(): Promise<ApiResponse<null>> {
        try {
            const { error } = await this.supabase.auth.signOut()
            if (error) {
                return { data: null, error: error.message, success: false }
            }
            return { data: null, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Logout failed', success: false }
        }
    }

    /**
     * Reset password
     */
    async resetPassword(data: { email: string }): Promise<ApiResponse<null>> {
        try {
            const { email } = data
            const baseUrl = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000'
            const { error } = await this.supabase.auth.resetPasswordForEmail(email, {
                redirectTo: `${baseUrl}/auth/reset-password`
            })
            if (error) {
                return { data: null, error: error.message, success: false }
            }
            return { data: null, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Password reset failed', success: false }
        }
    }

    /**
     * Update password
     */
    async updatePassword(data: { password: string }): Promise<ApiResponse<null>> {
        try {
            const { password } = data
            const { error } = await this.supabase.auth.updateUser({ password })
            if (error) {
                return { data: null, error: error.message, success: false }
            }
            return { data: null, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Password update failed', success: false }
        }
    }

    /**
     * Get current user
     */
    async getCurrentUser(): Promise<ApiResponse<User>> {
        try {
            const { data: authData, error: authError } = await this.supabase.auth.getUser()

            if (authError || !authData.user) {
                return { data: null, error: 'No authenticated user', success: false }
            }

            const { data: userData, error: userError } = await this.supabase
                .from('users')
                .select('*')
                .eq('id', authData.user.id)
                .single()

            if (userError) {
                return { data: null, error: userError.message, success: false }
            }

            return { data: userData, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to get current user', success: false }
        }
    }

    /**
     * Update user profile
     */
    async updateUser(updates: Partial<User>): Promise<ApiResponse<User>> {
        try {
            const { data: authData } = await this.supabase.auth.getUser()

            if (!authData.user) {
                return { data: null, error: 'No authenticated user', success: false }
            }

            const { data, error } = await this.supabase
                .from('users')
                .update({ ...updates, updated_at: new Date().toISOString() })
                .eq('id', authData.user.id)
                .select()
                .single()

            if (error) {
                return { data: null, error: error.message, success: false }
            }

            return { data, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to update user', success: false }
        }
    }

    /**
     * Subscribe to auth state changes
     */
    onAuthStateChange(callback: (user: User | null) => void) {
        return this.supabase.auth.onAuthStateChange(async (event, session) => {
            if (session?.user) {
                const { data } = await this.getCurrentUser()
                callback(data)
            } else {
                callback(null)
            }
        })
    }
}
