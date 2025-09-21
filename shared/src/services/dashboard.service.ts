import { SupabaseClient } from '@supabase/supabase-js'
import { ApiResponse, DashboardStats } from '../types/api.types'

export class DashboardService {
    constructor(private supabase: SupabaseClient) { }

    /**
     * Get customer dashboard statistics
     */
    async getCustomerStats(userId: string): Promise<ApiResponse<DashboardStats>> {
        try {
            // Use Supabase function for optimized stats calculation
            const { data, error } = await this.supabase.rpc('get_customer_dashboard_stats', {
                customer_id: userId
            })

            if (error) {
                // Fallback to manual calculation if function doesn't exist
                return this.calculateCustomerStatsManually(userId)
            }

            return { data, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to fetch customer stats', success: false }
        }
    }

    /**
     * Get provider dashboard statistics
     */
    async getProviderStats(userId: string): Promise<ApiResponse<DashboardStats>> {
        try {
            // Use Supabase function for optimized stats calculation
            const { data, error } = await this.supabase.rpc('get_provider_dashboard_stats', {
                provider_id: userId
            })

            if (error) {
                // Fallback to manual calculation if function doesn't exist
                return this.calculateProviderStatsManually(userId)
            }

            return { data, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to fetch provider stats', success: false }
        }
    }

    /**
     * Fallback method to calculate customer stats manually
     */
    private async calculateCustomerStatsManually(userId: string): Promise<ApiResponse<DashboardStats>> {
        try {
            // Get booking stats
            const { data: bookings, error: bookingsError } = await this.supabase
                .from('bookings')
                .select('status')
                .eq('customer_id', userId)

            if (bookingsError) {
                return { data: null, error: bookingsError.message, success: false }
            }

            // Get wallet balance
            const { data: wallet, error: walletError } = await this.supabase
                .from('wallets')
                .select('balance')
                .eq('user_id', userId)
                .single()

            if (walletError) {
                return { data: null, error: walletError.message, success: false }
            }

            // Get pending reviews count
            const { data: completedBookings, error: completedError } = await this.supabase
                .from('bookings')
                .select('id')
                .eq('customer_id', userId)
                .eq('status', 'completed')

            if (completedError) {
                return { data: null, error: completedError.message, success: false }
            }

            const { data: existingReviews, error: reviewsError } = await this.supabase
                .from('reviews')
                .select('id')
                .eq('customer_id', userId)

            if (reviewsError) {
                return { data: null, error: reviewsError.message, success: false }
            }

            const totalBookings = bookings?.length || 0
            const completedBookingsCount = bookings?.filter(b => b.status === 'completed').length || 0
            const walletBalance = wallet?.balance || 0
            const pendingReviews = Math.max(0, (completedBookings?.length || 0) - (existingReviews?.length || 0))

            const stats: DashboardStats = {
                total_bookings: totalBookings,
                completed_bookings: completedBookingsCount,
                pending_reviews: pendingReviews,
                wallet_balance: walletBalance
            }

            return { data: stats, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to calculate customer stats', success: false }
        }
    }

    /**
     * Fallback method to calculate provider stats manually
     */
    private async calculateProviderStatsManually(userId: string): Promise<ApiResponse<DashboardStats>> {
        try {
            // Get booking stats
            const { data: bookings, error: bookingsError } = await this.supabase
                .from('bookings')
                .select('status, price')
                .eq('provider_id', userId)

            if (bookingsError) {
                return { data: null, error: bookingsError.message, success: false }
            }

            // Get services count
            const { data: services, error: servicesError } = await this.supabase
                .from('provider_services')
                .select('id')
                .eq('provider_id', userId)
                .eq('is_active', true)

            if (servicesError) {
                return { data: null, error: servicesError.message, success: false }
            }

            // Get provider profile for rating
            const { data: profile, error: profileError } = await this.supabase
                .from('provider_profiles')
                .select('average_rating')
                .eq('user_id', userId)
                .single()

            if (profileError) {
                return { data: null, error: profileError.message, success: false }
            }

            // Get wallet balance
            const { data: wallet, error: walletError } = await this.supabase
                .from('wallets')
                .select('balance')
                .eq('user_id', userId)
                .single()

            const totalBookings = bookings?.length || 0
            const completedBookings = bookings?.filter(b => b.status === 'completed').length || 0
            const monthlyEarnings = bookings?.filter(b => b.status === 'completed')
                .reduce((acc, b) => acc + b.price, 0) || 0
            const totalServices = services?.length || 0
            const averageRating = profile?.average_rating || 0
            const walletBalance = wallet?.balance || 0

            const stats: DashboardStats = {
                total_bookings: totalBookings,
                completed_bookings: completedBookings,
                pending_reviews: 0,
                wallet_balance: walletBalance,
                monthly_earnings: monthlyEarnings,
                average_rating: averageRating,
                total_services: totalServices
            }

            return { data: stats, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to calculate provider stats', success: false }
        }
    }

    /**
     * Get recent activity for dashboard
     */
    async getRecentActivity(userId: string, userType: 'customer' | 'provider', limit: number = 10): Promise<ApiResponse<any[]>> {
        try {
            const filterField = userType === 'customer' ? 'customer_id' : 'provider_id'

            const { data, error } = await this.supabase
                .from('bookings')
                .select(`
          *,
          services(name),
          provider_profiles(business_name, users(name)),
          profiles(users(name))
        `)
                .eq(filterField, userId)
                .order('updated_at', { ascending: false })
                .limit(limit)

            if (error) {
                return { data: null, error: error.message, success: false }
            }

            return { data: data || [], error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to fetch recent activity', success: false }
        }
    }

    /**
     * Get earnings summary for providers
     */
    async getEarningsSummary(userId: string, period: 'week' | 'month' | 'year' = 'month'): Promise<ApiResponse<any>> {
        try {
            let dateFilter = new Date()

            switch (period) {
                case 'week':
                    dateFilter.setDate(dateFilter.getDate() - 7)
                    break
                case 'month':
                    dateFilter.setMonth(dateFilter.getMonth() - 1)
                    break
                case 'year':
                    dateFilter.setFullYear(dateFilter.getFullYear() - 1)
                    break
            }

            const { data: transactions, error } = await this.supabase
                .from('transactions')
                .select('amount, type, created_at')
                .eq('user_id', userId)
                .gte('created_at', dateFilter.toISOString())
                .eq('status', 'completed')

            if (error) {
                return { data: null, error: error.message, success: false }
            }

            const earnings = transactions?.filter(t => t.type === 'payout').reduce((acc, t) => acc + t.amount, 0) || 0
            const fees = transactions?.filter(t => t.type === 'fee').reduce((acc, t) => acc + t.amount, 0) || 0
            const commissions = transactions?.filter(t => t.type === 'commission').reduce((acc, t) => acc + t.amount, 0) || 0

            const summary = {
                period,
                total_earnings: earnings,
                total_fees: fees,
                total_commissions: commissions,
                net_earnings: earnings - fees - commissions,
                transaction_count: transactions?.length || 0
            }

            return { data: summary, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to fetch earnings summary', success: false }
        }
    }
}
