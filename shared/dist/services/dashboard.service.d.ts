import { SupabaseClient } from '@supabase/supabase-js';
import { ApiResponse, DashboardStats } from '../types/api.types';
export declare class DashboardService {
    private supabase;
    constructor(supabase: SupabaseClient);
    /**
     * Get customer dashboard statistics
     */
    getCustomerStats(userId: string): Promise<ApiResponse<DashboardStats>>;
    /**
     * Get provider dashboard statistics
     */
    getProviderStats(userId: string): Promise<ApiResponse<DashboardStats>>;
    /**
     * Fallback method to calculate customer stats manually
     */
    private calculateCustomerStatsManually;
    /**
     * Fallback method to calculate provider stats manually
     */
    private calculateProviderStatsManually;
    /**
     * Get recent activity for dashboard
     */
    getRecentActivity(userId: string, userType: 'customer' | 'provider', limit?: number): Promise<ApiResponse<any[]>>;
    /**
     * Get earnings summary for providers
     */
    getEarningsSummary(userId: string, period?: 'week' | 'month' | 'year'): Promise<ApiResponse<any>>;
}
