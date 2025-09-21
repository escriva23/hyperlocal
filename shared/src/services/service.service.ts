import { SupabaseClient } from '@supabase/supabase-js'
import {
    ApiResponse,
    SearchFilters,
    ServiceSearchResult,
    ProviderSearchResult,
    LocationCoordinates
} from '../types/api.types'
import {
    Service,
    ServiceInsert,
    ServiceUpdate,
    ProviderService,
    ProviderServiceInsert,
    ProviderServiceUpdate,
    ServiceCategory
} from '../types/database.types'

export class ServiceService {
    constructor(private supabase: SupabaseClient) { }

    /**
     * Get all service categories
     */
    async getCategories(): Promise<ApiResponse<ServiceCategory[]>> {
        try {
            const { data, error } = await this.supabase
                .from('service_categories')
                .select('*')
                .eq('is_active', true)
                .order('sort_order', { ascending: true })

            if (error) {
                return { data: null, error: error.message, success: false }
            }

            return { data: data || [], error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to fetch categories', success: false }
        }
    }

    /**
     * Search services with filters
     */
    async searchServices(
        filters: SearchFilters = {},
        location?: LocationCoordinates
    ): Promise<ApiResponse<ServiceSearchResult[]>> {
        try {
            // Use Supabase function for complex search
            const { data, error } = await this.supabase.rpc('search_services', {
                search_query: filters.category || '',
                user_lat: location?.latitude,
                user_lng: location?.longitude,
                max_distance_km: 50, // Default 50km radius
                min_rating: filters.rating,
                max_price: filters.maxPrice,
                category_slug: filters.category
            })

            if (error) {
                return { data: null, error: error.message, success: false }
            }

            return { data: data || [], error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to search services', success: false }
        }
    }

    /**
     * Search providers with filters
     */
    async searchProviders(
        filters: SearchFilters = {},
        location?: LocationCoordinates
    ): Promise<ApiResponse<ProviderSearchResult[]>> {
        try {
            const { data, error } = await this.supabase.rpc('get_nearby_providers', {
                user_lat: location?.latitude || 0,
                user_lng: location?.longitude || 0,
                radius_km: 50,
                service_category: filters.category
            })

            if (error) {
                return { data: null, error: error.message, success: false }
            }

            return { data: data || [], error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to search providers', success: false }
        }
    }

    /**
     * Get services by provider
     */
    async getProviderServices(providerId: string): Promise<ApiResponse<Service[]>> {
        try {
            const { data, error } = await this.supabase
                .from('services')
                .select(`
          *,
          service_categories(*)
        `)
                .eq('provider_id', providerId)
                .eq('status', 'active')
                .order('created_at', { ascending: false })

            if (error) {
                return { data: null, error: error.message, success: false }
            }

            return { data: data || [], error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to fetch provider services', success: false }
        }
    }

    /**
     * Get provider services from provider_services table
     */
    async getProviderServicesList(providerId: string): Promise<ApiResponse<ProviderService[]>> {
        try {
            const { data, error } = await this.supabase
                .from('provider_services')
                .select('*')
                .eq('provider_id', providerId)
                .eq('is_active', true)
                .order('created_at', { ascending: false })

            if (error) {
                return { data: null, error: error.message, success: false }
            }

            return { data: data || [], error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to fetch provider services list', success: false }
        }
    }

    /**
     * Create a new provider service
     */
    async createProviderService(service: ProviderServiceInsert): Promise<ApiResponse<ProviderService>> {
        try {
            const { data, error } = await this.supabase
                .from('provider_services')
                .insert(service)
                .select()
                .single()

            if (error) {
                return { data: null, error: error.message, success: false }
            }

            return { data, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to create service', success: false }
        }
    }

    /**
     * Update provider service
     */
    async updateProviderService(
        serviceId: string,
        updates: ProviderServiceUpdate
    ): Promise<ApiResponse<ProviderService>> {
        try {
            const { data, error } = await this.supabase
                .from('provider_services')
                .update({ ...updates, updated_at: new Date().toISOString() })
                .eq('id', serviceId)
                .select()
                .single()

            if (error) {
                return { data: null, error: error.message, success: false }
            }

            return { data, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to update service', success: false }
        }
    }

    /**
     * Delete provider service
     */
    async deleteProviderService(serviceId: string): Promise<ApiResponse<null>> {
        try {
            const { error } = await this.supabase
                .from('provider_services')
                .delete()
                .eq('id', serviceId)

            if (error) {
                return { data: null, error: error.message, success: false }
            }

            return { data: null, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to delete service', success: false }
        }
    }

    /**
     * Toggle service active status
     */
    async toggleServiceStatus(serviceId: string, isActive: boolean): Promise<ApiResponse<ProviderService>> {
        try {
            const { data, error } = await this.supabase
                .from('provider_services')
                .update({
                    is_active: isActive,
                    updated_at: new Date().toISOString()
                })
                .eq('id', serviceId)
                .select()
                .single()

            if (error) {
                return { data: null, error: error.message, success: false }
            }

            return { data, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to toggle service status', success: false }
        }
    }

    /**
     * Get service by ID
     */
    async getServiceById(serviceId: string): Promise<ApiResponse<Service>> {
        try {
            const { data, error } = await this.supabase
                .from('services')
                .select(`
          *,
          service_categories(*),
          provider_profiles(
            *,
            users(*)
          )
        `)
                .eq('id', serviceId)
                .single()

            if (error) {
                return { data: null, error: error.message, success: false }
            }

            return { data, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to fetch service', success: false }
        }
    }

    /**
     * Get provider service by ID
     */
    async getProviderServiceById(serviceId: string): Promise<ApiResponse<ProviderService>> {
        try {
            const { data, error } = await this.supabase
                .from('provider_services')
                .select('*')
                .eq('id', serviceId)
                .single()

            if (error) {
                return { data: null, error: error.message, success: false }
            }

            return { data, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to fetch provider service', success: false }
        }
    }

    /**
     * Get services by category
     */
    async getServicesByCategory(categorySlug: string): Promise<ApiResponse<Service[]>> {
        try {
            const { data, error } = await this.supabase
                .from('services')
                .select(`
          *,
          service_categories!inner(*),
          provider_profiles(
            *,
            users(*)
          )
        `)
                .eq('service_categories.slug', categorySlug)
                .eq('status', 'active')
                .order('created_at', { ascending: false })

            if (error) {
                return { data: null, error: error.message, success: false }
            }

            return { data: data || [], error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to fetch services by category', success: false }
        }
    }

    /**
     * Get featured services
     */
    async getFeaturedServices(limit: number = 10): Promise<ApiResponse<Service[]>> {
        try {
            const { data, error } = await this.supabase
                .from('services')
                .select(`
          *,
          service_categories(*),
          provider_profiles(
            *,
            users(*)
          )
        `)
                .eq('status', 'active')
                .order('created_at', { ascending: false })
                .limit(limit)

            if (error) {
                return { data: null, error: error.message, success: false }
            }

            return { data: data || [], error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to fetch featured services', success: false }
        }
    }
}
