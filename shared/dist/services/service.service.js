"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ServiceService = void 0;
class ServiceService {
    constructor(supabase) {
        this.supabase = supabase;
    }
    /**
     * Get all service categories
     */
    async getCategories() {
        try {
            const { data, error } = await this.supabase
                .from('service_categories')
                .select('*')
                .eq('is_active', true)
                .order('sort_order', { ascending: true });
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data: data || [], error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to fetch categories', success: false };
        }
    }
    /**
     * Search services with filters
     */
    async searchServices(filters = {}, location) {
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
            });
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data: data || [], error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to search services', success: false };
        }
    }
    /**
     * Search providers with filters
     */
    async searchProviders(filters = {}, location) {
        try {
            const { data, error } = await this.supabase.rpc('get_nearby_providers', {
                user_lat: location?.latitude || 0,
                user_lng: location?.longitude || 0,
                radius_km: 50,
                service_category: filters.category
            });
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data: data || [], error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to search providers', success: false };
        }
    }
    /**
     * Get services by provider
     */
    async getProviderServices(providerId) {
        try {
            const { data, error } = await this.supabase
                .from('services')
                .select(`
          *,
          service_categories(*)
        `)
                .eq('provider_id', providerId)
                .eq('status', 'active')
                .order('created_at', { ascending: false });
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data: data || [], error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to fetch provider services', success: false };
        }
    }
    /**
     * Get provider services from provider_services table
     */
    async getProviderServicesList(providerId) {
        try {
            const { data, error } = await this.supabase
                .from('provider_services')
                .select('*')
                .eq('provider_id', providerId)
                .eq('is_active', true)
                .order('created_at', { ascending: false });
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data: data || [], error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to fetch provider services list', success: false };
        }
    }
    /**
     * Create a new provider service
     */
    async createProviderService(service) {
        try {
            const { data, error } = await this.supabase
                .from('provider_services')
                .insert(service)
                .select()
                .single();
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to create service', success: false };
        }
    }
    /**
     * Update provider service
     */
    async updateProviderService(serviceId, updates) {
        try {
            const { data, error } = await this.supabase
                .from('provider_services')
                .update({ ...updates, updated_at: new Date().toISOString() })
                .eq('id', serviceId)
                .select()
                .single();
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to update service', success: false };
        }
    }
    /**
     * Delete provider service
     */
    async deleteProviderService(serviceId) {
        try {
            const { error } = await this.supabase
                .from('provider_services')
                .delete()
                .eq('id', serviceId);
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data: null, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to delete service', success: false };
        }
    }
    /**
     * Toggle service active status
     */
    async toggleServiceStatus(serviceId, isActive) {
        try {
            const { data, error } = await this.supabase
                .from('provider_services')
                .update({
                is_active: isActive,
                updated_at: new Date().toISOString()
            })
                .eq('id', serviceId)
                .select()
                .single();
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to toggle service status', success: false };
        }
    }
    /**
     * Get service by ID
     */
    async getServiceById(serviceId) {
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
                .single();
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to fetch service', success: false };
        }
    }
    /**
     * Get provider service by ID
     */
    async getProviderServiceById(serviceId) {
        try {
            const { data, error } = await this.supabase
                .from('provider_services')
                .select('*')
                .eq('id', serviceId)
                .single();
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to fetch provider service', success: false };
        }
    }
    /**
     * Get services by category
     */
    async getServicesByCategory(categorySlug) {
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
                .order('created_at', { ascending: false });
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data: data || [], error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to fetch services by category', success: false };
        }
    }
    /**
     * Get featured services
     */
    async getFeaturedServices(limit = 10) {
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
                .limit(limit);
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data: data || [], error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to fetch featured services', success: false };
        }
    }
}
exports.ServiceService = ServiceService;
