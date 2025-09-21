import { SupabaseClient } from '@supabase/supabase-js';
import { ApiResponse, SearchFilters, ServiceSearchResult, ProviderSearchResult, LocationCoordinates } from '../types/api.types';
import { Service, ProviderService, ProviderServiceInsert, ProviderServiceUpdate, ServiceCategory } from '../types/database.types';
export declare class ServiceService {
    private supabase;
    constructor(supabase: SupabaseClient);
    /**
     * Get all service categories
     */
    getCategories(): Promise<ApiResponse<ServiceCategory[]>>;
    /**
     * Search services with filters
     */
    searchServices(filters?: SearchFilters, location?: LocationCoordinates): Promise<ApiResponse<ServiceSearchResult[]>>;
    /**
     * Search providers with filters
     */
    searchProviders(filters?: SearchFilters, location?: LocationCoordinates): Promise<ApiResponse<ProviderSearchResult[]>>;
    /**
     * Get services by provider
     */
    getProviderServices(providerId: string): Promise<ApiResponse<Service[]>>;
    /**
     * Get provider services from provider_services table
     */
    getProviderServicesList(providerId: string): Promise<ApiResponse<ProviderService[]>>;
    /**
     * Create a new provider service
     */
    createProviderService(service: ProviderServiceInsert): Promise<ApiResponse<ProviderService>>;
    /**
     * Update provider service
     */
    updateProviderService(serviceId: string, updates: ProviderServiceUpdate): Promise<ApiResponse<ProviderService>>;
    /**
     * Delete provider service
     */
    deleteProviderService(serviceId: string): Promise<ApiResponse<null>>;
    /**
     * Toggle service active status
     */
    toggleServiceStatus(serviceId: string, isActive: boolean): Promise<ApiResponse<ProviderService>>;
    /**
     * Get service by ID
     */
    getServiceById(serviceId: string): Promise<ApiResponse<Service>>;
    /**
     * Get provider service by ID
     */
    getProviderServiceById(serviceId: string): Promise<ApiResponse<ProviderService>>;
    /**
     * Get services by category
     */
    getServicesByCategory(categorySlug: string): Promise<ApiResponse<Service[]>>;
    /**
     * Get featured services
     */
    getFeaturedServices(limit?: number): Promise<ApiResponse<Service[]>>;
}
