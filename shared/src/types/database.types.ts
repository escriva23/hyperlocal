export type Json =
    | string
    | number
    | boolean
    | null
    | { [key: string]: Json | undefined }
    | Json[]

export interface Database {
    public: {
        Tables: {
            users: {
                Row: {
                    id: string
                    email: string
                    name: string
                    role: 'customer' | 'provider' | 'admin'
                    phone: string | null
                    avatar_url: string | null
                    is_verified: boolean
                    is_active: boolean
                    created_at: string
                    updated_at: string
                }
                Insert: {
                    id: string
                    email: string
                    name: string
                    role?: 'customer' | 'provider' | 'admin'
                    phone?: string | null
                    avatar_url?: string | null
                    is_verified?: boolean
                    is_active?: boolean
                    created_at?: string
                    updated_at?: string
                }
                Update: {
                    id?: string
                    email?: string
                    name?: string
                    role?: 'customer' | 'provider' | 'admin'
                    phone?: string | null
                    avatar_url?: string | null
                    is_verified?: boolean
                    is_active?: boolean
                    created_at?: string
                    updated_at?: string
                }
            }
            profiles: {
                Row: {
                    id: string
                    user_id: string
                    address: string | null
                    city: string | null
                    country: string | null
                    date_of_birth: string | null
                    gender: string | null
                    preferences: Json
                    location: unknown | null
                    created_at: string
                    updated_at: string
                }
                Insert: {
                    id?: string
                    user_id: string
                    address?: string | null
                    city?: string | null
                    country?: string | null
                    date_of_birth?: string | null
                    gender?: string | null
                    preferences?: Json
                    location?: unknown | null
                    created_at?: string
                    updated_at?: string
                }
                Update: {
                    id?: string
                    user_id?: string
                    address?: string | null
                    city?: string | null
                    country?: string | null
                    date_of_birth?: string | null
                    gender?: string | null
                    preferences?: Json
                    location?: unknown | null
                    created_at?: string
                    updated_at?: string
                }
            }
            provider_profiles: {
                Row: {
                    id: string
                    user_id: string
                    business_name: string
                    description: string | null
                    years_of_experience: number | null
                    verification_status: 'pending' | 'verified' | 'rejected'
                    verification_documents: Json
                    business_license: string | null
                    tax_id: string | null
                    average_rating: number | null
                    total_reviews: number
                    total_bookings: number
                    response_time_minutes: number | null
                    location: unknown | null
                    service_radius_km: number | null
                    is_available: boolean
                    created_at: string
                    updated_at: string
                }
                Insert: {
                    id?: string
                    user_id: string
                    business_name: string
                    description?: string | null
                    years_of_experience?: number | null
                    verification_status?: 'pending' | 'verified' | 'rejected'
                    verification_documents?: Json
                    business_license?: string | null
                    tax_id?: string | null
                    average_rating?: number | null
                    total_reviews?: number
                    total_bookings?: number
                    response_time_minutes?: number | null
                    location?: unknown | null
                    service_radius_km?: number | null
                    is_available?: boolean
                    created_at?: string
                    updated_at?: string
                }
                Update: {
                    id?: string
                    user_id?: string
                    business_name?: string
                    description?: string | null
                    years_of_experience?: number | null
                    verification_status?: 'pending' | 'verified' | 'rejected'
                    verification_documents?: Json
                    business_license?: string | null
                    tax_id?: string | null
                    average_rating?: number | null
                    total_reviews?: number
                    total_bookings?: number
                    response_time_minutes?: number | null
                    location?: unknown | null
                    service_radius_km?: number | null
                    is_available?: boolean
                    created_at?: string
                    updated_at?: string
                }
            }
            service_categories: {
                Row: {
                    id: string
                    name: string
                    description: string | null
                    icon: string | null
                    slug: string
                    parent_id: string | null
                    is_active: boolean
                    sort_order: number
                    created_at: string
                    updated_at: string
                }
                Insert: {
                    id?: string
                    name: string
                    description?: string | null
                    icon?: string | null
                    slug: string
                    parent_id?: string | null
                    is_active?: boolean
                    sort_order?: number
                    created_at?: string
                    updated_at?: string
                }
                Update: {
                    id?: string
                    name?: string
                    description?: string | null
                    icon?: string | null
                    slug?: string
                    parent_id?: string | null
                    is_active?: boolean
                    sort_order?: number
                    created_at?: string
                    updated_at?: string
                }
            }
            services: {
                Row: {
                    id: string
                    provider_id: string
                    category_id: string
                    name: string
                    description: string | null
                    price: number
                    price_type: 'fixed' | 'hourly' | 'negotiable'
                    duration_minutes: number | null
                    status: 'active' | 'inactive' | 'pending'
                    images: Json
                    requirements: string | null
                    location_specific: boolean
                    icon: string | null
                    created_at: string
                    updated_at: string
                }
                Insert: {
                    id?: string
                    provider_id: string
                    category_id: string
                    name: string
                    description?: string | null
                    price: number
                    price_type?: 'fixed' | 'hourly' | 'negotiable'
                    duration_minutes?: number | null
                    status?: 'active' | 'inactive' | 'pending'
                    images?: Json
                    requirements?: string | null
                    location_specific?: boolean
                    icon?: string | null
                    created_at?: string
                    updated_at?: string
                }
                Update: {
                    id?: string
                    provider_id?: string
                    category_id?: string
                    name?: string
                    description?: string | null
                    price?: number
                    price_type?: 'fixed' | 'hourly' | 'negotiable'
                    duration_minutes?: number | null
                    status?: 'active' | 'inactive' | 'pending'
                    images?: Json
                    requirements?: string | null
                    location_specific?: boolean
                    icon?: string | null
                    created_at?: string
                    updated_at?: string
                }
            }
            provider_services: {
                Row: {
                    id: string
                    provider_id: string
                    title: string
                    description: string | null
                    category: string
                    price: number
                    price_type: 'fixed' | 'hourly' | 'negotiable'
                    duration: number | null
                    location_type: 'on_site' | 'remote' | 'both'
                    requirements: string | null
                    images: Json
                    is_active: boolean
                    created_at: string
                    updated_at: string
                }
                Insert: {
                    id?: string
                    provider_id: string
                    title: string
                    description?: string | null
                    category: string
                    price: number
                    price_type?: 'fixed' | 'hourly' | 'negotiable'
                    duration?: number | null
                    location_type?: 'on_site' | 'remote' | 'both'
                    requirements?: string | null
                    images?: Json
                    is_active?: boolean
                    created_at?: string
                    updated_at?: string
                }
                Update: {
                    id?: string
                    provider_id?: string
                    title?: string
                    description?: string | null
                    category?: string
                    price?: number
                    price_type?: 'fixed' | 'hourly' | 'negotiable'
                    duration?: number | null
                    location_type?: 'on_site' | 'remote' | 'both'
                    requirements?: string | null
                    images?: Json
                    is_active?: boolean
                    created_at?: string
                    updated_at?: string
                }
            }
            bookings: {
                Row: {
                    id: string
                    customer_id: string
                    provider_id: string
                    service_id: string
                    booking_time: string
                    status: 'pending' | 'confirmed' | 'in_progress' | 'completed' | 'cancelled'
                    price: number
                    commission_rate: number
                    commission_amount: number | null
                    notes: string | null
                    customer_location: unknown | null
                    service_address: string | null
                    estimated_duration: number | null
                    actual_start_time: string | null
                    actual_end_time: string | null
                    cancellation_reason: string | null
                    cancelled_by: string | null
                    cancelled_at: string | null
                    created_at: string
                    updated_at: string
                }
                Insert: {
                    id?: string
                    customer_id: string
                    provider_id: string
                    service_id: string
                    booking_time: string
                    status?: 'pending' | 'confirmed' | 'in_progress' | 'completed' | 'cancelled'
                    price: number
                    commission_rate?: number
                    commission_amount?: number | null
                    notes?: string | null
                    customer_location?: unknown | null
                    service_address?: string | null
                    estimated_duration?: number | null
                    actual_start_time?: string | null
                    actual_end_time?: string | null
                    cancellation_reason?: string | null
                    cancelled_by?: string | null
                    cancelled_at?: string | null
                    created_at?: string
                    updated_at?: string
                }
                Update: {
                    id?: string
                    customer_id?: string
                    provider_id?: string
                    service_id?: string
                    booking_time?: string
                    status?: 'pending' | 'confirmed' | 'in_progress' | 'completed' | 'cancelled'
                    price?: number
                    commission_rate?: number
                    commission_amount?: number | null
                    notes?: string | null
                    customer_location?: unknown | null
                    service_address?: string | null
                    estimated_duration?: number | null
                    actual_start_time?: string | null
                    actual_end_time?: string | null
                    cancellation_reason?: string | null
                    cancelled_by?: string | null
                    cancelled_at?: string | null
                    created_at?: string
                    updated_at?: string
                }
            }
            reviews: {
                Row: {
                    id: string
                    booking_id: string
                    customer_id: string
                    provider_id: string
                    rating: number
                    comment: string | null
                    images: Json
                    helpful_count: number
                    response: string | null
                    response_at: string | null
                    created_at: string
                    updated_at: string
                }
                Insert: {
                    id?: string
                    booking_id: string
                    customer_id: string
                    provider_id: string
                    rating: number
                    comment?: string | null
                    images?: Json
                    helpful_count?: number
                    response?: string | null
                    response_at?: string | null
                    created_at?: string
                    updated_at?: string
                }
                Update: {
                    id?: string
                    booking_id?: string
                    customer_id?: string
                    provider_id?: string
                    rating?: number
                    comment?: string | null
                    images?: Json
                    helpful_count?: number
                    response?: string | null
                    response_at?: string | null
                    created_at?: string
                    updated_at?: string
                }
            }
            transactions: {
                Row: {
                    id: string
                    user_id: string
                    booking_id: string | null
                    amount: number
                    type: 'payment' | 'payout' | 'refund' | 'fee' | 'commission'
                    status: 'pending' | 'completed' | 'failed' | 'cancelled'
                    payment_method: string | null
                    reference: string | null
                    mpesa_receipt: string | null
                    stripe_payment_intent: string | null
                    description: string | null
                    metadata: Json
                    processed_at: string | null
                    created_at: string
                    updated_at: string
                }
                Insert: {
                    id?: string
                    user_id: string
                    booking_id?: string | null
                    amount: number
                    type: 'payment' | 'payout' | 'refund' | 'fee' | 'commission'
                    status?: 'pending' | 'completed' | 'failed' | 'cancelled'
                    payment_method?: string | null
                    reference?: string | null
                    mpesa_receipt?: string | null
                    stripe_payment_intent?: string | null
                    description?: string | null
                    metadata?: Json
                    processed_at?: string | null
                    created_at?: string
                    updated_at?: string
                }
                Update: {
                    id?: string
                    user_id?: string
                    booking_id?: string | null
                    amount?: number
                    type?: 'payment' | 'payout' | 'refund' | 'fee' | 'commission'
                    status?: 'pending' | 'completed' | 'failed' | 'cancelled'
                    payment_method?: string | null
                    reference?: string | null
                    mpesa_receipt?: string | null
                    stripe_payment_intent?: string | null
                    description?: string | null
                    metadata?: Json
                    processed_at?: string | null
                    created_at?: string
                    updated_at?: string
                }
            }
            wallets: {
                Row: {
                    id: string
                    user_id: string
                    balance: number
                    pending_balance: number
                    total_earned: number
                    total_spent: number
                    created_at: string
                    updated_at: string
                }
                Insert: {
                    id?: string
                    user_id: string
                    balance?: number
                    pending_balance?: number
                    total_earned?: number
                    total_spent?: number
                    created_at?: string
                    updated_at?: string
                }
                Update: {
                    id?: string
                    user_id?: string
                    balance?: number
                    pending_balance?: number
                    total_earned?: number
                    total_spent?: number
                    created_at?: string
                    updated_at?: string
                }
            }
            notifications: {
                Row: {
                    id: string
                    user_id: string
                    title: string
                    message: string
                    type: string
                    priority: 'low' | 'medium' | 'high'
                    action_url: string | null
                    metadata: Json
                    is_read: boolean
                    read_at: string | null
                    created_at: string
                }
                Insert: {
                    id?: string
                    user_id: string
                    title: string
                    message: string
                    type: string
                    priority?: 'low' | 'medium' | 'high'
                    action_url?: string | null
                    metadata?: Json
                    is_read?: boolean
                    read_at?: string | null
                    created_at?: string
                }
                Update: {
                    id?: string
                    user_id?: string
                    title?: string
                    message?: string
                    type?: string
                    priority?: 'low' | 'medium' | 'high'
                    action_url?: string | null
                    metadata?: Json
                    is_read?: boolean
                    read_at?: string | null
                    created_at?: string
                }
            }
            mtaa_shares: {
                Row: {
                    id: string
                    user_id: string
                    total_shares: number
                    current_value: number
                    total_earned: number
                    created_at: string
                    updated_at: string
                }
                Insert: {
                    id?: string
                    user_id: string
                    total_shares?: number
                    current_value?: number
                    total_earned?: number
                    created_at?: string
                    updated_at?: string
                }
                Update: {
                    id?: string
                    user_id?: string
                    total_shares?: number
                    current_value?: number
                    total_earned?: number
                    created_at?: string
                    updated_at?: string
                }
            }
            mtaa_share_activities: {
                Row: {
                    id: string
                    user_id: string
                    activity_type: 'earned' | 'redeemed' | 'bonus' | 'referral'
                    shares_amount: number
                    description: string
                    metadata: Json
                    created_at: string
                }
                Insert: {
                    id?: string
                    user_id: string
                    activity_type: 'earned' | 'redeemed' | 'bonus' | 'referral'
                    shares_amount: number
                    description: string
                    metadata?: Json
                    created_at?: string
                }
                Update: {
                    id?: string
                    user_id?: string
                    activity_type?: 'earned' | 'redeemed' | 'bonus' | 'referral'
                    shares_amount?: number
                    description?: string
                    metadata?: Json
                    created_at?: string
                }
            }
            referral_history: {
                Row: {
                    id: string
                    referrer_id: string
                    referred_id: string
                    referral_code: string
                    bonus_shares: number
                    status: 'pending' | 'completed' | 'cancelled'
                    created_at: string
                    completed_at: string | null
                }
                Insert: {
                    id?: string
                    referrer_id: string
                    referred_id: string
                    referral_code: string
                    bonus_shares?: number
                    status?: 'pending' | 'completed' | 'cancelled'
                    created_at?: string
                    completed_at?: string | null
                }
                Update: {
                    id?: string
                    referrer_id?: string
                    referred_id?: string
                    referral_code?: string
                    bonus_shares?: number
                    status?: 'pending' | 'completed' | 'cancelled'
                    created_at?: string
                    completed_at?: string | null
                }
            }
        }
        Views: {
            mtaa_shares_leaderboard: {
                Row: {
                    user_id: string
                    name: string
                    avatar_url: string | null
                    total_shares: number
                    current_value: number
                    rank: number
                }
            }
        }
        Functions: {
            get_customer_dashboard_stats: {
                Args: {
                    customer_id: string
                }
                Returns: Json
            }
            get_provider_dashboard_stats: {
                Args: {
                    provider_id: string
                }
                Returns: Json
            }
            get_nearby_providers: {
                Args: {
                    user_lat: number
                    user_lng: number
                    radius_km?: number
                    service_category?: string
                }
                Returns: {
                    provider_id: string
                    business_name: string
                    description: string | null
                    average_rating: number | null
                    total_reviews: number
                    distance_km: number
                    services: Json
                }[]
            }
            search_services: {
                Args: {
                    search_query: string
                    user_lat?: number
                    user_lng?: number
                    max_distance_km?: number
                    min_rating?: number
                    max_price?: number
                    category_slug?: string
                }
                Returns: {
                    service_id: string
                    service_name: string
                    service_description: string | null
                    price: number
                    price_type: string
                    provider_id: string
                    business_name: string
                    average_rating: number | null
                    total_reviews: number
                    distance_km: number | null
                    relevance_score: number
                }[]
            }
        }
        Enums: {
            [_ in never]: never
        }
    }
}

// Convenience type exports
export type Tables = Database['public']['Tables']
export type Views = Database['public']['Views']
export type Functions = Database['public']['Functions']

// Table row types
export type User = Tables['users']['Row']
export type Profile = Tables['profiles']['Row']
export type ProviderProfile = Tables['provider_profiles']['Row']
export type ServiceCategory = Tables['service_categories']['Row']
export type Service = Tables['services']['Row']
export type ProviderService = Tables['provider_services']['Row']
export type Booking = Tables['bookings']['Row']
export type Review = Tables['reviews']['Row']
export type Transaction = Tables['transactions']['Row']
export type Wallet = Tables['wallets']['Row']
export type Notification = Tables['notifications']['Row']
export type MtaaShare = Tables['mtaa_shares']['Row']
export type MtaaShareActivity = Tables['mtaa_share_activities']['Row']
export type ReferralHistory = Tables['referral_history']['Row']

// Insert types
export type UserInsert = Tables['users']['Insert']
export type ProfileInsert = Tables['profiles']['Insert']
export type ProviderProfileInsert = Tables['provider_profiles']['Insert']
export type ServiceCategoryInsert = Tables['service_categories']['Insert']
export type ServiceInsert = Tables['services']['Insert']
export type ProviderServiceInsert = Tables['provider_services']['Insert']
export type BookingInsert = Tables['bookings']['Insert']
export type ReviewInsert = Tables['reviews']['Insert']
export type TransactionInsert = Tables['transactions']['Insert']
export type WalletInsert = Tables['wallets']['Insert']
export type NotificationInsert = Tables['notifications']['Insert']
export type MtaaShareInsert = Tables['mtaa_shares']['Insert']
export type MtaaShareActivityInsert = Tables['mtaa_share_activities']['Insert']
export type ReferralHistoryInsert = Tables['referral_history']['Insert']

// Update types
export type UserUpdate = Tables['users']['Update']
export type ProfileUpdate = Tables['profiles']['Update']
export type ProviderProfileUpdate = Tables['provider_profiles']['Update']
export type ServiceCategoryUpdate = Tables['service_categories']['Update']
export type ServiceUpdate = Tables['services']['Update']
export type ProviderServiceUpdate = Tables['provider_services']['Update']
export type BookingUpdate = Tables['bookings']['Update']
export type ReviewUpdate = Tables['reviews']['Update']
export type TransactionUpdate = Tables['transactions']['Update']
export type WalletUpdate = Tables['wallets']['Update']
export type NotificationUpdate = Tables['notifications']['Update']
export type MtaaShareUpdate = Tables['mtaa_shares']['Update']
export type MtaaShareActivityUpdate = Tables['mtaa_share_activities']['Update']
export type ReferralHistoryUpdate = Tables['referral_history']['Update']

// View types
export type MtaaSharesLeaderboard = Views['mtaa_shares_leaderboard']['Row']
