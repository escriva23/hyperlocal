// API Response types
export interface ApiResponse<T> {
    data: T | null
    error: string | null
    success: boolean
}

export interface PaginatedResponse<T> {
    data: T[]
    count: number
    page: number
    limit: number
    totalPages: number
    hasNext: boolean
    hasPrev: boolean
}

export interface DashboardStats {
    total_bookings: number
    completed_bookings: number
    pending_reviews: number
    wallet_balance: number
    monthly_earnings?: number
    average_rating?: number
    total_services?: number
}

export interface SearchFilters {
    category?: string
    location?: string
    minPrice?: number
    maxPrice?: number
    rating?: number
    availability?: boolean
    priceType?: 'fixed' | 'hourly' | 'negotiable'
    sortBy?: 'price' | 'rating' | 'distance' | 'created_at'
    sortOrder?: 'asc' | 'desc'
}

export interface LocationCoordinates {
    latitude: number
    longitude: number
}

export interface ServiceSearchResult {
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
}

export interface ProviderSearchResult {
    provider_id: string
    business_name: string
    description: string | null
    average_rating: number | null
    total_reviews: number
    distance_km: number
    services: any[]
}

// Notification types
export interface CreateNotificationParams {
    user_id: string
    type: 'booking' | 'payment' | 'review' | 'system' | 'message' | 'reminder'
    title: string
    message: string
    priority?: 'low' | 'medium' | 'high'
    action_url?: string
    metadata?: Record<string, any>
}

export interface NotificationFilters {
    limit?: number
    offset?: number
    filter?: 'all' | 'unread' | 'booking' | 'payment' | 'system' | 'message' | 'review'
}

// Booking types
export interface BookingWithDetails {
    id: string
    customer_id: string
    provider_id: string
    service_id: string
    booking_time: string
    status: 'pending' | 'confirmed' | 'in_progress' | 'completed' | 'cancelled'
    price: number
    notes: string | null
    created_at: string
    updated_at: string
    service?: {
        name: string
        description: string | null
        category: string
    }
    provider?: {
        business_name: string
        user: {
            name: string
            email: string
            phone: string | null
        }
    }
    customer?: {
        user: {
            name: string
            email: string
            phone: string | null
        }
    }
}

// Review types
export interface ReviewWithDetails {
    id: string
    booking_id: string
    customer_id: string
    provider_id: string
    rating: number
    comment: string | null
    images: any[]
    helpful_count: number
    response: string | null
    response_at: string | null
    created_at: string
    updated_at: string
    customer?: {
        user: {
            name: string
            avatar_url: string | null
        }
    }
}

// Wallet and transaction types
export interface WalletBalance {
    balance: number
    pending_balance: number
    total_earned: number
    total_spent: number
}

export interface TransactionWithDetails {
    id: string
    user_id: string
    booking_id: string | null
    amount: number
    type: 'payment' | 'payout' | 'refund' | 'fee' | 'commission'
    status: 'pending' | 'completed' | 'failed' | 'cancelled'
    payment_method: string | null
    reference: string | null
    description: string | null
    created_at: string
    booking?: {
        service: {
            name: string
        }
    }
}

// Mtaa Shares types
export interface MtaaSharesOverview {
    total_shares: number
    current_value: number
    total_earned: number
    recent_activities: MtaaShareActivity[]
    leaderboard_position?: number
}

export interface MtaaShareActivity {
    id: string
    user_id: string
    activity_type: 'earned' | 'redeemed' | 'bonus' | 'referral'
    shares_amount: number
    description: string
    metadata: any
    created_at: string
}

// Error types
export interface ApiError {
    code: string
    message: string
    details?: any
}

// Auth types
export interface AuthUser {
    id: string
    email: string
    name: string
    role: 'customer' | 'provider' | 'admin'
    phone: string | null
    avatar_url: string | null
    is_verified: boolean
    is_active: boolean
}

export interface LoginCredentials {
    email: string
    password: string
}

export interface RegisterData {
    email: string
    password: string
    name: string
    role?: 'customer' | 'provider'
    phone?: string
}

// File upload types
export interface FileUploadResult {
    url: string
    path: string
    size: number
    type: string
}

// Real-time subscription types
export interface RealtimeSubscription {
    unsubscribe: () => void
}

export interface RealtimePayload<T = any> {
    eventType: 'INSERT' | 'UPDATE' | 'DELETE'
    new: T
    old: T
    errors: any[]
}

// Additional response types for backward compatibility
export interface Session {
    access_token: string
    refresh_token: string
    expires_in: number
    expires_at?: number
    token_type: string
    user: AuthUser
}

export interface AuthResponse {
    user: AuthUser | null
    session: Session | null
    error: string | null
}

export interface SignUpResponse extends AuthResponse { }

export interface SignInResponse extends AuthResponse { }

export interface BookingResponse extends ApiResponse<BookingWithDetails> { }

export interface BookingListResponse extends ApiResponse<BookingWithDetails[]> { }

export interface ServiceResponse extends ApiResponse<any> { }

export interface ServiceListResponse extends ApiResponse<any[]> { }

export interface NotificationResponse extends ApiResponse<any> { }

export interface DashboardStatsResponse extends ApiResponse<DashboardStats> { }
