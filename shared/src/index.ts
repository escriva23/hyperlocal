// Configuration
export { supabase as supabaseClient, createSupabaseClient, createServiceRoleClient } from './config/supabase'

// Types
export * from './types/database.types'
export * from './types/api.types'

// Services
import { AuthService } from './services/auth.service'
import { BookingService } from './services/booking.service'
import { ServiceService } from './services/service.service'
import { NotificationService } from './services/notification.service'
import { DashboardService } from './services/dashboard.service'

export { AuthService, BookingService, ServiceService, NotificationService, DashboardService }

// Service instances for direct use
import { supabase } from './config/supabase'
export const authService = new AuthService(supabase)
export const bookingService = new BookingService(supabase)
export const serviceService = new ServiceService(supabase)
export const notificationService = new NotificationService(supabase)
export const dashboardService = new DashboardService(supabase)

// Constants
export const USER_ROLES = {
    CUSTOMER: 'customer',
    PROVIDER: 'provider',
    ADMIN: 'admin'
} as const

export const BOOKING_STATUS = {
    PENDING: 'pending',
    CONFIRMED: 'confirmed',
    IN_PROGRESS: 'in_progress',
    COMPLETED: 'completed',
    CANCELLED: 'cancelled'
} as const

export const PRICE_TYPES = {
    FIXED: 'fixed',
    HOURLY: 'hourly',
    DAILY: 'daily'
} as const

export const LOCATION_TYPES = {
    ON_SITE: 'on_site',
    REMOTE: 'remote',
    HYBRID: 'hybrid'
} as const

export const NOTIFICATION_TYPES = {
    BOOKING: 'booking',
    PAYMENT: 'payment',
    SYSTEM: 'system',
    PROMOTION: 'promotion'
} as const

export const SERVICE_CATEGORIES = [
    'home_services',
    'automotive',
    'health_wellness',
    'education',
    'technology',
    'events',
    'business',
    'other'
] as const

// Utilities
export const validateEmail = (email: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return emailRegex.test(email)
}

export const validatePhone = (phone: string): boolean => {
    const phoneRegex = /^\+?[\d\s\-\(\)]{10,}$/
    return phoneRegex.test(phone)
}

export const validatePassword = (password: string): boolean => {
    return password.length >= 8
}

export const formatCurrency = (amount: number, currency = 'KES'): string => {
    return new Intl.NumberFormat('en-KE', {
        style: 'currency',
        currency,
    }).format(amount)
}

export const formatDate = (date: string | Date): string => {
    return new Intl.DateTimeFormat('en-KE', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
    }).format(new Date(date))
}

export const formatTime = (date: string | Date): string => {
    return new Intl.DateTimeFormat('en-KE', {
        hour: '2-digit',
        minute: '2-digit',
    }).format(new Date(date))
}

export const formatRelativeTime = (date: string | Date): string => {
    const now = new Date()
    const target = new Date(date)
    const diffInSeconds = Math.floor((now.getTime() - target.getTime()) / 1000)

    if (diffInSeconds < 60) return 'Just now'
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} minutes ago`
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`
    return formatDate(date)
}

// Re-export commonly used types for convenience
export type {
    User,
    Profile,
    ProviderProfile,
    Service,
    ProviderService,
    Booking,
    Review,
    Transaction,
    Wallet,
    Notification,
    ServiceCategory,
    MtaaShare,
    MtaaShareActivity,
    ReferralHistory
} from './types/database.types'

export type {
    ApiResponse,
    DashboardStats,
    SearchFilters,
    LocationCoordinates,
    BookingWithDetails,
    ReviewWithDetails,
    AuthUser,
    LoginCredentials,
    RegisterData,
    Session,
    AuthResponse,
    SignUpResponse,
    SignInResponse,
    BookingResponse,
    BookingListResponse,
    ServiceResponse,
    ServiceListResponse,
    NotificationResponse,
    DashboardStatsResponse
} from './types/api.types'
