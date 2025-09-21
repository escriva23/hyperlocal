// API Configuration
export const API_CONFIG = {
    TIMEOUT: 30000, // 30 seconds
    RETRY_ATTEMPTS: 3,
    RETRY_DELAY: 1000, // 1 second
} as const

// File Upload Limits
export const FILE_LIMITS = {
    MAX_IMAGE_SIZE_MB: 5,
    MAX_DOCUMENT_SIZE_MB: 10,
    ALLOWED_IMAGE_TYPES: ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif'],
    ALLOWED_DOCUMENT_TYPES: ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    MAX_IMAGES_PER_SERVICE: 5,
} as const

// Service Categories
export const SERVICE_CATEGORIES = [
    { id: 'cleaning', name: 'Cleaning', icon: '🧹' },
    { id: 'plumbing', name: 'Plumbing', icon: '🔧' },
    { id: 'electrical', name: 'Electrical', icon: '⚡' },
    { id: 'carpentry', name: 'Carpentry', icon: '🔨' },
    { id: 'painting', name: 'Painting', icon: '🎨' },
    { id: 'gardening', name: 'Gardening', icon: '🌱' },
    { id: 'tutoring', name: 'Tutoring', icon: '📚' },
    { id: 'fitness', name: 'Fitness', icon: '💪' },
    { id: 'beauty', name: 'Beauty', icon: '💄' },
    { id: 'tech-support', name: 'Tech Support', icon: '💻' },
    { id: 'delivery', name: 'Delivery', icon: '📦' },
    { id: 'other', name: 'Other', icon: '🔧' },
] as const

// User Roles
export const USER_ROLES = {
    CUSTOMER: 'customer',
    PROVIDER: 'provider',
    ADMIN: 'admin',
} as const

// Booking Status
export const BOOKING_STATUS = {
    PENDING: 'pending',
    CONFIRMED: 'confirmed',
    IN_PROGRESS: 'in_progress',
    COMPLETED: 'completed',
    CANCELLED: 'cancelled',
} as const

// Price Types
export const PRICE_TYPES = {
    FIXED: 'fixed',
    HOURLY: 'hourly',
    NEGOTIABLE: 'negotiable',
} as const

// Location Types
export const LOCATION_TYPES = {
    ON_SITE: 'on_site',
    REMOTE: 'remote',
    BOTH: 'both',
} as const

// Notification Types
export const NOTIFICATION_TYPES = {
    BOOKING: 'booking',
    PAYMENT: 'payment',
    REVIEW: 'review',
    SYSTEM: 'system',
    MESSAGE: 'message',
    REMINDER: 'reminder',
} as const

// Notification Priorities
export const NOTIFICATION_PRIORITIES = {
    LOW: 'low',
    MEDIUM: 'medium',
    HIGH: 'high',
} as const

// Transaction Types
export const TRANSACTION_TYPES = {
    PAYMENT: 'payment',
    PAYOUT: 'payout',
    REFUND: 'refund',
    FEE: 'fee',
    COMMISSION: 'commission',
} as const

// Transaction Status
export const TRANSACTION_STATUS = {
    PENDING: 'pending',
    COMPLETED: 'completed',
    FAILED: 'failed',
    CANCELLED: 'cancelled',
} as const

// Verification Status
export const VERIFICATION_STATUS = {
    PENDING: 'pending',
    VERIFIED: 'verified',
    REJECTED: 'rejected',
} as const

// Mtaa Shares Activity Types
export const MTAA_SHARES_ACTIVITY_TYPES = {
    EARNED: 'earned',
    REDEEMED: 'redeemed',
    BONUS: 'bonus',
    REFERRAL: 'referral',
} as const

// Referral Status
export const REFERRAL_STATUS = {
    PENDING: 'pending',
    COMPLETED: 'completed',
    CANCELLED: 'cancelled',
} as const

// Pagination Defaults
export const PAGINATION = {
    DEFAULT_PAGE_SIZE: 20,
    MAX_PAGE_SIZE: 100,
    DEFAULT_PAGE: 1,
} as const

// Search Defaults
export const SEARCH_DEFAULTS = {
    DEFAULT_RADIUS_KM: 50,
    MAX_RADIUS_KM: 200,
    MIN_RATING: 1,
    MAX_RATING: 5,
} as const

// Validation Limits
export const VALIDATION_LIMITS = {
    MIN_PASSWORD_LENGTH: 8,
    MAX_PASSWORD_LENGTH: 128,
    MIN_NAME_LENGTH: 2,
    MAX_NAME_LENGTH: 100,
    MIN_BUSINESS_NAME_LENGTH: 2,
    MAX_BUSINESS_NAME_LENGTH: 200,
    MIN_SERVICE_TITLE_LENGTH: 5,
    MAX_SERVICE_TITLE_LENGTH: 100,
    MIN_DESCRIPTION_LENGTH: 10,
    MAX_DESCRIPTION_LENGTH: 1000,
    MIN_PRICE: 0.01,
    MAX_PRICE: 1000000,
    MIN_DURATION_MINUTES: 15,
    MAX_DURATION_MINUTES: 1440, // 24 hours
    MIN_BOOKING_ADVANCE_MINUTES: 30,
} as const

// Date/Time Formats
export const DATE_FORMATS = {
    DISPLAY_DATE: 'MMMM d, yyyy',
    DISPLAY_TIME: 'h:mm a',
    DISPLAY_DATETIME: 'MMM d, yyyy h:mm a',
    ISO_DATE: 'yyyy-MM-dd',
    ISO_DATETIME: "yyyy-MM-dd'T'HH:mm:ss.SSSxxx",
} as const

// Currency
export const CURRENCY = {
    DEFAULT: 'KES',
    SYMBOL: 'KSh',
    LOCALE: 'en-KE',
} as const

// Map Configuration
export const MAP_CONFIG = {
    DEFAULT_ZOOM: 13,
    DEFAULT_CENTER: {
        lat: -1.286389, // Nairobi
        lng: 36.817223,
    },
    MARKER_COLORS: {
        CUSTOMER: '#3B82F6', // Blue
        PROVIDER: '#10B981', // Green
        SERVICE: '#F59E0B', // Yellow
    },
} as const

// Theme Colors
export const THEME_COLORS = {
    PRIMARY: '#3B82F6',
    SECONDARY: '#10B981',
    SUCCESS: '#22C55E',
    WARNING: '#F59E0B',
    ERROR: '#EF4444',
    INFO: '#06B6D4',
} as const

// Status Colors
export const STATUS_COLORS = {
    [BOOKING_STATUS.PENDING]: '#F59E0B',
    [BOOKING_STATUS.CONFIRMED]: '#3B82F6',
    [BOOKING_STATUS.IN_PROGRESS]: '#8B5CF6',
    [BOOKING_STATUS.COMPLETED]: '#22C55E',
    [BOOKING_STATUS.CANCELLED]: '#EF4444',
} as const

// Priority Colors
export const PRIORITY_COLORS = {
    [NOTIFICATION_PRIORITIES.LOW]: '#6B7280',
    [NOTIFICATION_PRIORITIES.MEDIUM]: '#F59E0B',
    [NOTIFICATION_PRIORITIES.HIGH]: '#EF4444',
} as const

// Rating Colors
export const RATING_COLORS = {
    1: '#EF4444', // Red
    2: '#F97316', // Orange
    3: '#F59E0B', // Yellow
    4: '#84CC16', // Lime
    5: '#22C55E', // Green
} as const

// Error Messages
export const ERROR_MESSAGES = {
    NETWORK_ERROR: 'Network error. Please check your connection and try again.',
    UNAUTHORIZED: 'You are not authorized to perform this action.',
    FORBIDDEN: 'Access denied.',
    NOT_FOUND: 'The requested resource was not found.',
    SERVER_ERROR: 'Server error. Please try again later.',
    VALIDATION_ERROR: 'Please check your input and try again.',
    TIMEOUT_ERROR: 'Request timed out. Please try again.',
} as const

// Success Messages
export const SUCCESS_MESSAGES = {
    BOOKING_CREATED: 'Booking created successfully!',
    BOOKING_UPDATED: 'Booking updated successfully!',
    BOOKING_CANCELLED: 'Booking cancelled successfully!',
    SERVICE_CREATED: 'Service created successfully!',
    SERVICE_UPDATED: 'Service updated successfully!',
    SERVICE_DELETED: 'Service deleted successfully!',
    PROFILE_UPDATED: 'Profile updated successfully!',
    PASSWORD_UPDATED: 'Password updated successfully!',
    NOTIFICATION_MARKED_READ: 'Notification marked as read!',
} as const

// Local Storage Keys
export const STORAGE_KEYS = {
    AUTH_TOKEN: 'hequeendo_auth_token',
    USER_DATA: 'hequeendo_user_data',
    THEME_PREFERENCE: 'hequeendo_theme',
    LANGUAGE_PREFERENCE: 'hequeendo_language',
    LOCATION_PERMISSION: 'hequeendo_location_permission',
    NOTIFICATION_PERMISSION: 'hequeendo_notification_permission',
} as const

// Feature Flags
export const FEATURE_FLAGS = {
    ENABLE_PUSH_NOTIFICATIONS: true,
    ENABLE_LOCATION_SERVICES: true,
    ENABLE_REAL_TIME_CHAT: true,
    ENABLE_MTAA_SHARES: true,
    ENABLE_REFERRAL_PROGRAM: true,
    ENABLE_ADVANCED_SEARCH: true,
} as const
