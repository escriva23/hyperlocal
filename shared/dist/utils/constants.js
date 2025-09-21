"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FEATURE_FLAGS = exports.STORAGE_KEYS = exports.SUCCESS_MESSAGES = exports.ERROR_MESSAGES = exports.RATING_COLORS = exports.PRIORITY_COLORS = exports.STATUS_COLORS = exports.THEME_COLORS = exports.MAP_CONFIG = exports.CURRENCY = exports.DATE_FORMATS = exports.VALIDATION_LIMITS = exports.SEARCH_DEFAULTS = exports.PAGINATION = exports.REFERRAL_STATUS = exports.MTAA_SHARES_ACTIVITY_TYPES = exports.VERIFICATION_STATUS = exports.TRANSACTION_STATUS = exports.TRANSACTION_TYPES = exports.NOTIFICATION_PRIORITIES = exports.NOTIFICATION_TYPES = exports.LOCATION_TYPES = exports.PRICE_TYPES = exports.BOOKING_STATUS = exports.USER_ROLES = exports.SERVICE_CATEGORIES = exports.FILE_LIMITS = exports.API_CONFIG = void 0;
// API Configuration
exports.API_CONFIG = {
    TIMEOUT: 30000, // 30 seconds
    RETRY_ATTEMPTS: 3,
    RETRY_DELAY: 1000, // 1 second
};
// File Upload Limits
exports.FILE_LIMITS = {
    MAX_IMAGE_SIZE_MB: 5,
    MAX_DOCUMENT_SIZE_MB: 10,
    ALLOWED_IMAGE_TYPES: ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif'],
    ALLOWED_DOCUMENT_TYPES: ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    MAX_IMAGES_PER_SERVICE: 5,
};
// Service Categories
exports.SERVICE_CATEGORIES = [
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
];
// User Roles
exports.USER_ROLES = {
    CUSTOMER: 'customer',
    PROVIDER: 'provider',
    ADMIN: 'admin',
};
// Booking Status
exports.BOOKING_STATUS = {
    PENDING: 'pending',
    CONFIRMED: 'confirmed',
    IN_PROGRESS: 'in_progress',
    COMPLETED: 'completed',
    CANCELLED: 'cancelled',
};
// Price Types
exports.PRICE_TYPES = {
    FIXED: 'fixed',
    HOURLY: 'hourly',
    NEGOTIABLE: 'negotiable',
};
// Location Types
exports.LOCATION_TYPES = {
    ON_SITE: 'on_site',
    REMOTE: 'remote',
    BOTH: 'both',
};
// Notification Types
exports.NOTIFICATION_TYPES = {
    BOOKING: 'booking',
    PAYMENT: 'payment',
    REVIEW: 'review',
    SYSTEM: 'system',
    MESSAGE: 'message',
    REMINDER: 'reminder',
};
// Notification Priorities
exports.NOTIFICATION_PRIORITIES = {
    LOW: 'low',
    MEDIUM: 'medium',
    HIGH: 'high',
};
// Transaction Types
exports.TRANSACTION_TYPES = {
    PAYMENT: 'payment',
    PAYOUT: 'payout',
    REFUND: 'refund',
    FEE: 'fee',
    COMMISSION: 'commission',
};
// Transaction Status
exports.TRANSACTION_STATUS = {
    PENDING: 'pending',
    COMPLETED: 'completed',
    FAILED: 'failed',
    CANCELLED: 'cancelled',
};
// Verification Status
exports.VERIFICATION_STATUS = {
    PENDING: 'pending',
    VERIFIED: 'verified',
    REJECTED: 'rejected',
};
// Mtaa Shares Activity Types
exports.MTAA_SHARES_ACTIVITY_TYPES = {
    EARNED: 'earned',
    REDEEMED: 'redeemed',
    BONUS: 'bonus',
    REFERRAL: 'referral',
};
// Referral Status
exports.REFERRAL_STATUS = {
    PENDING: 'pending',
    COMPLETED: 'completed',
    CANCELLED: 'cancelled',
};
// Pagination Defaults
exports.PAGINATION = {
    DEFAULT_PAGE_SIZE: 20,
    MAX_PAGE_SIZE: 100,
    DEFAULT_PAGE: 1,
};
// Search Defaults
exports.SEARCH_DEFAULTS = {
    DEFAULT_RADIUS_KM: 50,
    MAX_RADIUS_KM: 200,
    MIN_RATING: 1,
    MAX_RATING: 5,
};
// Validation Limits
exports.VALIDATION_LIMITS = {
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
};
// Date/Time Formats
exports.DATE_FORMATS = {
    DISPLAY_DATE: 'MMMM d, yyyy',
    DISPLAY_TIME: 'h:mm a',
    DISPLAY_DATETIME: 'MMM d, yyyy h:mm a',
    ISO_DATE: 'yyyy-MM-dd',
    ISO_DATETIME: "yyyy-MM-dd'T'HH:mm:ss.SSSxxx",
};
// Currency
exports.CURRENCY = {
    DEFAULT: 'KES',
    SYMBOL: 'KSh',
    LOCALE: 'en-KE',
};
// Map Configuration
exports.MAP_CONFIG = {
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
};
// Theme Colors
exports.THEME_COLORS = {
    PRIMARY: '#3B82F6',
    SECONDARY: '#10B981',
    SUCCESS: '#22C55E',
    WARNING: '#F59E0B',
    ERROR: '#EF4444',
    INFO: '#06B6D4',
};
// Status Colors
exports.STATUS_COLORS = {
    [exports.BOOKING_STATUS.PENDING]: '#F59E0B',
    [exports.BOOKING_STATUS.CONFIRMED]: '#3B82F6',
    [exports.BOOKING_STATUS.IN_PROGRESS]: '#8B5CF6',
    [exports.BOOKING_STATUS.COMPLETED]: '#22C55E',
    [exports.BOOKING_STATUS.CANCELLED]: '#EF4444',
};
// Priority Colors
exports.PRIORITY_COLORS = {
    [exports.NOTIFICATION_PRIORITIES.LOW]: '#6B7280',
    [exports.NOTIFICATION_PRIORITIES.MEDIUM]: '#F59E0B',
    [exports.NOTIFICATION_PRIORITIES.HIGH]: '#EF4444',
};
// Rating Colors
exports.RATING_COLORS = {
    1: '#EF4444', // Red
    2: '#F97316', // Orange
    3: '#F59E0B', // Yellow
    4: '#84CC16', // Lime
    5: '#22C55E', // Green
};
// Error Messages
exports.ERROR_MESSAGES = {
    NETWORK_ERROR: 'Network error. Please check your connection and try again.',
    UNAUTHORIZED: 'You are not authorized to perform this action.',
    FORBIDDEN: 'Access denied.',
    NOT_FOUND: 'The requested resource was not found.',
    SERVER_ERROR: 'Server error. Please try again later.',
    VALIDATION_ERROR: 'Please check your input and try again.',
    TIMEOUT_ERROR: 'Request timed out. Please try again.',
};
// Success Messages
exports.SUCCESS_MESSAGES = {
    BOOKING_CREATED: 'Booking created successfully!',
    BOOKING_UPDATED: 'Booking updated successfully!',
    BOOKING_CANCELLED: 'Booking cancelled successfully!',
    SERVICE_CREATED: 'Service created successfully!',
    SERVICE_UPDATED: 'Service updated successfully!',
    SERVICE_DELETED: 'Service deleted successfully!',
    PROFILE_UPDATED: 'Profile updated successfully!',
    PASSWORD_UPDATED: 'Password updated successfully!',
    NOTIFICATION_MARKED_READ: 'Notification marked as read!',
};
// Local Storage Keys
exports.STORAGE_KEYS = {
    AUTH_TOKEN: 'hequeendo_auth_token',
    USER_DATA: 'hequeendo_user_data',
    THEME_PREFERENCE: 'hequeendo_theme',
    LANGUAGE_PREFERENCE: 'hequeendo_language',
    LOCATION_PERMISSION: 'hequeendo_location_permission',
    NOTIFICATION_PERMISSION: 'hequeendo_notification_permission',
};
// Feature Flags
exports.FEATURE_FLAGS = {
    ENABLE_PUSH_NOTIFICATIONS: true,
    ENABLE_LOCATION_SERVICES: true,
    ENABLE_REAL_TIME_CHAT: true,
    ENABLE_MTAA_SHARES: true,
    ENABLE_REFERRAL_PROGRAM: true,
    ENABLE_ADVANCED_SEARCH: true,
};
