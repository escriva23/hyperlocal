export declare const API_CONFIG: {
    readonly TIMEOUT: 30000;
    readonly RETRY_ATTEMPTS: 3;
    readonly RETRY_DELAY: 1000;
};
export declare const FILE_LIMITS: {
    readonly MAX_IMAGE_SIZE_MB: 5;
    readonly MAX_DOCUMENT_SIZE_MB: 10;
    readonly ALLOWED_IMAGE_TYPES: readonly ["image/jpeg", "image/jpg", "image/png", "image/webp", "image/gif"];
    readonly ALLOWED_DOCUMENT_TYPES: readonly ["application/pdf", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"];
    readonly MAX_IMAGES_PER_SERVICE: 5;
};
export declare const SERVICE_CATEGORIES: readonly [{
    readonly id: "cleaning";
    readonly name: "Cleaning";
    readonly icon: "🧹";
}, {
    readonly id: "plumbing";
    readonly name: "Plumbing";
    readonly icon: "🔧";
}, {
    readonly id: "electrical";
    readonly name: "Electrical";
    readonly icon: "⚡";
}, {
    readonly id: "carpentry";
    readonly name: "Carpentry";
    readonly icon: "🔨";
}, {
    readonly id: "painting";
    readonly name: "Painting";
    readonly icon: "🎨";
}, {
    readonly id: "gardening";
    readonly name: "Gardening";
    readonly icon: "🌱";
}, {
    readonly id: "tutoring";
    readonly name: "Tutoring";
    readonly icon: "📚";
}, {
    readonly id: "fitness";
    readonly name: "Fitness";
    readonly icon: "💪";
}, {
    readonly id: "beauty";
    readonly name: "Beauty";
    readonly icon: "💄";
}, {
    readonly id: "tech-support";
    readonly name: "Tech Support";
    readonly icon: "💻";
}, {
    readonly id: "delivery";
    readonly name: "Delivery";
    readonly icon: "📦";
}, {
    readonly id: "other";
    readonly name: "Other";
    readonly icon: "🔧";
}];
export declare const USER_ROLES: {
    readonly CUSTOMER: "customer";
    readonly PROVIDER: "provider";
    readonly ADMIN: "admin";
};
export declare const BOOKING_STATUS: {
    readonly PENDING: "pending";
    readonly CONFIRMED: "confirmed";
    readonly IN_PROGRESS: "in_progress";
    readonly COMPLETED: "completed";
    readonly CANCELLED: "cancelled";
};
export declare const PRICE_TYPES: {
    readonly FIXED: "fixed";
    readonly HOURLY: "hourly";
    readonly NEGOTIABLE: "negotiable";
};
export declare const LOCATION_TYPES: {
    readonly ON_SITE: "on_site";
    readonly REMOTE: "remote";
    readonly BOTH: "both";
};
export declare const NOTIFICATION_TYPES: {
    readonly BOOKING: "booking";
    readonly PAYMENT: "payment";
    readonly REVIEW: "review";
    readonly SYSTEM: "system";
    readonly MESSAGE: "message";
    readonly REMINDER: "reminder";
};
export declare const NOTIFICATION_PRIORITIES: {
    readonly LOW: "low";
    readonly MEDIUM: "medium";
    readonly HIGH: "high";
};
export declare const TRANSACTION_TYPES: {
    readonly PAYMENT: "payment";
    readonly PAYOUT: "payout";
    readonly REFUND: "refund";
    readonly FEE: "fee";
    readonly COMMISSION: "commission";
};
export declare const TRANSACTION_STATUS: {
    readonly PENDING: "pending";
    readonly COMPLETED: "completed";
    readonly FAILED: "failed";
    readonly CANCELLED: "cancelled";
};
export declare const VERIFICATION_STATUS: {
    readonly PENDING: "pending";
    readonly VERIFIED: "verified";
    readonly REJECTED: "rejected";
};
export declare const MTAA_SHARES_ACTIVITY_TYPES: {
    readonly EARNED: "earned";
    readonly REDEEMED: "redeemed";
    readonly BONUS: "bonus";
    readonly REFERRAL: "referral";
};
export declare const REFERRAL_STATUS: {
    readonly PENDING: "pending";
    readonly COMPLETED: "completed";
    readonly CANCELLED: "cancelled";
};
export declare const PAGINATION: {
    readonly DEFAULT_PAGE_SIZE: 20;
    readonly MAX_PAGE_SIZE: 100;
    readonly DEFAULT_PAGE: 1;
};
export declare const SEARCH_DEFAULTS: {
    readonly DEFAULT_RADIUS_KM: 50;
    readonly MAX_RADIUS_KM: 200;
    readonly MIN_RATING: 1;
    readonly MAX_RATING: 5;
};
export declare const VALIDATION_LIMITS: {
    readonly MIN_PASSWORD_LENGTH: 8;
    readonly MAX_PASSWORD_LENGTH: 128;
    readonly MIN_NAME_LENGTH: 2;
    readonly MAX_NAME_LENGTH: 100;
    readonly MIN_BUSINESS_NAME_LENGTH: 2;
    readonly MAX_BUSINESS_NAME_LENGTH: 200;
    readonly MIN_SERVICE_TITLE_LENGTH: 5;
    readonly MAX_SERVICE_TITLE_LENGTH: 100;
    readonly MIN_DESCRIPTION_LENGTH: 10;
    readonly MAX_DESCRIPTION_LENGTH: 1000;
    readonly MIN_PRICE: 0.01;
    readonly MAX_PRICE: 1000000;
    readonly MIN_DURATION_MINUTES: 15;
    readonly MAX_DURATION_MINUTES: 1440;
    readonly MIN_BOOKING_ADVANCE_MINUTES: 30;
};
export declare const DATE_FORMATS: {
    readonly DISPLAY_DATE: "MMMM d, yyyy";
    readonly DISPLAY_TIME: "h:mm a";
    readonly DISPLAY_DATETIME: "MMM d, yyyy h:mm a";
    readonly ISO_DATE: "yyyy-MM-dd";
    readonly ISO_DATETIME: "yyyy-MM-dd'T'HH:mm:ss.SSSxxx";
};
export declare const CURRENCY: {
    readonly DEFAULT: "KES";
    readonly SYMBOL: "KSh";
    readonly LOCALE: "en-KE";
};
export declare const MAP_CONFIG: {
    readonly DEFAULT_ZOOM: 13;
    readonly DEFAULT_CENTER: {
        readonly lat: -1.286389;
        readonly lng: 36.817223;
    };
    readonly MARKER_COLORS: {
        readonly CUSTOMER: "#3B82F6";
        readonly PROVIDER: "#10B981";
        readonly SERVICE: "#F59E0B";
    };
};
export declare const THEME_COLORS: {
    readonly PRIMARY: "#3B82F6";
    readonly SECONDARY: "#10B981";
    readonly SUCCESS: "#22C55E";
    readonly WARNING: "#F59E0B";
    readonly ERROR: "#EF4444";
    readonly INFO: "#06B6D4";
};
export declare const STATUS_COLORS: {
    readonly pending: "#F59E0B";
    readonly confirmed: "#3B82F6";
    readonly in_progress: "#8B5CF6";
    readonly completed: "#22C55E";
    readonly cancelled: "#EF4444";
};
export declare const PRIORITY_COLORS: {
    readonly low: "#6B7280";
    readonly medium: "#F59E0B";
    readonly high: "#EF4444";
};
export declare const RATING_COLORS: {
    readonly 1: "#EF4444";
    readonly 2: "#F97316";
    readonly 3: "#F59E0B";
    readonly 4: "#84CC16";
    readonly 5: "#22C55E";
};
export declare const ERROR_MESSAGES: {
    readonly NETWORK_ERROR: "Network error. Please check your connection and try again.";
    readonly UNAUTHORIZED: "You are not authorized to perform this action.";
    readonly FORBIDDEN: "Access denied.";
    readonly NOT_FOUND: "The requested resource was not found.";
    readonly SERVER_ERROR: "Server error. Please try again later.";
    readonly VALIDATION_ERROR: "Please check your input and try again.";
    readonly TIMEOUT_ERROR: "Request timed out. Please try again.";
};
export declare const SUCCESS_MESSAGES: {
    readonly BOOKING_CREATED: "Booking created successfully!";
    readonly BOOKING_UPDATED: "Booking updated successfully!";
    readonly BOOKING_CANCELLED: "Booking cancelled successfully!";
    readonly SERVICE_CREATED: "Service created successfully!";
    readonly SERVICE_UPDATED: "Service updated successfully!";
    readonly SERVICE_DELETED: "Service deleted successfully!";
    readonly PROFILE_UPDATED: "Profile updated successfully!";
    readonly PASSWORD_UPDATED: "Password updated successfully!";
    readonly NOTIFICATION_MARKED_READ: "Notification marked as read!";
};
export declare const STORAGE_KEYS: {
    readonly AUTH_TOKEN: "hequeendo_auth_token";
    readonly USER_DATA: "hequeendo_user_data";
    readonly THEME_PREFERENCE: "hequeendo_theme";
    readonly LANGUAGE_PREFERENCE: "hequeendo_language";
    readonly LOCATION_PERMISSION: "hequeendo_location_permission";
    readonly NOTIFICATION_PERMISSION: "hequeendo_notification_permission";
};
export declare const FEATURE_FLAGS: {
    readonly ENABLE_PUSH_NOTIFICATIONS: true;
    readonly ENABLE_LOCATION_SERVICES: true;
    readonly ENABLE_REAL_TIME_CHAT: true;
    readonly ENABLE_MTAA_SHARES: true;
    readonly ENABLE_REFERRAL_PROGRAM: true;
    readonly ENABLE_ADVANCED_SEARCH: true;
};
