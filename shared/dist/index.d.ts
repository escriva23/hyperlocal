export { supabase as supabaseClient, createSupabaseClient, createServiceRoleClient } from './config/supabase';
export * from './types/database.types';
export * from './types/api.types';
import { AuthService } from './services/auth.service';
import { BookingService } from './services/booking.service';
import { ServiceService } from './services/service.service';
import { NotificationService } from './services/notification.service';
import { DashboardService } from './services/dashboard.service';
export { AuthService, BookingService, ServiceService, NotificationService, DashboardService };
export declare const authService: AuthService;
export declare const bookingService: BookingService;
export declare const serviceService: ServiceService;
export declare const notificationService: NotificationService;
export declare const dashboardService: DashboardService;
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
    readonly DAILY: "daily";
};
export declare const LOCATION_TYPES: {
    readonly ON_SITE: "on_site";
    readonly REMOTE: "remote";
    readonly HYBRID: "hybrid";
};
export declare const NOTIFICATION_TYPES: {
    readonly BOOKING: "booking";
    readonly PAYMENT: "payment";
    readonly SYSTEM: "system";
    readonly PROMOTION: "promotion";
};
export declare const SERVICE_CATEGORIES: readonly ["home_services", "automotive", "health_wellness", "education", "technology", "events", "business", "other"];
export declare const validateEmail: (email: string) => boolean;
export declare const validatePhone: (phone: string) => boolean;
export declare const validatePassword: (password: string) => boolean;
export declare const formatCurrency: (amount: number, currency?: string) => string;
export declare const formatDate: (date: string | Date) => string;
export declare const formatTime: (date: string | Date) => string;
export declare const formatRelativeTime: (date: string | Date) => string;
export type { User, Profile, ProviderProfile, Service, ProviderService, Booking, Review, Transaction, Wallet, Notification, ServiceCategory, MtaaShare, MtaaShareActivity, ReferralHistory } from './types/database.types';
export type { ApiResponse, DashboardStats, SearchFilters, LocationCoordinates, BookingWithDetails, ReviewWithDetails, AuthUser, LoginCredentials, RegisterData, Session, AuthResponse, SignUpResponse, SignInResponse, BookingResponse, BookingListResponse, ServiceResponse, ServiceListResponse, NotificationResponse, DashboardStatsResponse } from './types/api.types';
