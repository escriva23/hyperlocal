"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatRelativeTime = exports.formatTime = exports.formatDate = exports.formatCurrency = exports.validatePassword = exports.validatePhone = exports.validateEmail = exports.SERVICE_CATEGORIES = exports.NOTIFICATION_TYPES = exports.LOCATION_TYPES = exports.PRICE_TYPES = exports.BOOKING_STATUS = exports.USER_ROLES = exports.dashboardService = exports.notificationService = exports.serviceService = exports.bookingService = exports.authService = exports.DashboardService = exports.NotificationService = exports.ServiceService = exports.BookingService = exports.AuthService = exports.createServiceRoleClient = exports.createSupabaseClient = exports.supabaseClient = void 0;
// Configuration
var supabase_1 = require("./config/supabase");
Object.defineProperty(exports, "supabaseClient", { enumerable: true, get: function () { return supabase_1.supabase; } });
Object.defineProperty(exports, "createSupabaseClient", { enumerable: true, get: function () { return supabase_1.createSupabaseClient; } });
Object.defineProperty(exports, "createServiceRoleClient", { enumerable: true, get: function () { return supabase_1.createServiceRoleClient; } });
// Types
__exportStar(require("./types/database.types"), exports);
__exportStar(require("./types/api.types"), exports);
// Services
const auth_service_1 = require("./services/auth.service");
Object.defineProperty(exports, "AuthService", { enumerable: true, get: function () { return auth_service_1.AuthService; } });
const booking_service_1 = require("./services/booking.service");
Object.defineProperty(exports, "BookingService", { enumerable: true, get: function () { return booking_service_1.BookingService; } });
const service_service_1 = require("./services/service.service");
Object.defineProperty(exports, "ServiceService", { enumerable: true, get: function () { return service_service_1.ServiceService; } });
const notification_service_1 = require("./services/notification.service");
Object.defineProperty(exports, "NotificationService", { enumerable: true, get: function () { return notification_service_1.NotificationService; } });
const dashboard_service_1 = require("./services/dashboard.service");
Object.defineProperty(exports, "DashboardService", { enumerable: true, get: function () { return dashboard_service_1.DashboardService; } });
// Service instances for direct use
const supabase_2 = require("./config/supabase");
exports.authService = new auth_service_1.AuthService(supabase_2.supabase);
exports.bookingService = new booking_service_1.BookingService(supabase_2.supabase);
exports.serviceService = new service_service_1.ServiceService(supabase_2.supabase);
exports.notificationService = new notification_service_1.NotificationService(supabase_2.supabase);
exports.dashboardService = new dashboard_service_1.DashboardService(supabase_2.supabase);
// Constants
exports.USER_ROLES = {
    CUSTOMER: 'customer',
    PROVIDER: 'provider',
    ADMIN: 'admin'
};
exports.BOOKING_STATUS = {
    PENDING: 'pending',
    CONFIRMED: 'confirmed',
    IN_PROGRESS: 'in_progress',
    COMPLETED: 'completed',
    CANCELLED: 'cancelled'
};
exports.PRICE_TYPES = {
    FIXED: 'fixed',
    HOURLY: 'hourly',
    DAILY: 'daily'
};
exports.LOCATION_TYPES = {
    ON_SITE: 'on_site',
    REMOTE: 'remote',
    HYBRID: 'hybrid'
};
exports.NOTIFICATION_TYPES = {
    BOOKING: 'booking',
    PAYMENT: 'payment',
    SYSTEM: 'system',
    PROMOTION: 'promotion'
};
exports.SERVICE_CATEGORIES = [
    'home_services',
    'automotive',
    'health_wellness',
    'education',
    'technology',
    'events',
    'business',
    'other'
];
// Utilities
const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};
exports.validateEmail = validateEmail;
const validatePhone = (phone) => {
    const phoneRegex = /^\+?[\d\s\-\(\)]{10,}$/;
    return phoneRegex.test(phone);
};
exports.validatePhone = validatePhone;
const validatePassword = (password) => {
    return password.length >= 8;
};
exports.validatePassword = validatePassword;
const formatCurrency = (amount, currency = 'KES') => {
    return new Intl.NumberFormat('en-KE', {
        style: 'currency',
        currency,
    }).format(amount);
};
exports.formatCurrency = formatCurrency;
const formatDate = (date) => {
    return new Intl.DateTimeFormat('en-KE', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
    }).format(new Date(date));
};
exports.formatDate = formatDate;
const formatTime = (date) => {
    return new Intl.DateTimeFormat('en-KE', {
        hour: '2-digit',
        minute: '2-digit',
    }).format(new Date(date));
};
exports.formatTime = formatTime;
const formatRelativeTime = (date) => {
    const now = new Date();
    const target = new Date(date);
    const diffInSeconds = Math.floor((now.getTime() - target.getTime()) / 1000);
    if (diffInSeconds < 60)
        return 'Just now';
    if (diffInSeconds < 3600)
        return `${Math.floor(diffInSeconds / 60)} minutes ago`;
    if (diffInSeconds < 86400)
        return `${Math.floor(diffInSeconds / 3600)} hours ago`;
    return (0, exports.formatDate)(date);
};
exports.formatRelativeTime = formatRelativeTime;
