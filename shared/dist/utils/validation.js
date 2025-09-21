"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isValidNotificationPriority = exports.isValidNotificationType = exports.isValidBookingStatus = exports.isValidUserRole = exports.isValidLocationType = exports.isValidPriceType = exports.isValidServiceCategory = exports.isValidBookingTime = exports.sanitizeString = exports.isValidImageType = exports.isValidFileSize = exports.isValidCoordinate = exports.isValidRating = exports.isValidDuration = exports.isValidDescription = exports.isValidServiceTitle = exports.isValidBusinessName = exports.isValidName = exports.isValidUrl = exports.isValidPrice = exports.validatePassword = exports.isValidPhone = exports.isValidEmail = void 0;
// Email validation
const isValidEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};
exports.isValidEmail = isValidEmail;
// Phone validation (supports various formats)
const isValidPhone = (phone) => {
    const phoneRegex = /^[\+]?[1-9][\d]{0,15}$/;
    return phoneRegex.test(phone.replace(/[\s\-\(\)]/g, ''));
};
exports.isValidPhone = isValidPhone;
// Password strength validation
const validatePassword = (password) => {
    const errors = [];
    if (password.length < 8) {
        errors.push('Password must be at least 8 characters long');
    }
    if (!/[A-Z]/.test(password)) {
        errors.push('Password must contain at least one uppercase letter');
    }
    if (!/[a-z]/.test(password)) {
        errors.push('Password must contain at least one lowercase letter');
    }
    if (!/\d/.test(password)) {
        errors.push('Password must contain at least one number');
    }
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
        errors.push('Password must contain at least one special character');
    }
    return {
        isValid: errors.length === 0,
        errors
    };
};
exports.validatePassword = validatePassword;
// Price validation
const isValidPrice = (price) => {
    return price > 0 && price <= 1000000 && Number.isFinite(price);
};
exports.isValidPrice = isValidPrice;
// URL validation
const isValidUrl = (url) => {
    try {
        new URL(url);
        return true;
    }
    catch {
        return false;
    }
};
exports.isValidUrl = isValidUrl;
// Name validation
const isValidName = (name) => {
    return name.trim().length >= 2 && name.trim().length <= 100;
};
exports.isValidName = isValidName;
// Business name validation
const isValidBusinessName = (name) => {
    return name.trim().length >= 2 && name.trim().length <= 200;
};
exports.isValidBusinessName = isValidBusinessName;
// Service title validation
const isValidServiceTitle = (title) => {
    return title.trim().length >= 5 && title.trim().length <= 100;
};
exports.isValidServiceTitle = isValidServiceTitle;
// Description validation
const isValidDescription = (description, minLength = 10, maxLength = 1000) => {
    const trimmed = description.trim();
    return trimmed.length >= minLength && trimmed.length <= maxLength;
};
exports.isValidDescription = isValidDescription;
// Duration validation (in minutes)
const isValidDuration = (duration) => {
    return duration > 0 && duration <= 1440 && Number.isInteger(duration); // Max 24 hours
};
exports.isValidDuration = isValidDuration;
// Rating validation
const isValidRating = (rating) => {
    return rating >= 1 && rating <= 5 && Number.isInteger(rating);
};
exports.isValidRating = isValidRating;
// Coordinate validation
const isValidCoordinate = (lat, lng) => {
    return (lat >= -90 && lat <= 90 &&
        lng >= -180 && lng <= 180 &&
        Number.isFinite(lat) && Number.isFinite(lng));
};
exports.isValidCoordinate = isValidCoordinate;
// File size validation (in bytes)
const isValidFileSize = (size, maxSizeMB = 5) => {
    const maxSizeBytes = maxSizeMB * 1024 * 1024;
    return size > 0 && size <= maxSizeBytes;
};
exports.isValidFileSize = isValidFileSize;
// Image file type validation
const isValidImageType = (type) => {
    const validTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif'];
    return validTypes.includes(type.toLowerCase());
};
exports.isValidImageType = isValidImageType;
// Sanitize string input
const sanitizeString = (input) => {
    return input.trim().replace(/[<>]/g, '');
};
exports.sanitizeString = sanitizeString;
// Validate booking time (must be in the future)
const isValidBookingTime = (bookingTime) => {
    const bookingDate = new Date(bookingTime);
    const now = new Date();
    return bookingDate > now && bookingDate.getTime() - now.getTime() >= 30 * 60 * 1000; // At least 30 minutes in future
};
exports.isValidBookingTime = isValidBookingTime;
// Validate service category
const isValidServiceCategory = (category) => {
    const validCategories = [
        'cleaning',
        'plumbing',
        'electrical',
        'carpentry',
        'painting',
        'gardening',
        'tutoring',
        'fitness',
        'beauty',
        'tech-support',
        'delivery',
        'other'
    ];
    return validCategories.includes(category.toLowerCase());
};
exports.isValidServiceCategory = isValidServiceCategory;
// Validate price type
const isValidPriceType = (priceType) => {
    return ['fixed', 'hourly', 'negotiable'].includes(priceType);
};
exports.isValidPriceType = isValidPriceType;
// Validate location type
const isValidLocationType = (locationType) => {
    return ['on_site', 'remote', 'both'].includes(locationType);
};
exports.isValidLocationType = isValidLocationType;
// Validate user role
const isValidUserRole = (role) => {
    return ['customer', 'provider', 'admin'].includes(role);
};
exports.isValidUserRole = isValidUserRole;
// Validate booking status
const isValidBookingStatus = (status) => {
    return ['pending', 'confirmed', 'in_progress', 'completed', 'cancelled'].includes(status);
};
exports.isValidBookingStatus = isValidBookingStatus;
// Validate notification type
const isValidNotificationType = (type) => {
    return ['booking', 'payment', 'review', 'system', 'message', 'reminder'].includes(type);
};
exports.isValidNotificationType = isValidNotificationType;
// Validate notification priority
const isValidNotificationPriority = (priority) => {
    return ['low', 'medium', 'high'].includes(priority);
};
exports.isValidNotificationPriority = isValidNotificationPriority;
