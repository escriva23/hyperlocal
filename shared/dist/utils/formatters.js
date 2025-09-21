"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatBusinessHours = exports.formatAddress = exports.formatDistance = exports.formatNotificationPriority = exports.formatUserRole = exports.formatLocationType = exports.formatPriceType = exports.formatBookingStatus = exports.truncateText = exports.formatName = exports.formatPercentage = exports.formatRating = exports.formatFileSize = exports.formatDuration = exports.formatPhoneNumber = exports.formatRelativeTime = exports.formatDateTime = exports.formatTime = exports.formatDate = exports.formatKES = exports.formatCurrency = void 0;
// Currency formatting
const formatCurrency = (amount, currency = 'USD') => {
    return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: currency,
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
    }).format(amount);
};
exports.formatCurrency = formatCurrency;
// Kenyan Shilling formatting
const formatKES = (amount) => {
    return new Intl.NumberFormat('en-KE', {
        style: 'currency',
        currency: 'KES',
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
    }).format(amount);
};
exports.formatKES = formatKES;
// Date formatting
const formatDate = (date, options) => {
    const dateObj = typeof date === 'string' ? new Date(date) : date;
    const defaultOptions = {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    };
    return new Intl.DateTimeFormat('en-US', { ...defaultOptions, ...options }).format(dateObj);
};
exports.formatDate = formatDate;
// Time formatting
const formatTime = (date) => {
    const dateObj = typeof date === 'string' ? new Date(date) : date;
    return new Intl.DateTimeFormat('en-US', {
        hour: 'numeric',
        minute: '2-digit',
        hour12: true
    }).format(dateObj);
};
exports.formatTime = formatTime;
// DateTime formatting
const formatDateTime = (date) => {
    const dateObj = typeof date === 'string' ? new Date(date) : date;
    return new Intl.DateTimeFormat('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        hour12: true
    }).format(dateObj);
};
exports.formatDateTime = formatDateTime;
// Relative time formatting (e.g., "2 hours ago")
const formatRelativeTime = (date) => {
    const dateObj = typeof date === 'string' ? new Date(date) : date;
    const now = new Date();
    const diffInSeconds = Math.floor((now.getTime() - dateObj.getTime()) / 1000);
    if (diffInSeconds < 60) {
        return 'Just now';
    }
    const diffInMinutes = Math.floor(diffInSeconds / 60);
    if (diffInMinutes < 60) {
        return `${diffInMinutes} minute${diffInMinutes === 1 ? '' : 's'} ago`;
    }
    const diffInHours = Math.floor(diffInMinutes / 60);
    if (diffInHours < 24) {
        return `${diffInHours} hour${diffInHours === 1 ? '' : 's'} ago`;
    }
    const diffInDays = Math.floor(diffInHours / 24);
    if (diffInDays < 7) {
        return `${diffInDays} day${diffInDays === 1 ? '' : 's'} ago`;
    }
    const diffInWeeks = Math.floor(diffInDays / 7);
    if (diffInWeeks < 4) {
        return `${diffInWeeks} week${diffInWeeks === 1 ? '' : 's'} ago`;
    }
    const diffInMonths = Math.floor(diffInDays / 30);
    if (diffInMonths < 12) {
        return `${diffInMonths} month${diffInMonths === 1 ? '' : 's'} ago`;
    }
    const diffInYears = Math.floor(diffInDays / 365);
    return `${diffInYears} year${diffInYears === 1 ? '' : 's'} ago`;
};
exports.formatRelativeTime = formatRelativeTime;
// Phone number formatting
const formatPhoneNumber = (phone) => {
    const cleaned = phone.replace(/\D/g, '');
    // Kenyan format
    if (cleaned.startsWith('254')) {
        return `+${cleaned.slice(0, 3)} ${cleaned.slice(3, 6)} ${cleaned.slice(6, 9)} ${cleaned.slice(9)}`;
    }
    // US format
    if (cleaned.length === 10) {
        return `(${cleaned.slice(0, 3)}) ${cleaned.slice(3, 6)}-${cleaned.slice(6)}`;
    }
    // International format
    if (cleaned.length > 10) {
        return `+${cleaned.slice(0, -10)} ${cleaned.slice(-10, -7)} ${cleaned.slice(-7, -4)} ${cleaned.slice(-4)}`;
    }
    return phone;
};
exports.formatPhoneNumber = formatPhoneNumber;
// Duration formatting (minutes to human readable)
const formatDuration = (minutes) => {
    if (minutes < 60) {
        return `${minutes} min${minutes === 1 ? '' : 's'}`;
    }
    const hours = Math.floor(minutes / 60);
    const remainingMinutes = minutes % 60;
    if (remainingMinutes === 0) {
        return `${hours} hour${hours === 1 ? '' : 's'}`;
    }
    return `${hours}h ${remainingMinutes}m`;
};
exports.formatDuration = formatDuration;
// File size formatting
const formatFileSize = (bytes) => {
    if (bytes === 0)
        return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};
exports.formatFileSize = formatFileSize;
// Rating formatting (with stars)
const formatRating = (rating) => {
    const fullStars = Math.floor(rating);
    const hasHalfStar = rating % 1 >= 0.5;
    const emptyStars = 5 - fullStars - (hasHalfStar ? 1 : 0);
    return '★'.repeat(fullStars) + (hasHalfStar ? '☆' : '') + '☆'.repeat(emptyStars);
};
exports.formatRating = formatRating;
// Percentage formatting
const formatPercentage = (value, total) => {
    if (total === 0)
        return '0%';
    const percentage = (value / total) * 100;
    return `${Math.round(percentage)}%`;
};
exports.formatPercentage = formatPercentage;
// Name formatting (capitalize first letter of each word)
const formatName = (name) => {
    return name
        .toLowerCase()
        .split(' ')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
};
exports.formatName = formatName;
// Truncate text with ellipsis
const truncateText = (text, maxLength) => {
    if (text.length <= maxLength)
        return text;
    return text.slice(0, maxLength - 3) + '...';
};
exports.truncateText = truncateText;
// Format booking status for display
const formatBookingStatus = (status) => {
    const statusMap = {
        'pending': 'Pending',
        'confirmed': 'Confirmed',
        'in_progress': 'In Progress',
        'completed': 'Completed',
        'cancelled': 'Cancelled'
    };
    return statusMap[status] || status;
};
exports.formatBookingStatus = formatBookingStatus;
// Format price type for display
const formatPriceType = (priceType) => {
    const typeMap = {
        'fixed': 'Fixed Price',
        'hourly': 'Per Hour',
        'negotiable': 'Negotiable'
    };
    return typeMap[priceType] || priceType;
};
exports.formatPriceType = formatPriceType;
// Format location type for display
const formatLocationType = (locationType) => {
    const typeMap = {
        'on_site': 'On-site',
        'remote': 'Remote',
        'both': 'On-site & Remote'
    };
    return typeMap[locationType] || locationType;
};
exports.formatLocationType = formatLocationType;
// Format user role for display
const formatUserRole = (role) => {
    const roleMap = {
        'customer': 'Customer',
        'provider': 'Service Provider',
        'admin': 'Administrator'
    };
    return roleMap[role] || role;
};
exports.formatUserRole = formatUserRole;
// Format notification priority for display
const formatNotificationPriority = (priority) => {
    const priorityMap = {
        'low': 'Low Priority',
        'medium': 'Medium Priority',
        'high': 'High Priority'
    };
    return priorityMap[priority] || priority;
};
exports.formatNotificationPriority = formatNotificationPriority;
// Format distance
const formatDistance = (distanceKm) => {
    if (distanceKm < 1) {
        return `${Math.round(distanceKm * 1000)}m`;
    }
    if (distanceKm < 10) {
        return `${distanceKm.toFixed(1)}km`;
    }
    return `${Math.round(distanceKm)}km`;
};
exports.formatDistance = formatDistance;
// Format address (truncate long addresses)
const formatAddress = (address, maxLength = 50) => {
    return (0, exports.truncateText)(address, maxLength);
};
exports.formatAddress = formatAddress;
// Format business hours
const formatBusinessHours = (openTime, closeTime) => {
    return `${(0, exports.formatTime)(openTime)} - ${(0, exports.formatTime)(closeTime)}`;
};
exports.formatBusinessHours = formatBusinessHours;
