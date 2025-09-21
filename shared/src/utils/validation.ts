// Email validation
export const isValidEmail = (email: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return emailRegex.test(email)
}

// Phone validation (supports various formats)
export const isValidPhone = (phone: string): boolean => {
    const phoneRegex = /^[\+]?[1-9][\d]{0,15}$/
    return phoneRegex.test(phone.replace(/[\s\-\(\)]/g, ''))
}

// Password strength validation
export const validatePassword = (password: string): { isValid: boolean; errors: string[] } => {
    const errors: string[] = []

    if (password.length < 8) {
        errors.push('Password must be at least 8 characters long')
    }

    if (!/[A-Z]/.test(password)) {
        errors.push('Password must contain at least one uppercase letter')
    }

    if (!/[a-z]/.test(password)) {
        errors.push('Password must contain at least one lowercase letter')
    }

    if (!/\d/.test(password)) {
        errors.push('Password must contain at least one number')
    }

    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
        errors.push('Password must contain at least one special character')
    }

    return {
        isValid: errors.length === 0,
        errors
    }
}

// Price validation
export const isValidPrice = (price: number): boolean => {
    return price > 0 && price <= 1000000 && Number.isFinite(price)
}

// URL validation
export const isValidUrl = (url: string): boolean => {
    try {
        new URL(url)
        return true
    } catch {
        return false
    }
}

// Name validation
export const isValidName = (name: string): boolean => {
    return name.trim().length >= 2 && name.trim().length <= 100
}

// Business name validation
export const isValidBusinessName = (name: string): boolean => {
    return name.trim().length >= 2 && name.trim().length <= 200
}

// Service title validation
export const isValidServiceTitle = (title: string): boolean => {
    return title.trim().length >= 5 && title.trim().length <= 100
}

// Description validation
export const isValidDescription = (description: string, minLength: number = 10, maxLength: number = 1000): boolean => {
    const trimmed = description.trim()
    return trimmed.length >= minLength && trimmed.length <= maxLength
}

// Duration validation (in minutes)
export const isValidDuration = (duration: number): boolean => {
    return duration > 0 && duration <= 1440 && Number.isInteger(duration) // Max 24 hours
}

// Rating validation
export const isValidRating = (rating: number): boolean => {
    return rating >= 1 && rating <= 5 && Number.isInteger(rating)
}

// Coordinate validation
export const isValidCoordinate = (lat: number, lng: number): boolean => {
    return (
        lat >= -90 && lat <= 90 &&
        lng >= -180 && lng <= 180 &&
        Number.isFinite(lat) && Number.isFinite(lng)
    )
}

// File size validation (in bytes)
export const isValidFileSize = (size: number, maxSizeMB: number = 5): boolean => {
    const maxSizeBytes = maxSizeMB * 1024 * 1024
    return size > 0 && size <= maxSizeBytes
}

// Image file type validation
export const isValidImageType = (type: string): boolean => {
    const validTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif']
    return validTypes.includes(type.toLowerCase())
}

// Sanitize string input
export const sanitizeString = (input: string): string => {
    return input.trim().replace(/[<>]/g, '')
}

// Validate booking time (must be in the future)
export const isValidBookingTime = (bookingTime: string): boolean => {
    const bookingDate = new Date(bookingTime)
    const now = new Date()
    return bookingDate > now && bookingDate.getTime() - now.getTime() >= 30 * 60 * 1000 // At least 30 minutes in future
}

// Validate service category
export const isValidServiceCategory = (category: string): boolean => {
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
    ]
    return validCategories.includes(category.toLowerCase())
}

// Validate price type
export const isValidPriceType = (priceType: string): boolean => {
    return ['fixed', 'hourly', 'negotiable'].includes(priceType)
}

// Validate location type
export const isValidLocationType = (locationType: string): boolean => {
    return ['on_site', 'remote', 'both'].includes(locationType)
}

// Validate user role
export const isValidUserRole = (role: string): boolean => {
    return ['customer', 'provider', 'admin'].includes(role)
}

// Validate booking status
export const isValidBookingStatus = (status: string): boolean => {
    return ['pending', 'confirmed', 'in_progress', 'completed', 'cancelled'].includes(status)
}

// Validate notification type
export const isValidNotificationType = (type: string): boolean => {
    return ['booking', 'payment', 'review', 'system', 'message', 'reminder'].includes(type)
}

// Validate notification priority
export const isValidNotificationPriority = (priority: string): boolean => {
    return ['low', 'medium', 'high'].includes(priority)
}
