// Currency formatting
export const formatCurrency = (amount: number, currency: string = 'USD'): string => {
    return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: currency,
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
    }).format(amount)
}

// Kenyan Shilling formatting
export const formatKES = (amount: number): string => {
    return new Intl.NumberFormat('en-KE', {
        style: 'currency',
        currency: 'KES',
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
    }).format(amount)
}

// Date formatting
export const formatDate = (date: string | Date, options?: Intl.DateTimeFormatOptions): string => {
    const dateObj = typeof date === 'string' ? new Date(date) : date

    const defaultOptions: Intl.DateTimeFormatOptions = {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    }

    return new Intl.DateTimeFormat('en-US', { ...defaultOptions, ...options }).format(dateObj)
}

// Time formatting
export const formatTime = (date: string | Date): string => {
    const dateObj = typeof date === 'string' ? new Date(date) : date

    return new Intl.DateTimeFormat('en-US', {
        hour: 'numeric',
        minute: '2-digit',
        hour12: true
    }).format(dateObj)
}

// DateTime formatting
export const formatDateTime = (date: string | Date): string => {
    const dateObj = typeof date === 'string' ? new Date(date) : date

    return new Intl.DateTimeFormat('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        hour12: true
    }).format(dateObj)
}

// Relative time formatting (e.g., "2 hours ago")
export const formatRelativeTime = (date: string | Date): string => {
    const dateObj = typeof date === 'string' ? new Date(date) : date
    const now = new Date()
    const diffInSeconds = Math.floor((now.getTime() - dateObj.getTime()) / 1000)

    if (diffInSeconds < 60) {
        return 'Just now'
    }

    const diffInMinutes = Math.floor(diffInSeconds / 60)
    if (diffInMinutes < 60) {
        return `${diffInMinutes} minute${diffInMinutes === 1 ? '' : 's'} ago`
    }

    const diffInHours = Math.floor(diffInMinutes / 60)
    if (diffInHours < 24) {
        return `${diffInHours} hour${diffInHours === 1 ? '' : 's'} ago`
    }

    const diffInDays = Math.floor(diffInHours / 24)
    if (diffInDays < 7) {
        return `${diffInDays} day${diffInDays === 1 ? '' : 's'} ago`
    }

    const diffInWeeks = Math.floor(diffInDays / 7)
    if (diffInWeeks < 4) {
        return `${diffInWeeks} week${diffInWeeks === 1 ? '' : 's'} ago`
    }

    const diffInMonths = Math.floor(diffInDays / 30)
    if (diffInMonths < 12) {
        return `${diffInMonths} month${diffInMonths === 1 ? '' : 's'} ago`
    }

    const diffInYears = Math.floor(diffInDays / 365)
    return `${diffInYears} year${diffInYears === 1 ? '' : 's'} ago`
}

// Phone number formatting
export const formatPhoneNumber = (phone: string): string => {
    const cleaned = phone.replace(/\D/g, '')

    // Kenyan format
    if (cleaned.startsWith('254')) {
        return `+${cleaned.slice(0, 3)} ${cleaned.slice(3, 6)} ${cleaned.slice(6, 9)} ${cleaned.slice(9)}`
    }

    // US format
    if (cleaned.length === 10) {
        return `(${cleaned.slice(0, 3)}) ${cleaned.slice(3, 6)}-${cleaned.slice(6)}`
    }

    // International format
    if (cleaned.length > 10) {
        return `+${cleaned.slice(0, -10)} ${cleaned.slice(-10, -7)} ${cleaned.slice(-7, -4)} ${cleaned.slice(-4)}`
    }

    return phone
}

// Duration formatting (minutes to human readable)
export const formatDuration = (minutes: number): string => {
    if (minutes < 60) {
        return `${minutes} min${minutes === 1 ? '' : 's'}`
    }

    const hours = Math.floor(minutes / 60)
    const remainingMinutes = minutes % 60

    if (remainingMinutes === 0) {
        return `${hours} hour${hours === 1 ? '' : 's'}`
    }

    return `${hours}h ${remainingMinutes}m`
}

// File size formatting
export const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes'

    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))

    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

// Rating formatting (with stars)
export const formatRating = (rating: number): string => {
    const fullStars = Math.floor(rating)
    const hasHalfStar = rating % 1 >= 0.5
    const emptyStars = 5 - fullStars - (hasHalfStar ? 1 : 0)

    return '★'.repeat(fullStars) + (hasHalfStar ? '☆' : '') + '☆'.repeat(emptyStars)
}

// Percentage formatting
export const formatPercentage = (value: number, total: number): string => {
    if (total === 0) return '0%'
    const percentage = (value / total) * 100
    return `${Math.round(percentage)}%`
}

// Name formatting (capitalize first letter of each word)
export const formatName = (name: string): string => {
    return name
        .toLowerCase()
        .split(' ')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ')
}

// Truncate text with ellipsis
export const truncateText = (text: string, maxLength: number): string => {
    if (text.length <= maxLength) return text
    return text.slice(0, maxLength - 3) + '...'
}

// Format booking status for display
export const formatBookingStatus = (status: string): string => {
    const statusMap: Record<string, string> = {
        'pending': 'Pending',
        'confirmed': 'Confirmed',
        'in_progress': 'In Progress',
        'completed': 'Completed',
        'cancelled': 'Cancelled'
    }

    return statusMap[status] || status
}

// Format price type for display
export const formatPriceType = (priceType: string): string => {
    const typeMap: Record<string, string> = {
        'fixed': 'Fixed Price',
        'hourly': 'Per Hour',
        'negotiable': 'Negotiable'
    }

    return typeMap[priceType] || priceType
}

// Format location type for display
export const formatLocationType = (locationType: string): string => {
    const typeMap: Record<string, string> = {
        'on_site': 'On-site',
        'remote': 'Remote',
        'both': 'On-site & Remote'
    }

    return typeMap[locationType] || locationType
}

// Format user role for display
export const formatUserRole = (role: string): string => {
    const roleMap: Record<string, string> = {
        'customer': 'Customer',
        'provider': 'Service Provider',
        'admin': 'Administrator'
    }

    return roleMap[role] || role
}

// Format notification priority for display
export const formatNotificationPriority = (priority: string): string => {
    const priorityMap: Record<string, string> = {
        'low': 'Low Priority',
        'medium': 'Medium Priority',
        'high': 'High Priority'
    }

    return priorityMap[priority] || priority
}

// Format distance
export const formatDistance = (distanceKm: number): string => {
    if (distanceKm < 1) {
        return `${Math.round(distanceKm * 1000)}m`
    }

    if (distanceKm < 10) {
        return `${distanceKm.toFixed(1)}km`
    }

    return `${Math.round(distanceKm)}km`
}

// Format address (truncate long addresses)
export const formatAddress = (address: string, maxLength: number = 50): string => {
    return truncateText(address, maxLength)
}

// Format business hours
export const formatBusinessHours = (openTime: string, closeTime: string): string => {
    return `${formatTime(openTime)} - ${formatTime(closeTime)}`
}
