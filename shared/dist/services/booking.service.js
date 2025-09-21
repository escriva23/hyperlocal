"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BookingService = void 0;
class BookingService {
    constructor(supabase) {
        this.supabase = supabase;
    }
    /**
     * Create a new booking
     */
    async createBooking(booking) {
        try {
            const { data, error } = await this.supabase
                .from('bookings')
                .insert(booking)
                .select()
                .single();
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to create booking', success: false };
        }
    }
    /**
     * Get customer bookings with details - Use database function instead of complex joins
     */
    async getCustomerBookings(customerId) {
        try {
            // Use the database function we created for booking queries
            const { data, error } = await this.supabase
                .rpc('get_user_bookings', {
                user_id: customerId,
                user_type: 'customer'
            });
            if (error) {
                // Fallback to simple bookings query if function doesn't exist
                const { data: fallbackData, error: fallbackError } = await this.supabase
                    .from('bookings')
                    .select('*')
                    .eq('customer_id', customerId)
                    .order('created_at', { ascending: false });
                if (fallbackError) {
                    return { data: null, error: fallbackError.message, success: false };
                }
                return { data: fallbackData || [], error: null, success: true };
            }
            return { data: data || [], error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to fetch customer bookings', success: false };
        }
    }
    /**
     * Get provider bookings with details - Use database function instead of complex joins
     */
    async getProviderBookings(providerId) {
        try {
            // Use the database function we created for booking queries
            const { data, error } = await this.supabase
                .rpc('get_user_bookings', {
                user_id: providerId,
                user_type: 'provider'
            });
            if (error) {
                // Fallback to simple bookings query if function doesn't exist
                const { data: fallbackData, error: fallbackError } = await this.supabase
                    .from('bookings')
                    .select('*')
                    .eq('provider_id', providerId)
                    .order('created_at', { ascending: false });
                if (fallbackError) {
                    return { data: null, error: fallbackError.message, success: false };
                }
                return { data: fallbackData || [], error: null, success: true };
            }
            return { data: data || [], error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to fetch provider bookings', success: false };
        }
    }
    /**
     * Get booking by ID with details
     */
    async getBookingById(bookingId) {
        try {
            const { data, error } = await this.supabase
                .from('bookings')
                .select('*')
                .eq('id', bookingId)
                .single();
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to fetch booking', success: false };
        }
    }
    /**
     * Update booking status
     */
    async updateBookingStatus(bookingId, status, updates) {
        try {
            const updateData = {
                status,
                updated_at: new Date().toISOString(),
                ...updates
            };
            const { data, error } = await this.supabase
                .from('bookings')
                .update(updateData)
                .eq('id', bookingId)
                .select()
                .single();
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to update booking', success: false };
        }
    }
    /**
     * Cancel booking
     */
    async cancelBooking(bookingId, cancelledBy, cancellationReason) {
        try {
            const { data, error } = await this.supabase
                .from('bookings')
                .update({
                status: 'cancelled',
                cancelled_by: cancelledBy,
                cancellation_reason: cancellationReason,
                cancelled_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            })
                .eq('id', bookingId)
                .select()
                .single();
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to cancel booking', success: false };
        }
    }
    /**
     * Start booking (mark as in progress)
     */
    async startBooking(bookingId) {
        try {
            const { data, error } = await this.supabase
                .from('bookings')
                .update({
                status: 'in_progress',
                actual_start_time: new Date().toISOString(),
                updated_at: new Date().toISOString()
            })
                .eq('id', bookingId)
                .select()
                .single();
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to start booking', success: false };
        }
    }
    /**
     * Complete booking
     */
    async completeBooking(bookingId) {
        try {
            const { data, error } = await this.supabase
                .from('bookings')
                .update({
                status: 'completed',
                actual_end_time: new Date().toISOString(),
                updated_at: new Date().toISOString()
            })
                .eq('id', bookingId)
                .select()
                .single();
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to complete booking', success: false };
        }
    }
    /**
     * Get bookings by status - Use simple queries without complex joins
     */
    async getBookingsByStatus(userId, status, userType = 'customer') {
        try {
            const filterField = userType === 'customer' ? 'customer_id' : 'provider_id';
            const { data, error } = await this.supabase
                .from('bookings')
                .select('*')
                .eq(filterField, userId)
                .eq('status', status)
                .order('created_at', { ascending: false });
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data: data || [], error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to fetch bookings by status', success: false };
        }
    }
    /**
     * Get upcoming bookings - Use simple queries without complex joins
     */
    async getUpcomingBookings(userId, userType = 'customer') {
        try {
            const filterField = userType === 'customer' ? 'customer_id' : 'provider_id';
            const { data, error } = await this.supabase
                .from('bookings')
                .select('*')
                .eq(filterField, userId)
                .in('status', ['pending', 'confirmed'])
                .gte('scheduled_date', new Date().toISOString())
                .order('scheduled_date', { ascending: true });
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data: data || [], error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to fetch upcoming bookings', success: false };
        }
    }
    /**
     * Subscribe to booking changes
     */
    subscribeToBookings(userId, userType, callback) {
        const filterField = userType === 'customer' ? 'customer_id' : 'provider_id';
        const subscription = this.supabase
            .channel(`bookings_${userId}`)
            .on('postgres_changes', {
            event: '*',
            schema: 'public',
            table: 'bookings',
            filter: `${filterField}=eq.${userId}`
        }, callback)
            .subscribe();
        return subscription;
    }
}
exports.BookingService = BookingService;
