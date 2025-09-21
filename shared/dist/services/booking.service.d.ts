import { SupabaseClient } from '@supabase/supabase-js';
import { ApiResponse, BookingWithDetails } from '../types/api.types';
import { Booking, BookingInsert, BookingUpdate } from '../types/database.types';
export declare class BookingService {
    private supabase;
    constructor(supabase: SupabaseClient);
    /**
     * Create a new booking
     */
    createBooking(booking: BookingInsert): Promise<ApiResponse<Booking>>;
    /**
     * Get customer bookings with details - Use database function instead of complex joins
     */
    getCustomerBookings(customerId: string): Promise<ApiResponse<BookingWithDetails[]>>;
    /**
     * Get provider bookings with details - Use database function instead of complex joins
     */
    getProviderBookings(providerId: string): Promise<ApiResponse<BookingWithDetails[]>>;
    /**
     * Get booking by ID with details
     */
    getBookingById(bookingId: string): Promise<ApiResponse<BookingWithDetails>>;
    /**
     * Update booking status
     */
    updateBookingStatus(bookingId: string, status: Booking['status'], updates?: Partial<BookingUpdate>): Promise<ApiResponse<Booking>>;
    /**
     * Cancel booking
     */
    cancelBooking(bookingId: string, cancelledBy: string, cancellationReason?: string): Promise<ApiResponse<Booking>>;
    /**
     * Start booking (mark as in progress)
     */
    startBooking(bookingId: string): Promise<ApiResponse<Booking>>;
    /**
     * Complete booking
     */
    completeBooking(bookingId: string): Promise<ApiResponse<Booking>>;
    /**
     * Get bookings by status - Use simple queries without complex joins
     */
    getBookingsByStatus(userId: string, status: Booking['status'], userType?: 'customer' | 'provider'): Promise<ApiResponse<BookingWithDetails[]>>;
    /**
     * Get upcoming bookings - Use simple queries without complex joins
     */
    getUpcomingBookings(userId: string, userType?: 'customer' | 'provider'): Promise<ApiResponse<BookingWithDetails[]>>;
    /**
     * Subscribe to booking changes
     */
    subscribeToBookings(userId: string, userType: 'customer' | 'provider', callback: () => void): import("@supabase/supabase-js").RealtimeChannel;
}
