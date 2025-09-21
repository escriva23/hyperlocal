import { SupabaseClient } from '@supabase/supabase-js';
import { ApiResponse, NotificationFilters, RealtimeSubscription } from '../types/api.types';
import { Notification, NotificationInsert } from '../types/database.types';
export declare class NotificationService {
    private supabase;
    constructor(supabase: SupabaseClient);
    /**
     * Create a new notification
     */
    createNotification(notification: NotificationInsert): Promise<ApiResponse<Notification>>;
    /**
     * Mark notification as read
     */
    markAsRead(notificationId: string, userId: string): Promise<ApiResponse<Notification>>;
    /**
     * Mark all notifications as read for a user
     */
    markAllAsRead(userId: string): Promise<ApiResponse<null>>;
    /**
     * Delete a notification
     */
    deleteNotification(notificationId: string, userId: string): Promise<ApiResponse<null>>;
    /**
     * Get unread notification count
     */
    getUnreadCount(userId: string): Promise<ApiResponse<number>>;
    /**
     * Get notifications for a user with pagination and filtering
     */
    getNotifications(userId: string, options?: NotificationFilters): Promise<ApiResponse<Notification[]>>;
    /**
     * Subscribe to real-time notification changes
     */
    subscribeToNotifications(userId: string, callback: () => void): RealtimeSubscription;
    /**
     * Helper methods for common notification types
     */
    notifyBookingConfirmed(customerId: string, bookingId: string, serviceName: string, scheduledDate: Date): Promise<ApiResponse<Notification>>;
    notifyBookingCancelled(userId: string, bookingId: string, serviceName: string, reason?: string): Promise<ApiResponse<Notification>>;
    notifyPaymentProcessed(customerId: string, amount: number, serviceName: string): Promise<ApiResponse<Notification>>;
    notifyNewReview(providerId: string, rating: number, customerName: string): Promise<ApiResponse<Notification>>;
    notifyNewBookingRequest(providerId: string, bookingId: string, customerName: string, serviceName: string): Promise<ApiResponse<Notification>>;
    notifySystemMessage(userId: string, title: string, message: string, actionUrl?: string): Promise<ApiResponse<Notification>>;
    notifyMtaaSharesEarned(userId: string, sharesAmount: number, reason: string): Promise<ApiResponse<Notification>>;
}
