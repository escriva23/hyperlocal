"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NotificationService = void 0;
class NotificationService {
    constructor(supabase) {
        this.supabase = supabase;
    }
    /**
     * Create a new notification
     */
    async createNotification(notification) {
        try {
            const { data, error } = await this.supabase
                .from('notifications')
                .insert(notification)
                .select()
                .single();
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to create notification', success: false };
        }
    }
    /**
     * Mark notification as read
     */
    async markAsRead(notificationId, userId) {
        try {
            const { data, error } = await this.supabase
                .from('notifications')
                .update({
                is_read: true,
                read_at: new Date().toISOString()
            })
                .eq('id', notificationId)
                .eq('user_id', userId)
                .select()
                .single();
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to mark notification as read', success: false };
        }
    }
    /**
     * Mark all notifications as read for a user
     */
    async markAllAsRead(userId) {
        try {
            const { error } = await this.supabase
                .from('notifications')
                .update({
                is_read: true,
                read_at: new Date().toISOString()
            })
                .eq('user_id', userId)
                .eq('is_read', false);
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data: null, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to mark all notifications as read', success: false };
        }
    }
    /**
     * Delete a notification
     */
    async deleteNotification(notificationId, userId) {
        try {
            const { error } = await this.supabase
                .from('notifications')
                .delete()
                .eq('id', notificationId)
                .eq('user_id', userId);
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data: null, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to delete notification', success: false };
        }
    }
    /**
     * Get unread notification count
     */
    async getUnreadCount(userId) {
        try {
            const { data, error } = await this.supabase
                .from('notifications')
                .select('id', { count: 'exact' })
                .eq('user_id', userId)
                .eq('is_read', false);
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data: data?.length || 0, error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to get unread count', success: false };
        }
    }
    /**
     * Get notifications for a user with pagination and filtering
     */
    async getNotifications(userId, options = {}) {
        try {
            let query = this.supabase
                .from('notifications')
                .select('*')
                .eq('user_id', userId)
                .order('created_at', { ascending: false });
            // Apply filters
            if (options.filter && options.filter !== 'all') {
                if (options.filter === 'unread') {
                    query = query.eq('is_read', false);
                }
                else {
                    query = query.eq('type', options.filter);
                }
            }
            // Apply pagination
            if (options.limit) {
                query = query.limit(options.limit);
            }
            if (options.offset) {
                query = query.range(options.offset, options.offset + (options.limit || 50) - 1);
            }
            const { data, error } = await query;
            if (error) {
                return { data: null, error: error.message, success: false };
            }
            return { data: data || [], error: null, success: true };
        }
        catch (error) {
            return { data: null, error: error.message || 'Failed to get notifications', success: false };
        }
    }
    /**
     * Subscribe to real-time notification changes
     */
    subscribeToNotifications(userId, callback) {
        const subscription = this.supabase
            .channel(`notifications_${userId}`)
            .on('postgres_changes', {
            event: '*',
            schema: 'public',
            table: 'notifications',
            filter: `user_id=eq.${userId}`
        }, callback)
            .subscribe();
        return {
            unsubscribe: () => subscription.unsubscribe()
        };
    }
    /**
     * Helper methods for common notification types
     */
    async notifyBookingConfirmed(customerId, bookingId, serviceName, scheduledDate) {
        return this.createNotification({
            user_id: customerId,
            type: 'booking',
            title: 'Booking Confirmed',
            message: `Your ${serviceName} booking has been confirmed for ${scheduledDate.toLocaleDateString()}`,
            priority: 'high',
            action_url: `/customer/bookings/${bookingId}`,
            metadata: { booking_id: bookingId, service_name: serviceName }
        });
    }
    async notifyBookingCancelled(userId, bookingId, serviceName, reason) {
        return this.createNotification({
            user_id: userId,
            type: 'booking',
            title: 'Booking Cancelled',
            message: `Your ${serviceName} booking has been cancelled${reason ? `: ${reason}` : ''}`,
            priority: 'high',
            action_url: `/customer/bookings/${bookingId}`,
            metadata: { booking_id: bookingId, service_name: serviceName, reason }
        });
    }
    async notifyPaymentProcessed(customerId, amount, serviceName) {
        return this.createNotification({
            user_id: customerId,
            type: 'payment',
            title: 'Payment Processed',
            message: `Payment of $${amount} has been successfully processed for your ${serviceName}`,
            priority: 'medium',
            metadata: { amount, service_name: serviceName }
        });
    }
    async notifyNewReview(providerId, rating, customerName) {
        return this.createNotification({
            user_id: providerId,
            type: 'review',
            title: rating >= 4 ? `New ${rating}-Star Review!` : 'New Review Received',
            message: `${customerName} left you a ${rating}-star review`,
            priority: rating >= 4 ? 'low' : 'medium',
            action_url: '/provider/reviews',
            metadata: { rating, customer_name: customerName }
        });
    }
    async notifyNewBookingRequest(providerId, bookingId, customerName, serviceName) {
        return this.createNotification({
            user_id: providerId,
            type: 'booking',
            title: 'New Booking Request',
            message: `${customerName} has requested your ${serviceName} service`,
            priority: 'high',
            action_url: `/provider/bookings/${bookingId}`,
            metadata: { booking_id: bookingId, customer_name: customerName, service_name: serviceName }
        });
    }
    async notifySystemMessage(userId, title, message, actionUrl) {
        return this.createNotification({
            user_id: userId,
            type: 'system',
            title,
            message,
            priority: 'medium',
            action_url: actionUrl
        });
    }
    async notifyMtaaSharesEarned(userId, sharesAmount, reason) {
        return this.createNotification({
            user_id: userId,
            type: 'system',
            title: 'Mtaa Shares Earned!',
            message: `You've earned ${sharesAmount} Mtaa Shares for ${reason}`,
            priority: 'low',
            action_url: '/mtaa-shares',
            metadata: { shares_amount: sharesAmount, reason }
        });
    }
}
exports.NotificationService = NotificationService;
