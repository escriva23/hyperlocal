import { SupabaseClient } from '@supabase/supabase-js'
import { ApiResponse, NotificationFilters, RealtimeSubscription } from '../types/api.types'
import {
    Notification,
    NotificationInsert,
    NotificationUpdate
} from '../types/database.types'

export class NotificationService {
    constructor(private supabase: SupabaseClient) { }

    /**
     * Create a new notification
     */
    async createNotification(notification: NotificationInsert): Promise<ApiResponse<Notification>> {
        try {
            const { data, error } = await this.supabase
                .from('notifications')
                .insert(notification)
                .select()
                .single()

            if (error) {
                return { data: null, error: error.message, success: false }
            }

            return { data, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to create notification', success: false }
        }
    }

    /**
     * Mark notification as read
     */
    async markAsRead(notificationId: string, userId: string): Promise<ApiResponse<Notification>> {
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
                .single()

            if (error) {
                return { data: null, error: error.message, success: false }
            }

            return { data, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to mark notification as read', success: false }
        }
    }

    /**
     * Mark all notifications as read for a user
     */
    async markAllAsRead(userId: string): Promise<ApiResponse<null>> {
        try {
            const { error } = await this.supabase
                .from('notifications')
                .update({
                    is_read: true,
                    read_at: new Date().toISOString()
                })
                .eq('user_id', userId)
                .eq('is_read', false)

            if (error) {
                return { data: null, error: error.message, success: false }
            }

            return { data: null, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to mark all notifications as read', success: false }
        }
    }

    /**
     * Delete a notification
     */
    async deleteNotification(notificationId: string, userId: string): Promise<ApiResponse<null>> {
        try {
            const { error } = await this.supabase
                .from('notifications')
                .delete()
                .eq('id', notificationId)
                .eq('user_id', userId)

            if (error) {
                return { data: null, error: error.message, success: false }
            }

            return { data: null, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to delete notification', success: false }
        }
    }

    /**
     * Get unread notification count
     */
    async getUnreadCount(userId: string): Promise<ApiResponse<number>> {
        try {
            const { data, error } = await this.supabase
                .from('notifications')
                .select('id', { count: 'exact' })
                .eq('user_id', userId)
                .eq('is_read', false)

            if (error) {
                return { data: null, error: error.message, success: false }
            }

            return { data: data?.length || 0, error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to get unread count', success: false }
        }
    }

    /**
     * Get notifications for a user with pagination and filtering
     */
    async getNotifications(
        userId: string,
        options: NotificationFilters = {}
    ): Promise<ApiResponse<Notification[]>> {
        try {
            let query = this.supabase
                .from('notifications')
                .select('*')
                .eq('user_id', userId)
                .order('created_at', { ascending: false })

            // Apply filters
            if (options.filter && options.filter !== 'all') {
                if (options.filter === 'unread') {
                    query = query.eq('is_read', false)
                } else {
                    query = query.eq('type', options.filter)
                }
            }

            // Apply pagination
            if (options.limit) {
                query = query.limit(options.limit)
            }
            if (options.offset) {
                query = query.range(options.offset, options.offset + (options.limit || 50) - 1)
            }

            const { data, error } = await query

            if (error) {
                return { data: null, error: error.message, success: false }
            }

            return { data: data || [], error: null, success: true }
        } catch (error: any) {
            return { data: null, error: error.message || 'Failed to get notifications', success: false }
        }
    }

    /**
     * Subscribe to real-time notification changes
     */
    subscribeToNotifications(userId: string, callback: () => void): RealtimeSubscription {
        const subscription = this.supabase
            .channel(`notifications_${userId}`)
            .on(
                'postgres_changes',
                {
                    event: '*',
                    schema: 'public',
                    table: 'notifications',
                    filter: `user_id=eq.${userId}`
                },
                callback
            )
            .subscribe()

        return {
            unsubscribe: () => subscription.unsubscribe()
        }
    }

    /**
     * Helper methods for common notification types
     */
    async notifyBookingConfirmed(
        customerId: string,
        bookingId: string,
        serviceName: string,
        scheduledDate: Date
    ): Promise<ApiResponse<Notification>> {
        return this.createNotification({
            user_id: customerId,
            type: 'booking',
            title: 'Booking Confirmed',
            message: `Your ${serviceName} booking has been confirmed for ${scheduledDate.toLocaleDateString()}`,
            priority: 'high',
            action_url: `/customer/bookings/${bookingId}`,
            metadata: { booking_id: bookingId, service_name: serviceName }
        })
    }

    async notifyBookingCancelled(
        userId: string,
        bookingId: string,
        serviceName: string,
        reason?: string
    ): Promise<ApiResponse<Notification>> {
        return this.createNotification({
            user_id: userId,
            type: 'booking',
            title: 'Booking Cancelled',
            message: `Your ${serviceName} booking has been cancelled${reason ? `: ${reason}` : ''}`,
            priority: 'high',
            action_url: `/customer/bookings/${bookingId}`,
            metadata: { booking_id: bookingId, service_name: serviceName, reason }
        })
    }

    async notifyPaymentProcessed(
        customerId: string,
        amount: number,
        serviceName: string
    ): Promise<ApiResponse<Notification>> {
        return this.createNotification({
            user_id: customerId,
            type: 'payment',
            title: 'Payment Processed',
            message: `Payment of $${amount} has been successfully processed for your ${serviceName}`,
            priority: 'medium',
            metadata: { amount, service_name: serviceName }
        })
    }

    async notifyNewReview(
        providerId: string,
        rating: number,
        customerName: string
    ): Promise<ApiResponse<Notification>> {
        return this.createNotification({
            user_id: providerId,
            type: 'review',
            title: rating >= 4 ? `New ${rating}-Star Review!` : 'New Review Received',
            message: `${customerName} left you a ${rating}-star review`,
            priority: rating >= 4 ? 'low' : 'medium',
            action_url: '/provider/reviews',
            metadata: { rating, customer_name: customerName }
        })
    }

    async notifyNewBookingRequest(
        providerId: string,
        bookingId: string,
        customerName: string,
        serviceName: string
    ): Promise<ApiResponse<Notification>> {
        return this.createNotification({
            user_id: providerId,
            type: 'booking',
            title: 'New Booking Request',
            message: `${customerName} has requested your ${serviceName} service`,
            priority: 'high',
            action_url: `/provider/bookings/${bookingId}`,
            metadata: { booking_id: bookingId, customer_name: customerName, service_name: serviceName }
        })
    }

    async notifySystemMessage(
        userId: string,
        title: string,
        message: string,
        actionUrl?: string
    ): Promise<ApiResponse<Notification>> {
        return this.createNotification({
            user_id: userId,
            type: 'system',
            title,
            message,
            priority: 'medium',
            action_url: actionUrl
        })
    }

    async notifyMtaaSharesEarned(
        userId: string,
        sharesAmount: number,
        reason: string
    ): Promise<ApiResponse<Notification>> {
        return this.createNotification({
            user_id: userId,
            type: 'system',
            title: 'Mtaa Shares Earned!',
            message: `You've earned ${sharesAmount} Mtaa Shares for ${reason}`,
            priority: 'low',
            action_url: '/mtaa-shares',
            metadata: { shares_amount: sharesAmount, reason }
        })
    }
}
