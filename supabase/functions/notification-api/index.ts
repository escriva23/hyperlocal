import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

interface NotificationRequest {
    user_id: string
    type: 'booking' | 'payment' | 'review' | 'system' | 'message' | 'reminder'
    title: string
    message: string
    priority?: 'low' | 'medium' | 'high'
    action_url?: string
    metadata?: Record<string, any>
}

serve(async (req) => {
    // Handle CORS preflight requests
    if (req.method === 'OPTIONS') {
        return new Response('ok', { headers: corsHeaders })
    }

    try {
        // Create Supabase client
        const supabaseClient = createClient(
            Deno.env.get('SUPABASE_URL') ?? '',
            Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
        )

        // Get the authorization header
        const authHeader = req.headers.get('Authorization')
        if (!authHeader) {
            throw new Error('No authorization header')
        }

        // Verify the user
        const { data: { user }, error: authError } = await supabaseClient.auth.getUser(
            authHeader.replace('Bearer ', '')
        )

        if (authError || !user) {
            throw new Error('Invalid authorization')
        }

        const { method, url } = req
        const urlPath = new URL(url).pathname

        switch (method) {
            case 'POST':
                if (urlPath.endsWith('/create')) {
                    return await createNotification(req, supabaseClient)
                } else if (urlPath.endsWith('/mark-read')) {
                    return await markNotificationRead(req, supabaseClient, user.id)
                } else if (urlPath.endsWith('/mark-all-read')) {
                    return await markAllNotificationsRead(req, supabaseClient, user.id)
                } else if (urlPath.endsWith('/delete')) {
                    return await deleteNotification(req, supabaseClient, user.id)
                }
                break

            case 'GET':
                if (urlPath.endsWith('/count')) {
                    return await getUnreadCount(supabaseClient, user.id)
                }
                break
        }

        return new Response(
            JSON.stringify({ error: 'Method not allowed' }),
            {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            }
        )

    } catch (error) {
        return new Response(
            JSON.stringify({ error: error.message }),
            {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            }
        )
    }
})

async function createNotification(req: Request, supabaseClient: any) {
    const body: NotificationRequest = await req.json()

    const { data, error } = await supabaseClient
        .from('notifications')
        .insert({
            user_id: body.user_id,
            type: body.type,
            title: body.title,
            message: body.message,
            priority: body.priority || 'medium',
            action_url: body.action_url,
            metadata: body.metadata || {}
        })
        .select()
        .single()

    if (error) {
        throw new Error(`Failed to create notification: ${error.message}`)
    }

    return new Response(
        JSON.stringify({ success: true, notification: data }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )
}

async function markNotificationRead(req: Request, supabaseClient: any, userId: string) {
    const { notification_id } = await req.json()

    const { error } = await supabaseClient
        .from('notifications')
        .update({ is_read: true })
        .eq('id', notification_id)
        .eq('user_id', userId)

    if (error) {
        throw new Error(`Failed to mark notification as read: ${error.message}`)
    }

    return new Response(
        JSON.stringify({ success: true }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )
}

async function markAllNotificationsRead(req: Request, supabaseClient: any, userId: string) {
    const { error } = await supabaseClient
        .from('notifications')
        .update({ is_read: true })
        .eq('user_id', userId)
        .eq('is_read', false)

    if (error) {
        throw new Error(`Failed to mark all notifications as read: ${error.message}`)
    }

    return new Response(
        JSON.stringify({ success: true }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )
}

async function deleteNotification(req: Request, supabaseClient: any, userId: string) {
    const { notification_id } = await req.json()

    const { error } = await supabaseClient
        .from('notifications')
        .delete()
        .eq('id', notification_id)
        .eq('user_id', userId)

    if (error) {
        throw new Error(`Failed to delete notification: ${error.message}`)
    }

    return new Response(
        JSON.stringify({ success: true }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )
}

async function getUnreadCount(supabaseClient: any, userId: string) {
    const { data, error } = await supabaseClient
        .from('notifications')
        .select('id', { count: 'exact' })
        .eq('user_id', userId)
        .eq('is_read', false)

    if (error) {
        throw new Error(`Failed to get unread count: ${error.message}`)
    }

    return new Response(
        JSON.stringify({ count: data?.length || 0 }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )
}
