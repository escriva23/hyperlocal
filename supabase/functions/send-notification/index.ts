import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
    )

    const { user_id, title, message, type, data } = await req.json()

    // Create notification in database
    const { data: notification, error } = await supabaseClient
      .from('notifications')
      .insert({
        user_id,
        title,
        message,
        type,
        data: data || {}
      })
      .select()
      .single()

    if (error) {
      throw error
    }

    // Here you could add push notification logic
    // For example, using Firebase Cloud Messaging or similar service

    return new Response(JSON.stringify({ 
      success: true, 
      notification_id: notification.id 
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })

  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})
