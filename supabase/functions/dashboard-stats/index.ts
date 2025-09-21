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
      Deno.env.get('SUPABASE_ANON_KEY') ?? '',
      { global: { headers: { Authorization: req.headers.get('Authorization')! } } }
    )

    // Get user from JWT
    const { data: { user }, error: userError } = await supabaseClient.auth.getUser()
    if (userError || !user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const url = new URL(req.url)
    const userType = url.searchParams.get('type') || 'customer'

    let stats
    if (userType === 'customer') {
      const { data, error } = await supabaseClient.rpc('get_customer_dashboard_stats', {
        customer_id: user.id
      })
      
      if (error) throw error
      stats = data
    } else if (userType === 'provider') {
      const { data, error } = await supabaseClient.rpc('get_provider_dashboard_stats', {
        provider_id: user.id
      })
      
      if (error) throw error
      stats = data
    } else {
      // Admin stats
      const { data: totalUsers } = await supabaseClient
        .from('users')
        .select('id', { count: 'exact' })
      
      const { data: totalBookings } = await supabaseClient
        .from('bookings')
        .select('id', { count: 'exact' })
      
      const { data: totalRevenue } = await supabaseClient
        .from('transactions')
        .select('amount')
        .eq('type', 'commission')
        .eq('status', 'completed')
      
      const revenue = totalRevenue?.reduce((sum, t) => sum + Number(t.amount), 0) || 0
      
      stats = {
        total_users: totalUsers?.length || 0,
        total_bookings: totalBookings?.length || 0,
        total_revenue: revenue,
        active_providers: 0, // Will be calculated separately
        pending_verifications: 0
      }
    }

    return new Response(JSON.stringify(stats), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})
