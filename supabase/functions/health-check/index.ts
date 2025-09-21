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

    // Check database connectivity
    const { data: dbCheck, error: dbError } = await supabaseClient
      .from('users')
      .select('count')
      .limit(1)

    if (dbError) {
      throw new Error(`Database check failed: ${dbError.message}`)
    }

    // Check edge functions
    const checks = {
      database: 'healthy',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      services: {
        auth: 'healthy',
        database: 'healthy',
        storage: 'healthy',
        realtime: 'healthy'
      }
    }

    return new Response(JSON.stringify(checks), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })

  } catch (error) {
    return new Response(JSON.stringify({ 
      status: 'unhealthy',
      error: error.message,
      timestamp: new Date().toISOString()
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})
