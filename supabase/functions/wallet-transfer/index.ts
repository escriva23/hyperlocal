import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

interface TransferRequest {
  recipient_id: string
  amount: number
  pin: string
  description?: string
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '',
    )

    // Get user from JWT
    const authHeader = req.headers.get('Authorization')
    if (!authHeader) {
      return new Response(JSON.stringify({ error: 'Missing authorization header' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const { data: { user }, error: userError } = await supabaseClient.auth.getUser(
      authHeader.replace('Bearer ', '')
    )
    
    if (userError || !user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const { recipient_id, amount, pin, description }: TransferRequest = await req.json()

    // Validate input
    if (!recipient_id || !amount || !pin) {
      return new Response(JSON.stringify({ error: 'Missing required fields' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    if (amount <= 0) {
      return new Response(JSON.stringify({ error: 'Amount must be positive' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Verify recipient exists
    const { data: recipient, error: recipientError } = await supabaseClient
      .from('users')
      .select('id, name')
      .eq('id', recipient_id)
      .single()

    if (recipientError || !recipient) {
      return new Response(JSON.stringify({ error: 'Recipient not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Hash PIN (simplified - in production use proper bcrypt/argon2)
    const encoder = new TextEncoder()
    const data = encoder.encode(pin + user.id) // Add user ID as salt
    const hashBuffer = await crypto.subtle.digest('SHA-256', data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const pin_hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')

    // Call transfer function
    const { data: transferResult, error: transferError } = await supabaseClient
      .rpc('transfer_funds', {
        sender_id: user.id,
        recipient_id: recipient_id,
        amount: amount,
        pin_hash: pin_hash,
        description: description || `Transfer to ${recipient.name}`
      })

    if (transferError) {
      console.error('Transfer error:', transferError)
      return new Response(JSON.stringify({ error: 'Transfer failed' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    if (!transferResult.success) {
      return new Response(JSON.stringify({ error: transferResult.error }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Send notifications to both users
    await Promise.all([
      // Notify sender
      supabaseClient.from('notifications').insert({
        user_id: user.id,
        title: 'Transfer Sent',
        message: `You sent KES ${amount} to ${recipient.name}`,
        type: 'transfer',
        metadata: {
          amount: amount,
          recipient_id: recipient_id,
          tx_code: transferResult.tx_code_send
        }
      }),
      // Notify recipient
      supabaseClient.from('notifications').insert({
        user_id: recipient_id,
        title: 'Money Received',
        message: `You received KES ${amount} from ${user.user_metadata?.name || 'someone'}`,
        type: 'transfer',
        metadata: {
          amount: amount,
          sender_id: user.id,
          tx_code: transferResult.tx_code_receive
        }
      })
    ])

    return new Response(JSON.stringify({
      success: true,
      message: 'Transfer completed successfully',
      tx_code_send: transferResult.tx_code_send,
      tx_code_receive: transferResult.tx_code_receive,
      amount: amount,
      recipient: recipient.name
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })

  } catch (error) {
    console.error('Wallet transfer error:', error)
    return new Response(JSON.stringify({ error: 'Internal server error' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})
