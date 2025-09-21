import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

interface QRPaymentRequest {
  qr_code: string
  amount?: number
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

    const { qr_code, amount, pin, description }: QRPaymentRequest = await req.json()

    // Validate input
    if (!qr_code || !pin) {
      return new Response(JSON.stringify({ error: 'Missing required fields' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Get QR code details
    const { data: qrData, error: qrError } = await supabaseClient
      .from('qr_codes')
      .select(`
        *,
        owner:users!owner_user_id(id, name)
      `)
      .eq('code_string', qr_code)
      .eq('is_active', true)
      .single()

    if (qrError || !qrData) {
      return new Response(JSON.stringify({ error: 'Invalid QR code' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Check if QR code is expired
    if (qrData.expires_at && new Date(qrData.expires_at) < new Date()) {
      return new Response(JSON.stringify({ error: 'QR code has expired' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Check if already redeemed (for dynamic QR)
    if (qrData.type === 'dynamic' && qrData.redeemed_at) {
      return new Response(JSON.stringify({ error: 'QR code already used' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Determine payment amount
    let paymentAmount: number
    if (qrData.type === 'dynamic') {
      paymentAmount = qrData.amount
    } else {
      if (!amount || amount <= 0) {
        return new Response(JSON.stringify({ error: 'Amount required for static QR code' }), {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }
      paymentAmount = amount
    }

    // Prevent self-payment
    if (qrData.owner_user_id === user.id) {
      return new Response(JSON.stringify({ error: 'Cannot pay yourself' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Hash PIN
    const encoder = new TextEncoder()
    const data = encoder.encode(pin + user.id)
    const hashBuffer = await crypto.subtle.digest('SHA-256', data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const pin_hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')

    // Process transfer
    const { data: transferResult, error: transferError } = await supabaseClient
      .rpc('transfer_funds', {
        sender_id: user.id,
        recipient_id: qrData.owner_user_id,
        amount: paymentAmount,
        pin_hash: pin_hash,
        description: description || `QR payment to ${qrData.owner.name}`
      })

    if (transferError) {
      console.error('QR payment transfer error:', transferError)
      return new Response(JSON.stringify({ error: 'Payment failed' }), {
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

    // Mark QR code as redeemed (for dynamic QR)
    if (qrData.type === 'dynamic') {
      await supabaseClient
        .from('qr_codes')
        .update({
          redeemed_by: user.id,
          redeemed_at: new Date().toISOString(),
          is_active: false
        })
        .eq('id', qrData.id)
    }

    // Send notifications
    await Promise.all([
      // Notify payer
      supabaseClient.from('notifications').insert({
        user_id: user.id,
        title: 'QR Payment Sent',
        message: `You paid KES ${paymentAmount} via QR code to ${qrData.owner.name}`,
        type: 'qr_payment',
        metadata: {
          amount: paymentAmount,
          recipient_id: qrData.owner_user_id,
          qr_id: qrData.qr_id,
          tx_code: transferResult.tx_code_send
        }
      }),
      // Notify recipient
      supabaseClient.from('notifications').insert({
        user_id: qrData.owner_user_id,
        title: 'QR Payment Received',
        message: `You received KES ${paymentAmount} via QR code from ${user.user_metadata?.name || 'someone'}`,
        type: 'qr_payment',
        metadata: {
          amount: paymentAmount,
          sender_id: user.id,
          qr_id: qrData.qr_id,
          tx_code: transferResult.tx_code_receive
        }
      })
    ])

    return new Response(JSON.stringify({
      success: true,
      message: 'QR payment completed successfully',
      amount: paymentAmount,
      recipient: qrData.owner.name,
      qr_type: qrData.type,
      tx_code: transferResult.tx_code_send
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })

  } catch (error) {
    console.error('QR payment error:', error)
    return new Response(JSON.stringify({ error: 'Internal server error' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})
