import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

interface TopUpRequest {
  amount: number
  payment_method: 'mpesa' | 'card'
  phone_number?: string
  card_token?: string
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

    const { amount, payment_method, phone_number, card_token }: TopUpRequest = await req.json()

    // Validate input
    if (!amount || amount <= 0) {
      return new Response(JSON.stringify({ error: 'Invalid amount' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    let paymentResult

    if (payment_method === 'mpesa') {
      if (!phone_number) {
        return new Response(JSON.stringify({ error: 'Phone number required for M-Pesa' }), {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }

      // Call M-Pesa payment function
      const { data: mpesaData, error: mpesaError } = await supabaseClient.functions.invoke('mpesa-payment', {
        body: {
          booking_id: `wallet_topup_${user.id}_${Date.now()}`,
          amount: amount,
          phone: phone_number,
          account_reference: `WALLET_${user.id}`
        }
      })

      if (mpesaError || !mpesaData.success) {
        return new Response(JSON.stringify({ error: 'M-Pesa payment failed' }), {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }

      paymentResult = mpesaData
    } else if (payment_method === 'card') {
      // For card payments, you would integrate with Stripe here
      // This is a placeholder for Stripe integration
      return new Response(JSON.stringify({ error: 'Card payments not yet implemented' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Create pending transaction record
    const { data: transaction, error: txError } = await supabaseClient
      .from('transactions')
      .insert({
        user_id: user.id,
        amount: amount,
        type: 'deposit',
        status: 'pending',
        payment_method: payment_method,
        reference: paymentResult.checkout_request_id || paymentResult.transaction_id,
        description: `Wallet top-up via ${payment_method}`,
        metadata: {
          payment_method: payment_method,
          external_reference: paymentResult.checkout_request_id || paymentResult.transaction_id
        }
      })
      .select()
      .single()

    if (txError) {
      console.error('Transaction creation error:', txError)
      return new Response(JSON.stringify({ error: 'Failed to create transaction record' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    return new Response(JSON.stringify({
      success: true,
      transaction_id: transaction.id,
      status: 'pending',
      message: payment_method === 'mpesa' 
        ? 'M-Pesa prompt sent to your phone' 
        : 'Payment processing',
      external_reference: paymentResult.checkout_request_id || paymentResult.transaction_id
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })

  } catch (error) {
    console.error('Wallet top-up error:', error)
    return new Response(JSON.stringify({ error: 'Internal server error' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})
