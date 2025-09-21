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

    const callbackData = await req.json()
    console.log('M-Pesa Callback received:', JSON.stringify(callbackData, null, 2))

    const { Body } = callbackData
    const { stkCallback } = Body

    const checkoutRequestId = stkCallback.CheckoutRequestID
    const resultCode = stkCallback.ResultCode
    const resultDesc = stkCallback.ResultDesc

    // Find the transaction
    const { data: transaction, error: findError } = await supabaseClient
      .from('transactions')
      .select('*')
      .eq('reference', checkoutRequestId)
      .single()

    if (findError || !transaction) {
      console.error('Transaction not found:', findError)
      return new Response(JSON.stringify({ error: 'Transaction not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    let updateData: any = {
      processed_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    }

    if (resultCode === 0) {
      // Payment successful
      const callbackMetadata = stkCallback.CallbackMetadata?.Item || []
      const mpesaReceiptNumber = callbackMetadata.find((item: any) => item.Name === 'MpesaReceiptNumber')?.Value
      const transactionDate = callbackMetadata.find((item: any) => item.Name === 'TransactionDate')?.Value
      const phoneNumber = callbackMetadata.find((item: any) => item.Name === 'PhoneNumber')?.Value

      updateData = {
        ...updateData,
        status: 'completed',
        mpesa_receipt: mpesaReceiptNumber,
        metadata: {
          ...transaction.metadata,
          mpesa_receipt_number: mpesaReceiptNumber,
          transaction_date: transactionDate,
          phone_number: phoneNumber,
          callback_data: callbackData
        }
      }

      // Update booking status to confirmed if payment is successful
      if (transaction.booking_id) {
        await supabaseClient
          .from('bookings')
          .update({ 
            status: 'confirmed',
            updated_at: new Date().toISOString()
          })
          .eq('id', transaction.booking_id)

        // Create notification for successful payment
        await supabaseClient
          .from('notifications')
          .insert({
            user_id: transaction.user_id,
            title: 'Payment Successful',
            message: `Your payment of KSh ${transaction.amount} has been processed successfully.`,
            type: 'payment_success',
            data: {
              booking_id: transaction.booking_id,
              amount: transaction.amount,
              mpesa_receipt: mpesaReceiptNumber
            }
          })
      }
    } else {
      // Payment failed
      updateData = {
        ...updateData,
        status: 'failed',
        metadata: {
          ...transaction.metadata,
          failure_reason: resultDesc,
          callback_data: callbackData
        }
      }

      // Create notification for failed payment
      await supabaseClient
        .from('notifications')
        .insert({
          user_id: transaction.user_id,
          title: 'Payment Failed',
          message: `Your payment could not be processed. Reason: ${resultDesc}`,
          type: 'payment_failed',
          data: {
            booking_id: transaction.booking_id,
            amount: transaction.amount,
            failure_reason: resultDesc
          }
        })
    }

    // Update transaction
    const { error: updateError } = await supabaseClient
      .from('transactions')
      .update(updateData)
      .eq('id', transaction.id)

    if (updateError) {
      console.error('Transaction update error:', updateError)
      return new Response(JSON.stringify({ error: 'Failed to update transaction' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    return new Response(JSON.stringify({ 
      success: true, 
      message: 'Callback processed successfully' 
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })

  } catch (error) {
    console.error('M-Pesa callback error:', error)
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})
