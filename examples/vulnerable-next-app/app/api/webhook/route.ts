// VULNERABLE EXAMPLE — Webhook route missing signature verification
// Scanner should flag: webhook missing constructEvent / signature check
// FAKE test values only — do not use in production

import { NextRequest, NextResponse } from 'next/server';

// VULNERABLE: Webhook route processes raw body without verifying Stripe/GitHub signature
export async function POST(request: NextRequest) {
  const body = await request.json();

  // VULNERABLE: No stripe.webhooks.constructEvent() call
  // No x-hub-signature check
  // No svix webhook verification
  // Any attacker can POST fake events here

  const { type, data } = body;

  if (type === 'payment_intent.succeeded') {
    // Process payment — triggered without proof of authenticity
    console.log('Payment succeeded for:', data?.object?.id);
    await fulfillOrder(data?.object?.metadata?.orderId);
  }

  if (type === 'customer.subscription.deleted') {
    await cancelUserSubscription(data?.object?.customer);
  }

  return NextResponse.json({ received: true });
}

async function fulfillOrder(_orderId: string) { /* stub */ }
async function cancelUserSubscription(_customerId: string) { /* stub */ }
