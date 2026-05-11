// VULNERABLE EXAMPLE — Payment route with multiple security issues
// Scanner should flag: SSRF via fetch(req.body.url), redirect from query param,
// payment success trusting query params
// FAKE credentials only

import { NextRequest, NextResponse } from 'next/server';

// FAKE test secret — should be caught by secrets scanner
const STRIPE_SECRET_KEY = 'sk_live_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE5678';

// VULNERABLE: SSRF — fetch URL comes from request body without validation
export async function POST(request: NextRequest) {
  const body = await request.json();

  // VULNERABLE: fetch(variableUrl) — attacker controls the URL (SSRF)
  const webhookUrl = body.callbackUrl;
  const response = await fetch(webhookUrl, {
    method: 'POST',
    body: JSON.stringify({ status: 'processed' }),
  });

  return NextResponse.json({ ok: response.ok });
}

// VULNERABLE: Payment success trusting query parameter — attacker can craft ?success=true
export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);

  // VULNERABLE: Trusting success status from query param
  const success = searchParams.get('success');
  const orderId = searchParams.get('orderId');

  if (success === 'true') {
    // VULNERABLE: This can be triggered by anyone with ?success=true&orderId=anything
    await unlockPremiumFeatures(orderId ?? '');
    return NextResponse.redirect(new URL('/dashboard', request.url));
  }

  // VULNERABLE: Open redirect — returnUrl from query param without allowlist
  const returnUrl = searchParams.get('returnUrl') ?? '/';
  return NextResponse.redirect(returnUrl);
}

async function unlockPremiumFeatures(_orderId: string) { /* stub */ }
