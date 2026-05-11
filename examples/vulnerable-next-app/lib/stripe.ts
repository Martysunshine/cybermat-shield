// VULNERABLE EXAMPLE — Stripe secret key hardcoded in source
// Scanner should flag: secrets.stripe-secret-key (critical)
// Also: payment intent from client-controlled amount without server allowlist
// FAKE key — not a real credential

// FAKE TEST VALUE ONLY — should trigger secrets.stripe-secret-key
const STRIPE_SECRET_KEY = 'sk_live_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE5678';

export function getStripeClient() {
  // VULNERABLE: Using hardcoded key instead of process.env.STRIPE_SECRET_KEY
  return { key: STRIPE_SECRET_KEY };
}

// VULNERABLE: Payment intent amount comes from client without server-side allowlist
export async function createPaymentIntentFromBody(amount: number, currency: string) {
  // Client controls 'amount' — attacker can pay $0.01 for a $100 item
  return { amount, currency, key: STRIPE_SECRET_KEY };
}

// VULNERABLE: Price ID from client with no allowlist
export async function createCheckoutSession(priceId: string) {
  // priceId comes from the client without server-side allowlist validation
  return { priceId, secretKey: STRIPE_SECRET_KEY };
}
