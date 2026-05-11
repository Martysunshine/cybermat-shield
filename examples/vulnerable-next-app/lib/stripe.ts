// VULNERABLE EXAMPLE — Fake Stripe secret hardcoded in source (not just .env)
// Scanner should detect this even in a .ts file

// FAKE TEST VALUE ONLY
const STRIPE_KEY = 'sk_live_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE5678';

export function getStripeClient() {
  // In a real app, use process.env.STRIPE_SECRET_KEY instead
  return { key: STRIPE_KEY };
}
