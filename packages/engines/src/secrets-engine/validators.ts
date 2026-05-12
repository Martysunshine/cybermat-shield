/**
 * Local structure validators for common secret formats.
 * These perform no network calls — they only check value shape/format.
 * A failed validation downgrades confidence to 'low' rather than discarding the finding.
 */

/** JWT: three base64url segments separated by dots */
export function isJwtShape(value: string): boolean {
  const parts = value.split('.');
  if (parts.length !== 3) return false;
  return parts.every(p => /^[A-Za-z0-9_\-]+={0,2}$/.test(p) && p.length > 0);
}

/** Stripe live/test secret or restricted key */
export function isStripeKey(value: string): boolean {
  return /^(sk_live_|sk_test_|rk_live_)[A-Za-z0-9]{20,}$/.test(value);
}

/** OpenAI API key */
export function isOpenAIKey(value: string): boolean {
  // sk- prefix, 48 chars total is common; sk-proj- is newer format
  return /^sk-(proj-)?[A-Za-z0-9\-_]{20,}$/.test(value);
}

/** Anthropic API key */
export function isAnthropicKey(value: string): boolean {
  return /^sk-ant-[A-Za-z0-9\-_]{20,}$/.test(value);
}

/** AWS access key ID: starts with AKIA (or ASIA for temporary), exactly 20 chars */
export function isAWSAccessKey(value: string): boolean {
  return /^(AKIA|ASIA|AROA|AIDA|ANPA|ANVA|APKA)[A-Z0-9]{16}$/.test(value);
}

/** PEM block: contains BEGIN and END markers */
export function isPemBlock(value: string): boolean {
  return value.includes('-----BEGIN') && value.includes('-----END');
}

/** GitHub personal access token or app token */
export function isGitHubToken(value: string): boolean {
  // Classic: ghp_, gho_, ghs_, ghu_ prefixes; fine-grained: github_pat_
  return /^(ghp_|gho_|ghs_|ghu_|github_pat_)[A-Za-z0-9_]{20,}$/.test(value);
}

/** Supabase service role or anon key: looks like a JWT */
export function isSupabaseKey(value: string): boolean {
  return isJwtShape(value);
}

/** Generic: likely a placeholder / example value */
export function isLikelyPlaceholder(value: string): boolean {
  const lower = value.toLowerCase();
  return (
    lower.includes('your_') ||
    lower.includes('_here') ||
    lower.includes('_placeholder') ||
    lower.includes('_example') ||
    lower.includes('changeme') ||
    lower.includes('replace_me') ||
    lower.includes('xxxxxxxxxx') ||
    lower.includes('0000000000') ||
    /^(.)\1{6,}$/.test(value)  // repeated character
  );
}
