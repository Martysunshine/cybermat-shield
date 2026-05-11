// VULNERABLE EXAMPLE — Fake private key fixture
// Scanner should flag: secrets.private-key (critical)
// These are FAKE test keys — not real credentials

export const FAKE_RSA_PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5TNJKK5PdXMjFIHDIRRHKtNVWnJpRFQID
FAKE_FAKE_FAKE_THIS_IS_NOT_A_REAL_PRIVATE_KEY_IT_IS_FOR_SCANNER_TESTING
ONLYTHISISBOGUSDONOTUSEINPRODUCTIONTHISISFORTESTINGCYBERMATSCANNERONLY
MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5TNJKFAKEkeyfortest123456789
-----END RSA PRIVATE KEY-----`;

// VULNERABLE: Private key stored in source code (not in env/secrets manager)
// Should trigger secrets.private-key rule

// Also — hardcoded JWT secret (another finding)
export const JWT_SIGNING_SECRET = 'hardcoded-jwt-secret-very-insecure-1234567890';

// VULNERABLE: Token stored in module scope (accessible to any import)
export let sessionToken = '';
export function setSessionToken(token: string) {
  sessionToken = token;
  // VULNERABLE: also storing in localStorage
  if (typeof window !== 'undefined') {
    localStorage.setItem('auth_token', token);
  }
}
