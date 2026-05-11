import type { CrawledCookie, RuntimeFinding } from '@cybermat/shared';
import { RuntimeFindingBuilder } from './runtime-finding-builder';

const A07 = 'A07 Authentication Failures';
const A04 = 'A04 Cryptographic Failures';

const AUTH_NAME_RE = /^(session|auth|token|jwt|sid|connect\.sid|__session|next-auth|supabase-auth)/i;
const JWT_RE = /^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

function isAuthCookie(name: string): boolean {
  return AUTH_NAME_RE.test(name);
}

function isJwtLike(value: string): boolean {
  return JWT_RE.test(value);
}

export function analyzeCookies(
  url: string,
  cookies: CrawledCookie[],
  isHttps: boolean,
): RuntimeFinding[] {
  const findings: RuntimeFinding[] = [];

  for (const cookie of cookies) {
    const auth = isAuthCookie(cookie.name);

    if (auth && !cookie.httpOnly) {
      findings.push(RuntimeFindingBuilder.cookie(
        'runtime.cookie-missing-httponly',
        'Session Cookie Missing HttpOnly Flag',
        'high',
        url,
        cookie.name,
        `Auth cookie "${cookie.name}" is accessible via JavaScript (no HttpOnly). Enables session hijacking via XSS.`,
        `Set-Cookie: ${cookie.name}=...; HttpOnly; Secure; SameSite=Lax`,
        [A07],
      ));
    }

    if (auth && isHttps && !cookie.secure) {
      findings.push(RuntimeFindingBuilder.cookie(
        'runtime.cookie-missing-secure',
        'Session Cookie Missing Secure Flag',
        'high',
        url,
        cookie.name,
        `Auth cookie "${cookie.name}" will transmit over HTTP. Can be intercepted in transit.`,
        `Set-Cookie: ${cookie.name}=...; Secure`,
        [A07, A04],
      ));
    }

    if (auth && (!cookie.sameSite || cookie.sameSite.toLowerCase() === 'none')) {
      findings.push(RuntimeFindingBuilder.cookie(
        'runtime.cookie-missing-samesite',
        'Session Cookie Missing SameSite Attribute',
        'medium',
        url,
        cookie.name,
        `Auth cookie "${cookie.name}" has no SameSite attribute. Vulnerable to CSRF attacks.`,
        `Set-Cookie: ${cookie.name}=...; SameSite=Lax`,
        [A07],
      ));
    }

    if (isJwtLike(cookie.value)) {
      findings.push(RuntimeFindingBuilder.cookie(
        'runtime.cookie-jwt-value',
        'JWT Stored in Cookie',
        'info',
        url,
        cookie.name,
        `Cookie "${cookie.name}" contains a JWT. Ensure HttpOnly, Secure, and SameSite=Strict are set.`,
        'Use HttpOnly + Secure + SameSite=Strict for JWT cookies to prevent XSS theft.',
        [A07],
      ));
    }

    if (cookie.expires && cookie.expires > 0) {
      const daysUntilExpiry = (cookie.expires * 1000 - Date.now()) / 86_400_000;
      if (daysUntilExpiry > 30) {
        findings.push(RuntimeFindingBuilder.cookie(
          'runtime.cookie-long-expiry',
          'Cookie with Long Expiry',
          'low',
          url,
          cookie.name,
          `Cookie "${cookie.name}" expires in ${Math.round(daysUntilExpiry)} days. Long-lived sessions increase the attack window.`,
          'Reduce session lifetime to 7–30 days and implement refresh token rotation.',
          [A07],
        ));
      }
    }
  }

  return findings;
}
