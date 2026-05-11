import type { Rule, Finding, RuleContext } from '@cybermat/shared';
import { makeFindingId, truncate } from '../utils';

export const cryptoRule: Rule = {
  id: 'crypto',
  name: 'Cryptography & Session Security',
  description: 'Detects insecure token storage and misconfigured cookie settings',
  category: 'Cryptography',
  owasp: ['A04 Cryptographic Failures', 'A07 Authentication Failures'],
  severity: 'high',
  run: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    const TOKEN_KEYS = /['"`](?:token|jwt|session|access_token|refresh_token|auth_token|id_token)['"`]/i;

    for (const file of context.files) {
      if (!['.ts', '.tsx', '.js', '.jsx', '.mjs'].includes(file.extension)) continue;
      const lines = file.content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!line.trim() || line.trim().startsWith('//')) continue;

        // localStorage/sessionStorage with token-like keys
        if (/localStorage\.setItem\s*\(/.test(line) && TOKEN_KEYS.test(line)) {
          findings.push({
            id: makeFindingId('crypto.token-in-localstorage', file.relativePath, i + 1),
            title: 'Auth Token Stored in localStorage',
            severity: 'high',
            confidence: 'high',
            owasp: ['A04 Cryptographic Failures', 'A07 Authentication Failures'],
            category: 'Cryptography',
            file: file.relativePath,
            line: i + 1,
            evidence: truncate(line),
            impact: 'localStorage is accessible to any JavaScript on the page. XSS attacks can steal tokens.',
            recommendation: 'Use HttpOnly cookies for session tokens instead of localStorage.',
          });
        }

        if (/sessionStorage\.setItem\s*\(/.test(line) && TOKEN_KEYS.test(line)) {
          findings.push({
            id: makeFindingId('crypto.token-in-sessionstorage', file.relativePath, i + 1),
            title: 'Auth Token Stored in sessionStorage',
            severity: 'medium',
            confidence: 'high',
            owasp: ['A04 Cryptographic Failures'],
            category: 'Cryptography',
            file: file.relativePath,
            line: i + 1,
            evidence: truncate(line),
            impact: 'sessionStorage is accessible to any JavaScript on the page, vulnerable to XSS.',
            recommendation: 'Use HttpOnly cookies for session tokens instead of sessionStorage.',
          });
        }

        // Cookie set without security flags
        if (/(?:res\.cookie|document\.cookie|Set-Cookie)\s*[=(]/.test(line)) {
          const context5 = lines.slice(Math.max(0, i - 1), i + 3).join(' ');
          const missingHttpOnly = !/httpOnly\s*:\s*true|HttpOnly/i.test(context5);
          const missingSecure = !/secure\s*:\s*true|;\s*Secure/i.test(context5);
          const missingSameSite = !/sameSite|SameSite/i.test(context5);

          if (missingHttpOnly || missingSecure || missingSameSite) {
            const missing = [
              missingHttpOnly && 'HttpOnly',
              missingSecure && 'Secure',
              missingSameSite && 'SameSite',
            ].filter(Boolean).join(', ');

            findings.push({
              id: makeFindingId('crypto.insecure-cookie', file.relativePath, i + 1),
              title: `Cookie Missing Security Flags: ${missing}`,
              severity: 'medium',
              confidence: 'low',
              owasp: ['A04 Cryptographic Failures', 'A07 Authentication Failures'],
              category: 'Cryptography',
              file: file.relativePath,
              line: i + 1,
              evidence: truncate(line),
              impact: `Missing ${missing} makes cookies vulnerable to XSS, network interception, or CSRF.`,
              recommendation: `Set cookies with HttpOnly, Secure, and SameSite=Lax (or Strict) flags.`,
            });
          }
        }
      }
    }

    return findings;
  },
};
