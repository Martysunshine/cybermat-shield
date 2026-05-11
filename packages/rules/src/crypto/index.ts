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

        if (/localStorage\.setItem\s*\(/.test(line) && TOKEN_KEYS.test(line)) {
          findings.push({
            id: makeFindingId('crypto.token-in-localstorage', file.relativePath, i + 1),
            ruleId: 'crypto.token-in-localstorage',
            title: 'Auth Token Stored in localStorage',
            severity: 'high',
            confidence: 'high',
            owasp: ['A04 Cryptographic Failures', 'A07 Authentication Failures'],
            cwe: ['CWE-922'],
            category: 'Cryptography',
            file: file.relativePath,
            line: i + 1,
            evidence: {
              snippet: truncate(line),
              reason: 'Auth token written to localStorage — readable by any JavaScript on the page',
            },
            impact: 'localStorage is accessible to any JavaScript on the page. XSS attacks can steal tokens.',
            recommendation: 'Use HttpOnly cookies for session tokens instead of localStorage.',
            tags: ['localstorage', 'token', 'xss', 'session'],
          });
        }

        if (/sessionStorage\.setItem\s*\(/.test(line) && TOKEN_KEYS.test(line)) {
          findings.push({
            id: makeFindingId('crypto.token-in-sessionstorage', file.relativePath, i + 1),
            ruleId: 'crypto.token-in-sessionstorage',
            title: 'Auth Token Stored in sessionStorage',
            severity: 'medium',
            confidence: 'high',
            owasp: ['A04 Cryptographic Failures'],
            cwe: ['CWE-922'],
            category: 'Cryptography',
            file: file.relativePath,
            line: i + 1,
            evidence: {
              snippet: truncate(line),
              reason: 'Auth token written to sessionStorage — vulnerable to XSS',
            },
            impact: 'sessionStorage is accessible to any JavaScript on the page, vulnerable to XSS.',
            recommendation: 'Use HttpOnly cookies for session tokens instead of sessionStorage.',
            tags: ['sessionstorage', 'token', 'xss', 'session'],
          });
        }

        if (/(?:res\.cookie|document\.cookie|Set-Cookie)\s*[=(]/.test(line)) {
          const ctx5 = lines.slice(Math.max(0, i - 1), i + 3).join(' ');
          const missingHttpOnly = !/httpOnly\s*:\s*true|HttpOnly/i.test(ctx5);
          const missingSecure = !/secure\s*:\s*true|;\s*Secure/i.test(ctx5);
          const missingSameSite = !/sameSite|SameSite/i.test(ctx5);

          if (missingHttpOnly || missingSecure || missingSameSite) {
            const missing = [
              missingHttpOnly && 'HttpOnly',
              missingSecure && 'Secure',
              missingSameSite && 'SameSite',
            ].filter(Boolean).join(', ');

            findings.push({
              id: makeFindingId('crypto.insecure-cookie', file.relativePath, i + 1),
              ruleId: 'crypto.insecure-cookie',
              title: `Cookie Missing Security Flags: ${missing}`,
              severity: 'medium',
              confidence: 'low',
              owasp: ['A04 Cryptographic Failures', 'A07 Authentication Failures'],
              cwe: ['CWE-614', 'CWE-1004'],
              category: 'Cryptography',
              file: file.relativePath,
              line: i + 1,
              evidence: {
                snippet: truncate(line),
                reason: `Cookie set without: ${missing}`,
              },
              impact: `Missing ${missing} makes cookies vulnerable to XSS, network interception, or CSRF.`,
              recommendation: 'Set cookies with HttpOnly, Secure, and SameSite=Lax (or Strict) flags.',
              tags: ['cookie', 'session', 'csrf', 'xss'],
            });
          }
        }
      }
    }

    return findings;
  },
};
