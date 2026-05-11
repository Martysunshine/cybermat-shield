import type { RuntimeFinding } from '@cybermat/shared';
import { RuntimeFindingBuilder } from './runtime-finding-builder';

const A02 = 'A02 Security Misconfiguration';
const A05 = 'A05 Injection';

export function analyzeHeaders(
  url: string,
  headers: Record<string, string>,
  isHttps: boolean,
): RuntimeFinding[] {
  const findings: RuntimeFinding[] = [];
  const h = (name: string): string | undefined => headers[name.toLowerCase()];

  const csp = h('content-security-policy');

  if (!csp) {
    findings.push(RuntimeFindingBuilder.header(
      'runtime.missing-csp',
      'Missing Content-Security-Policy Header',
      'high',
      url,
      'content-security-policy',
      'No Content-Security-Policy header. CSP prevents XSS by controlling loadable resources.',
      "Add a restrictive CSP: Content-Security-Policy: default-src 'self'",
      [A05, A02],
    ));
  } else {
    const weakDirectives: string[] = [];
    if (csp.includes("'unsafe-inline'")) weakDirectives.push("'unsafe-inline'");
    if (csp.includes("'unsafe-eval'")) weakDirectives.push("'unsafe-eval'");
    if (weakDirectives.length > 0) {
      findings.push(RuntimeFindingBuilder.header(
        'runtime.weak-csp',
        'Weak Content-Security-Policy',
        'medium',
        url,
        'content-security-policy',
        `CSP uses weak directives: ${weakDirectives.join(', ')}. These allow inline scripts or eval, enabling XSS.`,
        "Remove 'unsafe-inline' and 'unsafe-eval' from your CSP. Use nonces or hashes instead.",
        [A05, A02],
        csp,
      ));
    }
  }

  if (isHttps && !h('strict-transport-security')) {
    findings.push(RuntimeFindingBuilder.header(
      'runtime.missing-hsts',
      'Missing Strict-Transport-Security Header',
      'medium',
      url,
      'strict-transport-security',
      'No HSTS header on an HTTPS site. Allows protocol downgrade attacks.',
      'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
      [A02],
    ));
  }

  if (!h('x-frame-options') && !(csp?.includes('frame-ancestors'))) {
    findings.push(RuntimeFindingBuilder.header(
      'runtime.missing-x-frame-options',
      'Missing Clickjacking Protection',
      'medium',
      url,
      'x-frame-options',
      'No X-Frame-Options or CSP frame-ancestors. The page may be embeddable in iframes (clickjacking).',
      "Add: X-Frame-Options: DENY, or CSP: frame-ancestors 'none'",
      [A02],
    ));
  }

  if (!h('x-content-type-options')) {
    findings.push(RuntimeFindingBuilder.header(
      'runtime.missing-x-content-type-options',
      'Missing X-Content-Type-Options Header',
      'low',
      url,
      'x-content-type-options',
      'No X-Content-Type-Options header. Browsers may MIME-sniff responses, enabling MIME confusion attacks.',
      'Add: X-Content-Type-Options: nosniff',
      [A02],
    ));
  }

  if (!h('referrer-policy')) {
    findings.push(RuntimeFindingBuilder.header(
      'runtime.missing-referrer-policy',
      'Missing Referrer-Policy Header',
      'low',
      url,
      'referrer-policy',
      'No Referrer-Policy header. The full URL may be sent in Referer headers to third parties.',
      'Add: Referrer-Policy: strict-origin-when-cross-origin',
      [A02],
    ));
  }

  return findings;
}
