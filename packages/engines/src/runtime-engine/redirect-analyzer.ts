import type { RuntimeFinding } from '@cybermat/shared';
import { RuntimeFindingBuilder } from './runtime-finding-builder';

export const REDIRECT_PARAMS = [
  'next', 'redirect', 'redirect_url', 'returnUrl',
  'callbackUrl', 'continue', 'url',
] as const;

export const SAFE_REDIRECT_TARGET = 'https://example.com/cybermat-redirect-test';

export function buildRedirectTestUrls(baseUrl: string): Array<{ url: string; param: string }> {
  return REDIRECT_PARAMS.map(param => ({
    url: `${baseUrl}?${param}=${encodeURIComponent(SAFE_REDIRECT_TARGET)}`,
    param,
  }));
}

export interface RedirectProbeResult {
  url: string;
  param: string;
  statusCode: number;
  locationHeader?: string;
}

export function analyzeRedirectResults(results: RedirectProbeResult[]): RuntimeFinding[] {
  const findings: RuntimeFinding[] = [];

  for (const result of results) {
    const loc = result.locationHeader ?? '';
    if (loc.startsWith('https://example.com/cybermat-redirect-test')) {
      findings.push(RuntimeFindingBuilder.redirect(
        'runtime.open-redirect',
        'Open Redirect',
        'high',
        result.url,
        result.param,
        `Parameter "${result.param}" caused a redirect to an attacker-controlled URL. Can be exploited in phishing and auth token theft.`,
        "Validate redirect targets against an allowlist of trusted internal paths. Reject arbitrary external URLs.",
        ['A01 Broken Access Control'],
      ));
    }
  }

  return findings;
}
