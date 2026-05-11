import type { RuntimeFinding } from '@cybermat/shared';
import { RuntimeFindingBuilder } from './runtime-finding-builder';

export const CORS_TEST_ORIGINS = [
  'https://evil.example',
  'null',
  'http://localhost:9999',
] as const;

export interface CorsProbeResult {
  testOrigin: string;
  allowOrigin?: string;
  allowCredentials?: string;
  statusCode: number;
}

export function analyzeCorsResults(url: string, results: CorsProbeResult[]): RuntimeFinding[] {
  const findings: RuntimeFinding[] = [];

  for (const { testOrigin, allowOrigin, allowCredentials } of results) {
    if (!allowOrigin) continue;

    const credTrue = allowCredentials?.toLowerCase() === 'true';

    if (allowOrigin === '*' && credTrue) {
      findings.push(RuntimeFindingBuilder.cors(
        'runtime.cors-wildcard-credentials',
        'CORS Wildcard Origin with Credentials',
        'critical',
        url,
        testOrigin,
        'Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true enables cross-origin credential theft.',
        "Never combine wildcard ACAO with credentials=true. Use an explicit allowlist of trusted origins.",
      ));
    }

    if (allowOrigin === testOrigin && testOrigin !== 'null' && testOrigin !== '*') {
      const severity = credTrue ? 'critical' : 'high';
      findings.push(RuntimeFindingBuilder.cors(
        'runtime.cors-reflected-origin',
        'CORS Arbitrary Origin Reflected',
        severity,
        url,
        testOrigin,
        `Server reflects origin "${testOrigin}" in Access-Control-Allow-Origin${credTrue ? ' with credentials=true' : ''}. Any domain can make cross-origin requests.`,
        "Validate the Origin header against an explicit allowlist. Never reflect the request Origin directly.",
      ));
    }

    if (
      credTrue && allowOrigin && allowOrigin !== '*' && allowOrigin === testOrigin &&
      (testOrigin.includes('localhost') || testOrigin === 'null')
    ) {
      findings.push(RuntimeFindingBuilder.cors(
        'runtime.cors-dev-origin-allowed',
        'Development Origin Accepted by CORS Policy',
        'medium',
        url,
        testOrigin,
        `Dev origin "${testOrigin}" is accepted with credentials. This should not be allowed on production.`,
        "Remove localhost/null origins from your CORS allowlist before deploying to production.",
      ));
    }
  }

  return findings;
}
