import type { RuntimeFinding, Severity } from '@cybermat/shared';
import { RuntimeFindingBuilder } from './runtime-finding-builder';

const A02 = 'A02 Security Misconfiguration';

export interface ExposedFileCheck {
  path: string;
  severity: Severity;
  description: string;
}

export const EXPOSED_FILE_CHECKS: ExposedFileCheck[] = [
  { path: '/.env', severity: 'critical', description: 'Environment file with secrets exposed publicly' },
  { path: '/.git/config', severity: 'critical', description: '.git/config exposed — reveals repo internals and potential tokens' },
  { path: '/package.json', severity: 'medium', description: 'package.json exposed — reveals dependency versions and project metadata' },
  { path: '/pnpm-lock.yaml', severity: 'low', description: 'pnpm lock file exposed — reveals exact dependency tree' },
  { path: '/yarn.lock', severity: 'low', description: 'yarn.lock exposed — reveals exact dependency tree' },
  { path: '/package-lock.json', severity: 'low', description: 'npm lock file exposed — reveals exact dependency tree' },
  { path: '/tsconfig.json', severity: 'medium', description: 'TypeScript config exposed — reveals internal project structure' },
  { path: '/next.config.js', severity: 'medium', description: 'Next.js config exposed — may reveal internal paths or env vars' },
  { path: '/vite.config.ts', severity: 'medium', description: 'Vite config exposed — reveals build configuration' },
  { path: '/swagger.json', severity: 'medium', description: 'Swagger spec exposed — full API surface visible to attackers' },
  { path: '/openapi.json', severity: 'medium', description: 'OpenAPI spec exposed — full API surface visible to attackers' },
  { path: '/api-docs', severity: 'medium', description: 'API documentation endpoint accessible — maps the entire API surface' },
  { path: '/graphql', severity: 'info', description: 'GraphQL endpoint found — verify introspection is disabled in production' },
  { path: '/metrics', severity: 'medium', description: 'Metrics endpoint exposed — may reveal internal application state' },
  { path: '/debug', severity: 'high', description: 'Debug endpoint exposed — may reveal stack traces, config, or memory dumps' },
];

export interface ExposedFileProbeResult {
  path: string;
  statusCode: number;
  contentType?: string;
  bodyPreview?: string;
}

function ruleId(filePath: string): string {
  return `runtime.exposed-file${filePath.replace(/[^a-z0-9]/gi, '-')}`;
}

export function analyzeExposedFiles(
  baseUrl: string,
  results: ExposedFileProbeResult[],
): RuntimeFinding[] {
  const findings: RuntimeFinding[] = [];
  const baseUrlClean = baseUrl.replace(/\/$/, '');

  for (const result of results) {
    if (result.statusCode !== 200) continue;
    const check = EXPOSED_FILE_CHECKS.find(c => c.path === result.path);
    if (!check) continue;

    const preview = result.bodyPreview ? ` Response preview: ${result.bodyPreview.slice(0, 60)}...` : '';
    findings.push(RuntimeFindingBuilder.exposedFile(
      ruleId(check.path),
      `Exposed File: ${check.path}`,
      check.severity,
      `${baseUrlClean}${check.path}`,
      check.path,
      check.description + preview,
      `Block public access to ${check.path} via server/CDN configuration. These files must not be served.`,
      [A02],
      result.statusCode,
    ));
  }

  return findings;
}
