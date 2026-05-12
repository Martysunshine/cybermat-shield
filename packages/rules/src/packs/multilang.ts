import type { RulePack, RuleMetadata } from '@cybermat/shared';
import { MULTILANG_DETECTORS } from '@cybermat/engines';

function categoryFromId(id: string): string {
  if (id.startsWith('docker.')) return 'Container Security';
  if (id.startsWith('shell.')) return 'Shell Security';
  if (id.startsWith('terraform.') || id.startsWith('k8s.')) return 'Infrastructure Security';
  if (id.startsWith('python.')) return 'Python Security';
  if (id.startsWith('php.')) return 'PHP Security';
  if (id.startsWith('cicd.')) return 'CI/CD Security';
  return 'Multi-language Security';
}

export const multilangPack: RulePack = {
  id: 'multilang',
  name: 'Multi-language Dangerous Patterns',
  description: 'Dangerous code patterns across Docker, Shell, Terraform, Kubernetes, Python, PHP, and CI/CD pipelines. Pattern-based — does not require AST parsing.',
  rules: MULTILANG_DETECTORS.map((d): RuleMetadata => ({
    id: d.id,
    name: d.name,
    description: d.impact,
    engine: 'static',
    category: categoryFromId(d.id),
    severity: d.severity,
    confidence: d.confidence,
    owasp2025: d.owasp,
    cwe: d.cwe,
    tags: d.tags,
    enabledByDefault: true,
    safeForCI: true,
    requiresRuntime: false,
    requiresAuth: false,
    remediation: d.recommendation,
  })),
};
