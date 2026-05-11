import type { RulePack, RuleMetadata } from '@cybermat/shared';
import type { SecretDetector } from '@cybermat/engines';
import { SECRET_DETECTORS } from '@cybermat/engines';

function detectorToMetadata(d: SecretDetector): RuleMetadata {
  return {
    id: d.id,
    name: d.name,
    description: d.impact,
    engine: 'secrets',
    category: 'Secrets',
    severity: d.baseSeverity,
    confidence: d.confidence ?? 'high',
    owasp2025: d.owasp,
    cwe: d.cwe,
    tags: d.tags,
    enabledByDefault: true,
    safeForCI: true,
    requiresRuntime: false,
    requiresAuth: false,
    remediation: d.recommendation,
    insecureExample: `const key = "actual-secret-value"; // hardcoded — never do this`,
    saferExample: `const key = process.env.${d.id.replace('secrets.', '').toUpperCase().replace(/-/g, '_')}; // from environment`,
  };
}

export const secretsPack: RulePack = {
  id: 'secrets',
  name: 'Secret Detection',
  description: 'Detects API keys, credentials, and secrets across 60+ provider-specific and generic patterns',
  rules: SECRET_DETECTORS.map(detectorToMetadata),
};
