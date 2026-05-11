import type { Rule, Finding, RuleContext } from '@cybermat/shared';
import { scanFilesForSecrets, secretFindingToFinding } from '@cybermat/engines';

export const secretsRule: Rule = {
  id: 'secrets',
  name: 'Secret Detection',
  description: 'Detects API keys, credentials, and secrets across 60+ provider-specific and generic patterns',
  category: 'Secrets',
  owasp: ['A04 Cryptographic Failures'],
  severity: 'critical',
  run: async (context: RuleContext): Promise<Finding[]> => {
    const secretFindings = scanFilesForSecrets(context.files);
    return secretFindings.map(secretFindingToFinding);
  },
};
