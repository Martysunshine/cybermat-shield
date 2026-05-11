import type { RulePack } from '@cybermat/shared';

export const runtimePack: RulePack = {
  id: 'runtime',
  name: 'Runtime Scanner',
  description: 'Safe browser-based runtime checks: missing security headers, insecure cookies, CORS misconfigurations, open redirects, and reflected input detection (Phase 6)',
  rules: [],
};
