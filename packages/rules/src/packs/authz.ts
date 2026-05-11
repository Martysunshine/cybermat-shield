import type { RulePack } from '@cybermat/shared';

export const authzPack: RulePack = {
  id: 'authz',
  name: 'Auth/Access Control Scanner',
  description: 'Authenticated testing for IDOR/BOLA, vertical privilege escalation, anonymous access, and tenant boundary violations (Phase 7)',
  rules: [],
};
