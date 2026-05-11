import type { Rule } from '@cybermat/shared';
import { secretsRule } from './secrets';
import { injectionRule } from './injection';
import { authRule } from './auth';
import { configRule } from './config';
import { cryptoRule } from './crypto';
import { supplyChainRule } from './supply-chain';
import { aiSecurityRule } from './ai';
import { runtimeRules } from './runtime';
import { authzRules } from './authz';

/** All code-scanner rules (Layer 1) */
export const codeRules: Rule[] = [
  secretsRule,
  injectionRule,
  authRule,
  configRule,
  cryptoRule,
  supplyChainRule,
  aiSecurityRule,
];

/** All rules active during a default `appsec scan` */
export const allRules: Rule[] = codeRules;

export {
  secretsRule,
  injectionRule,
  authRule,
  configRule,
  cryptoRule,
  supplyChainRule,
  aiSecurityRule,
  runtimeRules,
  authzRules,
};
