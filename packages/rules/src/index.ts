import type { Rule } from '@cybermat/shared';
import { secretsRule } from './secrets';
import { injectionRule } from './injection';
import { authRule } from './auth';
import { configRule } from './config';
import { cryptoRule } from './crypto';
import { supplyChainRule } from './supply-chain';
import { aiSecurityRule } from './ai';

export const allRules: Rule[] = [
  secretsRule,
  injectionRule,
  authRule,
  configRule,
  cryptoRule,
  supplyChainRule,
  aiSecurityRule,
];

export {
  secretsRule,
  injectionRule,
  authRule,
  configRule,
  cryptoRule,
  supplyChainRule,
  aiSecurityRule,
};
