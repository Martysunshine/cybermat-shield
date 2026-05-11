import { RuleRegistry } from '../registry';
import { secretsPack } from './secrets';
import { injectionPack } from './injection';
import { authPack } from './auth';
import { configPack } from './config';
import { cryptoPack } from './crypto';
import { supplyChainPack } from './supply-chain';
import { aiSecurityPack } from './ai-security';
import { runtimePack } from './runtime';
import { authzPack } from './authz';

export {
  secretsPack,
  injectionPack,
  authPack,
  configPack,
  cryptoPack,
  supplyChainPack,
  aiSecurityPack,
  runtimePack,
  authzPack,
};

export const defaultRegistry = new RuleRegistry();
defaultRegistry.registerRulePack(secretsPack);
defaultRegistry.registerRulePack(injectionPack);
defaultRegistry.registerRulePack(authPack);
defaultRegistry.registerRulePack(configPack);
defaultRegistry.registerRulePack(cryptoPack);
defaultRegistry.registerRulePack(supplyChainPack);
defaultRegistry.registerRulePack(aiSecurityPack);
defaultRegistry.registerRulePack(runtimePack);
defaultRegistry.registerRulePack(authzPack);
