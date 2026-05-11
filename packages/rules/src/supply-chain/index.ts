import type { Rule, Finding, RuleContext } from '@cybermat/shared';
import { makeFindingId } from '../utils';

const DANGEROUS_LIFECYCLE_SCRIPTS = ['postinstall', 'preinstall', 'prepare', 'install'];

export const supplyChainRule: Rule = {
  id: 'supply-chain',
  name: 'Supply Chain & Dependencies',
  description: 'Detects risky dependency patterns, suspicious lifecycle scripts, and missing lockfiles',
  category: 'Supply Chain',
  owasp: ['A03 Software Supply Chain Failures'],
  severity: 'medium',
  run: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    if (!context.packageJson) return findings;

    const pkg = context.packageJson;
    const scripts = (pkg.scripts as Record<string, string>) || {};
    const deps = (pkg.dependencies as Record<string, string>) || {};
    const devDeps = (pkg.devDependencies as Record<string, string>) || {};
    const allDeps = { ...deps, ...devDeps };

    // Suspicious lifecycle scripts
    for (const scriptName of DANGEROUS_LIFECYCLE_SCRIPTS) {
      if (scripts[scriptName]) {
        const scriptValue = scripts[scriptName];
        const isSuspicious = /curl|wget|eval|exec|fetch|base64|atob|btoa|sh\s|bash\s|python|node\s+-e/.test(scriptValue);

        findings.push({
          id: makeFindingId(`supply-chain.lifecycle-${scriptName}`, 'package.json', 0),
          title: `Lifecycle Script: ${scriptName}`,
          severity: isSuspicious ? 'high' : 'medium',
          confidence: isSuspicious ? 'high' : 'low',
          owasp: ['A03 Software Supply Chain Failures'],
          category: 'Supply Chain',
          file: 'package.json',
          evidence: `"${scriptName}": "${scriptValue}"`,
          impact: isSuspicious
            ? 'This lifecycle script runs automatically on install and contains suspicious commands that may execute malicious code.'
            : 'Lifecycle scripts run automatically on npm install. Malicious packages can exploit this to run code on developer machines.',
          recommendation: isSuspicious
            ? 'Audit this lifecycle script carefully. Consider using --ignore-scripts during installs.'
            : 'Audit this lifecycle script to ensure it only performs expected operations.',
        });
      }
    }

    // Wildcard dependency versions
    for (const [name, version] of Object.entries(allDeps)) {
      if (version === '*' || version === 'x' || version === 'latest') {
        findings.push({
          id: makeFindingId('supply-chain.wildcard-version', 'package.json', 0),
          title: `Wildcard Dependency Version: ${name}`,
          severity: 'medium',
          confidence: 'high',
          owasp: ['A03 Software Supply Chain Failures'],
          category: 'Supply Chain',
          file: 'package.json',
          evidence: `"${name}": "${version}"`,
          impact: 'Wildcard versions allow any version of the package to be installed, including ones with known vulnerabilities or malicious code.',
          recommendation: `Pin "${name}" to a specific version or use a conservative semver range like "^x.y.z".`,
        });
      }
    }

    // Check for missing lockfile
    const hasLockfile = context.files.some(f => {
      const base = f.relativePath.split('/').pop() ?? '';
      return ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb', 'bun.lock'].includes(base);
    });

    if (!hasLockfile) {
      findings.push({
        id: makeFindingId('supply-chain.missing-lockfile', 'package.json', 0),
        title: 'Missing Dependency Lockfile',
        severity: 'medium',
        confidence: 'high',
        owasp: ['A03 Software Supply Chain Failures'],
        category: 'Supply Chain',
        file: 'package.json',
        evidence: 'No lockfile found (package-lock.json, pnpm-lock.yaml, yarn.lock)',
        impact: 'Without a lockfile, dependency resolution is non-deterministic and can install unexpected versions.',
        recommendation: 'Commit a lockfile to version control. Run pnpm install / npm install / yarn to generate one.',
      });
    }

    return findings;
  },
};
