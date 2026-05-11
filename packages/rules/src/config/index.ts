import type { Rule, Finding, RuleContext } from '@cybermat/shared';
import { makeFindingId, truncate } from '../utils';

export const configRule: Rule = {
  id: 'config',
  name: 'Configuration & Misconfiguration',
  description: 'Detects insecure CORS, missing security headers, and exposed config files',
  category: 'Configuration',
  owasp: ['A02 Security Misconfiguration'],
  severity: 'medium',
  run: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    // Check for exposed .env files
    const envFiles = context.files.filter(f => {
      const basename = f.relativePath.split('/').pop() ?? '';
      return basename === '.env' || basename === '.env.production' || basename === '.env.staging';
    });
    for (const env of envFiles) {
      if (env.content.trim().length > 0 && !env.content.includes('# FAKE') && !env.content.includes('# TEST')) {
        findings.push({
          id: makeFindingId('config.exposed-env-file', env.relativePath, 0),
          ruleId: 'config.exposed-env-file',
          title: 'Environment File Potentially Committed',
          severity: 'high',
          confidence: 'medium',
          owasp: ['A02 Security Misconfiguration', 'A04 Cryptographic Failures'],
          cwe: ['CWE-312'],
          category: 'Configuration',
          file: env.relativePath,
          evidence: {
            reason: `.env file present in scanned directory: ${env.relativePath}`,
          },
          impact: 'If committed to version control, secrets in this file are exposed to everyone with repo access.',
          recommendation: 'Add .env to .gitignore. Use .env.example for documentation. Rotate any real secrets.',
          tags: ['env-file', 'secrets', 'config'],
        });
      }
    }

    // CORS misconfigurations in source files
    for (const file of context.files) {
      if (!['.ts', '.js', '.tsx', '.jsx'].includes(file.extension)) continue;
      const lines = file.content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        if (/origin\s*[:=]\s*['"`]\*['"`]/.test(line) || /Access-Control-Allow-Origin.*\*/.test(line)) {
          const nextLines = lines.slice(i, i + 5).join('\n');
          const hasCredentials = /credentials.*true|Access-Control-Allow-Credentials.*true/.test(nextLines);

          findings.push({
            id: makeFindingId('config.cors-wildcard-origin', file.relativePath, i + 1),
            ruleId: 'config.cors-wildcard-origin',
            title: hasCredentials ? 'CORS Wildcard Origin with Credentials' : 'Permissive CORS Wildcard Origin',
            severity: hasCredentials ? 'critical' : 'medium',
            confidence: 'high',
            owasp: ['A02 Security Misconfiguration'],
            cwe: ['CWE-942'],
            category: 'Configuration',
            file: file.relativePath,
            line: i + 1,
            evidence: {
              snippet: truncate(line),
              reason: hasCredentials
                ? 'CORS wildcard origin combined with credentials:true'
                : 'CORS wildcard origin allows any website to make requests',
            },
            impact: hasCredentials
              ? 'Attackers from any origin can make credentialed cross-origin requests, enabling session hijacking.'
              : 'Any website can make requests to your API, exposing data to unauthorized origins.',
            recommendation: 'Restrict CORS to specific allowed origins. Never use credentials:true with origin:*.',
            tags: ['cors', 'config', 'headers'],
          });
        }
      }
    }

    // next.config.js security checks
    const nextConfig = context.files.find(f =>
      f.relativePath === 'next.config.js' ||
      f.relativePath === 'next.config.ts' ||
      f.relativePath === 'next.config.mjs'
    );
    if (nextConfig && context.detectedStack.frameworks.includes('Next.js')) {
      if (!nextConfig.content.includes('headers()') && !nextConfig.content.includes('headers:')) {
        findings.push({
          id: makeFindingId('config.next-missing-security-headers', nextConfig.relativePath, 0),
          ruleId: 'config.next-missing-security-headers',
          title: 'Missing Security Headers in next.config.js',
          severity: 'medium',
          confidence: 'high',
          owasp: ['A02 Security Misconfiguration'],
          cwe: ['CWE-693'],
          category: 'Configuration',
          file: nextConfig.relativePath,
          evidence: {
            reason: 'next.config.js has no headers() configuration — CSP, HSTS, X-Frame-Options not set',
          },
          impact: 'Without security headers (CSP, HSTS, X-Frame-Options), browsers offer no extra protection layer.',
          recommendation: 'Add a headers() function in next.config.js to set Content-Security-Policy, HSTS, X-Frame-Options, X-Content-Type-Options.',
          tags: ['nextjs', 'headers', 'csp', 'hsts'],
        });
      }

      if (/productionBrowserSourceMaps\s*:\s*true/.test(nextConfig.content)) {
        findings.push({
          id: makeFindingId('config.next-source-maps', nextConfig.relativePath, 0),
          ruleId: 'config.next-source-maps',
          title: 'Production Source Maps Enabled',
          severity: 'medium',
          confidence: 'high',
          owasp: ['A02 Security Misconfiguration'],
          cwe: ['CWE-540'],
          category: 'Configuration',
          file: nextConfig.relativePath,
          evidence: {
            snippet: 'productionBrowserSourceMaps: true',
            reason: 'Source maps expose original application code in production',
          },
          impact: 'Source maps expose original application code to anyone viewing the site, aiding reverse engineering.',
          recommendation: 'Remove productionBrowserSourceMaps:true from next.config.js unless intentional for error tracking.',
          tags: ['nextjs', 'source-maps', 'config'],
        });
      }
    }

    return findings;
  },
};
