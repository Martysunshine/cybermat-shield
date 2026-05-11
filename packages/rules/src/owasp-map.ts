import type { Finding } from '@cybermat/shared';

const TAG_TO_OWASP: Record<string, string[]> = {
  'idor':             ['A01 Broken Access Control'],
  'bola':             ['A01 Broken Access Control'],
  'access-control':   ['A01 Broken Access Control'],
  'rbac':             ['A01 Broken Access Control'],
  'admin':            ['A01 Broken Access Control'],
  'cors':             ['A02 Security Misconfiguration'],
  'headers':          ['A02 Security Misconfiguration'],
  'csp':              ['A02 Security Misconfiguration'],
  'config':           ['A02 Security Misconfiguration'],
  'supply-chain':     ['A03 Software Supply Chain Failures'],
  'dependency':       ['A03 Software Supply Chain Failures'],
  'lifecycle-script': ['A03 Software Supply Chain Failures'],
  'npm':              ['A03 Software Supply Chain Failures'],
  'secrets':          ['A04 Cryptographic Failures'],
  'localstorage':     ['A04 Cryptographic Failures'],
  'cookie':           ['A04 Cryptographic Failures'],
  'token':            ['A04 Cryptographic Failures'],
  'private-key':      ['A04 Cryptographic Failures'],
  'xss':              ['A05 Injection'],
  'sql-injection':    ['A05 Injection'],
  'command-injection': ['A05 Injection'],
  'eval':             ['A05 Injection'],
  'dom':              ['A05 Injection'],
  'ssrf':             ['A01 Broken Access Control', 'A05 Injection'],
  'prompt-injection': ['A05 Injection', 'A06 Insecure Design'],
  'rag':              ['A05 Injection', 'A06 Insecure Design'],
  'llm':              ['A05 Injection', 'A06 Insecure Design'],
  'ai-agent':         ['A06 Insecure Design', 'A08 Software or Data Integrity Failures'],
  'human-in-loop':    ['A06 Insecure Design'],
  'auth':             ['A07 Authentication Failures'],
  'middleware':       ['A07 Authentication Failures'],
  'jwt':              ['A04 Cryptographic Failures', 'A07 Authentication Failures'],
  'session':          ['A07 Authentication Failures'],
  'webhook':          ['A08 Software or Data Integrity Failures'],
  'integrity':        ['A08 Software or Data Integrity Failures'],
  'payment':          ['A08 Software or Data Integrity Failures'],
};

const PREFIX_TO_OWASP: Record<string, string[]> = {
  'secrets':        ['A04 Cryptographic Failures'],
  'injection':      ['A05 Injection'],
  'auth':           ['A01 Broken Access Control', 'A07 Authentication Failures'],
  'config':         ['A02 Security Misconfiguration'],
  'supply-chain':   ['A03 Software Supply Chain Failures'],
  'crypto':         ['A04 Cryptographic Failures'],
  'ai':             ['A05 Injection', 'A06 Insecure Design'],
};

export function mapFindingToOwasp(finding: Finding): string[] {
  const owaspSet = new Set(finding.owasp);

  for (const tag of finding.tags) {
    const mapped = TAG_TO_OWASP[tag.toLowerCase()];
    if (mapped) mapped.forEach(o => owaspSet.add(o));
  }

  const prefix = finding.ruleId.split('.')[0];
  const prefixMapped = PREFIX_TO_OWASP[prefix];
  if (prefixMapped) prefixMapped.forEach(o => owaspSet.add(o));

  return Array.from(owaspSet);
}
