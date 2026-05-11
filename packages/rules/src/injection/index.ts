import type { Rule, Finding, RuleContext } from '@cybermat/shared';
import { truncate, makeFindingId } from '../utils';

interface InjectionPattern {
  id: string;
  name: string;
  pattern: RegExp;
  severity: 'critical' | 'high' | 'medium';
  confidence: 'high' | 'medium' | 'low';
  owasp: string[];
  cwe: string[];
  tags: string[];
  impact: string;
  recommendation: string;
  skip?: string[];
}

const INJECTION_PATTERNS: InjectionPattern[] = [
  {
    id: 'injection.dangerous-set-inner-html',
    name: 'dangerouslySetInnerHTML Usage',
    pattern: /dangerouslySetInnerHTML\s*=\s*\{/,
    severity: 'high',
    confidence: 'medium',
    owasp: ['A05 Injection'],
    cwe: ['CWE-79'],
    tags: ['xss', 'react', 'dom'],
    impact: 'XSS attacks can execute malicious scripts in users\' browsers via unescaped HTML.',
    recommendation: 'Avoid dangerouslySetInnerHTML. Use DOMPurify to sanitize HTML if rendering is required.',
  },
  {
    id: 'injection.inner-html-assignment',
    name: 'innerHTML / outerHTML / insertAdjacentHTML',
    pattern: /\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML\s*\(/,
    severity: 'high',
    confidence: 'medium',
    owasp: ['A05 Injection'],
    cwe: ['CWE-79'],
    tags: ['xss', 'dom'],
    impact: 'XSS attacks through unsanitized HTML injection into the DOM.',
    recommendation: 'Use textContent for plain text. Sanitize with DOMPurify before assigning innerHTML.',
  },
  {
    id: 'injection.document-write',
    name: 'document.write Usage',
    pattern: /document\.write\s*\(/,
    severity: 'high',
    confidence: 'high',
    owasp: ['A05 Injection'],
    cwe: ['CWE-79'],
    tags: ['xss', 'dom'],
    impact: 'document.write can be exploited for XSS and also blocks page rendering.',
    recommendation: 'Replace with safe DOM manipulation APIs (createElement, appendChild, textContent).',
  },
  {
    id: 'injection.eval-usage',
    name: 'eval() / new Function() Usage',
    pattern: /(?<!\w)eval\s*\(|new\s+Function\s*\(/,
    severity: 'high',
    confidence: 'high',
    owasp: ['A05 Injection'],
    cwe: ['CWE-78', 'CWE-79'],
    tags: ['code-injection', 'eval'],
    impact: 'Code injection and XSS attacks via dynamic code execution.',
    recommendation: 'Never use eval() or new Function() with untrusted input. Redesign logic using safe alternatives.',
  },
  {
    id: 'injection.settimeout-string',
    name: 'setTimeout / setInterval with String Argument',
    pattern: /(?:setTimeout|setInterval)\s*\(\s*["'`]/,
    severity: 'medium',
    confidence: 'high',
    owasp: ['A05 Injection'],
    cwe: ['CWE-79'],
    tags: ['eval', 'dom'],
    impact: 'String arguments to setTimeout/setInterval are evaluated via eval().',
    recommendation: 'Pass a function reference instead of a string: setTimeout(() => fn(), delay).',
  },
  {
    id: 'injection.prisma-query-raw-unsafe',
    name: 'Prisma.$queryRawUnsafe Usage',
    pattern: /\.\$queryRawUnsafe\s*\(|\.\$executeRawUnsafe\s*\(/,
    severity: 'critical',
    confidence: 'high',
    owasp: ['A05 Injection'],
    cwe: ['CWE-89'],
    tags: ['sql-injection', 'prisma', 'database'],
    impact: 'SQL injection attacks enabling data exfiltration, manipulation, or database destruction.',
    recommendation: 'Use Prisma.$queryRaw with tagged template literals, or use parameterized Prisma client methods.',
  },
  {
    id: 'injection.sql-string-concat',
    name: 'SQL String Concatenation',
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\s+.*\+\s*(?:req\.|request\.|params\.|query\.|body\.|\$\{)/i,
    severity: 'high',
    confidence: 'medium',
    owasp: ['A05 Injection'],
    cwe: ['CWE-89'],
    tags: ['sql-injection', 'database'],
    impact: 'SQL injection via user-controlled input concatenated into queries.',
    recommendation: 'Use parameterized queries or an ORM. Never concatenate user input into SQL strings.',
  },
  {
    id: 'injection.child-process-exec',
    name: 'child_process.exec / execSync',
    pattern: /(?:exec|execSync)\s*\(|child_process\.exec/,
    severity: 'critical',
    confidence: 'medium',
    owasp: ['A05 Injection'],
    cwe: ['CWE-78'],
    tags: ['command-injection', 'rce', 'shell'],
    impact: 'Command injection enabling arbitrary shell command execution on the server.',
    recommendation: 'Use execFile() with an array of arguments instead. Never pass user input to exec().',
    skip: ['node_modules', '.git', 'dist', 'build'],
  },
];

export const injectionRule: Rule = {
  id: 'injection',
  name: 'Injection & XSS Detection',
  description: 'Detects dangerous code patterns that can lead to XSS and injection attacks',
  category: 'Injection',
  owasp: ['A05 Injection'],
  severity: 'high',
  run: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    for (const file of context.files) {
      if (!['.ts', '.tsx', '.js', '.jsx', '.mjs'].includes(file.extension)) continue;

      const lines = file.content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!line.trim() || line.trim().startsWith('//') || line.trim().startsWith('*')) continue;

        for (const p of INJECTION_PATTERNS) {
          if (p.skip?.some(s => file.relativePath.includes(s))) continue;
          if (!p.pattern.test(line)) continue;

          findings.push({
            id: makeFindingId(p.id, file.relativePath, i + 1),
            ruleId: p.id,
            title: p.name,
            severity: p.severity,
            confidence: p.confidence,
            owasp: p.owasp,
            cwe: p.cwe,
            category: 'Injection',
            file: file.relativePath,
            line: i + 1,
            evidence: {
              snippet: truncate(line),
              reason: `${p.name} pattern matched`,
            },
            impact: p.impact,
            recommendation: p.recommendation,
            tags: p.tags,
          });
        }
      }
    }

    return findings;
  },
};
