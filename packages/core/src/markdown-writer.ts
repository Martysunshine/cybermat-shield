import type { ScanReport, Finding, Severity, RuntimeScanReport, AuthScanReport, AuthzFinding } from '@cybermat/shared';

const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵',
  info: '⚪',
};

function escapeTable(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

function scoreEmoji(score: number): string {
  if (score >= 70) return '✅';
  if (score >= 40) return '⚠️';
  return '❌';
}

function formatFinding(f: Finding, index: number, basePath?: string): string {
  const lines: string[] = [];
  lines.push(`### ${index}. ${SEVERITY_EMOJI[f.severity]} \`${f.severity.toUpperCase()}\` — ${f.title}`);
  lines.push('');

  if (f.file) {
    let loc = f.file;
    if (basePath) loc = loc.replace(basePath, '').replace(/^[/\\]/, '');
    lines.push(`**File:** \`${loc}${f.line ? `:${f.line}` : ''}\``);
  } else if ((f as AuthzFinding).url) {
    lines.push(`**URL:** \`${(f as AuthzFinding).url}\``);
  }

  if (f.owasp.length > 0) lines.push(`**OWASP:** ${f.owasp.join(', ')}`);
  if (f.cwe && f.cwe.length > 0) lines.push(`**CWE:** ${f.cwe.join(', ')}`);
  lines.push('');

  const ev = f.evidence.redactedSnippet ?? f.evidence.snippet ?? f.evidence.reason;
  lines.push('**Evidence:**');
  lines.push('```');
  lines.push(ev);
  lines.push('```');
  lines.push('');
  lines.push(`**Impact:** ${f.impact}`);
  lines.push('');
  lines.push(`**Fix:** ${f.recommendation}`);
  lines.push('');
  if (f.fixExample) {
    lines.push('**Example Fix:**');
    lines.push('```');
    lines.push(f.fixExample);
    lines.push('```');
    lines.push('');
  }
  lines.push('---');
  lines.push('');
  return lines.join('\n');
}

export function generateMarkdown(
  report: ScanReport,
  runtimeReport?: RuntimeScanReport,
  authReport?: AuthScanReport,
): string {
  const lines: string[] = [];
  const ts = new Date(report.timestamp).toISOString().split('T')[0];

  lines.push('# CyberMat Shield — Security Report');
  lines.push('');
  lines.push(`> Generated ${ts} | Risk Score: **${report.riskScore}/100** ${scoreEmoji(report.riskScore)}`);
  lines.push('');

  // Summary table
  lines.push('## Summary');
  lines.push('');
  lines.push('| | Critical | High | Medium | Low | Info | Total |');
  lines.push('|---|---|---|---|---|---|---|');

  const s = report.summary;
  const rt = runtimeReport?.summary;
  const at = authReport?.summary;

  lines.push(`| Static | ${s.critical} | ${s.high} | ${s.medium} | ${s.low} | ${s.info} | ${s.total} |`);
  if (rt) lines.push(`| Runtime | ${rt.critical} | ${rt.high} | ${rt.medium} | ${rt.low} | ${rt.info} | ${rt.total} |`);
  if (at) lines.push(`| Auth/Authz | ${at.critical} | ${at.high} | ${at.medium} | ${at.low} | ${at.info} | ${at.total} |`);
  lines.push('');

  // Scan metadata
  lines.push('## Scan Info');
  lines.push('');
  lines.push(`| Property | Value |`);
  lines.push(`|---|---|`);
  lines.push(`| Target | \`${escapeTable(report.scannedPath)}\` |`);
  lines.push(`| Files scanned | ${report.filesScanned} |`);
  lines.push(`| Files ignored | ${report.filesIgnored} |`);
  if (report.detectedStack.frameworks.length > 0) {
    lines.push(`| Frameworks | ${escapeTable(report.detectedStack.frameworks.join(', '))} |`);
  }
  if (runtimeReport) {
    lines.push(`| Runtime target | \`${escapeTable(runtimeReport.targetUrl)}\` |`);
    lines.push(`| Pages visited | ${runtimeReport.pagesVisited} |`);
  }
  if (authReport) {
    lines.push(`| Auth routes tested | ${authReport.routesTested} |`);
    lines.push(`| IDOR pairs | ${authReport.resourcePairsTested} |`);
  }
  lines.push('');

  // OWASP coverage
  if (report.owaspCoverage.length > 0) {
    lines.push('## OWASP Top 10:2025 Coverage');
    lines.push('');
    report.owaspCoverage.forEach(o => lines.push(`- ${o}`));
    lines.push('');
  }

  // Static findings
  if (report.findings.length > 0) {
    lines.push('## Static Analysis Findings');
    lines.push('');
    let idx = 1;
    const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    for (const sev of order) {
      const group = report.findings.filter(f => f.severity === sev);
      if (group.length === 0) continue;
      lines.push(`### ${SEVERITY_EMOJI[sev]} ${sev.toUpperCase()} (${group.length})`);
      lines.push('');
      for (const f of group) {
        lines.push(formatFinding(f, idx++, report.scannedPath));
      }
    }
  } else {
    lines.push('## Static Analysis Findings');
    lines.push('');
    lines.push('✅ No static findings detected.');
    lines.push('');
  }

  // Runtime findings
  if (runtimeReport && runtimeReport.findings.length > 0) {
    lines.push('## Runtime Findings');
    lines.push('');
    let idx = 1;
    const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    for (const sev of order) {
      const group = runtimeReport.findings.filter(f => f.severity === sev);
      if (group.length === 0) continue;
      lines.push(`### ${SEVERITY_EMOJI[sev]} ${sev.toUpperCase()} (${group.length})`);
      lines.push('');
      for (const f of group) {
        lines.push(formatFinding(f as Finding, idx++));
      }
    }
  }

  // Auth findings
  if (authReport && authReport.findings.length > 0) {
    lines.push('## Access Control Findings (IDOR / Privilege Escalation)');
    lines.push('');
    let idx = 1;
    const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    for (const sev of order) {
      const group = authReport.findings.filter(f => f.severity === sev);
      if (group.length === 0) continue;
      lines.push(`### ${SEVERITY_EMOJI[sev]} ${sev.toUpperCase()} (${group.length})`);
      lines.push('');
      for (const f of group) {
        lines.push(formatFinding(f as unknown as Finding, idx++));
      }
    }
  }

  // Top recommendations
  if (report.topRecommendations.length > 0) {
    lines.push('## Top Recommendations');
    lines.push('');
    report.topRecommendations.slice(0, 5).forEach((r, i) => {
      lines.push(`${i + 1}. ${r}`);
    });
    lines.push('');
  }

  lines.push('---');
  lines.push('');
  lines.push('*Generated by [CyberMat Shield](https://github.com/Martysunshine/cybermat-shield) — All secrets redacted*');
  lines.push('');

  return lines.join('\n');
}
