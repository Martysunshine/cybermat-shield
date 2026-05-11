import * as fs from 'fs';
import * as path from 'path';
import type { ScanReport, Finding, Severity } from '@cybermat/shared';

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
};

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function scoreColor(score: number): string {
  if (score >= 70) return '#22c55e';
  if (score >= 40) return '#eab308';
  if (score >= 20) return '#f97316';
  return '#ef4444';
}

function scoreLabel(score: number): string {
  if (score >= 70) return 'Good';
  if (score >= 40) return 'Fair';
  if (score >= 20) return 'Poor';
  return 'Critical';
}

function renderFindingCards(findings: Finding[], severity: Severity): string {
  const filtered = findings.filter(f => f.severity === severity);
  if (filtered.length === 0) return '';

  const cards = filtered.map(f => `
    <div class="finding-card" data-severity="${f.severity}">
      <div class="finding-header">
        <span class="severity-badge" style="background:${SEVERITY_COLOR[f.severity]}20;color:${SEVERITY_COLOR[f.severity]};border:1px solid ${SEVERITY_COLOR[f.severity]}40">
          ${f.severity.toUpperCase()}
        </span>
        <span class="finding-title">${escapeHtml(f.title)}</span>
        ${f.confidence ? `<span class="confidence-badge">${f.confidence} confidence</span>` : ''}
      </div>
      ${f.file ? `<div class="finding-location">📄 ${escapeHtml(f.file)}${f.line ? `:${f.line}` : ''}</div>` : ''}
      ${f.owasp.length > 0 ? `<div class="owasp-tags">${f.owasp.map(o => `<span class="owasp-tag">${escapeHtml(o)}</span>`).join('')}</div>` : ''}
      <div class="finding-section">
        <div class="section-label">Evidence</div>
        <code class="evidence-code">${escapeHtml(f.evidence)}</code>
      </div>
      <div class="finding-section">
        <div class="section-label">Impact</div>
        <p>${escapeHtml(f.impact)}</p>
      </div>
      <div class="finding-section">
        <div class="section-label">Recommendation</div>
        <p>${escapeHtml(f.recommendation)}</p>
      </div>
    </div>
  `).join('');

  return `
    <div class="severity-group">
      <h3 class="severity-heading" style="color:${SEVERITY_COLOR[severity]}">
        ${severity.toUpperCase()} <span class="count">(${filtered.length})</span>
      </h3>
      ${cards}
    </div>
  `;
}

export function generateHtml(report: ScanReport): string {
  const { summary, riskScore, detectedStack, findings, scannedPath, timestamp, filesScanned } = report;

  const findingsSections = SEVERITY_ORDER
    .map(s => renderFindingCards(findings, s))
    .join('');

  const stackItems = [
    ...detectedStack.frameworks.map(f => `<span class="stack-tag">${f}</span>`),
    ...detectedStack.databases.map(d => `<span class="stack-tag">${d}</span>`),
    ...detectedStack.authProviders.map(a => `<span class="stack-tag">${a}</span>`),
    ...detectedStack.aiProviders.map(a => `<span class="stack-tag ai-tag">${a} (AI)</span>`),
    ...detectedStack.deploymentTargets.map(d => `<span class="stack-tag">${d}</span>`),
  ].join('');

  const owaspRows = report.owaspCoverage.map(o =>
    `<li>${escapeHtml(o)}</li>`
  ).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CyberMat Shield — Security Report</title>
  <style>
    :root {
      --bg: #0f172a; --surface: #1e293b; --surface2: #263348;
      --border: #334155; --text: #e2e8f0; --muted: #94a3b8;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
    header { background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); border-bottom: 1px solid var(--border); padding: 2rem; }
    .header-inner { max-width: 1100px; margin: 0 auto; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1.5rem; }
    .logo { display: flex; align-items: center; gap: 0.75rem; }
    .logo-icon { font-size: 2rem; }
    .logo-text h1 { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.02em; }
    .logo-text p { color: var(--muted); font-size: 0.875rem; }
    .score-card { text-align: center; background: var(--surface2); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem 2rem; }
    .score-number { font-size: 3rem; font-weight: 800; line-height: 1; color: ${scoreColor(riskScore)}; }
    .score-label { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.1em; margin-top: 0.25rem; }
    .score-status { font-size: 0.875rem; font-weight: 600; color: ${scoreColor(riskScore)}; }
    main { max-width: 1100px; margin: 2rem auto; padding: 0 1.5rem; }
    .meta-row { display: flex; gap: 1.5rem; flex-wrap: wrap; margin-bottom: 2rem; color: var(--muted); font-size: 0.875rem; }
    .meta-item { display: flex; gap: 0.4rem; align-items: center; }
    .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
    .summary-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.25rem; text-align: center; }
    .summary-count { font-size: 2rem; font-weight: 700; }
    .summary-label { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.25rem; }
    .section { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.5rem; margin-bottom: 1.5rem; }
    .section-title { font-size: 1rem; font-weight: 600; margin-bottom: 1rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; font-size: 0.75rem; }
    .stack-tags { display: flex; flex-wrap: wrap; gap: 0.5rem; }
    .stack-tag { background: #1e3a5f; color: #93c5fd; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.8rem; border: 1px solid #1d4ed840; }
    .ai-tag { background: #1c1c3a; color: #a78bfa; border-color: #7c3aed40; }
    .severity-group { margin-bottom: 2rem; }
    .severity-heading { font-size: 1.1rem; font-weight: 700; margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem; }
    .severity-heading .count { color: var(--muted); font-weight: 400; font-size: 0.9rem; }
    .finding-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.25rem; margin-bottom: 1rem; transition: border-color 0.2s; }
    .finding-card:hover { border-color: #475569; }
    .finding-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem; flex-wrap: wrap; }
    .finding-title { font-size: 1rem; font-weight: 600; flex: 1; }
    .severity-badge { padding: 0.2rem 0.6rem; border-radius: 6px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }
    .confidence-badge { font-size: 0.7rem; color: var(--muted); background: var(--surface2); padding: 0.2rem 0.5rem; border-radius: 4px; border: 1px solid var(--border); }
    .finding-location { font-size: 0.8rem; color: #60a5fa; margin-bottom: 0.5rem; font-family: 'Courier New', monospace; }
    .owasp-tags { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-bottom: 0.75rem; }
    .owasp-tag { background: #1a2e1a; color: #86efac; border: 1px solid #16a34a30; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.7rem; }
    .finding-section { margin-top: 0.75rem; }
    .section-label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); font-weight: 600; margin-bottom: 0.25rem; }
    .evidence-code { display: block; background: #0a0f1a; border: 1px solid var(--border); border-radius: 6px; padding: 0.75rem; font-family: 'Courier New', monospace; font-size: 0.8rem; color: #fbbf24; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
    .finding-section p { font-size: 0.875rem; color: var(--muted); }
    .owasp-list { list-style: none; display: flex; flex-wrap: wrap; gap: 0.5rem; }
    .owasp-list li { background: #1a2e1a; color: #86efac; border: 1px solid #16a34a30; padding: 0.2rem 0.6rem; border-radius: 6px; font-size: 0.8rem; }
    .no-findings { text-align: center; padding: 3rem; color: var(--muted); }
    footer { text-align: center; padding: 2rem; color: var(--muted); font-size: 0.8rem; border-top: 1px solid var(--border); margin-top: 3rem; }
  </style>
</head>
<body>
  <header>
    <div class="header-inner">
      <div class="logo">
        <span class="logo-icon">🛡️</span>
        <div class="logo-text">
          <h1>CyberMat Shield</h1>
          <p>Application Security Scanner — Static Analysis Report</p>
        </div>
      </div>
      <div class="score-card">
        <div class="score-number">${riskScore}</div>
        <div class="score-status">${scoreLabel(riskScore)}</div>
        <div class="score-label">Risk Score / 100</div>
      </div>
    </div>
  </header>

  <main>
    <div class="meta-row">
      <span class="meta-item">📁 ${escapeHtml(scannedPath)}</span>
      <span class="meta-item">📄 ${filesScanned} files scanned</span>
      <span class="meta-item">🕐 ${new Date(timestamp).toLocaleString()}</span>
    </div>

    <div class="summary-grid">
      <div class="summary-card"><div class="summary-count" style="color:#ef4444">${summary.critical}</div><div class="summary-label">Critical</div></div>
      <div class="summary-card"><div class="summary-count" style="color:#f97316">${summary.high}</div><div class="summary-label">High</div></div>
      <div class="summary-card"><div class="summary-count" style="color:#eab308">${summary.medium}</div><div class="summary-label">Medium</div></div>
      <div class="summary-card"><div class="summary-count" style="color:#3b82f6">${summary.low}</div><div class="summary-label">Low</div></div>
      <div class="summary-card"><div class="summary-count" style="color:#6b7280">${summary.info}</div><div class="summary-label">Info</div></div>
      <div class="summary-card"><div class="summary-count">${summary.total}</div><div class="summary-label">Total</div></div>
    </div>

    ${stackItems ? `
    <div class="section">
      <div class="section-title">Detected Stack</div>
      <div class="stack-tags">${stackItems}</div>
    </div>` : ''}

    ${owaspRows ? `
    <div class="section">
      <div class="section-title">OWASP Top 10:2025 Coverage</div>
      <ul class="owasp-list">${owaspRows}</ul>
    </div>` : ''}

    <div class="findings-section">
      ${findings.length === 0
        ? '<div class="no-findings">✅ No findings detected.</div>'
        : findingsSections
      }
    </div>
  </main>

  <footer>
    Generated by CyberMat Shield &mdash; Local-first Application Security Scanner &mdash; All secrets redacted
  </footer>
</body>
</html>`;
}

export function writeReports(report: ScanReport, outputDir: string): void {
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const jsonPath = path.join(outputDir, 'report.json');
  fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2), 'utf-8');

  const htmlPath = path.join(outputDir, 'report.html');
  fs.writeFileSync(htmlPath, generateHtml(report), 'utf-8');
}
