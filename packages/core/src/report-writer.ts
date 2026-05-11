import * as fs from 'fs';
import * as path from 'path';
import type { ScanReport, Finding, Severity, RouteInfo } from '@cybermat/shared';

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

function evidenceText(f: Finding): string {
  return f.evidence.redactedSnippet ?? f.evidence.snippet ?? f.evidence.reason;
}

function renderFindingCards(findings: Finding[], severity: Severity): string {
  const filtered = findings.filter(f => f.severity === severity);
  if (filtered.length === 0) return '';

  const cards = filtered.map(f => {
    const evText = evidenceText(f);
    const hasMatch = !!f.evidence.redactedMatch;
    const cweHtml = f.cwe && f.cwe.length > 0
      ? `<div class="owasp-tags">${f.cwe.map(c => `<span class="owasp-tag cwe-tag">${escapeHtml(c)}</span>`).join('')}</div>`
      : '';
    const tagsHtml = f.tags && f.tags.length > 0
      ? `<div class="tag-row">${f.tags.map(t => `<span class="tag">${escapeHtml(t)}</span>`).join('')}</div>`
      : '';

    return `
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
      ${cweHtml}
      ${tagsHtml}
      <div class="finding-section">
        <div class="section-label">Evidence</div>
        <code class="evidence-code">${escapeHtml(evText)}</code>
        ${hasMatch ? `<div class="redacted-match">Matched: <code>${escapeHtml(f.evidence.redactedMatch!)}</code></div>` : ''}
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
  `;
  }).join('');

  return `
    <div class="severity-group">
      <h3 class="severity-heading" style="color:${SEVERITY_COLOR[severity]}">
        ${severity.toUpperCase()} <span class="count">(${filtered.length})</span>
      </h3>
      ${cards}
    </div>
  `;
}

function renderRoutesTable(routes: RouteInfo[]): string {
  if (routes.length === 0) return '';

  const apiRoutes = routes.filter(r => r.isApi);
  if (apiRoutes.length === 0) return '';

  const rows = apiRoutes.map(r => {
    const riskHtml = r.riskTags.length > 0
      ? r.riskTags.map(t => `<span class="tag">${escapeHtml(t)}</span>`).join(' ')
      : '<span style="color:var(--muted)">—</span>';
    const authBadge = r.requiresAuth
      ? `<span class="auth-badge auth-yes">auth</span>`
      : r.isApi ? `<span class="auth-badge auth-no">no auth</span>` : '';
    const methodColor = r.method === 'DELETE' || r.method === 'PUT' ? '#f97316' :
      r.method === 'POST' || r.method === 'PATCH' ? '#eab308' : '#94a3b8';

    return `
      <tr>
        <td><code style="color:${methodColor}">${escapeHtml(r.method ?? 'ANY')}</code></td>
        <td><code class="route-path">${escapeHtml(r.route)}</code></td>
        <td>${authBadge}</td>
        <td class="risk-tags">${riskHtml}</td>
        <td style="color:var(--muted);font-size:0.75rem">${escapeHtml(r.file)}</td>
      </tr>
    `;
  }).join('');

  return `
    <div class="section">
      <div class="section-title">API Routes Discovered (${apiRoutes.length})</div>
      <table class="routes-table">
        <thead>
          <tr>
            <th>Method</th><th>Route</th><th>Auth</th><th>Risk Tags</th><th>File</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

function renderTopRiskyFiles(topFiles: string[], findings: Finding[]): string {
  if (topFiles.length === 0) return '';

  const items = topFiles.map(file => {
    const fileFindings = findings.filter(f => f.file === file);
    const critCount = fileFindings.filter(f => f.severity === 'critical').length;
    const highCount = fileFindings.filter(f => f.severity === 'high').length;
    const badges = [
      critCount > 0 ? `<span class="severity-badge" style="background:#ef444420;color:#ef4444;border:1px solid #ef444440">${critCount} crit</span>` : '',
      highCount > 0 ? `<span class="severity-badge" style="background:#f9731620;color:#f97316;border:1px solid #f9731640">${highCount} high</span>` : '',
    ].filter(Boolean).join(' ');
    return `
      <li class="risky-file-item">
        <code class="risky-file-path">${escapeHtml(file)}</code>
        <span class="risky-badges">${badges}</span>
      </li>
    `;
  }).join('');

  return `
    <div class="section">
      <div class="section-title">Top Risky Files</div>
      <ul class="risky-file-list">${items}</ul>
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

  const routesHtml = renderRoutesTable(report.routes ?? []);
  const topRiskyFilesHtml = renderTopRiskyFiles(report.topRiskyFiles ?? [], findings);

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
    .section-title { font-size: 0.75rem; font-weight: 600; margin-bottom: 1rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
    .stack-tags { display: flex; flex-wrap: wrap; gap: 0.5rem; }
    .stack-tag { background: #1e3a5f; color: #93c5fd; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.8rem; border: 1px solid #1d4ed840; }
    .ai-tag { background: #1c1c3a; color: #a78bfa; border-color: #7c3aed40; }
    .routes-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    .routes-table th { text-align: left; padding: 0.5rem 0.75rem; color: var(--muted); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--border); }
    .routes-table td { padding: 0.5rem 0.75rem; border-bottom: 1px solid #1e293b; vertical-align: middle; }
    .routes-table tr:hover td { background: #263348; }
    .route-path { color: #60a5fa; }
    .risk-tags { display: flex; flex-wrap: wrap; gap: 0.25rem; }
    .auth-badge { padding: 0.1rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: 600; }
    .auth-yes { background: #14532d40; color: #86efac; border: 1px solid #16a34a30; }
    .auth-no { background: #7f1d1d40; color: #fca5a5; border: 1px solid #dc262630; }
    .risky-file-list { list-style: none; display: flex; flex-direction: column; gap: 0.5rem; }
    .risky-file-item { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: 0.5rem 0.75rem; background: var(--surface2); border-radius: 6px; }
    .risky-file-path { color: #60a5fa; font-size: 0.85rem; }
    .risky-badges { display: flex; gap: 0.4rem; flex-shrink: 0; }
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
    .cwe-tag { background: #1e1a2e; color: #c4b5fd; border-color: #7c3aed30 !important; }
    .tag-row { display: flex; flex-wrap: wrap; gap: 0.3rem; margin: 0.5rem 0; }
    .tag { background: var(--surface2); color: var(--muted); border: 1px solid var(--border); padding: 0.1rem 0.45rem; border-radius: 4px; font-size: 0.68rem; }
    .redacted-match { margin-top: 0.4rem; font-size: 0.8rem; color: var(--muted); }
    .redacted-match code { color: #fbbf24; font-family: 'Courier New', monospace; }
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
      ${(report.routes?.length ?? 0) > 0 ? `<span class="meta-item">🔗 ${report.routes!.filter(r => r.isApi).length} API routes</span>` : ''}
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

    ${routesHtml}

    ${topRiskyFilesHtml}

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
