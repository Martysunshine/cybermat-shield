import * as fs from 'fs';
import * as path from 'path';
import type {
  Rule, ScanReport, ScanOptions, ScanSummary, Finding,
  ScannerConfig, DetectedStack, Severity,
} from '@cybermat/shared';
import { DEFAULT_CONFIG } from '@cybermat/shared';
import { buildFileInventory } from './file-inventory';
import { detectStack } from './stack-detector';
import { writeReports } from './report-writer';
import { loadIgnoreRules, applyIgnoreRules } from './ignore-loader';

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 12,
  medium: 5,
  low: 2,
  info: 0,
};

const OWASP_CATEGORIES = [
  'A01 Broken Access Control',
  'A02 Security Misconfiguration',
  'A03 Software Supply Chain Failures',
  'A04 Cryptographic Failures',
  'A05 Injection',
  'A06 Insecure Design',
  'A07 Authentication Failures',
  'A08 Software or Data Integrity Failures',
  'A09 Security Logging and Alerting Failures',
  'A10 Mishandling of Exceptional Conditions',
];

function calcRiskScore(findings: Finding[]): number {
  const deduction = findings.reduce((sum, f) => sum + SEVERITY_WEIGHTS[f.severity], 0);
  return Math.max(0, 100 - deduction);
}

function calcSummary(findings: Finding[]): ScanSummary {
  const s: ScanSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  for (const f of findings) {
    s[f.severity]++;
    s.total++;
  }
  return s;
}

function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    if (seen.has(f.id)) return false;
    seen.add(f.id);
    return true;
  });
}

function getOwaspCoverage(findings: Finding[]): string[] {
  const covered = new Set<string>();
  for (const f of findings) {
    for (const o of f.owasp) {
      covered.add(o);
    }
  }
  return OWASP_CATEGORIES.filter(c => covered.has(c));
}

function getTopRecommendations(findings: Finding[]): string[] {
  const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const sorted = [...findings].sort((a, b) =>
    severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
  );
  const seen = new Set<string>();
  const recs: string[] = [];
  for (const f of sorted) {
    const key = f.recommendation.slice(0, 60);
    if (!seen.has(key)) {
      seen.add(key);
      recs.push(f.recommendation);
    }
    if (recs.length >= 5) break;
  }
  return recs;
}

function loadPackageJson(rootPath: string): Record<string, unknown> | undefined {
  const pkgPath = path.join(rootPath, 'package.json');
  try {
    if (fs.existsSync(pkgPath)) {
      return JSON.parse(fs.readFileSync(pkgPath, 'utf-8')) as Record<string, unknown>;
    }
  } catch {
    // ignore
  }
  return undefined;
}

export async function runScan(
  targetPath: string,
  rules: Rule[],
  options: ScanOptions = {},
): Promise<ScanReport> {
  const absolutePath = path.resolve(targetPath);
  const outputDir = path.join(absolutePath, options.outputDir ?? '.appsec');

  const config: ScannerConfig = {
    ...DEFAULT_CONFIG,
    outputDir,
  };

  const packageJson = loadPackageJson(absolutePath);
  const { files, ignored } = buildFileInventory(absolutePath, config);
  const detectedStack: DetectedStack = detectStack(files, packageJson);
  const ignoreRules = loadIgnoreRules(absolutePath);

  const ruleContext = {
    rootPath: absolutePath,
    files,
    packageJson,
    detectedStack,
    config,
  };

  const ruleResults = await Promise.all(rules.map(r => r.run(ruleContext).catch(() => [] as Finding[])));
  const allFindings = deduplicateFindings(ruleResults.flat());
  const filteredFindings = applyIgnoreRules(allFindings, ignoreRules);

  const report: ScanReport = {
    scannedPath: absolutePath,
    timestamp: new Date().toISOString(),
    filesScanned: files.length,
    filesIgnored: ignored,
    detectedStack,
    findings: filteredFindings,
    riskScore: calcRiskScore(filteredFindings),
    summary: calcSummary(filteredFindings),
    owaspCoverage: getOwaspCoverage(filteredFindings),
    topRecommendations: getTopRecommendations(filteredFindings),
  };

  writeReports(report, outputDir);

  return report;
}
