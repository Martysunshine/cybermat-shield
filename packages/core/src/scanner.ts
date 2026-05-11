import * as fs from 'fs';
import * as path from 'path';
import type {
  Rule, ScanReport, ScanOptions, ScanSummary, Finding,
  ScannerConfig, DetectedStack, Severity, ScannerLayer, ScanMetadata,
  RouteInfo, FileClassification, ParsedFile,
} from '@cybermat/shared';
import { DEFAULT_CONFIG } from '@cybermat/shared';
import { buildFileInventory } from './file-inventory';
import { detectStack } from './stack-detector';
import { writeReports } from './report-writer';
import { loadIgnoreRules, applyIgnoreRules } from './ignore-loader';
import { classifyFiles } from '@cybermat/analyzers';
import { discoverRoutes } from '@cybermat/analyzers';
import { buildImportGraph } from '@cybermat/analyzers';
import { analyzeAst } from '@cybermat/analyzers';
import { correlateSources } from '@cybermat/analyzers';

const SCANNER_VERSION = '0.5.0';

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

function getTopRiskyFiles(findings: Finding[]): string[] {
  const fileScore = new Map<string, number>();
  for (const f of findings) {
    if (!f.file) continue;
    const score = (fileScore.get(f.file) ?? 0) + SEVERITY_WEIGHTS[f.severity];
    fileScore.set(f.file, score);
  }
  return [...fileScore.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([file]) => file);
}

function groupByLayer(findings: Finding[]): Record<ScannerLayer, Finding[]> {
  const groups: Record<ScannerLayer, Finding[]> = { code: [], runtime: [], authz: [] };
  for (const f of findings) {
    const layer: ScannerLayer = f.layer ?? 'code';
    groups[layer].push(f);
  }
  return groups;
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

function tagFindingLayer(f: Finding, ruleLayer: ScannerLayer | undefined): Finding {
  if (f.layer) return f;
  return { ...f, layer: ruleLayer ?? 'code' };
}

/** Build ParsedFile entries from AST analysis results */
function buildParsedFiles(
  sinks: ReturnType<typeof analyzeAst>['sinks'],
  sources: ReturnType<typeof analyzeAst>['sources'],
): ParsedFile[] {
  const byFile = new Map<string, ParsedFile>();

  const getOrCreate = (file: string): ParsedFile => {
    if (!byFile.has(file)) {
      byFile.set(file, {
        file,
        astAvailable: true,
        imports: [],
        exports: [],
        functions: [],
        dangerousCalls: [],
        userInputSources: [],
      });
    }
    return byFile.get(file)!;
  };

  for (const sink of sinks) getOrCreate(sink.file).dangerousCalls.push(sink);
  for (const source of sources) getOrCreate(source.file).userInputSources.push(source);

  return [...byFile.values()];
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

  // ── Pipeline ──────────────────────────────────────────────────────────────

  // 1. Load config & inventory
  const packageJson = loadPackageJson(absolutePath);
  const { files, ignored } = buildFileInventory(absolutePath, config);
  const ignoreRules = loadIgnoreRules(absolutePath);

  // 2. Detect stack
  const detectedStack: DetectedStack = detectStack(files, packageJson);
  const primaryFramework = detectedStack.frameworks[0] ?? 'unknown';

  // 3. Classify files
  const fileClassifications: FileClassification[] = classifyFiles(files);

  // 4. Discover routes
  const { routes }: { routes: RouteInfo[] } = discoverRoutes(files, primaryFramework);

  // 5. Build import graph
  const importGraph = buildImportGraph(files);

  // 6. AST analysis
  const { sinks, sources } = analyzeAst(files);

  // 7. Source/sink correlation (for extra context — not yet used to modify findings)
  const fileContentsMap = new Map(files.map(f => [f.relativePath, f.content.split('\n')]));
  correlateSources(sources, sinks, fileContentsMap);

  // 8. Build parsed files list
  const parsedFiles = buildParsedFiles(sinks, sources);

  // 9. Run rules
  const ruleContext = {
    rootPath: absolutePath,
    files,
    packageJson,
    detectedStack,
    config,
    routes,
    fileClassifications,
    importGraph,
    parsedFiles,
  };

  const ruleResults = await Promise.all(
    rules.map(r =>
      r.run(ruleContext)
        .then(findings => findings.map(f => tagFindingLayer(f, r.layer)))
        .catch(() => [] as Finding[])
    )
  );

  // 10. Normalize, deduplicate, filter
  let allFindings = deduplicateFindings(ruleResults.flat());

  // Apply rules config overrides (disabled rules, severity overrides)
  if (options.rulesConfig) {
    const { disabled = [], severityOverrides = {} } = options.rulesConfig;
    if (disabled.length > 0) {
      const disabledSet = new Set(disabled);
      allFindings = allFindings.filter(f => !disabledSet.has(f.ruleId));
    }
    if (Object.keys(severityOverrides).length > 0) {
      allFindings = allFindings.map(f => {
        const override = severityOverrides[f.ruleId] as Severity | undefined;
        return override ? { ...f, severity: override } : f;
      });
    }
  }

  const filteredFindings = applyIgnoreRules(allFindings, ignoreRules);

  // 11. Score & report
  const timestamp = new Date().toISOString();
  const metadata: ScanMetadata = {
    timestamp,
    scannedPath: absolutePath,
    layers: ['code'],
    version: SCANNER_VERSION,
  };

  const report: ScanReport = {
    metadata,
    scannedPath: absolutePath,
    timestamp,
    filesScanned: files.length,
    filesIgnored: ignored,
    detectedStack,
    routes,
    fileClassifications,
    findings: filteredFindings,
    findingsByLayer: groupByLayer(filteredFindings),
    riskScore: calcRiskScore(filteredFindings),
    summary: calcSummary(filteredFindings),
    owaspCoverage: getOwaspCoverage(filteredFindings),
    topRecommendations: getTopRecommendations(filteredFindings),
    topRiskyFiles: getTopRiskyFiles(filteredFindings),
  };

  writeReports(report, outputDir);

  return report;
}
