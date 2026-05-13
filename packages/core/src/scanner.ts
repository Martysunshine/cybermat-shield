import * as fs from 'fs';
import * as path from 'path';
import type {
  Rule, ScanReport, ScanOptions, ScanSummary, Finding,
  ScannerConfig, DetectedStack, Severity, ScannerLayer, ScanMetadata, ScanCoverage,
  RouteInfo, FileClassification, ParsedFile,
  RuleExecutionResult, EngineHealth, ScannedFile,
  DangerousCall, UserInputSource,
} from '@cybermat/shared';
import { DEFAULT_CONFIG } from '@cybermat/shared';
import { buildFileInventory } from './file-inventory';
import { detectStack } from './stack-detector';
import { writeReports } from './report-writer';
import { loadIgnoreRules, applyIgnoreRules } from './ignore-loader';
import { createFindingFingerprint } from './fingerprint';
import { classifyFiles } from '@cybermat/analyzers';
import { discoverRoutes } from '@cybermat/analyzers';
import { buildImportGraph } from '@cybermat/analyzers';
import { analyzeAst } from '@cybermat/analyzers';

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

function computeCoverage(files: ScannedFile[], skippedByReason: Record<string, number>): ScanCoverage {
  const filesByLanguage: Record<string, number> = {};
  const filesByKind: Record<string, number> = {};
  for (const f of files) {
    const lang = f.language ?? 'unknown';
    filesByLanguage[lang] = (filesByLanguage[lang] ?? 0) + 1;
    const kind = f.fileKind ?? 'unknown';
    filesByKind[kind] = (filesByKind[kind] ?? 0) + 1;
  }
  return { filesByLanguage, filesByKind, skippedByReason };
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
  sinks: DangerousCall[],
  sources: UserInputSource[],
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

function raceTimeout<T>(promise: Promise<T>, ms: number, ruleId: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`Timed out after ${ms}ms`)),
      ms,
    );
    promise.then(
      val => { clearTimeout(timer); resolve(val); },
      err => { clearTimeout(timer); reject(err as Error); },
    );
  });
}

export async function runScan(
  targetPath: string,
  rules: Rule[],
  options: ScanOptions = {},
): Promise<ScanReport> {
  const absolutePath = path.resolve(targetPath);
  const outputDir = path.join(absolutePath, options.outputDir ?? '.cybermat');
  const { onProgress } = options;

  const config: ScannerConfig = {
    ...DEFAULT_CONFIG,
    outputDir,
    strictRuleFailures: options.strictRuleFailures,
    debug: options.debug,
    ...(options.maxFiles !== undefined ? { maxFiles: options.maxFiles } : {}),
    ...(options.ruleTimeoutMs !== undefined ? { ruleTimeoutMs: options.ruleTimeoutMs } : {}),
  };
  const ruleTimeoutMs = config.ruleTimeoutMs ?? 30_000;

  // ── Pipeline ──────────────────────────────────────────────────────────────

  // Yields the event loop so setInterval-based spinners can render between phases
  const yld = (): Promise<void> => new Promise(resolve => setImmediate(resolve));

  // 1. Load config & inventory
  const packageJson = loadPackageJson(absolutePath);
  onProgress?.('inventory', 'Building file inventory...');
  // buildFileInventory is async and yields every 100 files — spinner stays live throughout
  const { files, ignored, skippedByReason, cappedAt } = await buildFileInventory(absolutePath, config);
  const ignoreRules = loadIgnoreRules(absolutePath);
  const capNote = cappedAt ? ` (capped at ${cappedAt} — use --max-files to raise)` : '';
  onProgress?.('inventory_done', `Found ${files.length} files${capNote}, ${ignored} dirs ignored`);

  // 2. Detect stack
  const detectedStack: DetectedStack = detectStack(files, packageJson);
  const primaryFramework = detectedStack.frameworks[0] ?? 'unknown';

  // 3–6. Analysis — all async with internal per-file yields; spinner stays live throughout
  onProgress?.('analysis', 'Analyzing code structure (AST, imports, routes)...');
  const fileClassifications: FileClassification[] = await classifyFiles(files);
  const { routes }: { routes: RouteInfo[] } = await discoverRoutes(files, primaryFramework);
  const importGraph = await buildImportGraph(files);
  const { sinks, sources } = await analyzeAst(files);

  // 7. Build parsed files list
  const parsedFiles = buildParsedFiles(sinks, sources);
  onProgress?.('analysis_done', `${routes.length} routes, ${sinks.length} sinks, ${sources.length} sources`);

  // 9. Run rules
  onProgress?.('rules', `Running ${rules.length} security rules...`);
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

  let rulesCompleted = 0;
  const scanStart = performance.now();
  const executionResults: RuleExecutionResult[] = await Promise.all(
    rules.map(async (r): Promise<RuleExecutionResult> => {
      const ruleStart = performance.now();
      try {
        const findings = await raceTimeout(r.run(ruleContext), ruleTimeoutMs, r.id);
        onProgress?.('rule_done', `${++rulesCompleted}/${rules.length}`);
        return {
          ruleId: r.id,
          ruleName: r.name,
          status: 'success',
          findings: findings.map(f => tagFindingLayer(f, r.layer)),
          durationMs: Math.round(performance.now() - ruleStart),
          layer: r.layer,
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        onProgress?.('rule_done', `${++rulesCompleted}/${rules.length}`);
        return {
          ruleId: r.id,
          ruleName: r.name,
          status: 'failed',
          findings: [],
          error: message,
          durationMs: Math.round(performance.now() - ruleStart),
          layer: r.layer,
        };
      }
    })
  );
  const scanDurationMs = Math.round(performance.now() - scanStart);
  const totalFindings = executionResults.reduce((n, r) => n + r.findings.length, 0);
  onProgress?.('rules_done', `${totalFindings} finding${totalFindings !== 1 ? 's' : ''} from ${rules.length} rules`);

  const engineHealth: EngineHealth = {
    rulesTotal: executionResults.length,
    rulesSucceeded: executionResults.filter(r => r.status === 'success').length,
    rulesFailed: executionResults.filter(r => r.status === 'failed').length,
    rulesSkipped: executionResults.filter(r => r.status === 'skipped').length,
    failedRules: executionResults
      .filter(r => r.status === 'failed')
      .map(r => ({ ruleId: r.ruleId, error: r.error ?? 'unknown error' })),
    durationMs: scanDurationMs,
  };

  if (config.strictRuleFailures && engineHealth.rulesFailed > 0) {
    const ids = engineHealth.failedRules.map(r => r.ruleId).join(', ');
    throw new Error(`Strict mode: ${engineHealth.rulesFailed} rule(s) failed internally: ${ids}`);
  }

  const ruleResults = executionResults.map(r => r.findings);

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

  let filteredFindings = applyIgnoreRules(allFindings, ignoreRules);

  // Assign stable content-based fingerprints to every finding
  filteredFindings = filteredFindings.map(f => f.fingerprint ? f : { ...f, fingerprint: createFindingFingerprint(f) });

  // 11. Score & report
  const timestamp = new Date().toISOString();
  const metadata: ScanMetadata = {
    timestamp,
    scannedPath: absolutePath,
    layers: ['code'],
    version: SCANNER_VERSION,
    scannerVersion: SCANNER_VERSION,
    nodeVersion: process.version,
    platform: process.platform,
    scanDurationMs,
    engineHealth,
    coverage: computeCoverage(files, skippedByReason),
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
