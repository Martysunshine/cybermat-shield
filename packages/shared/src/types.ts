export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';
export type ScannerLayer = 'code' | 'runtime' | 'authz';

export interface FindingEvidence {
  snippet?: string;
  redactedSnippet?: string;
  match?: string;
  redactedMatch?: string;
  reason: string;
}

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  owasp: string[];
  category: string;
  cwe?: string[];
  file?: string;
  line?: number;
  column?: number;
  route?: string;
  evidence: FindingEvidence;
  impact: string;
  recommendation: string;
  fixExample?: string;
  references?: string[];
  tags: string[];
  /** Populated by the scanner orchestrator if omitted by the rule; defaults to 'code' */
  layer?: ScannerLayer;
}

export interface RouteInfo {
  path: string;
  method?: string;
  file?: string;
  line?: number;
  isDynamic: boolean;
  isProtected?: boolean;
  riskTags: string[];
}

export interface ScannedFile {
  path: string;
  relativePath: string;
  extension: string;
  sizeBytes: number;
  content: string;
}

export interface DetectedStack {
  languages: string[];
  frameworks: string[];
  packageManagers: string[];
  authProviders: string[];
  databases: string[];
  deploymentTargets: string[];
  aiProviders: string[];
}

export interface ScannerConfig {
  ignoreDirs: string[];
  ignoreFiles: string[];
  maxFileSizeBytes: number;
  severityThreshold?: Severity;
  outputDir: string;
}

export interface RuleContext {
  rootPath: string;
  files: ScannedFile[];
  packageJson?: Record<string, unknown>;
  detectedStack: DetectedStack;
  config: ScannerConfig;
  routes?: RouteInfo[];
}

/** Extended context passed to ScannerEngine.run — includes layer and optional runtime target */
export interface ScanContext extends RuleContext {
  layer: ScannerLayer;
  targetUrl?: string;
  authProfiles?: string[];
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  category: string;
  owasp: string[];
  severity: Severity;
  layer?: ScannerLayer;
  run: (context: RuleContext) => Promise<Finding[]>;
}

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface ScanMetadata {
  timestamp: string;
  scannedPath?: string;
  targetUrl?: string;
  layers: ScannerLayer[];
  version: string;
}

export type ScanMode = {
  layer: ScannerLayer;
  enabled: boolean;
  requiresTargetUrl: boolean;
  requiresAuthProfiles: boolean;
  safeByDefault: boolean;
};

export type ScanPlan = {
  targetPath?: string;
  targetUrl?: string;
  layers: ScanMode[];
  config: ScannerConfig;
};

export interface ExternalToolResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  raw?: unknown;
}

export type ScannerEngine = {
  id: string;
  name: string;
  layer: 'code' | 'runtime' | 'authz' | 'dependency' | 'external';
  supportedLanguages?: string[];
  supportedFrameworks?: string[];
  run: (context: ScanContext) => Promise<Finding[]>;
};

export type ExternalToolAdapter = {
  id: string;
  name: string;
  command: string;
  isAvailable: () => Promise<boolean>;
  run: (context: ScanContext) => Promise<ExternalToolResult>;
  normalize: (result: ExternalToolResult) => Finding[];
};

export interface ScanReport {
  metadata: ScanMetadata;
  scannedPath: string;
  timestamp: string;
  filesScanned: number;
  filesIgnored: number;
  detectedStack: DetectedStack;
  routes?: RouteInfo[];
  findings: Finding[];
  findingsByLayer: Record<ScannerLayer, Finding[]>;
  riskScore: number;
  summary: ScanSummary;
  owaspCoverage: string[];
  topRecommendations: string[];
}

export interface ScanOptions {
  json?: boolean;
  html?: boolean;
  outputDir?: string;
  severityThreshold?: Severity;
}

export const DEFAULT_CONFIG: ScannerConfig = {
  ignoreDirs: ['node_modules', '.next', 'dist', 'build', '.git', 'coverage', '.turbo', '.vercel', '.cache', 'out'],
  ignoreFiles: [],
  maxFileSizeBytes: 1_000_000,
  outputDir: '.appsec',
};
