export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';
export type ScannerLayer = 'code' | 'runtime' | 'authz';
export type RuleEngine = 'secrets' | 'static' | 'dependency' | 'config' | 'runtime' | 'authz' | 'ai';

export interface RuleMetadata {
  id: string;
  name: string;
  description: string;
  engine: RuleEngine;
  category: string;
  severity: Severity;
  confidence: Confidence;
  owasp2025: string[];
  cwe?: string[];
  asvs?: string[];
  wstg?: string[];
  tags: string[];
  enabledByDefault: boolean;
  safeForCI: boolean;
  requiresRuntime: boolean;
  requiresAuth: boolean;
  falsePositiveNotes?: string;
  remediation: string;
  insecureExample?: string;
  saferExample?: string;
}

export interface RulePack {
  id: string;
  name: string;
  description: string;
  rules: RuleMetadata[];
}

export interface RulesConfig {
  disabled?: string[];
  enabled?: string[];
  severityOverrides?: Record<string, Severity>;
}

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
  // Runtime-specific fields (populated by runtime scanner)
  url?: string;
  method?: string;
  statusCode?: number;
  requestEvidence?: string;
  responseEvidence?: string;
  headerName?: string;
  cookieName?: string;
}

export interface RuntimeFinding extends Finding {
  url: string;
  layer: 'runtime';
}

export type FileKind = 'client' | 'server' | 'shared' | 'config' | 'public' | 'test' | 'unknown';

export interface FileClassification {
  file: string;
  kind: FileKind;
  confidence: 'high' | 'medium' | 'low';
  reasons: string[];
}

export interface DangerousCall {
  name: string;
  file: string;
  line: number;
  column?: number;
  sinkType: 'xss' | 'sql' | 'command' | 'ssrf' | 'redirect' | 'filesystem' | 'crypto' | 'ai-output' | 'unknown';
  argumentPreview?: string;
}

export interface UserInputSource {
  name: string;
  file: string;
  line: number;
  sourceType: 'request-body' | 'request-query' | 'request-params' | 'url-search-params' | 'browser-location' | 'storage' | 'cookie' | 'post-message' | 'file-upload' | 'ai-output' | 'webhook' | 'unknown';
}

export interface ImportEdge {
  from: string;
  to: string;
  importType: 'static' | 'dynamic' | 'unknown';
}

export interface ImportGraph {
  nodes: string[];
  edges: ImportEdge[];
  serverClientLeaks: string[];
  clientServerLeaks: string[];
}

export interface ParsedFile {
  file: string;
  astAvailable: boolean;
  imports: string[];
  exports: string[];
  functions: string[];
  dangerousCalls: DangerousCall[];
  userInputSources: UserInputSource[];
}

export interface RouteInfo {
  route: string;
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'ANY';
  file: string;
  framework: 'nextjs' | 'express' | 'react-router' | 'unknown';
  isApi: boolean;
  isPage: boolean;
  requiresAuth?: boolean;
  hasRoleCheck?: boolean;
  acceptsUserInput?: boolean;
  riskTags: string[];
}

export interface ScannedFile {
  path: string;
  relativePath: string;
  extension: string;
  sizeBytes: number;
  content: string;
  sha256?: string;
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
  rules?: RulesConfig;
}

export interface RuleContext {
  rootPath: string;
  files: ScannedFile[];
  packageJson?: Record<string, unknown>;
  detectedStack: DetectedStack;
  config: ScannerConfig;
  routes?: RouteInfo[];
  fileClassifications?: FileClassification[];
  importGraph?: ImportGraph;
  parsedFiles?: ParsedFile[];
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
  fileClassifications?: FileClassification[];
  findings: Finding[];
  findingsByLayer: Record<ScannerLayer, Finding[]>;
  riskScore: number;
  summary: ScanSummary;
  owaspCoverage: string[];
  topRecommendations: string[];
  topRiskyFiles?: string[];
}

export interface ScanOptions {
  json?: boolean;
  html?: boolean;
  outputDir?: string;
  severityThreshold?: Severity;
  rulesConfig?: RulesConfig;
}

export const DEFAULT_CONFIG: ScannerConfig = {
  ignoreDirs: ['node_modules', '.next', 'dist', 'build', '.git', 'coverage', '.turbo', '.vercel', '.cache', 'out'],
  ignoreFiles: [],
  maxFileSizeBytes: 1_000_000,
  outputDir: '.appsec',
};

// ─── Runtime Scan Types ───────────────────────────────────────────────────────

export interface RuntimeConfig {
  baseUrl: string;
  allowedHosts?: string[];
  disallowedHosts?: string[];
  disallowedPaths?: string[];
  maxPages?: number;
  maxDepth?: number;
  maxRequests?: number;
  requestDelayMs?: number;
  timeoutMs?: number;
  safeMode?: boolean;
  userAgent?: string;
}

export interface CrawledCookie {
  name: string;
  value: string;
  domain?: string;
  path?: string;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: string;
  expires?: number;
}

export interface FormField {
  name?: string;
  type?: string;
  value?: string;
}

export interface CrawledForm {
  action?: string;
  method?: string;
  fields: FormField[];
}

export interface NetworkRequest {
  url: string;
  method: string;
  status?: number;
  headers?: Record<string, string>;
}

export interface CrawledPage {
  url: string;
  depth: number;
  statusCode: number;
  headers: Record<string, string>;
  cookies: CrawledCookie[];
  links: string[];
  forms: CrawledForm[];
  scripts: string[];
  networkRequests: NetworkRequest[];
  consoleErrors: string[];
  redirectChain: string[];
}

export interface RuntimeScanReport {
  targetUrl: string;
  pagesVisited: number;
  requestsMade: number;
  durationMs: number;
  findings: RuntimeFinding[];
  summary: ScanSummary;
  riskScore: number;
  owaspCoverage: string[];
  topRecommendations: string[];
}

// ─── Auth Scan Types ──────────────────────────────────────────────────────────

export interface AuthProfileConfig {
  label?: string;
  storageStatePath?: string;
  headers?: Record<string, string>;
  cookies?: string;
  isPrivileged?: boolean;
}

export interface AuthProfile {
  name: string;
  label: string;
  type: 'anonymous' | 'storageState' | 'headers' | 'cookies';
  headers: Record<string, string>;
  cookies?: string;
  storageStatePath?: string;
  isPrivileged?: boolean;
}

export interface AccessControlTestConfig {
  name: string;
  type: 'horizontal' | 'tenant-boundary';
  userAOwns?: string[];
  userBOwns?: string[];
  shouldBePrivate?: boolean;
}

export interface AuthScanConfig {
  baseUrl: string;
  profiles: Record<string, AuthProfileConfig>;
  accessControlTests?: AccessControlTestConfig[];
  maxAuthzRequests?: number;
  requestDelayMs?: number;
  timeoutMs?: number;
}

export interface AccessRouteCandidate {
  route: string;
  method: 'GET' | 'HEAD' | 'OPTIONS';
  source: 'static' | 'runtime' | 'config' | 'heuristic';
  file?: string;
  riskTags: string[];
  requiresAuthExpected: boolean;
  destructive: boolean;
}

export interface SensitiveSignal {
  field: string;
  confidence: 'high' | 'medium' | 'low';
  redactedEvidence: string;
}

export interface StaticCorrelation {
  file: string;
  reason: string;
}

export interface ResponseSnapshot {
  status: number;
  contentLength: number;
  jsonKeys: string[];
  sensitiveFields: string[];
  body: string;
}

export interface AuthzFinding extends Finding {
  layer: 'authz';
  url: string;
  profileUsed?: string;
  targetProfileName?: string;
  sensitiveFields?: string[];
  staticCorrelation?: StaticCorrelation;
}

export interface AuthScanReport {
  targetUrl: string;
  profilesUsed: string[];
  routesTested: number;
  resourcePairsTested: number;
  durationMs: number;
  findings: AuthzFinding[];
  summary: ScanSummary;
  riskScore: number;
  skippedDestructiveRoutes: string[];
  recommendations: string[];
}
