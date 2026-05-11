export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  owasp: string[];
  category: string;
  file?: string;
  line?: number;
  route?: string;
  evidence: string;
  impact: string;
  recommendation: string;
  references?: string[];
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
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  category: string;
  owasp: string[];
  severity: Severity;
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

export interface ScanReport {
  scannedPath: string;
  timestamp: string;
  filesScanned: number;
  filesIgnored: number;
  detectedStack: DetectedStack;
  findings: Finding[];
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
