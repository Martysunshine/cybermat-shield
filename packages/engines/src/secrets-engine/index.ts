import type { ScannedFile, Finding, Severity } from '@cybermat/shared';
import * as crypto from 'crypto';
import { SECRET_DETECTORS } from './detectors';

export { SECRET_DETECTORS } from './detectors';
export type { SecretDetector } from './detectors';

export function redactSecret(value: string): string {
  if (!value) return '****';
  if (value.length <= 8) return '****';
  return value.slice(0, 4) + '****' + value.slice(-4);
}

function redactLine(line: string, secretValue: string): string {
  return line.replace(secretValue, redactSecret(secretValue));
}

function truncate(str: string, max = 120): string {
  const t = str.trim();
  return t.length > max ? t.slice(0, max) + '...' : t;
}

function makeFindingId(ruleId: string, relativePath: string, line: number): string {
  const raw = `${ruleId}:${relativePath}:${line}`;
  return crypto.createHash('sha1').update(raw).digest('hex').slice(0, 12);
}

export function isClientFile(relativePath: string, content: string): boolean {
  const dirs = ['/components/', '/app/', '/pages/', '/src/components/', '/src/app/', '/public/'];
  if (dirs.some(d => relativePath.includes(d))) return true;
  if (content.includes('"use client"') || content.includes("'use client'")) return true;
  if (content.includes('NEXT_PUBLIC_') || content.includes('import.meta.env.VITE_')) return true;
  return false;
}

function isEnvFile(relativePath: string): boolean {
  const basename = relativePath.split('/').pop() ?? '';
  return basename.startsWith('.env');
}

function resolveSeverity(
  baseSeverity: Severity,
  frontendSeverity: Severity | undefined,
  envFileSeverity: Severity | undefined,
  inClientCode: boolean,
  inEnvFile: boolean,
): Severity {
  if (inClientCode && frontendSeverity) return frontendSeverity;
  if (inEnvFile && envFileSeverity) return envFileSeverity;
  return baseSeverity;
}

export interface SecretFinding {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: 'high' | 'medium' | 'low';
  owasp: string[];
  cwe: string[];
  category: string;
  file: string;
  line: number;
  redactedSnippet: string;
  redactedMatch: string;
  impact: string;
  recommendation: string;
  tags: string[];
  inClientCode: boolean;
}

export function scanFileForSecrets(file: ScannedFile): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const lines = file.content.split('\n');
  const inClient = isClientFile(file.relativePath, file.content);
  const inEnv = isEnvFile(file.relativePath);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('#')) continue;

    for (const detector of SECRET_DETECTORS) {
      // Reset lastIndex for global regexes
      detector.pattern.lastIndex = 0;
      const match = detector.pattern.exec(line);
      if (!match) continue;

      const secretValue = detector.valueGroup ? match[detector.valueGroup] : match[0];
      if (!secretValue || secretValue.length < 4) continue;

      const severity = resolveSeverity(
        detector.baseSeverity,
        detector.frontendSeverity,
        detector.envFileSeverity,
        inClient,
        inEnv,
      );

      const redactedSnippet = truncate(redactLine(line, secretValue));
      const redactedMatch = redactSecret(secretValue);

      findings.push({
        id: makeFindingId(detector.id, file.relativePath, i + 1),
        ruleId: detector.id,
        title: detector.name,
        severity,
        confidence: detector.confidence ?? 'high',
        owasp: detector.owasp,
        cwe: detector.cwe,
        category: 'Secrets',
        file: file.relativePath,
        line: i + 1,
        redactedSnippet,
        redactedMatch,
        impact: detector.impact,
        recommendation: detector.recommendation,
        tags: [...detector.tags, inClient ? 'frontend' : 'backend', inEnv ? 'env-file' : 'source-code'],
        inClientCode: inClient,
      });
    }
  }

  return findings;
}

export function scanFilesForSecrets(files: ScannedFile[]): SecretFinding[] {
  return files.flatMap(scanFileForSecrets);
}

export function secretFindingToFinding(sf: SecretFinding): Finding {
  return {
    id: sf.id,
    ruleId: sf.ruleId,
    title: sf.title,
    severity: sf.severity,
    confidence: sf.confidence,
    owasp: sf.owasp,
    cwe: sf.cwe,
    category: sf.category,
    file: sf.file,
    line: sf.line,
    evidence: {
      redactedSnippet: sf.redactedSnippet,
      redactedMatch: sf.redactedMatch,
      reason: `${sf.title} detected in ${sf.file}:${sf.line}`,
    },
    impact: sf.impact,
    recommendation: sf.recommendation,
    tags: sf.tags,
  };
}
