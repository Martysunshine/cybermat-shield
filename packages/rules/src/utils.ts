import type { Finding, Severity, Confidence } from '@cybermat/shared';
import * as crypto from 'crypto';

export function redactSecret(value: string): string {
  if (!value) return '****';
  if (value.length <= 8) return '****';
  return value.slice(0, 4) + '****' + value.slice(-4);
}

export function redactLine(line: string, secretValue: string): string {
  if (!secretValue) return line;
  const redacted = redactSecret(secretValue);
  return line.replace(secretValue, redacted);
}

export function truncate(str: string, max = 120): string {
  const trimmed = str.trim();
  return trimmed.length > max ? trimmed.slice(0, max) + '...' : trimmed;
}

export function makeFindingId(ruleId: string, relativePath: string, line: number): string {
  const raw = `${ruleId}:${relativePath}:${line}`;
  return crypto.createHash('sha1').update(raw).digest('hex').slice(0, 12);
}

export function createFinding(
  ruleId: string,
  title: string,
  severity: Severity,
  confidence: Confidence,
  owasp: string[],
  category: string,
  evidence: string,
  impact: string,
  recommendation: string,
  file?: string,
  line?: number,
  references?: string[],
): Finding {
  return {
    id: makeFindingId(ruleId, file ?? 'global', line ?? 0),
    title,
    severity,
    confidence,
    owasp,
    category,
    evidence: truncate(evidence),
    impact,
    recommendation,
    file,
    line,
    references,
  };
}

export function isClientFile(relativePath: string, content: string): boolean {
  const clientDirs = ['/components/', '/app/', '/pages/', '/src/components/', '/src/app/', '/public/'];
  const inClientDir = clientDirs.some(d => relativePath.includes(d));
  const hasUseClient = content.includes('"use client"') || content.includes("'use client'");
  const hasNextPublic = content.includes('NEXT_PUBLIC_') || content.includes('import.meta.env.VITE_');
  return inClientDir || hasUseClient || hasNextPublic;
}

export function isServerFile(relativePath: string, content: string): boolean {
  const serverPatterns = ['/api/', '/server/', '/lib/server/', 'route.ts', 'route.js', 'server.ts', 'middleware.ts'];
  const inServerDir = serverPatterns.some(p => relativePath.includes(p));
  const hasUseServer = content.includes('"use server"') || content.includes("'use server'");
  return inServerDir || hasUseServer;
}
