import type { Finding, FindingEvidence, Severity, Confidence } from '@cybermat/shared';
import * as crypto from 'crypto';

export function redactSecret(value: string): string {
  if (!value) return '****';
  if (value.length <= 8) return '****';
  return value.slice(0, 4) + '****' + value.slice(-4);
}

export function redactLine(line: string, secretValue: string): string {
  if (!secretValue) return line;
  return line.replace(secretValue, redactSecret(secretValue));
}

export function truncate(str: string, max = 120): string {
  const trimmed = str.trim();
  return trimmed.length > max ? trimmed.slice(0, max) + '...' : trimmed;
}

export function makeFindingId(ruleId: string, relativePath: string, line: number): string {
  const raw = `${ruleId}:${relativePath}:${line}`;
  return crypto.createHash('sha1').update(raw).digest('hex').slice(0, 12);
}

export function generateFingerprint(
  ruleId: string,
  file: string,
  line: number,
  redactedEvidence: string,
  category: string,
): string {
  // Line bucket (groups of 5) makes fingerprint resilient to minor line shifts
  const lineBucket = Math.floor(line / 5) * 5;
  const raw = `${ruleId}:${file}:${lineBucket}:${redactedEvidence}:${category}`;
  return crypto.createHash('sha1').update(raw).digest('hex').slice(0, 16);
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

export function evidenceFromLine(line: string, reason?: string): FindingEvidence {
  return {
    snippet: truncate(line),
    reason: reason ?? truncate(line),
  };
}

export function evidenceFromSecret(line: string, secretValue: string, reason?: string): FindingEvidence {
  const redactedSnippet = truncate(redactLine(line, secretValue));
  const redactedMatch = redactSecret(secretValue);
  return {
    redactedSnippet,
    redactedMatch,
    reason: reason ?? redactedSnippet,
  };
}

export function evidenceFromMessage(reason: string): FindingEvidence {
  return { reason };
}
