import { createHash } from 'crypto';
import type { Finding } from '@cybermat/shared';

export function normalizePath(p: string): string {
  return p.replace(/\\/g, '/').replace(/^\.\//, '');
}

export function normalizeSnippet(s: string): string {
  return s.trim().toLowerCase().replace(/\s+/g, ' ').slice(0, 120);
}

export function stableHash(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex').slice(0, 16);
}

/**
 * Produces a content-based fingerprint that does not depend on line number.
 * Stable across refactors that only move code without changing its content.
 */
export function createFindingFingerprint(f: Finding): string {
  const file = normalizePath(f.file ?? f.url ?? '');
  const evidenceKey = normalizeSnippet(f.evidence?.reason ?? f.evidence?.redactedSnippet ?? f.evidence?.snippet ?? '');
  return stableHash(`${f.ruleId}:${file}:${evidenceKey}`);
}

/**
 * Secondary fingerprint that includes the line bucket (5-line tolerance).
 * Used as a soft-match fallback when content-based fingerprints are unavailable.
 */
export function createLocationFingerprint(f: Finding): string {
  const file = normalizePath(f.file ?? f.url ?? '');
  const lineBucket = f.line !== undefined ? Math.floor(f.line / 5) * 5 : -1;
  return stableHash(`${f.ruleId}:${file}:${lineBucket}`);
}
