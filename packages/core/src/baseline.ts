import * as fs from 'fs';
import * as path from 'path';
import type { Finding, ScanReport } from '@cybermat/shared';
import { createFindingFingerprint, createLocationFingerprint } from './fingerprint';

export type FindingStatus = 'new' | 'existing' | 'fixed';

export interface BaselineEntry {
  id: string;
  ruleId: string;
  severity: string;
  title: string;
  file?: string;
  line?: number;
  /** Content-based stable fingerprint (v2+). Does not depend on line number. */
  fingerprint: string;
  /** Location-based fingerprint kept for backward-compat fallback */
  locationFingerprint?: string;
}

export interface Baseline {
  version: number;
  createdAt: string;
  scannedPath: string;
  entries: BaselineEntry[];
}

export interface BaselineDiff {
  newFindings: Finding[];
  existingFindings: Finding[];
  fixedEntries: BaselineEntry[];
  summary: {
    new: number;
    existing: number;
    fixed: number;
  };
}

/**
 * Resolves the best available fingerprint for a finding.
 * Prefers the content-based fingerprint assigned by the scanner pipeline.
 * Falls back to generating it inline, then to the legacy location-bucket formula.
 */
function resolveFindingFingerprint(f: Finding): string {
  if (f.fingerprint) return f.fingerprint;
  return createFindingFingerprint(f);
}

/**
 * Resolves the best fingerprint from a baseline entry for comparison.
 * Version-1 baselines used a legacy formula; version-2+ use content-based hashes.
 */
function resolveEntryFingerprint(entry: BaselineEntry): string {
  return entry.fingerprint;
}

export function createBaseline(report: ScanReport): Baseline {
  return {
    version: 2,
    createdAt: new Date().toISOString(),
    scannedPath: report.scannedPath,
    entries: report.findings.map(f => ({
      id: f.id,
      ruleId: f.ruleId,
      severity: f.severity,
      title: f.title,
      file: f.file,
      line: f.line,
      fingerprint: resolveFindingFingerprint(f),
      locationFingerprint: createLocationFingerprint(f),
    })),
  };
}

export function compareToBaseline(report: ScanReport, baseline: Baseline): BaselineDiff {
  const baselineFingerprints = new Set(baseline.entries.map(e => resolveEntryFingerprint(e)));

  // For v1 baselines, also collect location fingerprints as fallback keys
  const baselineLocationFingerprints = new Set(
    baseline.entries
      .filter(e => e.locationFingerprint)
      .map(e => e.locationFingerprint as string)
  );

  function isExistingFinding(f: Finding): boolean {
    const fp = resolveFindingFingerprint(f);
    if (baselineFingerprints.has(fp)) return true;
    // Fallback: match by location fingerprint (covers v1 baselines and moved code)
    const locFp = f.locationFingerprint ?? createLocationFingerprint(f);
    return baselineLocationFingerprints.has(locFp);
  }

  const currentFingerprints = new Set(report.findings.map(f => resolveFindingFingerprint(f)));
  const currentLocationFingerprints = new Set(report.findings.map(f => f.locationFingerprint ?? createLocationFingerprint(f)));

  const newFindings = report.findings.filter(f => !isExistingFinding(f));
  const existingFindings = report.findings.filter(f => isExistingFinding(f));
  const fixedEntries = baseline.entries.filter(e => {
    const fp = resolveEntryFingerprint(e);
    if (currentFingerprints.has(fp)) return false;
    if (e.locationFingerprint && currentLocationFingerprints.has(e.locationFingerprint)) return false;
    return true;
  });

  return {
    newFindings,
    existingFindings,
    fixedEntries,
    summary: {
      new: newFindings.length,
      existing: existingFindings.length,
      fixed: fixedEntries.length,
    },
  };
}

export function saveBaseline(baseline: Baseline, outputDir: string): string {
  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
  const filePath = path.join(outputDir, 'baseline.json');
  fs.writeFileSync(filePath, JSON.stringify(baseline, null, 2), 'utf-8');
  return filePath;
}

export function loadBaseline(outputDir: string): Baseline | null {
  const filePath = path.join(outputDir, 'baseline.json');
  if (!fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as Baseline;
  } catch {
    return null;
  }
}
