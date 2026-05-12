import * as fs from 'fs';
import * as path from 'path';
import type { Finding, ScanReport } from '@cybermat/shared';

export type FindingStatus = 'new' | 'existing' | 'fixed';

export interface BaselineEntry {
  id: string;
  ruleId: string;
  severity: string;
  title: string;
  file?: string;
  line?: number;
  /** Stable fingerprint — same rule + file + line bucket */
  fingerprint: string;
}

export interface Baseline {
  version: 1;
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

function fingerprintOf(f: Finding): string {
  const lineBucket = f.line !== undefined ? Math.floor(f.line / 5) * 5 : -1;
  const file = f.file ?? f.url ?? '';
  return `${f.ruleId}::${file}::${lineBucket}`;
}

export function createBaseline(report: ScanReport): Baseline {
  return {
    version: 1,
    createdAt: new Date().toISOString(),
    scannedPath: report.scannedPath,
    entries: report.findings.map(f => ({
      id: f.id,
      ruleId: f.ruleId,
      severity: f.severity,
      title: f.title,
      file: f.file,
      line: f.line,
      fingerprint: fingerprintOf(f),
    })),
  };
}

export function compareToBaseline(report: ScanReport, baseline: Baseline): BaselineDiff {
  const baselineFingerprints = new Set(baseline.entries.map(e => e.fingerprint));
  const currentFingerprints = new Set(report.findings.map(f => fingerprintOf(f)));

  const newFindings = report.findings.filter(f => !baselineFingerprints.has(fingerprintOf(f)));
  const existingFindings = report.findings.filter(f => baselineFingerprints.has(fingerprintOf(f)));
  const fixedEntries = baseline.entries.filter(e => !currentFingerprints.has(e.fingerprint));

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
  return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as Baseline;
}
