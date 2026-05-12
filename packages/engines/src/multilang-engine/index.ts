import * as crypto from 'crypto';
import type { ScannedFile, Finding, Severity } from '@cybermat/shared';
import { MULTILANG_DETECTORS } from './detectors';
import type { MultiLangDetector } from './detectors';

export type { MultiLangDetector } from './detectors';
export { MULTILANG_DETECTORS } from './detectors';

export interface MultiLangFinding {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: 'high' | 'medium' | 'low';
  owasp: string[];
  cwe: string[];
  file: string;
  line: number;
  snippet: string;
  impact: string;
  recommendation: string;
  tags: string[];
}

function makeFindingId(ruleId: string, relativePath: string, line: number): string {
  const raw = `${ruleId}:${relativePath}:${line}`;
  return crypto.createHash('sha1').update(raw).digest('hex').slice(0, 12);
}

function truncate(str: string, max = 120): string {
  const t = str.trim();
  return t.length > max ? t.slice(0, max) + '...' : t;
}

/** Returns detectors that apply to this file based on language and fileKind. */
function getApplicableDetectors(file: ScannedFile): MultiLangDetector[] {
  const lang = file.language ?? '';
  const kind = file.fileKind ?? '';
  return MULTILANG_DETECTORS.filter(d => {
    if (!d.languages.includes(lang)) return false;
    if (d.fileKinds && d.fileKinds.length > 0 && !d.fileKinds.includes(kind)) return false;
    return true;
  });
}

export function scanFileForPatterns(file: ScannedFile): MultiLangFinding[] {
  const detectors = getApplicableDetectors(file);
  if (detectors.length === 0) return [];

  const findings: MultiLangFinding[] = [];
  const lines = file.content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed) continue;
    // Skip comment lines — covers //, #, --, *, <!-- patterns
    if (
      trimmed.startsWith('//') ||
      trimmed.startsWith('#') ||
      trimmed.startsWith('--') ||
      trimmed.startsWith('*') ||
      trimmed.startsWith('<!--')
    ) continue;

    for (const detector of detectors) {
      detector.pattern.lastIndex = 0;
      if (!detector.pattern.test(line)) continue;

      findings.push({
        id: makeFindingId(detector.id, file.relativePath, i + 1),
        ruleId: detector.id,
        title: detector.name,
        severity: detector.severity,
        confidence: detector.confidence,
        owasp: detector.owasp,
        cwe: detector.cwe,
        file: file.relativePath,
        line: i + 1,
        snippet: truncate(line),
        impact: detector.impact,
        recommendation: detector.recommendation,
        tags: [...detector.tags, file.language ?? 'unknown'],
      });
      break; // one finding per line per file pass
    }
  }

  return findings;
}

export function scanFilesForPatterns(files: ScannedFile[]): MultiLangFinding[] {
  return files.flatMap(scanFileForPatterns);
}

export function multilangFindingToFinding(mf: MultiLangFinding): Finding {
  return {
    id: mf.id,
    ruleId: mf.ruleId,
    title: mf.title,
    severity: mf.severity,
    confidence: mf.confidence,
    owasp: mf.owasp,
    cwe: mf.cwe,
    category: 'Dangerous Patterns',
    file: mf.file,
    line: mf.line,
    evidence: {
      snippet: mf.snippet,
      reason: `${mf.title} detected in ${mf.file}:${mf.line}`,
    },
    impact: mf.impact,
    recommendation: mf.recommendation,
    tags: mf.tags,
  };
}
