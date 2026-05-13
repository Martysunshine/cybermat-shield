import * as fs from 'fs';
import * as path from 'path';
import type { Finding } from '@cybermat/shared';

export interface IgnoreRules {
  files: string[];
  ruleIds: string[];
  fingerprints: string[];
}

export function loadIgnoreRules(rootPath: string): IgnoreRules {
  const rules: IgnoreRules = { files: [], ruleIds: [], fingerprints: [] };

  const candidatePaths = [
    path.join(rootPath, '.cybermatignore'),
    path.join(rootPath, '.cybermat', '.cybermatignore'),
  ];

  for (const p of candidatePaths) {
    if (!fs.existsSync(p)) continue;
    try {
      const lines = fs.readFileSync(p, 'utf-8').split('\n');
      for (const raw of lines) {
        const line = raw.trim();
        if (!line || line.startsWith('#')) continue;

        if (line.startsWith('rule:')) {
          rules.ruleIds.push(line.slice('rule:'.length).trim());
        } else if (line.startsWith('fp:')) {
          rules.fingerprints.push(line.slice('fp:'.length).trim());
        } else {
          rules.files.push(line);
        }
      }
      break; // Use the first file found
    } catch {
      // ignore read errors
    }
  }

  return rules;
}

export function applyIgnoreRules(findings: Finding[], rules: IgnoreRules): Finding[] {
  if (!rules.files.length && !rules.ruleIds.length && !rules.fingerprints.length) {
    return findings;
  }

  return findings.filter(f => {
    // Ignore by rule ID
    if (f.ruleId && rules.ruleIds.includes(f.ruleId)) return false;

    // Ignore by file path (supports prefix matching and glob-like wildcards via includes)
    if (f.file) {
      for (const pattern of rules.files) {
        if (pattern.endsWith('*')) {
          if (f.file.startsWith(pattern.slice(0, -1))) return false;
        } else {
          if (f.file === pattern || f.file.includes(pattern)) return false;
        }
      }
    }

    // Ignore by fingerprint (finding ID)
    if (rules.fingerprints.includes(f.id)) return false;

    return true;
  });
}
