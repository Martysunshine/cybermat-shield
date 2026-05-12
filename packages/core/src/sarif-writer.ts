import type { ScanReport, Finding, Severity, RuntimeScanReport, AuthScanReport, AuthzFinding } from '@cybermat/shared';

const SEVERITY_TO_LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  helpUri?: string;
  properties?: {
    tags?: string[];
    precision?: string;
    'problem.severity'?: string;
    'security-severity'?: string;
  };
}

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations?: Array<{
    physicalLocation: {
      artifactLocation: { uri: string; uriBaseId?: string };
      region?: { startLine: number; startColumn?: number };
    };
  }>;
  partialFingerprints?: Record<string, string>;
  properties?: Record<string, unknown>;
}

function securitySeverity(sev: Severity): string {
  // GitHub uses 0.0–10.0; map our levels to CVSS-style ranges
  switch (sev) {
    case 'critical': return '9.5';
    case 'high': return '8.0';
    case 'medium': return '5.0';
    case 'low': return '2.0';
    case 'info': return '0.0';
  }
}

function findingToResult(f: Finding, baseDir?: string): SarifResult {
  const result: SarifResult = {
    ruleId: f.ruleId,
    level: SEVERITY_TO_LEVEL[f.severity],
    message: {
      text: [f.title, f.evidence.reason, f.recommendation].filter(Boolean).join(' — '),
    },
    partialFingerprints: {
      primaryLocationLineHash: f.id,
      ...(f.fingerprint ? { 'findingFingerprint/v1': f.fingerprint } : {}),
    },
    properties: {
      owasp: f.owasp,
      cwe: f.cwe ?? [],
      layer: f.layer ?? 'code',
    },
  };

  if (f.file) {
    let uri = f.file.replace(/\\/g, '/');
    if (baseDir) {
      const base = baseDir.replace(/\\/g, '/').replace(/\/$/, '');
      if (uri.startsWith(base)) uri = uri.slice(base.length + 1);
    }
    result.locations = [
      {
        physicalLocation: {
          artifactLocation: { uri, uriBaseId: '%SRCROOT%' },
          region: f.line !== undefined ? { startLine: f.line, startColumn: f.column ?? 1 } : undefined,
        },
      },
    ];
  } else if ((f as AuthzFinding).url) {
    const url = (f as AuthzFinding).url!;
    result.locations = [
      {
        physicalLocation: {
          artifactLocation: { uri: url },
        },
      },
    ];
  }

  return result;
}

function buildRules(findings: Finding[]): SarifRule[] {
  const seen = new Set<string>();
  const rules: SarifRule[] = [];
  for (const f of findings) {
    if (seen.has(f.ruleId)) continue;
    seen.add(f.ruleId);
    rules.push({
      id: f.ruleId,
      name: f.ruleId.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
      shortDescription: { text: f.title },
      properties: {
        tags: f.tags,
        precision: f.confidence === 'high' ? 'high' : f.confidence === 'medium' ? 'medium' : 'low',
        'problem.severity': f.severity === 'critical' || f.severity === 'high' ? 'error' : 'warning',
        'security-severity': securitySeverity(f.severity),
      },
    });
  }
  return rules;
}

export function generateSarif(
  report: ScanReport,
  runtimeReport?: RuntimeScanReport,
  authReport?: AuthScanReport,
): string {
  const allFindings: Finding[] = [
    ...report.findings,
    ...((runtimeReport?.findings ?? []) as Finding[]),
    ...((authReport?.findings ?? []) as Finding[]),
  ];

  const sarifRules = buildRules(allFindings);
  const results = allFindings.map(f => findingToResult(f, report.scannedPath));

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'CyberMat Shield',
            version: '0.1.0',
            informationUri: 'https://github.com/Martysunshine/cybermat-shield',
            rules: sarifRules,
          },
        },
        results,
        columnKind: 'utf16CodeUnits',
        properties: {
          riskScore: report.riskScore,
          scannedPath: report.scannedPath,
          timestamp: report.timestamp,
          totalFindings: allFindings.length,
        },
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
