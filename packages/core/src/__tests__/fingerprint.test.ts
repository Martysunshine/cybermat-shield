import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createFindingFingerprint, normalizePath, normalizeSnippet, stableHash } from '../fingerprint';
import { createBaseline, compareToBaseline } from '../baseline';
import type { Finding, ScanReport } from '@cybermat/shared';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'test-id',
    ruleId: 'secrets/aws-key',
    title: 'AWS Access Key',
    severity: 'critical',
    confidence: 'high',
    owasp: ['A04 Cryptographic Failures'],
    category: 'Secrets',
    file: 'src/config.ts',
    line: 10,
    evidence: { reason: 'AWS access key detected', redactedMatch: 'AKIA...1234' },
    impact: 'Credential exposure',
    recommendation: 'Remove and rotate the key',
    tags: ['aws'],
    ...overrides,
  };
}

function makeReport(findings: Finding[]): ScanReport {
  return {
    metadata: { timestamp: new Date().toISOString(), layers: ['code'], version: '0.5.0' },
    scannedPath: '/project',
    timestamp: new Date().toISOString(),
    filesScanned: 10,
    filesIgnored: 0,
    detectedStack: { languages: [], frameworks: [], databases: [], authProviders: [], aiProviders: [], deploymentTargets: [], packageManagers: [] },
    findings,
    findingsByLayer: { code: findings, runtime: [], authz: [] },
    riskScore: 50,
    summary: { critical: findings.filter(f => f.severity === 'critical').length, high: 0, medium: 0, low: 0, info: 0, total: findings.length },
    owaspCoverage: [],
    topRecommendations: [],
  };
}

describe('normalizePath', () => {
  test('converts backslashes to forward slashes', () => {
    assert.equal(normalizePath('src\\config\\db.ts'), 'src/config/db.ts');
  });

  test('strips leading ./', () => {
    assert.equal(normalizePath('./src/app.ts'), 'src/app.ts');
  });

  test('does not strip non-leading ./', () => {
    assert.equal(normalizePath('src/./app.ts'), 'src/./app.ts');
  });
});

describe('normalizeSnippet', () => {
  test('lowercases and trims', () => {
    assert.equal(normalizeSnippet('  AWS KEY Found  '), 'aws key found');
  });

  test('collapses whitespace', () => {
    assert.equal(normalizeSnippet('a  b\t\tc'), 'a b c');
  });

  test('truncates at 120 chars', () => {
    const long = 'a'.repeat(200);
    assert.equal(normalizeSnippet(long).length, 120);
  });
});

describe('stableHash', () => {
  test('same input produces same hash', () => {
    assert.equal(stableHash('hello:world'), stableHash('hello:world'));
  });

  test('different input produces different hash', () => {
    assert.notEqual(stableHash('hello:world'), stableHash('hello:earth'));
  });

  test('output is 16 hex chars', () => {
    assert.match(stableHash('test'), /^[0-9a-f]{16}$/);
  });
});

describe('createFindingFingerprint', () => {
  test('same finding moved from line 10 to line 20 keeps same fingerprint', () => {
    const f1 = makeFinding({ line: 10 });
    const f2 = makeFinding({ line: 20 });
    assert.equal(createFindingFingerprint(f1), createFindingFingerprint(f2));
  });

  test('different evidence in same file produces different fingerprint', () => {
    const f1 = makeFinding({ evidence: { reason: 'AWS key found', redactedMatch: 'AKIA...1234' } });
    const f2 = makeFinding({ evidence: { reason: 'Stripe key found', redactedMatch: 'sk_live_...5678' } });
    assert.notEqual(createFindingFingerprint(f1), createFindingFingerprint(f2));
  });

  test('same rule in different files produces different fingerprint', () => {
    const f1 = makeFinding({ file: 'src/config.ts' });
    const f2 = makeFinding({ file: 'src/database.ts' });
    assert.notEqual(createFindingFingerprint(f1), createFindingFingerprint(f2));
  });

  test('different rule IDs in same file produce different fingerprint', () => {
    const f1 = makeFinding({ ruleId: 'secrets/aws-key' });
    const f2 = makeFinding({ ruleId: 'secrets/stripe-key' });
    assert.notEqual(createFindingFingerprint(f1), createFindingFingerprint(f2));
  });

  test('path with backslashes matches path with forward slashes', () => {
    const f1 = makeFinding({ file: 'src\\config.ts' });
    const f2 = makeFinding({ file: 'src/config.ts' });
    assert.equal(createFindingFingerprint(f1), createFindingFingerprint(f2));
  });
});

describe('baseline comparison with content-based fingerprints', () => {
  test('finding moved from line 10 to line 20 is identified as existing', () => {
    const originalFinding = makeFinding({ id: 'f1', line: 10 });
    originalFinding.fingerprint = createFindingFingerprint(originalFinding);

    const baselineReport = makeReport([originalFinding]);
    const baseline = createBaseline(baselineReport);

    const movedFinding = makeFinding({ id: 'f1', line: 20 });
    movedFinding.fingerprint = createFindingFingerprint(movedFinding);

    const newReport = makeReport([movedFinding]);
    const diff = compareToBaseline(newReport, baseline);

    assert.equal(diff.summary.existing, 1, 'moved finding should be existing');
    assert.equal(diff.summary.new, 0, 'no new findings expected');
    assert.equal(diff.summary.fixed, 0, 'no fixed findings expected');
  });

  test('genuinely new finding is identified as new', () => {
    const original = makeFinding({ id: 'f1', ruleId: 'secrets/aws-key', file: 'src/a.ts' });
    original.fingerprint = createFindingFingerprint(original);

    const baseline = createBaseline(makeReport([original]));

    const newFinding = makeFinding({ id: 'f2', ruleId: 'secrets/stripe-key', file: 'src/b.ts', evidence: { reason: 'Stripe key' } });
    newFinding.fingerprint = createFindingFingerprint(newFinding);

    const diff = compareToBaseline(makeReport([original, newFinding]), baseline);
    assert.equal(diff.summary.new, 1);
    assert.equal(diff.summary.existing, 1);
  });

  test('removed finding is identified as fixed', () => {
    const f1 = makeFinding({ id: 'f1' });
    f1.fingerprint = createFindingFingerprint(f1);
    const baseline = createBaseline(makeReport([f1]));

    const diff = compareToBaseline(makeReport([]), baseline);
    assert.equal(diff.summary.fixed, 1);
  });
});
