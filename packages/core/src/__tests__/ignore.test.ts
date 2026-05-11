import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { applyIgnoreRules } from '../ignore-loader';
import type { Finding } from '@cybermat/shared';

function makeFinding(id: string, ruleId: string, file: string, severity: 'critical' | 'high' | 'medium' = 'high'): Finding {
  return {
    id,
    ruleId,
    title: 'Test Finding',
    severity,
    confidence: 'high',
    owasp: ['A04 Cryptographic Failures'],
    category: 'Secrets',
    file,
    line: 1,
    evidence: { reason: 'test' },
    impact: 'test impact',
    recommendation: 'test recommendation',
    tags: [],
  };
}

describe('applyIgnoreRules', () => {
  test('returns all findings when no rules', () => {
    const findings = [makeFinding('abc', 'secrets.stripe-secret-key', 'lib/foo.ts')];
    const result = applyIgnoreRules(findings, { files: [], ruleIds: [], fingerprints: [] });
    assert.equal(result.length, 1);
  });

  test('ignores finding by rule ID', () => {
    const findings = [
      makeFinding('abc', 'secrets.stripe-secret-key', 'lib/foo.ts'),
      makeFinding('def', 'injection.eval-usage', 'lib/bar.ts'),
    ];
    const result = applyIgnoreRules(findings, { files: [], ruleIds: ['secrets.stripe-secret-key'], fingerprints: [] });
    assert.equal(result.length, 1);
    assert.equal(result[0].ruleId, 'injection.eval-usage');
  });

  test('ignores finding by fingerprint (id)', () => {
    const findings = [
      makeFinding('abc123', 'secrets.stripe-secret-key', 'lib/foo.ts'),
      makeFinding('def456', 'injection.eval-usage', 'lib/bar.ts'),
    ];
    const result = applyIgnoreRules(findings, { files: [], ruleIds: [], fingerprints: ['abc123'] });
    assert.equal(result.length, 1);
    assert.equal(result[0].id, 'def456');
  });

  test('ignores finding by exact file path', () => {
    const findings = [
      makeFinding('abc', 'secrets.stripe-secret-key', 'examples/vulnerable-next-app/.env.local'),
      makeFinding('def', 'injection.eval-usage', 'lib/bar.ts'),
    ];
    const result = applyIgnoreRules(findings, { files: ['examples/vulnerable-next-app/.env.local'], ruleIds: [], fingerprints: [] });
    assert.equal(result.length, 1);
    assert.equal(result[0].id, 'def');
  });

  test('ignores findings by wildcard file prefix', () => {
    const findings = [
      makeFinding('abc', 'secrets.openai-api-key', 'examples/vulnerable-next-app/lib/ai.ts'),
      makeFinding('def', 'injection.eval-usage', 'src/lib/bar.ts'),
    ];
    const result = applyIgnoreRules(findings, { files: ['examples/*'], ruleIds: [], fingerprints: [] });
    assert.equal(result.length, 1);
    assert.equal(result[0].id, 'def');
  });

  test('keeps findings not matching any rule', () => {
    const findings = [makeFinding('abc', 'secrets.stripe-secret-key', 'lib/foo.ts')];
    const result = applyIgnoreRules(findings, { files: ['other/path'], ruleIds: ['injection.eval-usage'], fingerprints: [] });
    assert.equal(result.length, 1);
  });
});
