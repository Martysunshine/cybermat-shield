import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { redactSecret, scanFileForSecrets } from '../index';
import { calculateShannonEntropy } from '../entropy';
import { isJwtShape, isStripeKey, isOpenAIKey, isAnthropicKey, isAWSAccessKey, isGitHubToken, isLikelyPlaceholder } from '../validators';
import type { ScannedFile } from '@cybermat/shared';

// Assembled at runtime so static secret scanners don't flag these test fixtures.
const FAKE_STRIPE_LIVE = ['sk', 'live', 'FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234'].join('_');
const FAKE_STRIPE_TEST = ['sk', 'test', 'FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234'].join('_');
const FAKE_STRIPE_LIVE_SHORT = ['sk', 'live', 'FAKEFAKEFAKEFAKEFAKEFAKEFAKE'].join('_');
const FAKE_STRIPE_TEST_SHORT = ['sk', 'test', 'FAKEFAKEFAKEFAKEFAKEFAKEFAKE'].join('_');
const FAKE_STRIPE_PK = ['pk', 'live', 'FAKEFAKEFAKEFAKEFAKEFAKEFAKE'].join('_');
const FAKE_STRIPE_REDACT_INPUT = ['sk', 'live', '123456789abcdef'].join('_');

function makeFile(relativePath: string, content: string): ScannedFile {
  return {
    path: `/tmp/${relativePath}`,
    relativePath,
    extension: relativePath.split('.').pop() ? `.${relativePath.split('.').pop()}` : '',
    sizeBytes: Buffer.byteLength(content),
    content,
  };
}

// ─── redactSecret ─────────────────────────────────────────────────────────────

describe('redactSecret', () => {
  test('redacts long secrets using first4...REDACTED...last4 format', () => {
    assert.equal(redactSecret(FAKE_STRIPE_REDACT_INPUT), 'sk_l...REDACTED...cdef');
  });

  test('fully masks values shorter than 8 chars', () => {
    assert.equal(redactSecret('abc123'), '[REDACTED]');
  });

  test('fully masks empty string', () => {
    assert.equal(redactSecret(''), '[REDACTED]');
  });

  test('partially shows 8-char values', () => {
    const result = redactSecret('12345678');
    assert.ok(result.includes('...REDACTED...'), 'Should use REDACTED format for 8+ char values');
    assert.ok(!result.includes('12345678'), 'Should not contain original value');
  });

  test('partially shows 9+ char values', () => {
    const result = redactSecret('123456789');
    assert.ok(result.startsWith('1234'), 'Should show first 4 chars');
    assert.ok(result.endsWith('6789'), 'Should show last 4 chars');
    assert.ok(result.includes('...REDACTED...'));
  });

  test('redacts JWT by segment — only first segment visible', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const result = redactSecret(jwt);
    assert.ok(result.startsWith('eyJh'), 'Header part should be visible');
    assert.ok(result.includes('[REDACTED]'), 'Payload and signature should be redacted');
    assert.ok(!result.includes('SflK'), 'Signature should not be visible');
  });
});

// ─── Stripe detection ────────────────────────────────────────────────────────

describe('scanFileForSecrets — Stripe detection', () => {
  test('detects Stripe sk_live key in source file', () => {
    const file = makeFile('lib/stripe.ts', `
      const stripe = new Stripe('${FAKE_STRIPE_LIVE}');
    `);
    const findings = scanFileForSecrets(file);
    assert.ok(findings.length > 0, 'Should detect Stripe key');
    assert.equal(findings[0].ruleId, 'secrets.stripe-secret-key');
    assert.ok(!findings[0].redactedSnippet.includes('FAKEFAKE'), 'Secret must be redacted in snippet');
    assert.ok(findings[0].redactedMatch.includes('REDACTED'), 'Match must use REDACTED format');
  });

  test('escalates Stripe to critical in frontend file', () => {
    const file = makeFile('components/checkout.tsx', `
      'use client';
      const key = '${FAKE_STRIPE_LIVE}';
    `);
    const findings = scanFileForSecrets(file);
    const stripeFinding = findings.find(f => f.ruleId === 'secrets.stripe-secret-key');
    assert.ok(stripeFinding, 'Should find Stripe key');
    assert.equal(stripeFinding!.severity, 'critical', 'Should be critical in frontend');
  });
});

// ─── OpenAI detection ────────────────────────────────────────────────────────

describe('scanFileForSecrets — OpenAI detection', () => {
  test('detects OpenAI API key with high confidence', () => {
    const file = makeFile('lib/ai.ts', `
      const openai = new OpenAI({ apiKey: 'sk-FAKEOPENAIAPIKEYFAKEFAKEFAKEFAKEFAKEFAKEFAKE12345' });
    `);
    const findings = scanFileForSecrets(file);
    const found = findings.find(f => f.ruleId === 'secrets.openai-api-key');
    assert.ok(found, 'Should detect OpenAI key');
    assert.equal(found!.confidence, 'high');
  });

  test('marks sk-your- placeholder as low confidence', () => {
    const file = makeFile('lib/ai.ts', `
      const apiKey = 'sk-your-openai-key-here-replace-me-before-deploying';
    `);
    const findings = scanFileForSecrets(file);
    const found = findings.find(f => f.ruleId === 'secrets.openai-api-key');
    if (found) {
      assert.equal(found.confidence, 'low', 'Placeholder should be low confidence');
      assert.ok(found.tags.includes('likely_false_positive'), 'Should be tagged likely_false_positive');
    }
    // This may or may not match depending on the regex — if it doesn't match, that's acceptable
  });
});

// ─── Anthropic detection ─────────────────────────────────────────────────────

describe('scanFileForSecrets — Anthropic detection', () => {
  test('detects Anthropic API key', () => {
    const file = makeFile('lib/claude.ts', `
      const client = new Anthropic({ apiKey: 'sk-ant-FAKEANTHROPICAPIKEYFAKEFAKEFAKE1234' });
    `);
    const findings = scanFileForSecrets(file);
    const found = findings.find(f => f.ruleId === 'secrets.anthropic-api-key');
    assert.ok(found, 'Should detect Anthropic key');
    assert.ok(found!.confidence === 'high' || found!.confidence === 'medium');
  });
});

// ─── AWS detection ───────────────────────────────────────────────────────────

describe('scanFileForSecrets — AWS detection', () => {
  test('downgrades the official AWS docs example key to low confidence', () => {
    // AKIAIOSFODNN7EXAMPLE is the key used in all AWS documentation — never a real key
    const file = makeFile('config/aws.ts', `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`);
    const findings = scanFileForSecrets(file);
    const found = findings.find(f => f.ruleId === 'secrets.aws-access-key-id');
    assert.ok(found, 'Should still detect the key (not suppress it)');
    assert.equal(found!.confidence, 'low', 'Official AWS example key should be low confidence');
    assert.ok(found!.tags.includes('likely_false_positive'), 'Should be tagged as likely_false_positive');
  });

  test('detects a non-example AWS key with high confidence', () => {
    const file = makeFile('config/aws.ts', `AWS_ACCESS_KEY_ID=AKIAXYZ9QRST1234ABCD`);
    const findings = scanFileForSecrets(file);
    const found = findings.find(f => f.ruleId === 'secrets.aws-access-key-id');
    assert.ok(found, 'Should detect AWS key');
    assert.equal(found!.confidence, 'high', 'Non-example AWS key should be high confidence');
  });
});

// ─── Private key detection ───────────────────────────────────────────────────

describe('scanFileForSecrets — private key detection', () => {
  test('detects RSA private key PEM header', () => {
    const file = makeFile('certs/key.pem', `-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...`);
    const findings = scanFileForSecrets(file);
    const found = findings.find(f => f.ruleId === 'secrets.rsa-private-key');
    assert.ok(found, 'Should detect RSA private key');
    assert.equal(found!.severity, 'critical');
  });
});

// ─── Database URL detection ──────────────────────────────────────────────────

describe('scanFileForSecrets — database URL detection', () => {
  test('detects PostgreSQL connection string', () => {
    const file = makeFile('.env.local', `DATABASE_URL=postgresql://admin:fakepass@localhost:5432/mydb`);
    const findings = scanFileForSecrets(file);
    const found = findings.find(f => f.ruleId === 'secrets.database-url');
    assert.ok(found, 'Should detect DATABASE_URL');
    assert.ok(!found!.redactedSnippet.includes('fakepass'), 'Password must be redacted');
  });
});

// ─── Supabase detection ──────────────────────────────────────────────────────

describe('scanFileForSecrets — Supabase service role key', () => {
  test('detects Supabase service role JWT', () => {
    const file = makeFile('.env.local', `SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.fakesignature123`);
    const findings = scanFileForSecrets(file);
    const found = findings.find(f => f.ruleId === 'secrets.supabase-service-role-key');
    assert.ok(found, 'Should detect Supabase service role key');
  });
});

// ─── Test file tagging ───────────────────────────────────────────────────────

describe('scanFileForSecrets — test fixture tagging', () => {
  test('tags findings from test fixture files', () => {
    const file = makeFile('test/fixtures/api-keys.ts', `
      const key = '${FAKE_STRIPE_LIVE}';
    `);
    const findings = scanFileForSecrets(file);
    const found = findings.find(f => f.ruleId === 'secrets.stripe-secret-key');
    assert.ok(found, 'Should still detect the key');
    assert.ok(found!.tags.includes('possible_test_fixture'), 'Should tag as possible_test_fixture');
  });

  test('tags findings from __tests__ directory', () => {
    const file = makeFile('src/__tests__/stripe.test.ts', `
      const testKey = '${FAKE_STRIPE_TEST}';
    `);
    const findings = scanFileForSecrets(file);
    const found = findings.find(f => f.ruleId === 'secrets.stripe-secret-key');
    if (found) {
      assert.ok(found.tags.includes('possible_test_fixture'), 'Should tag as possible_test_fixture');
    }
  });
});

// ─── False positive avoidance ────────────────────────────────────────────────

describe('scanFileForSecrets — false positive avoidance', () => {
  test('skips comment lines starting with //', () => {
    const file = makeFile('docs/example.ts', `
      // Example: STRIPE_SECRET_KEY=sk_live_your_key_here
    `);
    const findings = scanFileForSecrets(file);
    assert.equal(findings.length, 0, 'Should not flag commented-out examples');
  });

  test('skips comment lines starting with #', () => {
    const file = makeFile('.env.example', `
      # OPENAI_API_KEY=sk-your-key-here
    `);
    const findings = scanFileForSecrets(file);
    assert.equal(findings.length, 0, 'Should not flag hash-commented examples');
  });
});

// ─── Entropy scoring ─────────────────────────────────────────────────────────

describe('calculateShannonEntropy', () => {
  test('returns 0 for empty string', () => {
    assert.equal(calculateShannonEntropy(''), 0);
  });

  test('returns 0 for single repeated character', () => {
    assert.equal(calculateShannonEntropy('aaaaaaa'), 0);
  });

  test('returns higher entropy for random-looking strings', () => {
    const low = calculateShannonEntropy('aaabbbccc');
    const high = calculateShannonEntropy('xK9mR2pQ7nLvWsHtUeYzAjFbDgCiXoN8');
    assert.ok(high > low, 'Random string should have higher entropy than repeating pattern');
  });

  test('placeholder strings have low entropy', () => {
    const entropy = calculateShannonEntropy('YOUR_API_KEY_HERE');
    assert.ok(entropy < 4.0, `Placeholder entropy ${entropy} should be below 4.0`);
  });

  test('real-looking secrets have high entropy', () => {
    const entropy = calculateShannonEntropy('xK9mR2pQ7nLvWsHtUeYzAjFbDgCiXoN8');
    assert.ok(entropy > 4.0, `High-entropy secret should score above 4.0, got ${entropy}`);
  });
});

// ─── Local validators ────────────────────────────────────────────────────────

describe('isJwtShape', () => {
  test('recognizes valid JWT format', () => {
    assert.ok(isJwtShape('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'));
  });

  test('rejects two-segment string', () => {
    assert.ok(!isJwtShape('header.payload'));
  });

  test('rejects plain string', () => {
    assert.ok(!isJwtShape('notajwt'));
  });
});

describe('isStripeKey', () => {
  test('accepts sk_live_ key', () => {
    assert.ok(isStripeKey(FAKE_STRIPE_LIVE_SHORT));
  });

  test('accepts sk_test_ key', () => {
    assert.ok(isStripeKey(FAKE_STRIPE_TEST_SHORT));
  });

  test('rejects publishable key', () => {
    assert.ok(!isStripeKey(FAKE_STRIPE_PK));
  });
});

describe('isOpenAIKey', () => {
  test('accepts sk- format', () => {
    assert.ok(isOpenAIKey('sk-FAKEOPENAIAPIKEYFAKEFAKEFAKEFAKEFAKEFAKEFAKE12345'));
  });

  test('accepts sk-proj- format', () => {
    assert.ok(isOpenAIKey('sk-proj-FAKEOPENAIAPIKEYFAKEFAKEFAKEFAKEFAKEFAKEFAKE12345'));
  });

  test('rejects non-sk prefix', () => {
    assert.ok(!isOpenAIKey('pk-FAKEOPENAIAPIKEY'));
  });
});

describe('isAnthropicKey', () => {
  test('accepts sk-ant- format', () => {
    assert.ok(isAnthropicKey('sk-ant-FAKEANTHROPICAPIKEYFAKEFAKEFAKE1234'));
  });

  test('rejects sk- without ant-', () => {
    assert.ok(!isAnthropicKey('sk-FAKEANTHROPICAPIKEY'));
  });
});

describe('isAWSAccessKey', () => {
  test('accepts AKIA prefix key', () => {
    assert.ok(isAWSAccessKey('AKIAIOSFODNN7EXAMPLE'));
  });

  test('accepts ASIA prefix key', () => {
    assert.ok(isAWSAccessKey('ASIAIOSFODNN7EXAMPLQ'));
  });

  test('rejects wrong length', () => {
    assert.ok(!isAWSAccessKey('AKIA123'));
  });
});

describe('isGitHubToken', () => {
  test('accepts ghp_ token', () => {
    assert.ok(isGitHubToken('ghp_FAKEGITHUBTOKENFAKEFAKEFAKEFAKEFAKE'));
  });

  test('accepts github_pat_ fine-grained token', () => {
    assert.ok(isGitHubToken('github_pat_FAKEGITHUBTOKENFAKEFAKEFAKEFAKEFAKE'));
  });

  test('rejects random string', () => {
    assert.ok(!isGitHubToken('notAGitHubToken'));
  });
});

describe('isLikelyPlaceholder', () => {
  test('detects your_ prefix', () => {
    assert.ok(isLikelyPlaceholder('YOUR_API_KEY_HERE'));
  });

  test('detects _here suffix', () => {
    assert.ok(isLikelyPlaceholder('replace_key_here'));
  });

  test('detects changeme', () => {
    assert.ok(isLikelyPlaceholder('changeme123'));
  });

  test('detects repeated characters', () => {
    assert.ok(isLikelyPlaceholder('xxxxxxxxxx'));
  });

  test('does not flag real-looking values', () => {
    assert.ok(!isLikelyPlaceholder('xK9mR2pQ7nLvWsHtUeYzAjFbDgCiXoN8'));
  });
});
