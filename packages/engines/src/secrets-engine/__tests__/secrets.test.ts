import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { redactSecret, scanFileForSecrets } from '../index';
import type { ScannedFile } from '@cybermat/shared';

function makeFile(relativePath: string, content: string): ScannedFile {
  return {
    path: `/tmp/${relativePath}`,
    relativePath,
    extension: relativePath.split('.').pop() ? `.${relativePath.split('.').pop()}` : '',
    sizeBytes: Buffer.byteLength(content),
    content,
  };
}

describe('redactSecret', () => {
  test('redacts long secrets to first4+****+last4', () => {
    assert.equal(redactSecret('sk_live_123456789abcdef'), 'sk_l****cdef');
  });

  test('fully masks short secrets', () => {
    assert.equal(redactSecret('abc123'), '****');
  });

  test('fully masks empty string', () => {
    assert.equal(redactSecret(''), '****');
  });

  test('shows exactly 8 chars as ****', () => {
    assert.equal(redactSecret('12345678'), '****');
  });

  test('shows 9+ chars as partial', () => {
    const result = redactSecret('123456789');
    assert.equal(result, '1234****6789');
  });
});

describe('scanFileForSecrets — Stripe detection', () => {
  test('detects Stripe sk_live key in source file', () => {
    const file = makeFile('lib/stripe.ts', `
      const stripe = new Stripe('sk_live_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234');
    `);
    const findings = scanFileForSecrets(file);
    assert.ok(findings.length > 0, 'Should detect Stripe key');
    assert.equal(findings[0].ruleId, 'secrets.stripe-secret-key');
    assert.ok(!findings[0].redactedSnippet.includes('sk_live_FAKE'), 'Secret must be redacted in snippet');
    assert.ok(findings[0].redactedMatch.includes('****'), 'Match must be redacted');
  });

  test('escalates Stripe to critical in frontend file', () => {
    const file = makeFile('components/checkout.tsx', `
      'use client';
      const key = 'sk_live_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234';
    `);
    const findings = scanFileForSecrets(file);
    const stripeFinding = findings.find(f => f.ruleId === 'secrets.stripe-secret-key');
    assert.ok(stripeFinding, 'Should find Stripe key');
    assert.equal(stripeFinding!.severity, 'critical', 'Should be critical in frontend');
  });
});

describe('scanFileForSecrets — OpenAI detection', () => {
  test('detects OpenAI API key', () => {
    const file = makeFile('lib/ai.ts', `
      const openai = new OpenAI({ apiKey: 'sk-FAKEOPENAIAPIKEYFAKEFAKEFAKEFAKEFAKEFAKEFAKE12345' });
    `);
    const findings = scanFileForSecrets(file);
    const found = findings.find(f => f.ruleId === 'secrets.openai-api-key');
    assert.ok(found, 'Should detect OpenAI key');
    assert.equal(found!.confidence, 'high');
  });
});

describe('scanFileForSecrets — private key detection', () => {
  test('detects RSA private key PEM header', () => {
    const file = makeFile('certs/key.pem', `-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...`);
    const findings = scanFileForSecrets(file);
    const found = findings.find(f => f.ruleId === 'secrets.rsa-private-key');
    assert.ok(found, 'Should detect RSA private key');
    assert.equal(found!.severity, 'critical');
  });
});

describe('scanFileForSecrets — database URL detection', () => {
  test('detects PostgreSQL connection string', () => {
    const file = makeFile('.env.local', `DATABASE_URL=postgresql://admin:fakepass@localhost:5432/mydb`);
    const findings = scanFileForSecrets(file);
    const found = findings.find(f => f.ruleId === 'secrets.database-url');
    assert.ok(found, 'Should detect DATABASE_URL');
    assert.ok(!found!.redactedSnippet.includes('fakepass'), 'Password must be redacted');
  });
});

describe('scanFileForSecrets — false positive avoidance', () => {
  test('skips comment lines starting with //', () => {
    const file = makeFile('docs/example.ts', `
      // Example: STRIPE_SECRET_KEY=sk_live_your_key_here
    `);
    const findings = scanFileForSecrets(file);
    // Comment lines should be skipped
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

describe('scanFileForSecrets — Anthropic detection', () => {
  test('detects Anthropic API key', () => {
    const file = makeFile('lib/claude.ts', `
      const client = new Anthropic({ apiKey: 'sk-ant-FAKEANTHROPICAPIKEYFAKEFAKEFAKE1234' });
    `);
    const findings = scanFileForSecrets(file);
    const found = findings.find(f => f.ruleId === 'secrets.anthropic-api-key');
    assert.ok(found, 'Should detect Anthropic key');
  });
});

describe('scanFileForSecrets — Supabase service role key', () => {
  test('detects Supabase service role JWT', () => {
    const file = makeFile('.env.local', `SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.fakesignature123`);
    const findings = scanFileForSecrets(file);
    const found = findings.find(f => f.ruleId === 'secrets.supabase-service-role-key');
    assert.ok(found, 'Should detect Supabase service role key');
  });
});
