/**
 * STOP #3 Setup Script — Run this after starting the vulnerable-next-app.
 *
 * Logs in as each test user via Playwright and saves their session cookies to
 * .appsec/auth/<name>.storage.json so Phase 7 can load them as auth profiles.
 *
 * Usage:
 *   Terminal 1: cd examples/vulnerable-next-app && npx next dev
 *   Terminal 2: npx tsx scripts/setup-auth-profiles.ts
 */

import { chromium } from 'playwright';
import { mkdir } from 'fs/promises';

const BASE_URL = 'http://localhost:3000';

const PROFILES = [
  { name: 'userA', email: 'usera@test.com', password: 'password123' },
  { name: 'userB', email: 'userb@test.com', password: 'password123' },
  { name: 'admin', email: 'admin@test.com', password: 'admin123' },
];

async function setupProfile(name: string, email: string, password: string, outPath: string) {
  console.log(`  Logging in as ${email}...`);
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  try {
    // Navigate to the app first so the cookie is set on the correct origin
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'domcontentloaded', timeout: 15000 });

    // Call the JSON API directly — avoids React hydration timing issues
    const ok = await page.evaluate(
      async ({ email, password }: { email: string; password: string }) => {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password }),
        });
        return res.ok;
      },
      { email, password },
    );

    if (!ok) throw new Error(`Login rejected for ${email} — check credentials`);

    await context.storageState({ path: outPath });
    console.log(`  ✓ ${name} → ${outPath}`);
  } finally {
    await browser.close();
  }
}

async function verifyApp() {
  try {
    const res = await fetch(`${BASE_URL}/api/auth/me`, { signal: AbortSignal.timeout(5000) });
    // 401 is expected (not logged in) — the app is running
    if (res.status === 401 || res.status === 200) return;
    throw new Error(`Unexpected status ${res.status}`);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('fetch failed') || msg.includes('ECONNREFUSED')) {
      console.error(`\nERROR: Could not reach ${BASE_URL}`);
      console.error('Make sure the vulnerable app is running:');
      console.error('  cd examples/vulnerable-next-app && npx next dev\n');
      process.exit(1);
    }
    throw err;
  }
}

async function main() {
  console.log('CyberMat Shield — STOP #3: Auth Profile Setup\n');
  console.log(`Checking app at ${BASE_URL}...`);
  await verifyApp();
  console.log('App is running.\n');

  await mkdir('.appsec/auth', { recursive: true });

  for (const { name, email, password } of PROFILES) {
    const outPath = `.appsec/auth/${name}.storage.json`;
    await setupProfile(name, email, password, outPath);
  }

  console.log('\n✓ All auth profiles saved.');
  console.log('Files created:');
  for (const { name } of PROFILES) {
    console.log(`  .appsec/auth/${name}.storage.json`);
  }
  console.log('\nSTOP #3 complete — you can now proceed with Phase 7.');
}

main().catch(err => {
  console.error('\nSetup failed:', err.message);
  process.exit(1);
});
