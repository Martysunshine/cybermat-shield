// Generates docs/demo.cast (asciinema v2) then renders to docs/demo.svg
// Simulates: npx install → real scanner output against vulnerable-next-app
import { spawn } from 'child_process';
import { createWriteStream } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';
import { execSync } from 'child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '..');
const outFile = resolve(repoRoot, 'docs', 'demo.cast');
const svgFile = resolve(repoRoot, 'docs', 'demo.svg');
const target = resolve(repoRoot, 'examples', 'vulnerable-next-app');

const WIDTH = 100;
const HEIGHT = 34;
const start = Date.now();

const ws = createWriteStream(outFile);
ws.write(JSON.stringify({ version: 2, width: WIDTH, height: HEIGHT, title: 'CyberMat Shield — Security Scanner' }) + '\n');

// ── 1. Type the npx command ───────────────────────────────────────────────────
const cmd = `npx cybermat scan ./my-project`;
let t = 0.5;
for (const ch of `$ ${cmd}`) {
  ws.write(JSON.stringify([+(t.toFixed(3)), 'o', ch]) + '\n');
  t += 0.04 + Math.random() * 0.04;
}
ws.write(JSON.stringify([+(t.toFixed(3)), 'o', '\r\n']) + '\n');

// ── 2. Simulate npx install phase ─────────────────────────────────────────────
const npxLines = [
  [0.35, '\r\n'],
  [0.15, 'Need to install the following packages:\r\n'],
  [0.1,  '  cybermat@0.2.0\r\n'],
  [0.12, 'Ok to proceed? (y) '],
  [0.9,  'y\r\n'],
  [1.5,  '\r\nadded 1 package in 1s\r\n\r\n'],
];
for (const [delay, text] of npxLines) {
  t += delay;
  ws.write(JSON.stringify([+(t.toFixed(3)), 'o', text]) + '\n');
}
t += 0.5;

// ── 3. Run the real scanner and capture output ────────────────────────────────
const proc = spawn('node', [
  resolve(repoRoot, 'packages/cli/dist/index.js'),
  'scan', target, '--fail-on', 'none',
], { env: { ...process.env, FORCE_COLOR: '1' }, cwd: repoRoot });

proc.stdout.on('data', chunk => {
  const elapsed = +(((Date.now() - start) / 1000 + t).toFixed(3));
  ws.write(JSON.stringify([elapsed, 'o', chunk.toString()]) + '\n');
});
proc.stderr.on('data', chunk => {
  const elapsed = +(((Date.now() - start) / 1000 + t).toFixed(3));
  ws.write(JSON.stringify([elapsed, 'o', chunk.toString()]) + '\n');
});

proc.on('close', () => {
  ws.end(() => {
    console.log(`Cast written to ${outFile}`);

    // ── 4. Render SVG ─────────────────────────────────────────────────────────
    try {
      execSync(`npx svg-term --in "${outFile}" --out "${svgFile}" --window`, { stdio: 'inherit' });
      console.log(`SVG written to ${svgFile}`);
    } catch (err) {
      console.error('svg-term failed:', err.message);
      process.exit(1);
    }
  });
});
