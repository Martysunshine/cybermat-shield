// Runs the scanner and captures output as an asciinema v2 cast file
import { spawn } from 'child_process';
import { createWriteStream } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '..');
const outFile = resolve(repoRoot, 'docs', 'demo.cast');
const target = resolve(repoRoot, 'examples', 'vulnerable-next-app');

const WIDTH = 90;
const HEIGHT = 22;
const start = Date.now();

const ws = createWriteStream(outFile);
ws.write(JSON.stringify({ version: 2, width: WIDTH, height: HEIGHT, title: 'CyberMat Shield — Security Scanner' }) + '\n');

// Simulate typing the command first
const cmd = `cybermat scan examples/vulnerable-next-app`;
let t = 0.3;
for (const ch of `$ ${cmd}`) {
  ws.write(JSON.stringify([+(t.toFixed(3)), 'o', ch]) + '\n');
  t += 0.04 + Math.random() * 0.03;
}
ws.write(JSON.stringify([+(t.toFixed(3)), 'o', '\r\n']) + '\n');
t += 0.8;

const proc = spawn('node', [
  resolve(repoRoot, 'packages/cli/dist/index.js'),
  'scan', target, '--fail-on', 'none'
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
  ws.end();
  console.log(`Cast written to ${outFile}`);
});
