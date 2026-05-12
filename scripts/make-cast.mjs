/**
 * Generates docs/demo.cast (asciinema v2) + docs/demo.svg
 *
 * Strategy:
 *  1. Run the real scanner with spawnSync to capture exact colored output
 *  2. Re-emit every line with controlled per-line delays so the animation
 *     streams at a readable pace (~12-15 s total)
 *  3. Render SVG via svg-term-cli
 */
import { spawnSync, execSync } from 'child_process';
import { createWriteStream } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, resolve as p } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root    = p(__dirname, '..');
const outCast = p(root, 'docs', 'demo.cast');
const outSvg  = p(root, 'docs', 'demo.svg');
const target  = p(root, 'examples', 'vulnerable-next-app');

const WIDTH  = 100;
const HEIGHT = 36;

// ── Step 1: capture real scanner output ──────────────────────────────────────
console.log('Running scanner to capture output…');
const run = spawnSync(
  process.execPath,
  [p(root, 'packages/cli/dist/index.js'), 'scan', target, '--fail-on', 'none'],
  { env: { ...process.env, FORCE_COLOR: '1' }, cwd: root, maxBuffer: 10_485_760 },
);
const scanLines = run.stdout.toString().split('\n');
console.log(`Captured ${scanLines.length} lines.`);

// ── Step 2: build cast with controlled timing ─────────────────────────────────
const ws  = createWriteStream(outCast);
const HDR = { version: 2, width: WIDTH, height: HEIGHT, title: 'CyberMat Shield — Security Scanner' };
ws.write(JSON.stringify(HDR) + '\n');

let t = 0;
const emit = (text) => ws.write(JSON.stringify([+(t.toFixed(3)), 'o', text]) + '\n');

// Helper: strip ANSI codes for delay classification (output keeps color)
const ANSI = /\x1b\[[0-9;]*m/g;
const plain = (s) => s.replace(ANSI, '');

// ── Phase A: Type the command ─────────────────────────────────────────────────
const CMD = 'npx cybermat scan ./my-project';
t = 0.6;
Array.from(`$ ${CMD}`).forEach((ch, i) => {
  emit(ch);
  t += 0.045 + (i % 5) * 0.005;   // 45–65 ms per char, deterministic variation
});
emit('\r\n');

// ── Phase B: npx install phase ────────────────────────────────────────────────
const NPX = [
  [0.30, '\r\n'],
  [0.18, 'Need to install the following packages:\r\n'],
  [0.12, '  cybermat@0.2.0\r\n'],
  [0.14, 'Ok to proceed? (y) '],
  [0.80, 'y\r\n'],
  [1.40, '\r\nadded 1 package in 1s\r\n\r\n'],
];
for (const [d, txt] of NPX) { t += d; emit(txt); }
t += 0.55;

// ── Phase C: stream scanner output line-by-line ───────────────────────────────
//
// Delay rules (ordered, first match wins):
//   • Banner box chars (╔ ║ ╚)          → 0.07 s  — fast, it's decorative
//   • Blank line                          → 0.03 s
//   • "Scanning…"                         → 0.25 s  — breathe after install
//   • Target / Files / Stack header lines → 0.10 s
//   • ───── divider                       → 0.18 s  — short pause
//   • CRITICAL/HIGH/MEDIUM/LOW (N)       → 0.30 s  — dramatic pause before section
//   • Finding title line (numbered)       → 0.13 s
//   • File: / OWASP: / Evidence: / Fix:  → 0.05 s  — quick sub-lines
//   • Risk Score:                         → 0.40 s  — big pause for reveal
//   • Critical: N | High: N …            → 0.10 s
//   • Top recommended fixes              → 0.08 s
//   • Reports saved / path lines         → 0.06 s
//   • Fallback                            → 0.09 s

function lineDelay(raw) {
  const s = plain(raw);
  if (/[╔╚║]/.test(s))                                       return 0.07;
  if (s.trim() === '')                                        return 0.03;
  if (/Scanning/.test(s))                                    return 0.25;
  if (/Target:|Files:|Languages:|Stack:/.test(s))            return 0.10;
  if (/─{5,}/.test(s))                                       return 0.18;
  if (/^\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s*\(/.test(s))    return 0.30;
  if (/^\s*\d+\./.test(s))                                   return 0.13;  // "  1. [CRITICAL]…"
  if (/^\s+(File|OWASP|Evidence|Match|Fix):/.test(s))        return 0.05;
  if (/Risk Score:/.test(s))                                 return 0.40;
  if (/Critical:|High:|Medium:|Low:|Info:/.test(s))          return 0.10;
  if (/Top recommended|Reports saved/.test(s))               return 0.08;
  if (/\.appsec[/\\]/.test(s))                               return 0.06;
  return 0.09;
}

for (const line of scanLines) {
  t += lineDelay(line);
  emit(line + '\n');
}

// ── Step 3: write cast + render SVG ──────────────────────────────────────────
ws.end(() => {
  console.log(`Cast written → ${outCast}  (duration ≈ ${t.toFixed(1)} s)`);
  try {
    execSync(`npx svg-term --in "${outCast}" --out "${outSvg}" --window`, { stdio: 'inherit' });
    console.log(`SVG written  → ${outSvg}`);
  } catch (e) {
    console.error('svg-term error:', e.message);
    process.exit(1);
  }
});
