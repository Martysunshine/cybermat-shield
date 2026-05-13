#!/usr/bin/env node
/**
 * scripts/generate-demo.js
 * Generates docs/demo.svg — animated terminal showing a complete cybermat scan.
 * Run: node scripts/generate-demo.js
 */
'use strict';

const path = require('path');
const fs   = require('fs');

// ── Layout ────────────────────────────────────────────────────────────────────
const W      = 900;
const FS     = 13;
const LH     = 20;
const PL     = 18;
const TBAR_H = 42;
const CPT    = 10;
const CPB    = 24;
const TOTAL  = 16;   // animation loop duration in seconds

const FONT = "'SFMono-Regular','Cascadia Code',Consolas,'Courier New',monospace";

// ── Palette (Catppuccin Mocha) ────────────────────────────────────────────────
const BG = '#1e1e2e';
const C = {
  sep:    '#45475a',
  gray:   '#9399b2',
  text:   '#cdd6f4',
  cyan:   '#89dceb',
  blue:   '#89b4fa',
  green:  '#a6e3a1',
  yellow: '#f9e2af',
  red:    '#f38ba8',
  crit:   '#f38ba8',
  wbold:  '#ffffff',
};

// ── Terminal content ──────────────────────────────────────────────────────────
// d:    time (seconds) when this line becomes visible
// dOut: time (seconds) when this line fades out — omit to hold until 96%
// row:  explicit y-row (required for spinner frames that share a row with the done line)
// s:    array of segments [{t: text, c: color, b?: bold}]
//       empty s = blank line (takes vertical space but renders nothing)

// Spinner characters used in the demo
const SP = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴'];

// Helper: cyan-colored percentage string as a segment
const pctSeg  = (p)  => ({ t: `  ${String(p).padStart(3)}%`, c: C.cyan });
const timeSeg = (t)  => ({ t: `   [${t}s]`, c: C.gray });
const checkSeg       =  { t: '  ✓ ', c: C.green };
const spinSeg = (fr) => ({ t: `  ${SP[fr]} `, c: C.gray });

const LINES = [
  // ── Command ────────────────────────────────────────────────────────────────
  { d: 0.4,  row: 0,  s: [{t:'$ ', c:C.green, b:true}, {t:'npx cybermat scan .', c:C.wbold, b:true}] },
  { d: 0.9,  row: 1,  s: [] },

  // ── Banner ─────────────────────────────────────────────────────────────────
  { d: 1.2,  row: 2,  s: [{t:'╔══════════════════════════════════════════════╗', c:C.cyan, b:true}] },
  { d: 1.24, row: 3,  s: [{t:'║  🛡️  CyberMat Shield — Security Scanner     ║', c:C.cyan, b:true}] },
  { d: 1.28, row: 4,  s: [{t:'╚══════════════════════════════════════════════╝', c:C.cyan, b:true}] },
  { d: 1.34, row: 5,  s: [] },

  // ── Row 6 — File inventory ─────────────────────────────────────────────────
  // Spinner frame 1
  { d: 1.5,  dOut: 1.72, row: 6,  s: [spinSeg(0), {t:'Building file inventory...', c:C.gray}, pctSeg(0),  timeSeg('0.0')] },
  // Spinner frame 2
  { d: 1.72, dOut: 1.94, row: 6,  s: [spinSeg(2), {t:'Building file inventory...', c:C.gray}, pctSeg(0),  timeSeg('0.2')] },
  // Done — stays
  { d: 1.94, row: 6,  s: [checkSeg, {t:'Found 312 files, 41 dirs ignored', c:C.gray}, pctSeg(10), timeSeg('0.4')] },

  // ── Row 7 — Code analysis ──────────────────────────────────────────────────
  { d: 1.94, dOut: 2.5,  row: 7,  s: [spinSeg(3), {t:'Analyzing code structure...', c:C.gray}, pctSeg(10), timeSeg('0.0')] },
  { d: 2.5,  dOut: 3.1,  row: 7,  s: [spinSeg(4), {t:'Analyzing code structure...', c:C.gray}, pctSeg(10), timeSeg('0.6')] },
  { d: 3.1,  row: 7,  s: [checkSeg, {t:'15 routes, 8 sinks, 13 sources', c:C.gray},  pctSeg(20), timeSeg('1.2')] },

  // ── Row 8 — Security rules (4 spinner frames, count advances) ──────────────
  { d: 3.1,  dOut: 3.85, row: 8,  s: [spinSeg(0), {t:'Running security rules... [0/95]',  c:C.gray}, pctSeg(20), timeSeg('0.0')] },
  { d: 3.85, dOut: 4.6,  row: 8,  s: [spinSeg(2), {t:'Running security rules... [22/95]', c:C.gray}, pctSeg(39), timeSeg('0.8')] },
  { d: 4.6,  dOut: 5.3,  row: 8,  s: [spinSeg(3), {t:'Running security rules... [55/95]', c:C.gray}, pctSeg(64), timeSeg('1.5')] },
  { d: 5.3,  dOut: 5.85, row: 8,  s: [spinSeg(4), {t:'Running security rules... [84/95]', c:C.gray}, pctSeg(87), timeSeg('2.2')] },
  { d: 5.85, row: 8,  s: [checkSeg, {t:'9 findings from 95 rules',         c:C.gray}, pctSeg(100), timeSeg('2.7')] },

  // ── Blank before results ───────────────────────────────────────────────────
  { d: 5.9,  row: 9,  s: [] },

  // ── Scan summary ──────────────────────────────────────────────────────────
  { d: 6.0,  row: 10, s: [{t:'  Target:    ', c:C.gray}, {t:'/Users/alex/projects/storefront', c:C.wbold}] },
  { d: 6.04, row: 11, s: [{t:'  Files:     ', c:C.gray}, {t:'312', c:C.wbold}, {t:' scanned, 41 ignored', c:C.gray}] },
  { d: 6.08, row: 12, s: [{t:'  Languages: ', c:C.gray}, {t:'typescript 198, javascript 67, json 47', c:C.cyan}] },
  { d: 6.12, row: 13, s: [{t:'  Stack:     ', c:C.gray}, {t:'Next.js, Supabase, Stripe, OpenAI', c:C.cyan}] },
  { d: 6.16, row: 14, s: [] },
  { d: 6.20, row: 15, s: [{t:'  ─────────────────────────────────────────────', c:C.sep}] },
  { d: 6.24, row: 16, s: [] },

  // ── CRITICAL ──────────────────────────────────────────────────────────────
  { d: 6.28, row: 17, s: [{t:'  CRITICAL (2)', c:C.crit, b:true}] },
  { d: 6.32, row: 18, s: [] },

  { d: 6.36, row: 19, s: [{t:'  1. ', c:C.gray}, {t:'[CRITICAL]', c:C.crit, b:true}, {t:' Stripe Secret Key', c:C.wbold, b:true}] },
  { d: 6.40, row: 20, s: [{t:'     File: ', c:C.gray}, {t:'lib/stripe.ts:5', c:C.cyan}] },
  { d: 6.44, row: 21, s: [{t:'     OWASP: ', c:C.gray}, {t:'A04 Cryptographic Failures', c:C.green}] },
  { d: 6.48, row: 22, s: [{t:'     Evidence: ', c:C.gray}, {t:"const STRIPE_SECRET_KEY = 'sk_live...REDACTED...key1'", c:C.yellow}] },
  { d: 6.52, row: 23, s: [{t:'     Match:    ', c:C.gray}, {t:'sk_live...REDACTED...key1', c:C.yellow}] },
  { d: 6.56, row: 24, s: [{t:'     Fix: ', c:C.gray}, {t:'Rotate the Stripe secret key immediately. Use env vars only.', c:C.text}] },
  { d: 6.60, row: 25, s: [] },

  { d: 6.75, row: 26, s: [{t:'  2. ', c:C.gray}, {t:'[CRITICAL]', c:C.crit, b:true}, {t:' Supabase Service Role Key', c:C.wbold, b:true}] },
  { d: 6.79, row: 27, s: [{t:'     File: ', c:C.gray}, {t:'.env.local:12', c:C.cyan}] },
  { d: 6.83, row: 28, s: [{t:'     OWASP: ', c:C.gray}, {t:'A04 Cryptographic Failures, A07 Authentication Failures', c:C.green}] },
  { d: 6.87, row: 29, s: [{t:'     Evidence: ', c:C.gray}, {t:'SUPABASE_SERVICE_ROLE_KEY=eyJhbGci...REDACTED...', c:C.yellow}] },
  { d: 6.91, row: 30, s: [{t:'     Match:    ', c:C.gray}, {t:'eyJhbGci...REDACTED...', c:C.yellow}] },
  { d: 6.95, row: 31, s: [{t:'     Fix: ', c:C.gray}, {t:'Rotate in Supabase dashboard. Never expose in client code.', c:C.text}] },
  { d: 6.99, row: 32, s: [] },

  // ── HIGH ──────────────────────────────────────────────────────────────────
  { d: 7.15, row: 33, s: [{t:'  HIGH (2)', c:C.red, b:true}] },
  { d: 7.19, row: 34, s: [] },

  { d: 7.23, row: 35, s: [{t:'  3. ', c:C.gray}, {t:'[HIGH]', c:C.red, b:true}, {t:' SQL Injection via Raw Query String', c:C.wbold, b:true}] },
  { d: 7.27, row: 36, s: [{t:'     File: ', c:C.gray}, {t:'app/api/search/route.ts:22', c:C.cyan}] },
  { d: 7.31, row: 37, s: [{t:'     OWASP: ', c:C.gray}, {t:'A05 Injection', c:C.green}] },
  { d: 7.35, row: 38, s: [{t:'     Evidence: ', c:C.gray}, {t:"db.query(\"SELECT * FROM orders WHERE user = '\" + userId + \"'\")", c:C.yellow}] },
  { d: 7.39, row: 39, s: [{t:'     Fix: ', c:C.gray}, {t:'Use parameterized queries or an ORM like Prisma.', c:C.text}] },
  { d: 7.43, row: 40, s: [] },

  { d: 7.58, row: 41, s: [{t:'  4. ', c:C.gray}, {t:'[HIGH]', c:C.red, b:true}, {t:' dangerouslySetInnerHTML with User Input', c:C.wbold, b:true}] },
  { d: 7.62, row: 42, s: [{t:'     File: ', c:C.gray}, {t:'components/ProductReview.tsx:31', c:C.cyan}] },
  { d: 7.66, row: 43, s: [{t:'     OWASP: ', c:C.gray}, {t:'A05 Injection', c:C.green}] },
  { d: 7.70, row: 44, s: [{t:'     Evidence: ', c:C.gray}, {t:'dangerouslySetInnerHTML={{ __html: review.body }}', c:C.yellow}] },
  { d: 7.74, row: 45, s: [{t:'     Fix: ', c:C.gray}, {t:'Sanitize with DOMPurify before rendering user-generated HTML.', c:C.text}] },
  { d: 7.78, row: 46, s: [] },

  // ── MEDIUM / LOW ──────────────────────────────────────────────────────────
  { d: 7.94, row: 47, s: [{t:'  MEDIUM (4)', c:C.yellow, b:true}, {t:'   ', c:C.gray}, {t:'LOW (1)', c:C.blue, b:true}] },
  { d: 7.98, row: 48, s: [] },

  // ── Summary ───────────────────────────────────────────────────────────────
  { d: 8.02, row: 49, s: [{t:'  ─────────────────────────────────────────────', c:C.sep}] },
  { d: 8.06, row: 50, s: [] },
  { d: 8.18, row: 51, s: [{t:'  Risk Score: ', c:C.gray}, {t:'12', c:C.crit, b:true}, {t:' / 100  ', c:C.gray}, {t:'Critical Risk', c:C.crit, b:true}] },
  { d: 8.22, row: 52, s: [{t:'  Critical: 2', c:C.crit}, {t:' | ', c:C.gray}, {t:'High: 2', c:C.red}, {t:' | ', c:C.gray}, {t:'Medium: 4', c:C.yellow}, {t:' | ', c:C.gray}, {t:'Low: 1', c:C.blue}] },
  { d: 8.26, row: 53, s: [] },

  // ── Recommendations ───────────────────────────────────────────────────────
  { d: 8.38, row: 54, s: [{t:'  Top recommended fixes:', c:C.gray}] },
  { d: 8.42, row: 55, s: [{t:'  1. ', c:C.gray}, {t:'Rotate the Stripe secret key immediately. Use env vars only.', c:C.text}] },
  { d: 8.46, row: 56, s: [{t:'  2. ', c:C.gray}, {t:'Rotate the Supabase service role key. Use the anon key for frontend.', c:C.text}] },
  { d: 8.50, row: 57, s: [{t:'  3. ', c:C.gray}, {t:'Use parameterized queries for all database operations.', c:C.text}] },
  { d: 8.54, row: 58, s: [] },

  // ── Reports saved ─────────────────────────────────────────────────────────
  { d: 8.66, row: 59, s: [{t:'  Reports saved:', c:C.gray}] },
  { d: 8.70, row: 60, s: [{t:'    /Users/alex/projects/storefront/.cybermat/report.json', c:C.cyan}] },
  { d: 8.74, row: 61, s: [{t:'    /Users/alex/projects/storefront/.cybermat/report.html', c:C.cyan}] },
  { d: 8.78, row: 62, s: [] },

  // ── Final prompt ──────────────────────────────────────────────────────────
  { d: 9.0,  row: 63, s: [{t:'$ ', c:C.green, b:true}] },
];

// ── Computed dimensions ────────────────────────────────────────────────────────
const maxRow       = Math.max(...LINES.map(l => l.row));
const firstBaseline = TBAR_H + CPT + FS;
const H            = firstBaseline + maxRow * LH + CPB;

// ── Helpers ───────────────────────────────────────────────────────────────────
function esc(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function pctOf(t) {
  return Math.min(100, Math.max(0, (t / TOTAL) * 100)).toFixed(3);
}

// Lines snap in instantly (0.01s), hold, then snap off.
// dOut: optional early fade-out time (for transient spinner frames).
function makeKeyframe(i, dIn, dOut) {
  const s0 = pctOf(dIn);
  const s1 = pctOf(dIn + 0.01);
  if (dOut !== undefined) {
    const e0 = pctOf(dOut);
    const e1 = pctOf(dOut + 0.04);
    return `@keyframes l${i}{0%,${s0}%{opacity:0}${s1}%{opacity:1}${e0}%{opacity:1}${e1}%,100%{opacity:0}}`;
  }
  return `@keyframes l${i}{0%,${s0}%{opacity:0}${s1}%{opacity:1}96%{opacity:1}99%,100%{opacity:0}}`;
}

function renderLine(line, i) {
  if (line.s.length === 0) return null;
  const y = firstBaseline + line.row * LH;
  const tspans = line.s.map(seg => {
    const fw = seg.b ? ' font-weight="bold"' : '';
    return `<tspan fill="${seg.c}"${fw}>${esc(seg.t)}</tspan>`;
  }).join('');
  return `<text class="l${i}" x="${PL}" y="${y}" font-family="${FONT}" font-size="${FS}" xml:space="preserve">${tspans}</text>`;
}

// ── Assemble SVG ──────────────────────────────────────────────────────────────
const keyframes = LINES.map((l, i) => l.s.length > 0 ? makeKeyframe(i, l.d, l.dOut) : '').join('');
const classes   = LINES.map((l, i) => l.s.length > 0 ? `.l${i}{opacity:0;animation:l${i} ${TOTAL}s linear infinite}` : '').join('');
const texts     = LINES.map((l, i) => renderLine(l, i)).filter(Boolean).join('\n  ');

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}">
  <!-- terminal background -->
  <rect width="${W}" height="${H}" rx="8" ry="8" fill="${BG}"/>
  <!-- traffic lights -->
  <circle cx="20" cy="22" r="6" fill="#ff5f58"/>
  <circle cx="40" cy="22" r="6" fill="#ffbd2e"/>
  <circle cx="60" cy="22" r="6" fill="#18c132"/>
  <!-- title bar label -->
  <text x="${W / 2}" y="26" font-family="system-ui,sans-serif" font-size="12" fill="#6c7086" text-anchor="middle">Terminal</text>
  <!-- title bar divider -->
  <rect y="${TBAR_H - 1}" width="${W}" height="1" fill="#313244"/>
  <!-- animations -->
  <style>${keyframes}${classes}</style>
  <!-- content -->
  ${texts}
</svg>`;

const outPath = path.resolve(__dirname, '..', 'docs', 'demo.svg');
fs.writeFileSync(outPath, svg, 'utf-8');

const kb = (svg.length / 1024).toFixed(1);
console.log(`✓ docs/demo.svg written  (${kb} KB, ${LINES.length} lines across ${maxRow + 1} rows, height=${H}px, loop=${TOTAL}s)`);
