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
const W      = 900;   // SVG width (px)
const FS     = 13;    // font-size (px)
const LH     = 20;    // line-height (px)
const PL     = 18;    // content left-padding (px)
const TBAR_H = 42;    // title-bar height (px)
const CPT    = 10;    // padding below title bar before first line (px)
const CPB    = 24;    // bottom padding (px)
const TOTAL  = 16;    // animation loop duration in seconds

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
// d: delay in seconds when this line becomes visible
// s: array of segments [{t: text, c: color, b?: bold}]
// empty s = blank line (invisible but takes vertical space)

const LINES = [
  // Command — appears like it was just typed
  { d: 0.4,  s: [{t:'$ ', c:C.green, b:true}, {t:'npx cybermat scan ./your-project', c:C.wbold, b:true}] },
  { d: 0.9,  s: [] },

  // Banner — all three lines snap in very fast (real chalk output)
  { d: 1.2,  s: [{t:'╔══════════════════════════════════════════════╗', c:C.cyan, b:true}] },
  { d: 1.24, s: [{t:'║  🛡️  CyberMat Shield — Security Scanner     ║', c:C.cyan, b:true}] },
  { d: 1.28, s: [{t:'╚══════════════════════════════════════════════╝', c:C.cyan, b:true}] },
  { d: 1.34, s: [] },

  // Scanning notice
  { d: 1.5,  s: [{t:'  Scanning...', c:C.gray}] },
  { d: 1.56, s: [] },

  // Scan info — bursts in rapidly after scan completes (~2s pause)
  { d: 3.5,  s: [{t:'  Target:    ', c:C.gray}, {t:'/Users/alex/projects/storefront', c:C.wbold}] },
  { d: 3.54, s: [{t:'  Files:     ', c:C.gray}, {t:'312', c:C.wbold}, {t:' scanned, 41 ignored', c:C.gray}] },
  { d: 3.58, s: [{t:'  Languages: ', c:C.gray}, {t:'typescript 198, javascript 67, json 47', c:C.cyan}] },
  { d: 3.62, s: [{t:'  Stack:     ', c:C.gray}, {t:'Next.js, Supabase, Stripe, OpenAI', c:C.cyan}] },
  { d: 3.66, s: [] },
  { d: 3.70, s: [{t:'  ─────────────────────────────────────────────', c:C.sep}] },
  { d: 3.74, s: [] },

  // CRITICAL section
  { d: 3.78, s: [{t:'  CRITICAL (2)', c:C.crit, b:true}] },
  { d: 3.82, s: [] },

  // Finding 1 — lines 40ms apart
  { d: 3.86, s: [{t:'  1. ', c:C.gray}, {t:'[CRITICAL]', c:C.crit, b:true}, {t:' Stripe Secret Key', c:C.wbold, b:true}] },
  { d: 3.90, s: [{t:'     File: ', c:C.gray}, {t:'lib/stripe.ts:5', c:C.cyan}] },
  { d: 3.94, s: [{t:'     OWASP: ', c:C.gray}, {t:'A04 Cryptographic Failures', c:C.green}] },
  { d: 3.98, s: [{t:'     Evidence: ', c:C.gray}, {t:"const STRIPE_SECRET_KEY = 'sk_live...REDACTED...key1'", c:C.yellow}] },
  { d: 4.02, s: [{t:'     Match:    ', c:C.gray}, {t:'sk_live...REDACTED...key1', c:C.yellow}] },
  { d: 4.06, s: [{t:'     Fix: ', c:C.gray}, {t:'Rotate the Stripe secret key immediately. Use env vars only.', c:C.text}] },
  { d: 4.10, s: [] },

  // Finding 2 — 150ms gap between findings
  { d: 4.25, s: [{t:'  2. ', c:C.gray}, {t:'[CRITICAL]', c:C.crit, b:true}, {t:' Supabase Service Role Key', c:C.wbold, b:true}] },
  { d: 4.29, s: [{t:'     File: ', c:C.gray}, {t:'.env.local:12', c:C.cyan}] },
  { d: 4.33, s: [{t:'     OWASP: ', c:C.gray}, {t:'A04 Cryptographic Failures, A07 Authentication Failures', c:C.green}] },
  { d: 4.37, s: [{t:'     Evidence: ', c:C.gray}, {t:'SUPABASE_SERVICE_ROLE_KEY=eyJhbGci...REDACTED...', c:C.yellow}] },
  { d: 4.41, s: [{t:'     Match:    ', c:C.gray}, {t:'eyJhbGci...REDACTED...', c:C.yellow}] },
  { d: 4.45, s: [{t:'     Fix: ', c:C.gray}, {t:'Rotate in Supabase dashboard. Never expose in client code.', c:C.text}] },
  { d: 4.49, s: [] },

  // HIGH section
  { d: 4.65, s: [{t:'  HIGH (2)', c:C.red, b:true}] },
  { d: 4.69, s: [] },

  // Finding 3
  { d: 4.73, s: [{t:'  3. ', c:C.gray}, {t:'[HIGH]', c:C.red, b:true}, {t:' SQL Injection via Raw Query String', c:C.wbold, b:true}] },
  { d: 4.77, s: [{t:'     File: ', c:C.gray}, {t:'app/api/search/route.ts:22', c:C.cyan}] },
  { d: 4.81, s: [{t:'     OWASP: ', c:C.gray}, {t:'A05 Injection', c:C.green}] },
  { d: 4.85, s: [{t:'     Evidence: ', c:C.gray}, {t:"db.query(\"SELECT * FROM orders WHERE user = '\" + userId + \"'\")", c:C.yellow}] },
  { d: 4.89, s: [{t:'     Fix: ', c:C.gray}, {t:'Use parameterized queries or an ORM like Prisma.', c:C.text}] },
  { d: 4.93, s: [] },

  // Finding 4
  { d: 5.08, s: [{t:'  4. ', c:C.gray}, {t:'[HIGH]', c:C.red, b:true}, {t:' dangerouslySetInnerHTML with User Input', c:C.wbold, b:true}] },
  { d: 5.12, s: [{t:'     File: ', c:C.gray}, {t:'components/ProductReview.tsx:31', c:C.cyan}] },
  { d: 5.16, s: [{t:'     OWASP: ', c:C.gray}, {t:'A05 Injection', c:C.green}] },
  { d: 5.20, s: [{t:'     Evidence: ', c:C.gray}, {t:'dangerouslySetInnerHTML={{ __html: review.body }}', c:C.yellow}] },
  { d: 5.24, s: [{t:'     Fix: ', c:C.gray}, {t:'Sanitize with DOMPurify before rendering user-generated HTML.', c:C.text}] },
  { d: 5.28, s: [] },

  // MEDIUM / LOW (just a summary line — not expanding every finding)
  { d: 5.44, s: [{t:'  MEDIUM (4)', c:C.yellow, b:true}, {t:'   ', c:C.gray}, {t:'LOW (1)', c:C.blue, b:true}] },
  { d: 5.48, s: [] },

  // Summary
  { d: 5.52, s: [{t:'  ─────────────────────────────────────────────', c:C.sep}] },
  { d: 5.56, s: [] },
  { d: 5.68, s: [{t:'  Risk Score: ', c:C.gray}, {t:'12', c:C.crit, b:true}, {t:' / 100  ', c:C.gray}, {t:'Critical Risk', c:C.crit, b:true}] },
  { d: 5.72, s: [{t:'  Critical: 2', c:C.crit}, {t:' | ', c:C.gray}, {t:'High: 2', c:C.red}, {t:' | ', c:C.gray}, {t:'Medium: 4', c:C.yellow}, {t:' | ', c:C.gray}, {t:'Low: 1', c:C.blue}] },
  { d: 5.76, s: [] },

  // Recommendations
  { d: 5.88, s: [{t:'  Top recommended fixes:', c:C.gray}] },
  { d: 5.92, s: [{t:'  1. ', c:C.gray}, {t:'Rotate the Stripe secret key immediately. Use env vars only.', c:C.text}] },
  { d: 5.96, s: [{t:'  2. ', c:C.gray}, {t:'Rotate the Supabase service role key. Use the anon key for frontend.', c:C.text}] },
  { d: 6.00, s: [{t:'  3. ', c:C.gray}, {t:'Use parameterized queries for all database operations.', c:C.text}] },
  { d: 6.04, s: [] },

  // Reports saved
  { d: 6.16, s: [{t:'  Reports saved:', c:C.gray}] },
  { d: 6.20, s: [{t:'    /Users/alex/projects/storefront/.appsec/report.json', c:C.cyan}] },
  { d: 6.24, s: [{t:'    /Users/alex/projects/storefront/.appsec/report.html', c:C.cyan}] },
  { d: 6.28, s: [] },

  // Final prompt
  { d: 6.5,  s: [{t:'$ ', c:C.green, b:true}] },
];

// ── Computed dimensions ────────────────────────────────────────────────────────
const firstBaseline = TBAR_H + CPT + FS;
const H = firstBaseline + (LINES.length - 1) * LH + CPB;

// ── Helpers ───────────────────────────────────────────────────────────────────
function esc(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function pct(t) {
  return Math.min(100, Math.max(0, (t / TOTAL) * 100)).toFixed(3);
}

// Lines snap in instantly (0.01s — imperceptible), hold until 96%, then snap off for a clean loop.
function makeKeyframe(i, delay) {
  const s0 = pct(delay);
  const s1 = pct(delay + 0.01);
  return `@keyframes l${i}{0%,${s0}%{opacity:0}${s1}%{opacity:1}96%{opacity:1}99%,100%{opacity:0}}`;
}

function renderLine(line, i) {
  if (line.s.length === 0) return null;
  const y = firstBaseline + i * LH;
  const tspans = line.s.map(seg => {
    const fw = seg.b ? ' font-weight="bold"' : '';
    return `<tspan fill="${seg.c}"${fw}>${esc(seg.t)}</tspan>`;
  }).join('');
  return `<text class="l${i}" x="${PL}" y="${y}" font-family="${FONT}" font-size="${FS}" xml:space="preserve">${tspans}</text>`;
}

// ── Assemble SVG ──────────────────────────────────────────────────────────────
const keyframes = LINES.map((l, i) => l.s.length > 0 ? makeKeyframe(i, l.d) : '').join('');
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
console.log(`✓ docs/demo.svg written  (${kb} KB, ${LINES.length} lines, height=${H}px, loop=${TOTAL}s)`);
