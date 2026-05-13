# 🛡️ CyberMat Shield 🛡️

> **Local-first Application Security Scanner** — finds secrets, vulnerabilities, misconfigs, and access-control bugs in your codebase. Runs entirely on your machine. Nothing leaves your computer.

[![npm](https://img.shields.io/npm/v/cybermat?color=crimson&label=npm)](https://www.npmjs.com/package/cybermat)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![OWASP Top 10:2025](https://img.shields.io/badge/OWASP-Top%2010%3A2025-orange)](docs/rules.md)
[![Node ≥18](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)

![CyberMat Shield demo](docs/demo.svg)

---

## ✨ What makes it different?

- 🔍 **Three scanner layers** — static code, live runtime, and authenticated access-control testing
- 🗺️ **OWASP Top 10:2025 mapped** — every finding links to a category, CWE, and remediation
- 🔒 **Privacy first** — no telemetry, no cloud upload, secrets redacted in all outputs
- 🚦 **CI-ready** — SARIF output, baseline diffing, GitHub Actions workflow included
- 🤖 **AI-security aware** — detects prompt injection, LLM output XSS, unsafe tool calls
- ⚡ **Fast** — scans < 500 files in under 5 seconds
- 🖥️ **VS Code extension** — inline diagnostics in your editor as you work

---

## 🚀 Quick Start

```bash
cd your-project
npx cybermat scan .
```

No install required. Node ≥18.

### Install globally

```bash
npm install -g cybermat
cd your-project
cybermat scan .
```

### Build from source

```bash
git clone https://github.com/Martysunshine/cybermat-shield.git
cd cybermat-shield
pnpm install && pnpm build
node packages/cli/dist/index.js scan examples/vulnerable-next-app
```

---

## 🔎 What it scans

### 🧱 Layer 1 — Static Code Analysis

Scans your source files without running anything.

| What it detects | Details |
|---|---|
| 🔑 Secrets & API keys | 66 detectors — AWS, Stripe, OpenAI, Supabase, Firebase, Twilio, and 60+ more |
| 💉 Injection sinks | XSS (dangerouslySetInnerHTML, innerHTML), SQL injection, eval, exec, SSRF |
| 🚪 Missing auth guards | Unprotected routes, missing middleware, IDOR-prone patterns |
| 📦 Supply chain risks | Lifecycle scripts, wildcard versions, missing lockfile |
| ⚙️ Misconfigurations | CORS wildcards, source maps in prod, disabled RLS, weak Firebase rules |
| 🤖 AI security | Prompt injection, LLM output rendered as HTML, tool calls without approval |

### 🌐 Layer 2 — Runtime Scanner (Playwright-based)

Spins up a real browser, crawls your app, and probes it safely.

| What it detects | Details |
|---|---|
| 🛡️ Missing security headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| 🍪 Insecure cookies | Missing HttpOnly/Secure/SameSite, JWT values in cookies, long expiry |
| 🌍 CORS misconfigs | Reflected origins, wildcard + credentials, dev origins in production |
| 🔀 Open redirects | Tests 7 common redirect params (next, returnUrl, callbackUrl, etc.) |
| 📂 Exposed sensitive files | `.env`, `.git/config`, `swagger.json`, `package.json`, and 11 more |
| 🪞 Reflected input | Harmless marker injection — detects HTML/attribute/script/JSON reflection |

### 🔐 Layer 3 — Auth/Access-Control Scanner

Makes real authenticated requests to find broken access control.

| What it detects | Details |
|---|---|
| 🚷 Anonymous route access | Protected routes accessible without any authentication |
| ⬆️ Vertical privilege escalation | Regular user accessing admin-only routes |
| 🔄 Horizontal IDOR | UserA reading/accessing UserB's resources |
| 🏢 Tenant boundary issues | Cross-org/tenant resource access via predictable IDs |

---

## 📋 All CLI Commands

```bash
# ── Static scanning ──────────────────────────────────────────
cybermat scan <path>                    # Scan a project directory
cybermat scan <path> --sarif            # Also output SARIF (GitHub Code Scanning)
cybermat scan <path> --markdown         # Also output Markdown report
cybermat scan <path> --fail-on high     # Exit 1 if any HIGH or above findings
cybermat scan <path> --ci               # CI mode — exit 5 if new vs baseline

# ── Runtime scanning ─────────────────────────────────────────
cybermat scan-runtime <url>             # Crawl + probe a live app
cybermat scan-runtime <url> --max-pages 10

# ── Auth/access-control scanning ─────────────────────────────
cybermat scan-auth <url>                # Run access-control tests
cybermat auth init                      # Create auth config template
cybermat auth test-config               # Validate auth profiles

# ── Rules ────────────────────────────────────────────────────
cybermat rules list                     # List all 120+ rules
cybermat rules list --owasp A01         # Filter by OWASP category
cybermat rules list --engine secrets    # Filter by engine
cybermat rules show <id>                # Full rule detail + examples
cybermat rules docs                     # Generate docs/rules.md

# ── Project setup ────────────────────────────────────────────
cybermat init                           # Create .cybermatignore + cybermat.config.json
cybermat doctor                         # Check Node, pnpm, Playwright, config
cybermat config validate                # Validate cybermat.config.json

# ── Baseline diffing ─────────────────────────────────────────
cybermat baseline create                # Snapshot current findings
cybermat baseline compare               # Show new / fixed / existing vs snapshot

# ── Reports ──────────────────────────────────────────────────
cybermat report --sarif                 # Generate SARIF from saved report.json
cybermat report --markdown              # Generate Markdown from saved report.json
cybermat report --all                   # Generate all formats
```

---

## 🛠️ Setting Up Auth Scanning

The auth scanner needs real session cookies for your test accounts. Here's how to set it up against the built-in vulnerable app:

### Step 1 — Start the test app

```bash
cd examples/vulnerable-next-app
npx next dev
# → http://localhost:3000
```

### Step 2 — Save auth sessions

```bash
# From repo root (Terminal 2)
npx tsx --tsconfig scripts/tsconfig.json scripts/setup-auth-profiles.ts
```

This logs in as each test user via Playwright and saves sessions to `.cybermat/auth/`.

### Step 3 — Run the scanner

```bash
# Always run both commands together — sessions reset on hot-reload!
npx tsx --tsconfig scripts/tsconfig.json scripts/setup-auth-profiles.ts && \
node packages/cli/dist/index.js scan-auth http://localhost:3000
```

> ⚠️ **Important:** The test app uses in-memory sessions. They reset whenever the Next.js dev server restarts or hot-reloads. Always run `setup-auth-profiles.ts` and `scan-auth` in the same command chain.

**Test accounts (all passwords are fake):**

| Profile | Email | Password | Role |
|---|---|---|---|
| 👤 userA | usera@test.com | password123 | user |
| 👤 userB | userb@test.com | password123 | user |
| 👑 admin | admin@test.com | admin123 | admin |

---

## ⚙️ Configuration

Run `cybermat init` to create `cybermat.config.json`:

```json
{
  "version": 1,
  "failOn": "high",
  "rules": {
    "disabled": ["secrets/generic-api-key"],
    "severityOverrides": {
      "supply-chain/wildcard-dependency": "high"
    }
  },
  "scan": {
    "maxFileSizeKb": 512,
    "skipDirs": ["node_modules", ".next", "dist"]
  },
  "runtime": {
    "maxPages": 20,
    "maxDepth": 3,
    "requestDelayMs": 150
  }
}
```

Full reference → [docs/configuration.md](docs/configuration.md)

---

## 🚦 CI / GitHub Actions

Push the included workflow and get SARIF results in your GitHub Security tab automatically:

```
.github/workflows/cybermat-scan.yml  ← already included
```

On every push and PR it will:
- ✅ Run `cybermat scan`
- 📤 Upload SARIF to GitHub Code Scanning
- 💬 Post a findings summary comment on the PR
- 🔕 Report findings without blocking CI by default (set `--fail-on high` to enable hard-fail)

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | Clean — no findings at or above threshold |
| `1` | Findings detected |
| `2` | Scan error |
| `3` | Config error |
| `4` | Missing dependency |
| `5` | New findings vs baseline (CI mode) |

Full guide → [docs/ci.md](docs/ci.md)

---

## 🗺️ OWASP Top 10:2025 Coverage

| # | Category | Covered by |
|---|---|---|
| A01 | Broken Access Control | Static (missing guards) + Auth (IDOR, privilege escalation) |
| A02 | Security Misconfiguration | Static (CORS, headers) + Runtime (headers, cookies) |
| A03 | Software Supply Chain | Static (lifecycle scripts, wildcard deps, missing lockfile) |
| A04 | Cryptographic Failures | Static (66 secret detectors, localStorage tokens) |
| A05 | Injection | Static (XSS, SQL, command, eval, SSRF) |
| A06 | Insecure Design | Static (AI tool calls, system prompt injection) |
| A07 | Authentication Failures | Static + Runtime + Auth (anonymous route access) |
| A08 | Data Integrity Failures | Static (webhook secrets, AI tool misuse) |

---

## 🔑 Secret Redaction

Secrets are **never stored raw** in any report. The format is:

```
sk-ant-api03-...wxyz   ← you see enough to identify it, not enough to use it
```

Values ≥ 8 chars → first 4 + `...` + last 4  
Values < 8 chars → fully masked as `[REDACTED]`

---

## 🙈 Ignoring False Positives

Create `.cybermatignore` in your project root:

```
# Ignore a directory
test/fixtures/

# Ignore a specific rule everywhere
rule:secrets/generic-api-key

# Ignore one specific finding (copy fingerprint from report.json)
fp:a1b2c3d4e5f6

# Wildcard
docs/*
```

---

## 📦 Monorepo Structure

```
packages/
  shared/      Core types (Finding, ScanReport, RuntimeFinding, AuthzFinding…)
  analyzers/   File inventory, stack detection, AST analysis, route discovery
  engines/     Scanner engines — secrets, static-code, runtime, authz
  rules/       95 rules across 9 packs with OWASP/CWE metadata
  core/        Orchestrator — runScan(), runRuntimeScan(), runAuthScan()
  cli/         Commander.js CLI entry point
  vscode/      VS Code extension — inline diagnostics, status bar, auto-scan on save

examples/
  vulnerable-next-app/   Intentionally vulnerable Next.js app (all secrets are FAKE)

scripts/
  setup-auth-profiles.ts   Playwright login script — saves session cookies

docs/
  product-architecture.md
  internal-architecture.md
  roadmap.md
  rules.md                        (auto-generated — run cybermat rules docs)
  auth-access-control-scanning.md
  configuration.md
  ci.md
  safety-model.md
```

---

## 🛡️ Safety Model

CyberMat Shield is **read-only and non-destructive**:

- 🚫 Never sends POST/PUT/PATCH/DELETE
- 🚫 Never requests URLs outside the configured origin
- 🚫 Never brute-forces IDs or tokens
- 🚫 Never stores or logs session credentials
- 🚫 Never sends anything to external servers
- ✅ Only writes to `.cybermat/` output directory

Full details → [docs/safety-model.md](docs/safety-model.md)

---

## 🏗️ Language & File Coverage

CyberMat Shield scans 60+ file extensions and 50+ special filenames.

| Language / File type | Coverage |
|---|---|
| TypeScript / JavaScript | Full AST analysis, source/sink correlation, secrets, patterns |
| Python | Pattern scanning + secrets (eval, exec, pickle, subprocess shell=True, yaml.load) |
| Go | Secrets |
| Java / Kotlin | Secrets |
| PHP | Pattern scanning + secrets (eval, shell_exec, unserialize) |
| Ruby | Secrets |
| Rust / C / C++ | Secrets |
| Shell scripts (.sh, .bash, .ps1) | Pattern scanning (curl\|sh, eval, chmod 777, TLS bypass) |
| Dockerfile / Containerfile | Pattern scanning (curl\|sh, ADD URL, ENV secrets, USER root) |
| Docker Compose (YAML) | Pattern scanning (privileged, docker.sock, host network) |
| Terraform / HCL | Pattern scanning (public S3, SSH/RDP open to world) |
| Kubernetes YAML | Pattern scanning (privileged, hostNetwork, hostPID, runAsRoot) |
| GitHub Actions / GitLab CI / CircleCI | Pattern scanning (curl\|bash, pull_request_target unsafe checkout) |
| Jenkinsfile / Makefile / Procfile | Secrets |
| Environment files (.env, .env.local, etc.) | Secrets |
| JSON / YAML / TOML / XML / INI | Secrets + config misconfigurations |
| GraphQL / Prisma / SQL | Secrets |
| Certificates & keys (.pem, .key, .crt) | Secrets |
| go.mod / Cargo.toml / requirements.txt / pom.xml | Dependency + secrets |
| Firebase / Firestore / Supabase rules | Config misconfigurations |

> Full AST analysis (import graph, source/sink correlation) is only for TypeScript/JavaScript. All other languages get pattern-based scanning and secret detection.

## 🏗️ Supported Stacks

| Category | Supported |
|---|---|
| Languages | TypeScript, JavaScript, Python, Go, Java, PHP, Ruby, Rust, C/C++, Kotlin, Swift |
| Infrastructure | Docker, Terraform, Kubernetes, HCL, Shell/Bash, PowerShell |
| Frameworks | Next.js, React, Express, Node.js, Fastify, NestJS, Vue, Svelte, Astro |
| Auth | Clerk, NextAuth/Auth.js, Supabase Auth, Firebase Auth |
| Databases | PostgreSQL, MySQL, MongoDB, Redis, Supabase, Firebase |
| Payments | Stripe, PayPal, Lemon Squeezy |
| AI Providers | OpenAI, Anthropic, Google Gemini, Mistral, Groq, ElevenLabs, HuggingFace, Replicate, Together AI |
| Platforms | Vercel, Netlify, Cloudflare |
| Comms | Resend, SendGrid, Mailgun, Twilio, Slack, Discord, Telegram |

---

## 🧑‍💻 Contributing

We'd love your help! Check [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

```bash
# Get started
git clone https://github.com/Martysunshine/cybermat-shield.git
cd cybermat-shield
pnpm install && pnpm build

# Run tests
npx tsx --test packages/engines/src/runtime-engine/__tests__/runtime.test.ts
npx tsx --test packages/engines/src/authz-engine/__tests__/authz.test.ts

# Try it on the vulnerable app
node packages/cli/dist/index.js scan examples/vulnerable-next-app
```

> **All secrets in `examples/` are fake test values. Never commit real credentials.**

---

## 📜 Build History

| Phase | What was built |
|---|---|
| ✅ 1 — MVP Foundation | Static scanner, Commander.js CLI, JSON + HTML reports |
| ✅ 2 — Architecture Hardening | 66 secret detectors, engines layer, `.cybermatignore` |
| ✅ 3 — Three-Layer Architecture | Code/Runtime/Authz separation, ScanPlanner, docs |
| ✅ 4 — Deep Static Analysis | AST analysis, source/sink correlation, route discovery |
| ✅ 5 — Rule Pack System | RuleRegistry, 9 RulePacks, 95 rules, OWASP mapping |
| ✅ 6 — Safe Runtime Scanner | Playwright crawler, 8 analyzers, 48 unit tests |
| ✅ 7 — Auth/Access-Control | IDOR, vertical privilege, anonymous route testing, 38 unit tests |
| ✅ 8 — Productionization | SARIF, baseline diffing, GitHub Actions, npm packaging |
| ✅ v0.2.0 — Multi-language | 60+ extensions, language classifier, 28 multilang detectors, entropy scoring, fingerprints |
| ✅ Step 3 — VS Code Extension | Inline diagnostics, status bar, auto-scan on save, F5 launch config |

---

## 📄 License

MIT © [CyberMat Shield Contributors](LICENSE)
