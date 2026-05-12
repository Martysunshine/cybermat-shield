# CyberMat Shield

Local-first Application Security Scanner for modern web apps, APIs, and AI-assisted codebases.  
Maps every finding to **OWASP Top 10:2025**. Runs entirely on your machine — no code upload, no cloud required.

---

## What it scans

| Layer | What it finds |
|---|---|
| **Static** | Secrets/API keys (66 detectors), XSS sinks, SQL injection, eval/exec, missing auth guards, insecure deps, supply-chain risks, AI security issues |
| **Runtime** | Missing security headers, insecure cookies, CORS misconfigs, open redirects, reflected input, exposed sensitive files (.env, .git/config, swagger, etc.) |
| **Auth/Access-Control** | IDOR, vertical privilege escalation, anonymous route exposure, tenant boundary issues |

---

## Requirements

- **Node.js ≥ 18** (tested on 22)
- **pnpm ≥ 8** — `npm install -g pnpm`
- **Playwright Chromium** — required for `scan-runtime` and `scan-auth`

---

## Quick start

```bash
git clone https://github.com/Martysunshine/cybermat-shield.git
cd cybermat-shield
pnpm install
pnpm build

# Static scan of any project
node packages/cli/dist/index.js scan ./your-app

# Runtime scan (requires a running app and Playwright)
npx playwright install chromium
node packages/cli/dist/index.js scan-runtime http://localhost:3000

# Auth/access-control scan (requires auth profiles — see below)
node packages/cli/dist/index.js scan-auth http://localhost:3000
```

---

## CLI commands

| Command | Description |
|---|---|
| `appsec scan <path>` | Static code scan |
| `appsec scan <path> --json` | Output JSON report to stdout |
| `appsec scan <path> --html` | Write an HTML report |
| `appsec scan-runtime <url>` | Safe browser-based runtime scan |
| `appsec scan-runtime <url> --max-pages 10` | Limit pages crawled |
| `appsec scan-runtime <url> --no-browser` | HTTP probes only, no Playwright |
| `appsec scan-auth <url>` | Authenticated access-control scan |
| `appsec scan-auth <url> --config .appsec/auth-config.json` | Use a specific config file |
| `appsec auth init` | Create `.appsec/auth-config.json` template |
| `appsec auth test-config` | Validate auth profiles and test connectivity |
| `appsec rules list` | List all 95 rules |
| `appsec rules list --owasp A01` | Filter by OWASP category |
| `appsec rules list --engine secrets` | Filter by engine |
| `appsec rules show <id>` | Show rule detail, examples, remediation |
| `appsec rules docs` | Generate `docs/rules.md` |

---

## Monorepo structure

```
packages/
  shared/      Core types (Finding, ScanReport, RuntimeFinding, AuthzFinding, …)
  analyzers/   File inventory, stack detection, AST analysis, route discovery
  engines/     Scanner engines — secrets, static-code, runtime, authz
  rules/       95 rules across 9 packs with OWASP/CWE metadata
  core/        Orchestrator — runScan(), runRuntimeScan(), runAuthScan()
  cli/         Commander.js CLI entry point

examples/
  vulnerable-next-app/   Intentionally vulnerable Next.js app (all secrets are FAKE)

scripts/
  setup-auth-profiles.ts   Saves Playwright storageState for all 3 test users

docs/
  product-architecture.md
  internal-architecture.md
  roadmap.md
  rules.md                      (auto-generated — run `appsec rules docs`)
  auth-access-control-scanning.md
```

---

## OWASP Top 10:2025 coverage

| OWASP Category | Scanner Layer |
|---|---|
| A01 Broken Access Control | Static (missing guards) + Auth (IDOR, privilege) |
| A02 Security Misconfiguration | Static (CORS, headers, source maps) + Runtime (headers, cookies) |
| A03 Software Supply Chain Failures | Static (lifecycle scripts, wildcard deps, missing lockfile) |
| A04 Cryptographic Failures | Static (66 secret detectors, localStorage tokens) |
| A05 Injection | Static (XSS, SQL, command, eval) |
| A06 Insecure Design | Static (AI tool calls, system prompt injection) |
| A07 Authentication Failures | Static (missing guards) + Runtime (missing headers) + Auth (anonymous access) |
| A08 Data Integrity Failures | Static (webhook secrets, AI tool misuse) |

---

## Secret detection

**66 detectors** across:

Cloud · Auth/Session · Databases · Payments · AI Providers · Platforms · Communication · Monitoring · Dev Platforms · Private Keys · Connection Strings

Secrets are **redacted in all outputs** — reports show `sk_l****cdef`, never the full value.

---

## Privacy model

- Local by default — nothing is sent anywhere
- Secrets redacted before being written to any report file
- Runtime scanner: GET/HEAD/OPTIONS only; no mutation, no data submission
- Auth scanner: no brute force, no random ID generation, maxAuthzRequests=75

---

## The test target — `examples/vulnerable-next-app`

An intentionally vulnerable Next.js app used for scanner testing. **All secrets are FAKE.**  
Contains controlled vulnerability fixtures for every scanner layer.

**Start it:**

```bash
cd examples/vulnerable-next-app
npx next dev
# → http://localhost:3000
```

**Test accounts (fake passwords):**

| Profile | Email | Password | Role |
|---|---|---|---|
| userA | usera@test.com | password123 | user |
| userB | userb@test.com | password123 | user |
| admin | admin@test.com | admin123 | admin |

**Auth/IDOR routes the scanner tests against:**

| Route | What is vulnerable |
|---|---|
| `GET /api/admin` | No authentication at all |
| `GET /api/users?userId=<id>` | No auth, arbitrary user ID from query param |
| `GET /api/users/<id>` | Auth required but no ownership check (any user can read any user's data) |
| `GET /api/resources/<id>` | Auth required but no ownership check (userB can read resource-1 which belongs to userA) |

---

## Setting up auth profiles for `scan-auth`

This is **STOP #3** in the build process. The `scan-auth` command needs session cookies for each test user. The setup script automates the login and saves them.

### Step 1 — Start the test app

```bash
# Terminal 1
cd examples/vulnerable-next-app
npx next dev
```

### Step 2 — Run the setup script

```bash
# Terminal 2 (from repo root)
npx tsx --tsconfig scripts/tsconfig.json scripts/setup-auth-profiles.ts
```

This logs in as each test user via Playwright and saves their sessions to:

```
.appsec/auth/userA.storage.json
.appsec/auth/userB.storage.json
.appsec/auth/admin.storage.json
```

### Step 3 — Run the auth scanner

```bash
node packages/cli/dist/index.js scan-auth http://localhost:3000
```

> **Session reset:** The test app stores sessions in-memory. They reset when the dev server restarts.  
> Re-run `setup-auth-profiles.ts` any time you restart the app.

### Using auth profiles against your own app

1. `node packages/cli/dist/index.js auth init` — creates `.appsec/auth-config.json` template
2. Edit the config with your login URL, test account credentials, and resource pairs
3. Export storageState for each user (either via the setup script or manually with Playwright)
4. `node packages/cli/dist/index.js auth test-config` — validates profiles
5. `node packages/cli/dist/index.js scan-auth <your-url>`

See [docs/auth-access-control-scanning.md](docs/auth-access-control-scanning.md) for the full guide.

---

## Supported stacks

| Category | Supported |
|---|---|
| Languages | TypeScript, JavaScript |
| Frameworks | Next.js, React, Express, Node.js |
| Auth | Clerk, NextAuth/Auth.js, Supabase Auth, Firebase Auth |
| Databases | PostgreSQL, MySQL, MongoDB, Redis, Supabase, Firebase |
| Payments | Stripe, PayPal, Lemon Squeezy |
| AI Providers | OpenAI, Anthropic, Google/Gemini, Mistral, Groq, ElevenLabs, HuggingFace, Replicate, Together AI |
| Platforms | Vercel, Netlify, Cloudflare |
| Comms | Resend, SendGrid, Mailgun, Twilio, Slack, Discord, Telegram |

---

## Risk score

Findings reduce the score from 100:

| Severity | Deduction |
|---|---|
| Critical | −25 |
| High | −12 |
| Medium | −5 |
| Low | −2 |
| Info | 0 |

≥70 = Good · ≥40 = Fair · ≥20 = Poor · <20 = Critical

---

## Ignore false positives

Create `.appsecignore` in your project root:

```
# By file path
examples/vulnerable-next-app/.env.local

# By rule ID
rule:supply-chain.missing-lockfile

# By fingerprint (from report.json)
fp:a1b2c3d4e5f6

# Wildcard
test/*
```

---

## Development

```bash
pnpm install
pnpm build

# Run unit tests
npx tsx --test packages/engines/src/runtime-engine/__tests__/runtime.test.ts
npx tsx --test packages/engines/src/authz-engine/__tests__/authz.test.ts
```

---

## Build phases

| Phase | Status | What was built |
|---|---|---|
| 1 — MVP Foundation | ✅ | Static scanner, Commander.js CLI, JSON + HTML reports |
| 2 — Architecture Hardening | ✅ | 66 secret detectors, engines layer, `.appsecignore`, upgraded Finding type |
| 3 — Three-Layer Architecture | ✅ | Code/Runtime/Authz layer separation, ScanPlanner, docs |
| 4 — Deep Static Analysis | ✅ | AST analysis, source/sink correlation, import graph, route discovery |
| 5 — Rule Pack System | ✅ | RuleRegistry, 9 RulePacks, 95 rules, OWASP mapping, `appsec rules` commands |
| 6 — Safe Runtime Scanner | ✅ | Playwright crawler, 8 analyzers, `appsec scan-runtime`, 48 unit tests |
| 7 — Auth/Access-Control Scanner | ✅ | IDOR, vertical privilege, anonymous route tests, `appsec scan-auth` |
| 8 — Productionization | ⬜ | SARIF, baseline diffing, GitHub Actions, npm packaging |

---

## Contributing

1. Fork and clone
2. `pnpm install && pnpm build`
3. Test against `examples/vulnerable-next-app`
4. Add unit tests for new engine logic
5. Submit a PR

**All secrets in `examples/` are fake test values. Do not commit real credentials.**

---

## License

MIT
