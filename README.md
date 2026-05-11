# CyberMat Shield

**Local-first Application Security Scanner for modern web apps, APIs, and AI-assisted codebases.**

Runs entirely on your machine. No code upload. No cloud required. Findings are written to `.appsec/` in your project.

---

## Supported Stacks

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
| Monitoring | Sentry, PostHog, Datadog, New Relic |
| CI/CD | GitHub Actions, GitLab CI |

---

## Install & Run

```bash
# Install dependencies
pnpm install

# Build all packages
pnpm build

# Scan a project
node packages/cli/dist/index.js scan <path-to-project>

# Options
node packages/cli/dist/index.js scan . --json     # Output JSON to stdout
node packages/cli/dist/index.js scan . --output-dir .reports
```

**Reports are saved to `.appsec/report.json` and `.appsec/report.html`.**

---

## OWASP Top 10:2025 Mapping

| OWASP Category | Scanner Coverage |
|---|---|
| A01 Broken Access Control | Missing middleware, unprotected admin routes, IDOR via user_id from body |
| A02 Security Misconfiguration | CORS wildcard, missing security headers, exposed source maps, .env committed |
| A03 Software Supply Chain Failures | Suspicious lifecycle scripts, wildcard dependency versions, missing lockfile |
| A04 Cryptographic Failures | 60+ secret detectors (API keys, private keys, connection strings) |
| A05 Injection | XSS sinks, SQL injection, command injection, eval usage |
| A06 Insecure Design | AI tool calls without approval, unsafe AI output rendering |
| A07 Authentication Failures | Missing auth guards, JWT stored in localStorage, insecure cookies |
| A08 Software or Data Integrity Failures | Webhook secret exposure, AI tool misuse |
| A09 Security Logging and Alerting Failures | (Phase 4+) |
| A10 Mishandling of Exceptional Conditions | (Phase 4+) |

---

## Privacy Model

- **Local only by default.** The scanner reads your files on disk. Nothing is sent to any server.
- **No secret upload.** Secrets detected in your code are redacted in all outputs. The raw value is never written to any report.
- **No destructive exploitation.** The scanner only reads files statically. It does not attempt to authenticate, make external API calls, or exploit findings.
- **No external scanning without explicit opt-in.** The runtime scanner (Phase 6) only runs when you explicitly provide a URL with `appsec scan-runtime <url>`.
- **Reports redact secrets.** JSON, HTML, and terminal output all show redacted values (e.g., `sk_l****cdef`). The full secret is never stored.
- **Future cloud mode is opt-in.** Any future cloud dashboard or remote scanning will require explicit configuration. Local mode remains the default.

---

## Ignore System

Create `.appsecignore` in your project root to suppress known findings:

```
# Ignore by file path
examples/vulnerable-next-app/.env.local

# Ignore by rule ID
rule:supply-chain.missing-lockfile

# Ignore by finding fingerprint (ID from report.json)
fp:a1b2c3d4e5f6

# Wildcard prefix
test/*
```

---

## Secret Detection

The scanner includes **66 secret detectors** across:

- **Cloud:** AWS, Azure, GCP, Cloudflare
- **Auth/Session:** Clerk, NextAuth, JWT, Session secrets
- **Databases:** PostgreSQL, MySQL, MongoDB, Redis, Upstash
- **Payments:** Stripe, PayPal, Lemon Squeezy
- **AI Providers:** OpenAI, Anthropic, Google/Gemini, Mistral, Groq, ElevenLabs, HuggingFace, Replicate, Together AI
- **Platforms:** Supabase, Firebase, Vercel, Netlify
- **Communication:** Resend, SendGrid, Mailgun, Twilio, Slack, Discord, Telegram
- **Monitoring:** Sentry, PostHog, Datadog, New Relic
- **Dev Platforms:** GitHub, GitLab, npm, Docker Hub
- **Private Keys:** RSA, EC, OpenSSH, PGP, generic PEM
- **Connection Strings:** PostgreSQL, MySQL, MongoDB, Redis, AMQP, SMTP

### Context-Aware Severity

Severity adjusts based on where a secret appears:

| Secret | Backend env file | Source code | Frontend / client code |
|---|---|---|---|
| Supabase service role key | high | critical | critical |
| Stripe secret key | high | critical | critical |
| OpenAI API key | high | high | critical |
| Private key | critical | critical | critical |
| Sentry DSN | info | info | info |

---

## Risk Score

Findings reduce the score from 100:

| Severity | Deduction |
|---|---|
| Critical | −25 |
| High | −12 |
| Medium | −5 |
| Low | −2 |
| Info | 0 |

Score is clamped to 0 minimum. A score ≥ 70 is Good, ≥ 40 is Fair, ≥ 20 is Poor, < 20 is Critical.

---

## Architecture

```
packages/
  shared/          Core types (Finding, Rule, ScanReport, etc.)
  engines/         Detection engines
    secrets-engine/    66 secret detectors, redaction utilities
    static-code-engine/   (Phase 4)
    dependency-engine/    (Phase 4)
    config-engine/        (Phase 4)
    ai-security-engine/   (Phase 4)
    runtime-engine/       (Phase 6 — Playwright)
    authz-engine/         (Phase 7 — IDOR/BOLA)
  rules/           Rule modules (use engines, produce Finding[])
  core/            Scanner orchestrator, file inventory, stack detection
  cli/             Commander.js CLI (appsec scan <path>)
  dashboard/       (Phase 8 — React + Vite)
examples/
  vulnerable-next-app/   Intentionally vulnerable test target
```

---

## Phases

| Phase | Status | Description |
|---|---|---|
| 1 — MVP Foundation | ✅ Done | Basic rules, terminal output, JSON + HTML reports |
| 2 — Architecture Hardening | ✅ Done | 66 secret detectors, engines layer, .appsecignore, upgraded types |
| 3 — Three-Layer Architecture | ⬜ Planned | Code / Runtime / Auth scanner separation, ScanPlanner |
| 4 — Deep Static Analysis | ⬜ Planned | AST, import graph, source/sink correlation, route discovery |
| 5 — Rule Pack System | ⬜ Planned | Full OWASP/CWE metadata, rule registry, CLI rule commands |
| 6 — Safe Runtime Scanner | ⬜ Planned | Playwright-based header/cookie/CORS/redirect analysis |
| 7 — Auth/Access-Control | ⬜ Planned | IDOR, vertical privilege, tenant boundary testing |
| 8 — Productionization | ⬜ Planned | SARIF, baseline, GitHub Actions, npm publish |
