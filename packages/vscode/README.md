# CyberMat Shield — Security Scanner

**Inline security findings as you code.** Detects secrets, XSS, SQL injection, IDOR patterns, supply chain risks, and 120+ more vulnerabilities — directly in your editor. No cloud. No telemetry. Everything runs on your machine.

---

## Features

- **Inline diagnostics** — red underlines on critical/high findings, yellow on medium/low. Hover for the rule, evidence snippet, and fix recommendation.
- **Status bar** — live finding count with risk score. Click to re-scan anytime.
- **Auto-scan on save** — rescans 2 seconds after any file save.
- **Auto-scan on open** — scans automatically when a workspace opens.
- **123+ rules** across 9 categories: secrets, static code, supply chain, AI security, misconfigs, and more.
- **OWASP Top 10:2025 mapped** — every finding links to a category and CWE.

---

## What it detects

| Category | Examples |
|---|---|
| 🔑 Secrets & API keys | AWS, Stripe, OpenAI, Supabase, Firebase, Twilio — 66 detectors |
| 💉 Injection | XSS (dangerouslySetInnerHTML), SQL injection, eval, exec, SSRF |
| 🚪 Missing auth guards | Unprotected routes, missing middleware, IDOR-prone patterns |
| 📦 Supply chain | Lifecycle scripts, wildcard versions, missing lockfile |
| ⚙️ Misconfigurations | CORS wildcards, source maps in prod, disabled RLS |
| 🤖 AI security | Prompt injection, LLM output rendered as HTML, unsafe tool calls |

---

## Usage

The extension activates automatically on workspaces containing TypeScript, JavaScript, or `package.json` files.

**Commands (Ctrl+Shift+P):**

| Command | Description |
|---|---|
| `CyberMat: Scan Workspace` | Run a full scan now |
| `CyberMat: Clear Findings` | Remove all diagnostics |

**Settings:**

| Setting | Default | Description |
|---|---|---|
| `cybermat.scanOnSave` | `true` | Re-scan 2 seconds after every file save |
| `cybermat.scanOnOpen` | `true` | Scan automatically when a workspace opens |

---

## Privacy

- No network requests
- No telemetry
- No data leaves your machine
- Secrets are redacted in all output (first 4 + `...` + last 4 chars)

---

## Links

- [GitHub](https://github.com/Martysunshine/cybermat-shield)
- [npm (CLI)](https://www.npmjs.com/package/cybermat)
- [Report an issue](https://github.com/Martysunshine/cybermat-shield/issues)
