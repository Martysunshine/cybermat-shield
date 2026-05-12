# Safety Model

CyberMat Shield is built around a strict safety model: it is a **read-only, non-destructive, local-first** tool.

---

## What the scanner will NEVER do

| Category | Guarantee |
|----------|-----------|
| **Network** | Never makes requests outside the configured origin (runtime/auth scanners) |
| **Mutations** | Never sends POST, PUT, PATCH, or DELETE requests |
| **Brute force** | Never generates or guesses IDs, tokens, or credentials |
| **Credentials** | Never stores or logs session tokens or API keys; raw values are redacted in all outputs |
| **Telemetry** | Never sends scan results, file contents, or metadata to any external server |
| **File writes** | Never modifies your source tree — only writes to the `.appsec/` output directory |
| **Destructive paths** | Blocks requests to paths containing: `/delete`, `/logout`, `/reset`, `/transfer`, `/withdraw`, `/checkout`, `/subscribe`, `/unsubscribe`, `/cancel`, `/remove`, `/destroy`, `/revoke`, `/purge`, `/wipe`, `/truncate`, `/drop`, `/erase` |

---

## Static scanner safety

- Opens files in read-only mode
- Respects `.appsecignore`
- Skips binary files, files > 512KB (configurable), and standard non-source directories
- Fingerprints are computed locally using SHA256; no file contents leave the machine
- Evidence snippets in reports are the raw file content at the matched line — make sure you don't share reports with sensitive file content you didn't intend to expose

---

## Runtime scanner safety

The runtime scanner (`scan-runtime`) uses Playwright to open a real browser and make HTTP requests. Safety guarantees:

- **Scope enforcement** — `ScopeManager` blocks any request outside the configured origin (same scheme + host + port)
- **Safe methods only** — GET and HEAD exclusively; OPTIONS only for method probing
- **Harmless marker injection** — the reflection analyzer injects a unique string like `appsec-probe-abc123` in query parameters. This string cannot cause harm in any common output context and is not a real XSS payload.
- **Destructive path guard** — blocks crawling or probing any URL with destructive path segments (see table above)
- **Form submission blocked** — the crawler never submits forms that contain `password`, `file`, `card`, or `cvv` field types
- **Request budget** — `maxPages`, `maxDepth`, `maxRequests` limits prevent runaway scanning
- **Delay between requests** — `requestDelayMs` (default 150ms) prevents overwhelming the target server

**Only scan applications you own or have explicit permission to test.**

---

## Auth scanner safety

The auth scanner (`scan-auth`) makes authenticated HTTP requests as real test users. Safety guarantees:

- **GET/HEAD only** — no mutation requests
- **Config-driven** — only tests the routes and resource pairs you explicitly configure
- **No brute force** — does not generate, guess, or enumerate IDs or tokens
- **No random IDs** — never constructs resource URLs it hasn't been told about
- **Request budget** — `maxAuthzRequests` (default 75) hard-stops the scan
- **Destructive path guard** — same blocked paths as the runtime scanner
- **Session tokens not logged** — storageState cookies are loaded into memory, used for the scan, and never written to outputs

**Never run `scan-auth` against production with real user sessions. Always use dedicated test accounts.**

---

## Secret redaction

All report formats (JSON, HTML, Markdown, SARIF) redact secret values:

- Values ≥ 8 characters: first 4 + `...` + last 4
- Values < 8 characters: fully masked as `[REDACTED]`
- Pattern: `sk-ant-...Wxyz` (you see enough to know which key was detected, but not enough to use it)

Redaction happens in the engines before findings reach the CLI or report writers. The raw value is never passed out of the detector function.

---

## Who is responsible for authorization?

CyberMat Shield checks that **your code enforces authorization** — but it is not itself an authorization enforcer. You are responsible for:

1. Only scanning applications you own or have explicit written permission to test
2. Using dedicated test accounts (never real user sessions) for `scan-auth`
3. Running `scan-runtime` only against localhost or explicitly approved staging environments
4. Keeping `.appsec/auth/` storageState files out of version control (the tool appends this to `.gitignore` automatically via `appsec init`)
5. Not sharing scan reports that contain sensitive application structure or route information
