# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes |

---

## Reporting a vulnerability in CyberMat Shield itself

If you find a security vulnerability in CyberMat Shield — such as a path traversal in the file scanner, secret leakage in report output, or a way to make the tool perform unintended network requests — please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, reach out to me: **LinkedIn from my Github profile** (or open a [GitHub private security advisory](https://github.com/Martysunshine/cybermat-shield/security/advisories/new))

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Your suggested fix (optional but appreciated)

We will acknowledge receipt within 48 hours and aim to release a fix within 14 days for critical issues.

---

## Security model

CyberMat Shield is a **local-first** tool. Key guarantees:

- **No telemetry** — nothing is sent to external servers. All scanning happens on your machine.
- **Secrets are redacted** — raw secret values are never written to report files. Reports contain only first/last 4 characters or a full mask.
- **Read-only file access** — the static scanner reads files but never writes to your source tree.
- **Safe-by-default runtime scanning** — only GET/HEAD requests, no mutations, no brute force, no random ID generation.
- **No credentials stored** — auth session tokens are loaded from storageState files, used in memory during the scan, and never written to log files or report outputs.

---

## Known limitations

- The scanner is a **best-effort** tool. It will produce false positives and miss some vulnerabilities. Do not use it as your only security control.
- The runtime scanner requires Playwright browser automation. Ensure you only point it at applications you own or have explicit permission to test.
- The auth scanner (`scan-auth`) makes real HTTP requests as real test users. Only use it against test environments with dedicated test accounts.
