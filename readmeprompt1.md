Build a TypeScript monorepo for a local defensive web application security scanner called VibeShield.

The product is a local-first scanner for AI/vibe-coded web applications. It should be installable and runnable from the terminal. The scanner maps findings to OWASP Top 10:2025 categories:

A01 Broken Access Control
A02 Security Misconfiguration
A03 Software Supply Chain Failures
A04 Cryptographic Failures
A05 Injection
A06 Insecure Design
A07 Authentication Failures
A08 Software or Data Integrity Failures
A09 Security Logging and Alerting Failures
A10 Mishandling of Exceptional Conditions

Architecture:

- packages/cli: terminal commands using Commander.js
- packages/core: scanner orchestration, shared finding type, risk scoring, report writing
- packages/rules: rule modules for secrets, static code, dependency, config, runtime, auth, and AI-specific checks
- packages/dashboard: local React dashboard for visualizing scan results
- packages/shared: shared types and utilities
- examples/vulnerable-next-app: small intentionally vulnerable test app
- examples/secure-next-app: small fixed comparison app

Implement the first MVP only:

CLI commands:
- vibeshield scan <path>
- vibeshield scan <path> --json
- vibeshield scan <path> --html
- vibeshield dashboard

Core features:
1. Recursively scan project files.
2. Ignore node_modules, .next, dist, build, .git, coverage.
3. Detect project stack from package.json and config files.
4. Run static code rules.
5. Run secrets/config rules.
6. Run dependency/package.json rules.
7. Output findings in terminal.
8. Save reports to .vibeshield/report.json and .vibeshield/report.html.

Finding type:

type Finding = {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: "high" | "medium" | "low";
  owasp: string[];
  category: string;
  file?: string;
  line?: number;
  route?: string;
  evidence: string;
  impact: string;
  recommendation: string;
  references?: string[];
};

MVP rules to implement:

Secrets:
- Detect SUPABASE_SERVICE_ROLE_KEY
- Detect STRIPE_SECRET_KEY
- Detect OPENAI_API_KEY
- Detect CLERK_SECRET_KEY
- Detect DATABASE_URL
- Detect JWT_SECRET
- Detect private keys
- Mask secrets in output

XSS / Injection:
- Flag dangerouslySetInnerHTML
- Flag innerHTML / outerHTML / insertAdjacentHTML
- Flag document.write
- Flag eval and new Function
- Flag setTimeout or setInterval with string argument
- Flag Prisma.$queryRawUnsafe
- Flag SQL string concatenation patterns
- Flag child_process.exec / execSync

Auth / Access Control:
- Flag app/api or pages/api route files with no obvious auth check
- Detect missing middleware.ts in Next.js projects
- Flag user_id/userId accepted from req.body or request body
- Flag admin routes with no role/admin check

Config / Misconfiguration:
- Flag permissive CORS patterns: origin "*", Access-Control-Allow-Origin "*", credentials true with wildcard
- Flag missing security headers in next.config.js if no headers() config exists
- Flag public source maps in production config
- Flag exposed .env files if present in scanned folder

Crypto / Session:
- Flag localStorage/sessionStorage usage for token/jwt/session
- Flag cookies set without HttpOnly/Secure/SameSite when visible in code

Supply Chain:
- Parse package.json
- Flag suspicious lifecycle scripts: postinstall, preinstall, prepare
- Flag wildcard dependency versions "*"
- Flag very broad versions if easy to detect
- Flag missing lockfile
- Optionally run npm audit if package-lock exists and npm is available

AI-specific:
- Flag variables named aiResponse, llmOutput, modelOutput, completion, generatedHtml being rendered through raw HTML sinks
- Flag tool execution functions that call shell/database/email/delete operations without approval keywords

Report:
- Print grouped findings by severity.
- Calculate score from 0 to 100.
- Generate report.html with a clean dashboard-style layout.
- Include OWASP category mapping per finding.
- Include recommended fixes.

Keep the code modular so new rules can be added easily. Do not implement destructive exploitation. Runtime scanning, browser extension, auth testing, and CI/CD integration will be later phases.