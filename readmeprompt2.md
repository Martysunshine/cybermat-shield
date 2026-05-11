Continue from the initial scanner architecture. Upgrade the project from a basic MVP into a production-grade local-first application security scanner architecture.

Important product framing:
This is not a “vibe-coded app scanner” brand. It is a serious local-first Application Security Scanner for modern web applications, APIs, and AI-assisted software. It should work for real production projects, while still being especially useful for AI-generated codebases.

Do not rename the project to anything vibe-specific. Use a neutral placeholder name like AppSec Scanner or SentinelScan in code/docs until final branding is chosen.

Main goals for this phase:
1. Harden the architecture.
2. Expand the secret scanning engine.
3. Make the rule system modular and updateable.
4. Make the scanner privacy-first and safe by default.
5. Prepare the project for future runtime scanning, browser extension, VS Code extension, and CI integration without building those yet.

Implement/adjust architecture as follows:

1. Create a clear package/module structure:

- packages/cli
- packages/core
- packages/rules
- packages/engines
- packages/reporters
- packages/shared
- packages/dashboard
- examples/vulnerable-app
- examples/secure-app

Inside packages/engines create:

- secrets-engine
- static-code-engine
- dependency-engine
- config-engine
- runtime-engine placeholder
- authz-engine placeholder
- ai-security-engine
- exception-handling-engine

Inside packages/rules create:

- secrets
- javascript-typescript
- react-nextjs
- node-express
- supabase
- firebase
- clerk
- stripe
- vercel
- ai-agents
- owasp-2025

2. Define a strict Rule interface.

Each rule should be independent and return Finding[].

Use this structure:

type RuleContext = {
  rootPath: string;
  files: ScannedFile[];
  packageJson?: any;
  detectedStack: DetectedStack;
  config: ScannerConfig;
};

type Rule = {
  id: string;
  name: string;
  description: string;
  category: string;
  owasp: string[];
  severity: "critical" | "high" | "medium" | "low" | "info";
  run: (context: RuleContext) => Promise<Finding[]>;
};

Keep the rule system extensible so new rules can be added without rewriting the scanner core.

3. Upgrade the Finding type.

Use this type:

type Finding = {
  id: string;
  ruleId: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: "high" | "medium" | "low";
  owasp: string[];
  category: string;
  cwe?: string[];
  file?: string;
  line?: number;
  column?: number;
  route?: string;
  evidence: {
    snippet?: string;
    redactedSnippet?: string;
    match?: string;
    redactedMatch?: string;
    reason: string;
  };
  impact: string;
  recommendation: string;
  fixExample?: string;
  references?: string[];
  tags: string[];
};

Important:
- Never store full secrets in findings.
- Always use redactedMatch/redactedSnippet for secrets.
- If snippet contains a secret, redact it before saving.
- Terminal output, JSON output, and HTML reports must never expose full secret values.

4. Build a proper Secret Detection Engine.

The engine must support:

- provider-specific regex detectors
- environment variable name detectors
- generic high-entropy detector
- private key detector
- connection string detector
- context-aware severity rules
- allowlist/ignore file support
- false-positive reduction
- secret redaction utility
- optional verification interface placeholder but do not verify live secrets yet

Create detectors for at least these groups:

Cloud:
- AWS_ACCESS_KEY_ID
- AWS_SECRET_ACCESS_KEY
- Azure client secrets
- GCP service account JSON
- Cloudflare API tokens

Auth/session:
- CLERK_SECRET_KEY
- NEXTAUTH_SECRET
- AUTH_SECRET
- JWT_SECRET
- SESSION_SECRET
- BETTER_AUTH_SECRET

Databases:
- DATABASE_URL
- POSTGRES_URL
- MONGODB_URI
- REDIS_URL
- UPSTASH_REDIS_REST_TOKEN

Payments:
- STRIPE_SECRET_KEY
- STRIPE_WEBHOOK_SECRET
- PAYPAL_CLIENT_SECRET
- LEMON_SQUEEZY_API_KEY

AI providers:
- OPENAI_API_KEY
- ANTHROPIC_API_KEY
- GOOGLE_API_KEY
- GEMINI_API_KEY
- MISTRAL_API_KEY
- GROQ_API_KEY
- ELEVENLABS_API_KEY
- HUGGINGFACE_TOKEN
- REPLICATE_API_TOKEN
- TOGETHER_API_KEY

Platforms:
- SUPABASE_SERVICE_ROLE_KEY
- SUPABASE_JWT_SECRET
- FIREBASE_PRIVATE_KEY
- FIREBASE_CLIENT_EMAIL
- VERCEL_TOKEN
- NETLIFY_AUTH_TOKEN

Communication:
- RESEND_API_KEY
- SENDGRID_API_KEY
- MAILGUN_API_KEY
- TWILIO_AUTH_TOKEN
- SLACK_BOT_TOKEN
- DISCORD_WEBHOOK_URL
- TELEGRAM_BOT_TOKEN

Monitoring:
- SENTRY_AUTH_TOKEN
- SENTRY_DSN
- POSTHOG_API_KEY
- DATADOG_API_KEY
- NEW_RELIC_LICENSE_KEY

Dev platforms:
- GITHUB_TOKEN
- GITHUB_PAT
- GITLAB_TOKEN
- NPM_TOKEN
- DOCKERHUB_TOKEN

Private keys:
- RSA private key
- EC private key
- OpenSSH private key
- PGP private key
- generic PEM private key

Connection strings:
- PostgreSQL
- MySQL
- MongoDB
- Redis
- AMQP
- SMTP

5. Add context-aware severity logic.

Examples:

- SUPABASE_SERVICE_ROLE_KEY in frontend/client code = critical
- SUPABASE_SERVICE_ROLE_KEY in .env.local = high
- Supabase anon key in frontend = info unless paired with dangerous config
- Firebase apiKey in frontend = info/low unless paired with permissive Firebase rules
- FIREBASE_PRIVATE_KEY anywhere in repo = critical
- STRIPE_SECRET_KEY in frontend/client code = critical
- STRIPE_SECRET_KEY in backend env file = high
- Webhook signing secret committed = high
- Public Sentry DSN = info/low
- SENTRY_AUTH_TOKEN = high/critical
- DATABASE_URL in committed file = critical/high
- JWT_SECRET shorter than 32 chars = high
- Token stored in localStorage = high

Frontend/client code indicators:
- /app
- /pages
- /components
- /src/components
- /src/app
- /public
- files containing "use client"
- Vite import.meta.env variables
- NEXT_PUBLIC_ variables

Backend/server code indicators:
- /api
- /server
- /lib/server
- route.ts
- server.ts
- middleware.ts

6. Add redaction and masking utilities.

Implement:

redactSecret(value: string): string

Rules:
- Show only first 4 and last 4 characters for long secrets.
- Fully mask short secrets.
- Preserve enough context for developer recognition.
- Never print raw secret.
- Add tests for redaction.

Example:
sk_live_123456789abcdef becomes sk_l****cdef

7. Add scanner safety/privacy policy in code and README.

Document:

- scanner runs locally by default
- no code upload by default
- no secret upload by default
- no destructive exploitation
- no external target scanning unless user explicitly provides target
- reports redact secrets
- future cloud mode must be opt-in

8. Add baseline/ignore system.

Create .appsecscannerignore or .sentinelscanignore file support.

Allow ignoring:
- specific files
- specific rule IDs
- specific finding fingerprints

Generate stable finding fingerprints based on:
- ruleId
- file
- line
- redacted evidence
- category

9. Add severity scoring.

Create risk score from 0 to 100.

Suggested weighting:
- critical = 25
- high = 12
- medium = 5
- low = 2
- info = 0

Score should never go below 0.
Also output:
- total findings
- findings by severity
- OWASP coverage
- top 5 recommended fixes

10. Add tests.

Create unit tests for:
- secret redaction
- secret detector matching
- false-positive reduction
- finding generation
- severity calculation
- ignore file matching

11. Update documentation.

README should explain:

- what the scanner does
- supported stacks
- local-first privacy model
- install/run commands
- report output
- OWASP Top 10:2025 mapping
- what is currently implemented
- what is planned later

Do not build runtime penetration testing yet.
Do not build browser extension yet.
Do not build cloud dashboard yet.
This phase is architecture hardening + secret engine + modular rule system + safe reporting.
