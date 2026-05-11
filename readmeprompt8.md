Continue from the local-first Application Security Scanner.

The project should now have:
- static scanning architecture
- secret scanning engine
- rule packs
- OWASP mapping
- safe runtime scanner
- authenticated access-control testing module

Now productionize the scanner so it is ready for serious developer use.

Goal:
Make the scanner stable, professional, testable, packageable, documented, and usable in local development and CI/CD.

1. Final CLI structure

Implement or refine these commands:

appsec init
appsec scan <path>
appsec scan-runtime <url>
appsec scan-auth <url>
appsec dashboard
appsec report
appsec rules list
appsec rules show <ruleId>
appsec baseline create
appsec baseline compare
appsec config validate
appsec doctor

Command behavior:

appsec init
- creates appsec.config.json
- creates .appsecignore
- creates .appsec/ directory
- prints next steps

appsec scan <path>
- runs static, secret, dependency, config, AI-security checks
- writes report.json and report.html

appsec scan-runtime <url>
- runs safe runtime checks
- respects scope settings

appsec scan-auth <url>
- runs authenticated access-control tests
- requires authProfiles or configured storage states

appsec dashboard
- opens local report dashboard
- can read latest .appsec/report.json

appsec doctor
- checks Node version
- checks package manager
- checks Playwright availability
- checks config validity
- checks writable report directory

2. Exit codes

Implement stable exit codes:

0 = scan completed, no findings at or above threshold
1 = scan completed, findings at or above threshold
2 = scanner error or invalid configuration
3 = unsafe scan configuration blocked
4 = authentication configuration error
5 = runtime target unreachable

3. Config file

Finalize appsec.config.json schema.

Example:

{
  "projectName": "My Application",
  "scan": {
    "include": ["src", "app", "pages", "server", "lib", "supabase", "prisma"],
    "exclude": ["node_modules", ".next", "dist", "build", ".git", "coverage"],
    "maxFileSizeBytes": 1000000,
    "severityThreshold": "high",
    "failOnNewOnly": false
  },
  "runtime": {
    "baseUrl": "http://localhost:3000",
    "allowedHosts": ["localhost", "127.0.0.1"],
    "disallowedPaths": [],
    "maxPages": 100,
    "maxDepth": 3,
    "maxRequests": 300,
    "requestDelayMs": 150,
    "timeoutMs": 10000,
    "safeMode": true
  },
  "rules": {
    "enabled": [],
    "disabled": [],
    "severityOverrides": {}
  },
  "authProfiles": {},
  "accessControlTests": [],
  "report": {
    "formats": ["json", "html", "markdown"],
    "outputDir": ".appsec"
  },
  "privacy": {
    "telemetry": false,
    "uploadCode": false,
    "redactSecrets": true
  }
}

Add schema validation with Zod.

4. Report formats

Implement:

- JSON report
- HTML report
- Markdown report
- SARIF report

SARIF is important for GitHub code scanning.

Report must include:
- scan metadata
- detected stack
- files scanned/ignored
- routes discovered
- findings by severity
- findings by OWASP category
- findings by rule pack
- top risky files
- top risky routes
- top recommended fixes
- static/runtime/auth sections
- redacted evidence
- confidence score
- finding fingerprints
- baseline status: new/existing/fixed if applicable

5. Dashboard

Polish the local dashboard.

Dashboard sections:

- Security Score
- Critical/High Findings
- OWASP Top 10 Coverage
- Secret Exposure
- Dependency/Supply Chain
- Static Code Risks
- Runtime Risks
- Access-Control Risks
- AI-Specific Risks
- Top Risky Files
- Top Risky Routes
- Recommended Fix Plan
- Scan History later placeholder

Features:
- filter by severity
- filter by OWASP category
- filter by engine
- search findings
- expand finding evidence
- copy fix recommendation
- export report
- all secrets redacted

6. Baseline and diffing

Implement:

appsec baseline create
appsec baseline compare

Baseline file:

.appsec/baseline.json

Behavior:
- baseline stores finding fingerprints
- compare marks findings as:
  - new
  - existing
  - fixed
- CI can fail only on new high/critical findings
- old accepted risks do not block CI unless configured

Finding fingerprint should be stable and based on:
- ruleId
- file
- route
- line bucket
- redacted evidence
- category

7. CI/CD integration

Add GitHub Actions support.

Create:

.github/workflows/appsec-scan.yml example

Example behavior:
- checkout code
- install scanner
- run appsec scan .
- generate SARIF
- upload SARIF to GitHub code scanning
- fail PR if high/critical findings exceed threshold

Also document:
- local scan
- PR scan
- baseline scan
- runtime scan in CI if app can be started

8. Package and release

Prepare npm packaging.

Requirements:
- package.json bin entry
- build command
- test command
- lint command
- typecheck command
- clean command
- version command
- README install instructions
- changelog
- license placeholder
- npm package name placeholder

Install command should eventually be:

npm install -g appsec-scanner-name

Run:

appsec scan .

9. Rule documentation generation

Generate documentation from rule metadata.

Create:

docs/rules.md

Include for every rule:
- rule ID
- rule name
- severity
- confidence
- engine
- OWASP mapping
- CWE mapping if available
- description
- insecure example
- safer example
- remediation
- false positive notes

Add command:

appsec rules docs

10. Scanner self-security

Harden the scanner itself.

Requirements:
- no telemetry by default
- no code upload by default
- no secret upload by default
- redaction tests mandatory
- never print raw secrets
- never save raw cookies/tokens in reports
- warn when auth profiles are configured
- warn when runtime target is not localhost/staging
- safeMode enabled by default
- external hosts blocked by default
- destructive methods blocked by default
- dependency audit for scanner package
- secure file permissions warning for .appsec/auth files

11. Performance

Add basic performance controls:
- max file size
- max total files
- ignored directories
- concurrent file parsing with safe limits
- timeout for runtime requests
- max runtime requests
- progress output in CLI
- summary timing per engine

Report timings:
- file inventory time
- static scan time
- secret scan time
- dependency scan time
- runtime scan time
- auth scan time
- report generation time

12. Testing strategy

Add tests for:

Core:
- config validation
- scanner pipeline
- file inventory
- stack detection
- file classification
- finding normalization
- deduplication
- scoring
- baseline diffing

Security:
- secret redaction
- no raw secrets in reports
- auth cookie redaction
- safeMode destructive blocking
- external host blocking

Rules:
- rule registry
- rule metadata validation
- rule config overrides
- OWASP mapping

Runtime:
- scope manager
- header analyzer
- cookie analyzer
- CORS analyzer
- redirect analyzer
- reflection analyzer

Auth:
- auth profile loader
- response comparator
- sensitive response analyzer

Reports:
- JSON output
- HTML output
- Markdown output
- SARIF output

13. Documentation

Create final documentation set:

README.md
SECURITY.md
CONTRIBUTING.md
docs/architecture.md
docs/configuration.md
docs/static-scanning.md
docs/secrets.md
docs/runtime-scanning.md
docs/auth-access-control-scanning.md
docs/rules.md
docs/ci.md
docs/safety-model.md
docs/roadmap.md

README should explain:
- what the scanner is
- who it is for
- local-first privacy model
- supported stacks
- install commands
- basic usage
- example report
- current limitations
- roadmap

14. Roadmap placeholders

Add roadmap but do not implement yet:

Future:
- VS Code extension
- Browser extension
- cloud dashboard opt-in
- signed remote rule updates
- custom organization policies
- SSO/team management
- deeper taint analysis
- deeper language support: Python, Go, Java, PHP
- Kubernetes/IaC scanning
- container image scanning
- API schema scanning from OpenAPI
- GraphQL-specific testing

15. Final acceptance criteria

The project is production-ready for initial release when:

- appsec scan . works on a real project
- secrets are redacted everywhere
- reports generate correctly
- rule metadata is documented
- CLI has stable commands and exit codes
- CI can run scanner and upload SARIF
- runtime scanner respects safe scope
- auth scanner requires explicit profiles
- tests pass
- README clearly explains limitations and safety model
