# Contributing to CyberMat Shield

Thank you for considering a contribution. This is an open-source security tool — every improvement makes software safer for everyone.

---

## Ways to contribute

- **Bug reports** — open a GitHub issue with steps to reproduce
- **New rules** — add detectors for frameworks, patterns, or secrets not yet covered
- **False positive reduction** — improve existing rules to reduce noise
- **Documentation** — improve docs, fix typos, add examples
- **Tests** — add unit tests for edge cases
- **Integrations** — IDE plugins, CI integrations, new report formats

---

## Development setup

```bash
# Clone
git clone https://github.com/Martysunshine/cybermat-shield.git
cd cybermat-shield

# Install dependencies (requires pnpm)
pnpm install

# Build all packages
pnpm build

# Run unit tests
pnpm test

# Run the scanner on the example app
node packages/cli/dist/index.js scan examples/vulnerable-next-app

# Run the runtime scanner (requires Playwright)
npx playwright install chromium
cd examples/vulnerable-next-app && npx next dev &
node packages/cli/dist/index.js scan-runtime http://localhost:3000
```

---

## Adding a new rule

1. Identify which rule pack it belongs to (`packages/rules/src/packs/`)
2. Add a `RuleMetadata` object to the appropriate pack
3. Implement the detector in `packages/engines/src/` (or extend an existing one)
4. Map it to OWASP Top 10:2025 and at least one CWE
5. Add an `insecureExample` and `saferExample`
6. Add a test fixture to `examples/vulnerable-next-app/` if applicable
7. Run `cybermat rules docs` to regenerate `docs/rules.md`

### Rule metadata required fields

```typescript
{
  id: 'category/rule-name',           // kebab-case, unique
  name: 'Human readable name',
  description: 'What this detects and why it matters',
  engine: 'secrets' | 'static' | 'config' | 'dependency' | 'ai' | 'runtime' | 'authz',
  category: 'Category name',
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info',
  confidence: 'high' | 'medium' | 'low',
  owasp2025: ['A01:2025 — Broken Access Control'],   // at least one
  cwe: ['CWE-200'],
  tags: ['nextjs', 'auth'],
  enabledByDefault: true,
  safeForCI: true,
  requiresRuntime: false,
  requiresAuth: false,
  remediation: 'Step-by-step fix description',
  insecureExample: 'code snippet showing the vulnerable pattern',
  saferExample: 'code snippet showing the secure pattern',
}
```

---

## Pull request checklist

- [ ] New rules have `insecureExample`, `saferExample`, and OWASP mapping
- [ ] Changes do not break existing tests (`pnpm test`)
- [ ] Changes do not break the build (`pnpm build`)
- [ ] `cybermat scan examples/vulnerable-next-app` still produces expected findings
- [ ] No raw secrets in any committed file
- [ ] `docs/rules.md` regenerated if rules changed (`cybermat rules docs`)

---

## Security policy

Do not include real credentials, API keys, or secrets in any test fixtures or examples. The `examples/vulnerable-next-app` uses intentionally fake secrets specifically constructed to trigger detectors.

See [SECURITY.md](SECURITY.md) for how to responsibly disclose vulnerabilities in CyberMat Shield itself.

---

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
