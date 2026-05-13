# CI / CD Integration

CyberMat Shield is designed to run in CI pipelines with zero configuration for basic static scanning.

---

## GitHub Actions (recommended)

The repo ships a ready-to-use workflow at `.github/workflows/cybermat-scan.yml`.

It automatically:
1. Runs `cybermat scan .` on every push and pull request
2. Uploads a **SARIF** report to the GitHub Security tab (Code Scanning)
3. Posts a **findings summary comment** on every pull request
4. Uploads JSON / HTML / Markdown reports as **Actions artifacts**
5. Fails the job if critical or high severity findings are detected

To enable it, just push the workflow file to your repository. No configuration required.

### GitHub Code Scanning setup

The workflow requires the `security-events: write` permission (already in the workflow file). To see findings in the Security tab:

1. Go to your repo → **Security** → **Code scanning**
2. After the first workflow run, findings appear automatically
3. Each finding links to the exact file and line

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no findings at or above the threshold |
| `1` | Findings detected at or above `--fail-on` severity |
| `2` | Scan error (invalid path, build failure, runtime error) |
| `3` | Config or validation error |
| `4` | Missing dependency (Playwright, pnpm, Node) |
| `5` | New findings vs baseline in `--ci` mode |

---

## Basic CI (any CI system)

```bash
# Install
npm install -g pnpm
pnpm install --frozen-lockfile
pnpm build

# Scan
node packages/cli/dist/index.js scan . --sarif --output-dir .cybermat

# Exit code 0 = clean, 1 = findings, 2 = error
echo "Exit: $?"
```

Or, once published to npm:
```bash
npx cybermat scan . --sarif
```

---

## Baseline diffing (fail only on new issues)

This is the recommended CI mode for teams that have existing findings they haven't fixed yet.

### Step 1 — Create a baseline

After your first clean scan, commit the baseline:

```bash
node packages/cli/dist/index.js scan .
node packages/cli/dist/index.js baseline create
git add .cybermat/baseline.json
git commit -m "chore: add cybermat baseline"
```

### Step 2 — Use --ci mode in subsequent scans

```bash
node packages/cli/dist/index.js scan . --ci
```

- Exit code `5` if any **new** findings appear (not in baseline)
- Exit code `0` if all findings were already in the baseline
- Fixed findings are logged but don't affect the exit code

### Step 3 — Update the baseline when you fix issues

```bash
# After fixing findings, run the scan and update the baseline
node packages/cli/dist/index.js scan .
node packages/cli/dist/index.js baseline create
git add .cybermat/baseline.json
git commit -m "chore: update cybermat baseline (fixed N findings)"
```

---

## Fail threshold configuration

Control when CI fails using `--fail-on`:

```bash
# Fail only on critical (most lenient)
cybermat scan . --fail-on critical

# Fail on high or above (default)
cybermat scan . --fail-on high

# Fail on medium or above (strictest for security teams)
cybermat scan . --fail-on medium

# Never fail CI regardless of findings
cybermat scan . --fail-on none
```

Or set it permanently in `cybermat.config.json`:
```json
{
  "failOn": "high"
}
```

---

## SARIF upload (other CI systems)

Any CI system that supports SARIF can import findings:

- **Azure DevOps** — use the [SARIF SAST Scans Tab](https://marketplace.visualstudio.com/items?itemName=sariftools.scans) extension
- **GitLab** — use `artifacts: reports: sast` in `.gitlab-ci.yml`
- **Semgrep cybermat Platform** — import via SARIF upload API
- **Defect Dojo** — import SARIF via the REST API

```bash
cybermat scan . --sarif
# Produces .cybermat/report.sarif
```

---

## Example: GitLab CI

```yaml
cybermat-scan:
  image: node:22
  stage: test
  script:
    - npm install -g pnpm
    - pnpm install --frozen-lockfile
    - pnpm build
    - node packages/cli/dist/index.js scan . --sarif --fail-on high
  artifacts:
    reports:
      sast: .cybermat/report.sarif
    paths:
      - .cybermat/
    when: always
```

---

## Performance

| Project size | Scan time |
|---|---|
| < 500 files | < 5 seconds |
| 500–2000 files | 5–20 seconds |
| > 2000 files | 20–60 seconds |

Large monorepos: scan only the changed package using `cybermat scan packages/my-package`.

The runtime scanner (`scan-runtime`) takes 30–120 seconds depending on the number of pages crawled.
