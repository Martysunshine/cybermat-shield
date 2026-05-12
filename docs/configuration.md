# Configuration Reference

CyberMat Shield reads configuration from `appsec.config.json` in the project root. Run `cybermat init` to create it.

---

## Full `appsec.config.json` schema

```json
{
  "$schema": "https://raw.githubusercontent.com/Martysunshine/cybermat-shield/main/schema/appsec-config.schema.json",
  "version": 1,

  "outputDir": ".appsec",
  "failOn": "high",

  "rules": {
    "disabled": [
      "secrets/generic-api-key"
    ],
    "enabled": [],
    "severityOverrides": {
      "supply-chain/wildcard-dependency": "high"
    }
  },

  "scan": {
    "maxFileSizeKb": 512,
    "skipDirs": ["node_modules", ".git", ".next", "dist", "build", "coverage"]
  },

  "runtime": {
    "maxPages": 20,
    "maxDepth": 3,
    "requestDelayMs": 150,
    "timeoutMs": 15000
  },

  "baseline": {
    "enabled": false,
    "failOnNew": true
  }
}
```

---

## Field reference

### Top-level

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `version` | `1` | required | Config schema version. Must be `1`. |
| `outputDir` | string | `.appsec` | Directory for report files |
| `failOn` | string | `high` | Minimum severity to exit with code 1. One of: `critical`, `high`, `medium`, `low`, `info`, `none` |

### `rules`

| Field | Type | Description |
|-------|------|-------------|
| `disabled` | string[] | Rule IDs to disable. See `cybermat rules list` for all IDs. |
| `enabled` | string[] | Rule IDs to enable (for rules disabled by default) |
| `severityOverrides` | `{[ruleId]: Severity}` | Override the severity of specific rules |

### `scan`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `maxFileSizeKb` | number | `512` | Skip files larger than this (kilobytes) |
| `skipDirs` | string[] | `["node_modules", ".git", ...]` | Directory names to skip entirely |

### `runtime`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `maxPages` | number | `20` | Maximum pages to crawl in `scan-runtime` |
| `maxDepth` | number | `3` | Maximum crawl depth |
| `requestDelayMs` | number | `150` | Delay between HTTP requests (ms) |
| `timeoutMs` | number | `15000` | Per-request timeout (ms) |

### `baseline`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable baseline comparison on every scan |
| `failOnNew` | boolean | `true` | Exit code 5 when new findings appear vs baseline |

---

## `.appsecignore`

Suppress findings by path, rule ID, or fingerprint:

```
# Ignore an entire directory
test/fixtures/

# Ignore a specific rule globally
rule:secrets/generic-api-key

# Ignore a specific finding fingerprint (from report.json)
fp:7a3f9b2c1d8e4a6b
```

Fingerprints are stable across runs for the same rule + file + line bucket. Copy them from `report.json → findings[n].id`.

---

## Auth config (`.appsec/auth-config.json`)

See [auth-access-control-scanning.md](auth-access-control-scanning.md) for the full auth config reference.

---

## Environment variables

| Variable | Description |
|----------|-------------|
| `APPSEC_OUTPUT_DIR` | Override `outputDir` without editing the config file |
| `APPSEC_FAIL_ON` | Override `failOn` for the current run |
| `NO_COLOR` | Disable chalk colors in terminal output |

---

## Validate your config

```bash
cybermat config validate
```

This parses the JSON, checks required fields, and reports any errors.
