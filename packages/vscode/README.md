# CyberMat Shield — VS Code Extension

Inline security findings in your editor. Secrets, XSS, injection, IDOR patterns — underlined as you work. No cloud. No telemetry.

## Features

- **Inline diagnostics** — red/yellow underlines on findings, hover for details and rule ID
- **Status bar** — live finding count and risk score, click to re-scan
- **Auto-scan on save** — rescans 2 seconds after you save any file
- **Auto-scan on open** — scans when a workspace is first opened

## Testing locally (F5 in VS Code)

```bash
# 1. Build the monorepo
pnpm build

# 2. Open the repo in VS Code, then press F5
#    This launches the Extension Development Host with the extension loaded

# 3. In the new VS Code window, open any project (e.g. examples/vulnerable-next-app)
#    The extension auto-scans on open — findings appear as diagnostics
```

## Commands

| Command | What it does |
|---|---|
| `CyberMat: Scan Workspace` | Run a full scan now |
| `CyberMat: Clear Findings` | Remove all diagnostics |

## Settings

| Setting | Default | Description |
|---|---|---|
| `cybermat.scanOnSave` | `true` | Re-scan 2s after every save |
| `cybermat.scanOnOpen` | `true` | Scan when workspace opens |

## Publishing to the VS Code Marketplace

```bash
# Install vsce (one-time)
npm install -g @vscode/vsce

# Package the extension
cd packages/vscode
vsce package --no-dependencies

# Publish (requires a PAT from marketplace.visualstudio.com)
vsce publish --no-dependencies
```
