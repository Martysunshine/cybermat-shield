import * as vscode from 'vscode';
import { runScan } from '@cybermat/core';
import { allRules } from '@cybermat/rules';
import { findingsToDiagnostics } from './diagnostics';

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBar: vscode.StatusBarItem;
let debounceTimer: ReturnType<typeof setTimeout> | undefined;
let scanning = false;

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection = vscode.languages.createDiagnosticCollection('cybermat');
  context.subscriptions.push(diagnosticCollection);

  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.command = 'cybermat.scan';
  statusBar.text = '$(shield) CyberMat';
  statusBar.tooltip = 'Click to scan workspace';
  statusBar.show();
  context.subscriptions.push(statusBar);

  context.subscriptions.push(
    vscode.commands.registerCommand('cybermat.scan', () => void scanWorkspace()),
    vscode.commands.registerCommand('cybermat.clear', () => {
      diagnosticCollection.clear();
      statusBar.text = '$(shield) CyberMat';
      statusBar.tooltip = 'Click to scan workspace';
    }),
    vscode.workspace.onDidSaveTextDocument(() => {
      const cfg = vscode.workspace.getConfiguration('cybermat');
      if (!cfg.get<boolean>('scanOnSave', true)) return;
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => void scanWorkspace(), 2000);
    }),
  );

  const cfg = vscode.workspace.getConfiguration('cybermat');
  if (cfg.get<boolean>('scanOnOpen', true)) {
    void scanWorkspace();
  }
}

async function scanWorkspace(): Promise<void> {
  if (scanning) return;

  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showWarningMessage('CyberMat Shield: No workspace folder open.');
    return;
  }

  const workspacePath = folders[0].uri.fsPath;
  scanning = true;
  statusBar.text = '$(loading~spin) CyberMat: Scanning…';
  statusBar.tooltip = 'Scanning for security issues…';

  try {
    const report = await runScan(workspacePath, allRules, {});
    const byFile = findingsToDiagnostics(report.findings, workspacePath);

    diagnosticCollection.clear();
    for (const [filePath, diags] of byFile) {
      diagnosticCollection.set(vscode.Uri.file(filePath), diags);
    }

    const { critical, high, medium, low, total } = report.summary;
    const icon =
      critical > 0 ? '$(error)' : high > 0 ? '$(warning)' : '$(pass-filled)';
    statusBar.text = `${icon} CyberMat: ${total} finding${total !== 1 ? 's' : ''}`;
    statusBar.tooltip =
      `Critical: ${critical}  High: ${high}  Medium: ${medium}  Low: ${low}` +
      `\nRisk score: ${report.riskScore}/100` +
      `\nClick to re-scan`;
  } catch (err) {
    statusBar.text = '$(error) CyberMat: Scan failed';
    statusBar.tooltip = 'Click to retry';
    vscode.window.showErrorMessage(
      `CyberMat Shield scan failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  } finally {
    scanning = false;
  }
}

export function deactivate(): void {
  diagnosticCollection?.dispose();
  statusBar?.dispose();
}
