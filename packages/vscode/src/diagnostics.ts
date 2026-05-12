import * as vscode from 'vscode';
import type { Finding } from '@cybermat/shared';

const SEVERITY_MAP: Record<string, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Warning,
  info: vscode.DiagnosticSeverity.Information,
};

export function findingsToDiagnostics(
  findings: Finding[],
  workspacePath: string,
): Map<string, vscode.Diagnostic[]> {
  const byFile = new Map<string, vscode.Diagnostic[]>();

  for (const f of findings) {
    if (!f.file) continue;

    const filePath =
      f.file.startsWith('/') || /^[A-Za-z]:/.test(f.file)
        ? f.file
        : `${workspacePath}/${f.file}`;

    const line = Math.max(0, (f.line ?? 1) - 1);
    const col = Math.max(0, (f.column ?? 1) - 1);
    const range = new vscode.Range(line, col, line, col + 100);

    const message = `[${f.severity.toUpperCase()}] ${f.title}: ${f.evidence.reason}`;
    const diag = new vscode.Diagnostic(
      range,
      message,
      SEVERITY_MAP[f.severity] ?? vscode.DiagnosticSeverity.Warning,
    );
    diag.source = 'CyberMat Shield';
    diag.code = {
      value: f.ruleId,
      target: vscode.Uri.parse(
        `https://github.com/Martysunshine/cybermat-shield/blob/master/docs/rules.md`,
      ),
    };

    const existing = byFile.get(filePath) ?? [];
    existing.push(diag);
    byFile.set(filePath, existing);
  }

  return byFile;
}
