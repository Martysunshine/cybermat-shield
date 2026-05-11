#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import * as path from 'path';
import * as fs from 'fs';
import type { ScanReport, Finding, Severity } from '@cybermat/shared';
import { runScan } from '@cybermat/core';
import { allRules } from '@cybermat/rules';

const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf-8')) as { version: string };

const SEVERITY_CHALK: Record<Severity, (s: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: (s: string) => chalk.red.bold(s),
  medium: (s: string) => chalk.yellow(s),
  low: (s: string) => chalk.blue(s),
  info: (s: string) => chalk.gray(s),
};

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function printBanner(): void {
  console.log('');
  console.log(chalk.cyan.bold('╔══════════════════════════════════════════════╗'));
  console.log(chalk.cyan.bold('║') + chalk.white.bold('  🛡️  CyberMat Shield — Security Scanner     ') + chalk.cyan.bold('║'));
  console.log(chalk.cyan.bold('╚══════════════════════════════════════════════╝'));
  console.log('');
}

function printFinding(f: Finding, index: number): void {
  const sev = SEVERITY_CHALK[f.severity](`[${f.severity.toUpperCase()}]`);
  console.log(`  ${chalk.gray(`${index}.`)} ${sev} ${chalk.white.bold(f.title)}`);

  if (f.file) {
    const loc = f.line ? `${f.file}:${f.line}` : f.file;
    console.log(`     ${chalk.gray('File:')} ${chalk.cyan(loc)}`);
  }

  if (f.owasp.length > 0) {
    console.log(`     ${chalk.gray('OWASP:')} ${chalk.green(f.owasp.join(', '))}`);
  }

  if (f.evidence) {
    console.log(`     ${chalk.gray('Evidence:')} ${chalk.yellow(f.evidence)}`);
  }

  console.log(`     ${chalk.gray('Fix:')} ${f.recommendation.slice(0, 100)}${f.recommendation.length > 100 ? '...' : ''}`);
  console.log('');
}

function printReport(report: ScanReport): void {
  const { summary, riskScore, detectedStack, findings, filesScanned, filesIgnored } = report;

  // Scan info
  const stackStr = [
    ...detectedStack.frameworks,
    ...detectedStack.databases.slice(0, 2),
    ...detectedStack.authProviders.slice(0, 2),
  ].join(', ') || 'Unknown';

  console.log(`  ${chalk.gray('Target:')}  ${chalk.white(report.scannedPath)}`);
  console.log(`  ${chalk.gray('Files:')}   ${chalk.white(String(filesScanned))} scanned, ${chalk.gray(String(filesIgnored))} ignored`);
  console.log(`  ${chalk.gray('Stack:')}   ${chalk.cyan(stackStr)}`);
  console.log('');
  console.log(chalk.gray('  ─────────────────────────────────────────────'));
  console.log('');

  if (findings.length === 0) {
    console.log(chalk.green.bold('  ✅  No findings detected. Looking good!'));
  } else {
    let idx = 1;
    for (const severity of SEVERITY_ORDER) {
      const group = findings.filter(f => f.severity === severity);
      if (group.length === 0) continue;

      const heading = SEVERITY_CHALK[severity](`${severity.toUpperCase()} (${group.length})`);
      console.log(`  ${heading}`);
      console.log('');
      for (const f of group) {
        printFinding(f, idx++);
      }
    }
  }

  console.log(chalk.gray('  ─────────────────────────────────────────────'));
  console.log('');

  // Score
  const scoreColor = riskScore >= 70 ? chalk.green : riskScore >= 40 ? chalk.yellow : riskScore >= 20 ? chalk.red : chalk.bgRed.white;
  console.log(`  ${chalk.gray('Risk Score:')} ${scoreColor.bold(String(riskScore))} ${chalk.gray('/ 100')}`);

  // Summary
  const summaryParts = [
    summary.critical > 0 ? chalk.red.bold(`Critical: ${summary.critical}`) : '',
    summary.high > 0 ? chalk.red(`High: ${summary.high}`) : '',
    summary.medium > 0 ? chalk.yellow(`Medium: ${summary.medium}`) : '',
    summary.low > 0 ? chalk.blue(`Low: ${summary.low}`) : '',
    summary.info > 0 ? chalk.gray(`Info: ${summary.info}`) : '',
  ].filter(Boolean).join(chalk.gray(' | '));

  if (summaryParts) {
    console.log(`  ${summaryParts}`);
  }

  console.log('');

  if (report.topRecommendations.length > 0) {
    console.log(chalk.gray('  Top recommended fixes:'));
    report.topRecommendations.slice(0, 3).forEach((rec, i) => {
      console.log(`  ${chalk.gray(`${i + 1}.`)} ${rec.slice(0, 100)}${rec.length > 100 ? '...' : ''}`);
    });
    console.log('');
  }

  const outputDir = path.join(report.scannedPath, '.appsec');
  console.log(`  ${chalk.gray('Reports saved:')}`);
  console.log(`    ${chalk.cyan(path.join(outputDir, 'report.json'))}`);
  console.log(`    ${chalk.cyan(path.join(outputDir, 'report.html'))}`);
  console.log('');
}

const program = new Command();

program
  .name('appsec')
  .description('CyberMat Shield — Local-first Application Security Scanner')
  .version(pkg.version);

program
  .command('scan <path>')
  .description('Scan a project directory for security issues')
  .option('--json', 'Output full JSON report to stdout')
  .option('--html', 'Open HTML report after scan (not yet implemented)')
  .option('--output-dir <dir>', 'Output directory for reports', '.appsec')
  .action(async (targetPath: string, opts: { json?: boolean; html?: boolean; outputDir?: string }) => {
    printBanner();

    const absolutePath = path.resolve(targetPath);
    if (!fs.existsSync(absolutePath)) {
      console.error(chalk.red(`  Error: Path not found: ${absolutePath}`));
      process.exit(2);
    }

    console.log(chalk.gray('  Scanning...'));
    console.log('');

    try {
      const report = await runScan(absolutePath, allRules, {
        outputDir: opts.outputDir,
      });

      if (opts.json) {
        process.stdout.write(JSON.stringify(report, null, 2));
        return;
      }

      printReport(report);

      const hasCritical = report.summary.critical > 0;
      const hasHigh = report.summary.high > 0;
      process.exit(hasCritical || hasHigh ? 1 : 0);

    } catch (err) {
      console.error(chalk.red('  Scan failed:'), err);
      process.exit(2);
    }
  });

program
  .command('dashboard')
  .description('Open the security dashboard (Phase 8)')
  .action(() => {
    console.log(chalk.yellow('  Dashboard coming in Phase 8. For now, open .appsec/report.html in your browser.'));
  });

program.parse(process.argv);
