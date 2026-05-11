#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import * as path from 'path';
import * as fs from 'fs';
import type { ScanReport, Finding, Severity, RuleMetadata, RuleEngine } from '@cybermat/shared';
import { runScan } from '@cybermat/core';
import { allRules, defaultRegistry } from '@cybermat/rules';

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
    const ev = f.evidence.redactedSnippet ?? f.evidence.snippet ?? f.evidence.reason;
    console.log(`     ${chalk.gray('Evidence:')} ${chalk.yellow(ev)}`);
    if (f.evidence.redactedMatch) {
      console.log(`     ${chalk.gray('Match:')}    ${chalk.yellow(f.evidence.redactedMatch)}`);
    }
  }

  console.log(`     ${chalk.gray('Fix:')} ${f.recommendation.slice(0, 100)}${f.recommendation.length > 100 ? '...' : ''}`);
  console.log('');
}

function printReport(report: ScanReport): void {
  const { summary, riskScore, detectedStack, findings, filesScanned, filesIgnored } = report;

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

  const scoreColor = riskScore >= 70 ? chalk.green : riskScore >= 40 ? chalk.yellow : riskScore >= 20 ? chalk.red : chalk.bgRed.white;
  console.log(`  ${chalk.gray('Risk Score:')} ${scoreColor.bold(String(riskScore))} ${chalk.gray('/ 100')}`);

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

// ─── Rules docs generator ──────────────────────────────────────────────────

function generateRulesDocs(rules: RuleMetadata[]): string {
  const byEngine = new Map<string, RuleMetadata[]>();
  for (const rule of rules) {
    if (!byEngine.has(rule.engine)) byEngine.set(rule.engine, []);
    byEngine.get(rule.engine)!.push(rule);
  }

  const engineOrder: RuleEngine[] = ['secrets', 'static', 'config', 'dependency', 'ai', 'runtime', 'authz'];
  const engineNames: Record<string, string> = {
    secrets: 'Secret Detection',
    static: 'Static Code Analysis',
    config: 'Configuration',
    dependency: 'Supply Chain',
    ai: 'AI Security',
    runtime: 'Runtime Scanner (Phase 6)',
    authz: 'Auth/Access Control Scanner (Phase 7)',
  };

  const lines: string[] = [
    '# CyberMat Shield — Security Rules Reference',
    '',
    `> Generated from rule registry. **${rules.length} rules** across ${byEngine.size} engines.`,
    '',
    '## Quick Reference',
    '',
    '| Rule ID | Severity | Engine | OWASP |',
    '|---------|----------|--------|-------|',
    ...rules.map(r =>
      `| \`${r.id}\` | ${r.severity} | ${r.engine} | ${r.owasp2025.join(', ')} |`
    ),
    '',
  ];

  for (const engine of engineOrder) {
    const engineRules = byEngine.get(engine);
    if (!engineRules || engineRules.length === 0) continue;

    lines.push(`## ${engineNames[engine] ?? engine} (\`${engine}\`)`);
    lines.push('');

    for (const rule of engineRules) {
      lines.push(`### \`${rule.id}\``);
      lines.push('');
      lines.push(`**${rule.name}**`);
      lines.push('');
      lines.push(`> ${rule.description}`);
      lines.push('');
      lines.push(`| Field | Value |`);
      lines.push(`|-------|-------|`);
      lines.push(`| Severity | \`${rule.severity}\` |`);
      lines.push(`| Confidence | \`${rule.confidence}\` |`);
      lines.push(`| Engine | \`${rule.engine}\` |`);
      lines.push(`| Category | ${rule.category} |`);
      lines.push(`| Enabled by default | ${rule.enabledByDefault ? 'Yes' : 'No'} |`);
      lines.push(`| Safe for CI | ${rule.safeForCI ? 'Yes' : 'No'} |`);
      lines.push(`| Requires runtime | ${rule.requiresRuntime ? 'Yes' : 'No'} |`);
      lines.push(`| Requires auth config | ${rule.requiresAuth ? 'Yes' : 'No'} |`);
      lines.push('');

      if (rule.owasp2025.length > 0) {
        lines.push(`**OWASP Top 10:2025:** ${rule.owasp2025.join(', ')}`);
        lines.push('');
      }
      if (rule.cwe && rule.cwe.length > 0) {
        lines.push(`**CWE:** ${rule.cwe.join(', ')}`);
        lines.push('');
      }
      if (rule.asvs && rule.asvs.length > 0) {
        lines.push(`**ASVS:** ${rule.asvs.join(', ')}`);
        lines.push('');
      }
      if (rule.wstg && rule.wstg.length > 0) {
        lines.push(`**WSTG:** ${rule.wstg.join(', ')}`);
        lines.push('');
      }
      if (rule.tags.length > 0) {
        lines.push(`**Tags:** ${rule.tags.map(t => `\`${t}\``).join(' ')}`);
        lines.push('');
      }
      if (rule.insecureExample) {
        lines.push('**Insecure Example:**');
        lines.push('```');
        lines.push(rule.insecureExample);
        lines.push('```');
        lines.push('');
      }
      if (rule.saferExample) {
        lines.push('**Safer Example:**');
        lines.push('```');
        lines.push(rule.saferExample);
        lines.push('```');
        lines.push('');
      }
      lines.push(`**Remediation:** ${rule.remediation}`);
      lines.push('');
      if (rule.falsePositiveNotes) {
        lines.push(`**False Positive Notes:** ${rule.falsePositiveNotes}`);
        lines.push('');
      }
      lines.push('---');
      lines.push('');
    }
  }

  return lines.join('\n');
}

// ─── CLI setup ────────────────────────────────────────────────────────────

const program = new Command();

program
  .name('appsec')
  .description('CyberMat Shield — Local-first Application Security Scanner')
  .version(pkg.version);

// ── scan command ────────────────────────────────────────────────────────────
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

// ── rules command group ──────────────────────────────────────────────────────
const rulesCmd = program
  .command('rules')
  .description('Inspect and manage security rules');

rulesCmd
  .command('list')
  .description('List all security rules')
  .option('--owasp <code>', 'Filter by OWASP Top 10:2025 category code (e.g. A05)')
  .option('--engine <engine>', 'Filter by engine (secrets, static, config, dependency, ai, runtime, authz)')
  .option('--tag <tag>', 'Filter by tag (e.g. nextjs, xss, jwt)')
  .action((opts: { owasp?: string; engine?: string; tag?: string }) => {
    let rules = defaultRegistry.listRules();

    if (opts.owasp) {
      rules = defaultRegistry.getRulesByOwasp(opts.owasp);
    }
    if (opts.engine) {
      rules = rules.filter(r => r.engine === opts.engine);
    }
    if (opts.tag) {
      rules = rules.filter(r => r.tags.some(t => t.toLowerCase() === opts.tag!.toLowerCase()));
    }

    if (rules.length === 0) {
      console.log(chalk.yellow('  No rules match the given filters.'));
      return;
    }

    console.log('');
    console.log(`  ${chalk.cyan.bold(`${rules.length} rules`)}\n`);

    const bySeverity = new Map<Severity, RuleMetadata[]>();
    for (const rule of rules) {
      if (!bySeverity.has(rule.severity)) bySeverity.set(rule.severity, []);
      bySeverity.get(rule.severity)!.push(rule);
    }

    for (const sev of SEVERITY_ORDER) {
      const group = bySeverity.get(sev);
      if (!group) continue;
      console.log(SEVERITY_CHALK[sev](`  ${sev.toUpperCase()} (${group.length})`));
      for (const r of group) {
        const enabled = defaultRegistry.isEnabled(r.id) ? chalk.green('●') : chalk.red('○');
        console.log(`  ${enabled} ${chalk.white(r.id.padEnd(50))} ${chalk.gray(r.engine.padEnd(12))} ${chalk.cyan(r.owasp2025[0] ?? '')}`);
      }
      console.log('');
    }
  });

rulesCmd
  .command('show <ruleId>')
  .description('Show full details for a specific rule')
  .action((ruleId: string) => {
    const rule = defaultRegistry.getRuleById(ruleId);
    if (!rule) {
      console.error(chalk.red(`  Rule not found: ${ruleId}`));
      console.log(chalk.gray(`  Run "appsec rules list" to see all available rule IDs.`));
      process.exit(1);
    }

    console.log('');
    console.log(chalk.cyan.bold(`  ${rule.id}`));
    console.log(`  ${chalk.white.bold(rule.name)}`);
    console.log('');
    console.log(`  ${chalk.gray('Description:')} ${rule.description}`);
    console.log('');
    console.log(`  ${chalk.gray('Severity:')}    ${SEVERITY_CHALK[rule.severity](rule.severity.toUpperCase())}`);
    console.log(`  ${chalk.gray('Confidence:')} ${rule.confidence}`);
    console.log(`  ${chalk.gray('Engine:')}     ${rule.engine}`);
    console.log(`  ${chalk.gray('Category:')}   ${rule.category}`);
    console.log(`  ${chalk.gray('Enabled:')}    ${defaultRegistry.isEnabled(rule.id) ? chalk.green('yes') : chalk.red('no (disabled)')}`);
    console.log('');
    if (rule.owasp2025.length > 0) {
      console.log(`  ${chalk.gray('OWASP 2025:')} ${chalk.green(rule.owasp2025.join(', '))}`);
    }
    if (rule.cwe && rule.cwe.length > 0) {
      console.log(`  ${chalk.gray('CWE:')}        ${rule.cwe.join(', ')}`);
    }
    if (rule.asvs && rule.asvs.length > 0) {
      console.log(`  ${chalk.gray('ASVS:')}       ${rule.asvs.join(', ')}`);
    }
    if (rule.wstg && rule.wstg.length > 0) {
      console.log(`  ${chalk.gray('WSTG:')}       ${rule.wstg.join(', ')}`);
    }
    if (rule.tags.length > 0) {
      console.log(`  ${chalk.gray('Tags:')}       ${rule.tags.join(', ')}`);
    }
    console.log('');
    console.log(`  ${chalk.gray('Remediation:')}`);
    console.log(`  ${rule.remediation}`);
    if (rule.falsePositiveNotes) {
      console.log('');
      console.log(`  ${chalk.gray('False positive notes:')}`);
      console.log(`  ${rule.falsePositiveNotes}`);
    }
    if (rule.insecureExample) {
      console.log('');
      console.log(`  ${chalk.red('Insecure example:')}`);
      rule.insecureExample.split('\n').forEach(l => console.log(`    ${chalk.gray(l)}`));
    }
    if (rule.saferExample) {
      console.log('');
      console.log(`  ${chalk.green('Safer example:')}`);
      rule.saferExample.split('\n').forEach(l => console.log(`    ${chalk.gray(l)}`));
    }
    console.log('');
  });

rulesCmd
  .command('docs')
  .description('Generate docs/rules.md from rule registry metadata')
  .option('--output <path>', 'Output file path', 'docs/rules.md')
  .action((opts: { output: string }) => {
    const rules = defaultRegistry.listRules();
    const markdown = generateRulesDocs(rules);

    const outputPath = path.resolve(opts.output);
    const outputDir = path.dirname(outputPath);

    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    fs.writeFileSync(outputPath, markdown, 'utf-8');

    console.log('');
    console.log(chalk.green(`  ✅  docs/rules.md generated — ${rules.length} rules documented`));
    console.log(`  ${chalk.cyan(outputPath)}`);
    console.log('');
  });

// ── dashboard command ────────────────────────────────────────────────────────
program
  .command('dashboard')
  .description('Open the security dashboard (Phase 8)')
  .action(() => {
    console.log(chalk.yellow('  Dashboard coming in Phase 8. For now, open .appsec/report.html in your browser.'));
  });

program.parse(process.argv);
