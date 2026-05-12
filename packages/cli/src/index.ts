#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import * as path from 'path';
import * as fs from 'fs';
import type { ScanReport, Finding, Severity, RuleMetadata, RuleEngine, RuntimeScanReport, RuntimeFinding, AuthScanReport, AuthzFinding, AuthScanConfig } from '@cybermat/shared';
import { runScan, runRuntimeScan, runAuthScan } from '@cybermat/core';
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

// ── scan-runtime command ─────────────────────────────────────────────────────

function printRuntimeFinding(f: RuntimeFinding, index: number): void {
  const sev = SEVERITY_CHALK[f.severity](`[${f.severity.toUpperCase()}]`);
  console.log(`  ${chalk.gray(`${index}.`)} ${sev} ${chalk.white.bold(f.title)}`);
  if (f.url) console.log(`     ${chalk.gray('URL:')}      ${chalk.cyan(f.url)}`);
  if (f.headerName) console.log(`     ${chalk.gray('Header:')}   ${chalk.yellow(f.headerName)}`);
  if (f.cookieName) console.log(`     ${chalk.gray('Cookie:')}   ${chalk.yellow(f.cookieName)}`);
  if (f.owasp.length > 0) console.log(`     ${chalk.gray('OWASP:')}    ${chalk.green(f.owasp.join(', '))}`);
  const ev = f.evidence?.redactedSnippet ?? f.evidence?.snippet ?? f.evidence?.reason;
  if (ev) console.log(`     ${chalk.gray('Evidence:')} ${chalk.yellow(ev)}`);
  console.log(`     ${chalk.gray('Fix:')}      ${f.recommendation.slice(0, 100)}${f.recommendation.length > 100 ? '...' : ''}`);
  console.log('');
}

function printRuntimeReport(report: RuntimeScanReport): void {
  const { summary, riskScore, findings, pagesVisited, requestsMade, durationMs } = report;

  console.log(`  ${chalk.gray('Target:')}    ${chalk.white(report.targetUrl)}`);
  console.log(`  ${chalk.gray('Pages:')}     ${chalk.white(String(pagesVisited))} visited`);
  console.log(`  ${chalk.gray('Requests:')} ${chalk.white(String(requestsMade))} made`);
  console.log(`  ${chalk.gray('Duration:')} ${chalk.white(`${(durationMs / 1000).toFixed(1)}s`)}`);
  console.log('');
  console.log(chalk.gray('  ─────────────────────────────────────────────'));
  console.log('');

  if (findings.length === 0) {
    console.log(chalk.green.bold('  ✅  No runtime findings detected.'));
  } else {
    let idx = 1;
    for (const severity of SEVERITY_ORDER) {
      const group = findings.filter(f => f.severity === severity);
      if (group.length === 0) continue;
      console.log(`  ${SEVERITY_CHALK[severity](`${severity.toUpperCase()} (${group.length})`)}`);
      console.log('');
      for (const f of group) printRuntimeFinding(f as RuntimeFinding, idx++);
    }
  }

  console.log(chalk.gray('  ─────────────────────────────────────────────'));
  console.log('');

  const scoreColor = riskScore >= 70 ? chalk.green : riskScore >= 40 ? chalk.yellow : chalk.red;
  console.log(`  ${chalk.gray('Risk Score:')} ${scoreColor.bold(String(riskScore))} ${chalk.gray('/ 100')}`);

  const summaryParts = [
    summary.critical > 0 ? chalk.red.bold(`Critical: ${summary.critical}`) : '',
    summary.high > 0 ? chalk.red(`High: ${summary.high}`) : '',
    summary.medium > 0 ? chalk.yellow(`Medium: ${summary.medium}`) : '',
    summary.low > 0 ? chalk.blue(`Low: ${summary.low}`) : '',
    summary.info > 0 ? chalk.gray(`Info: ${summary.info}`) : '',
  ].filter(Boolean).join(chalk.gray(' | '));
  if (summaryParts) console.log(`  ${summaryParts}`);

  console.log('');

  if (report.topRecommendations.length > 0) {
    console.log(chalk.gray('  Top fixes:'));
    report.topRecommendations.slice(0, 3).forEach((r, i) => {
      console.log(`  ${chalk.gray(`${i + 1}.`)} ${r.slice(0, 100)}${r.length > 100 ? '...' : ''}`);
    });
    console.log('');
  }
}

program
  .command('scan-runtime <url>')
  .description('Safely scan a running application via HTTP and Playwright browser automation')
  .option('--max-pages <n>', 'Maximum pages to crawl', '20')
  .option('--max-depth <n>', 'Maximum crawl depth', '3')
  .option('--delay <ms>', 'Delay between requests in milliseconds', '150')
  .option('--timeout <ms>', 'Request timeout in milliseconds', '15000')
  .option('--json', 'Output full JSON report to stdout')
  .option('--no-browser', 'Skip Playwright browser crawl (HTTP probes only)')
  .action(async (url: string, opts: {
    maxPages: string; maxDepth: string; delay: string; timeout: string;
    json?: boolean; browser: boolean;
  }) => {
    printBanner();

    // Validate URL
    try { new URL(url); } catch {
      console.error(chalk.red(`  Error: Invalid URL: ${url}`));
      process.exit(2);
    }

    const isLocalOrStaging = url.includes('localhost') || url.includes('127.0.0.1') ||
      url.includes('.local') || url.includes('staging') || url.includes('test');
    if (!isLocalOrStaging) {
      console.log(chalk.yellow(`  Warning: Target does not appear to be localhost or staging.`));
      console.log(chalk.yellow(`  Only scan applications you are authorized to test.`));
      console.log('');
    }

    console.log(chalk.gray(`  Scanning runtime target: ${url}`));
    console.log(chalk.gray(`  Safe mode: GET/HEAD probes only + harmless markers`));
    console.log('');

    try {
      const report = await runRuntimeScan({
        baseUrl: url,
        maxPages: parseInt(opts.maxPages, 10),
        maxDepth: parseInt(opts.maxDepth, 10),
        requestDelayMs: parseInt(opts.delay, 10),
        timeoutMs: parseInt(opts.timeout, 10),
        safeMode: true,
      });

      if (opts.json) {
        process.stdout.write(JSON.stringify(report, null, 2));
        return;
      }

      printRuntimeReport(report);

      const hasCritical = report.summary.critical > 0;
      const hasHigh = report.summary.high > 0;
      process.exit(hasCritical || hasHigh ? 1 : 0);
    } catch (err) {
      console.error(chalk.red('  Runtime scan failed:'), err);
      process.exit(2);
    }
  });

// ── scan-auth command ────────────────────────────────────────────────────────

const AUTH_CONFIG_TEMPLATE: AuthScanConfig = {
  baseUrl: 'http://localhost:3000',
  profiles: {
    userA: {
      label: 'low-privileged-user-a',
      storageStatePath: '.appsec/auth/userA.storage.json',
    },
    userB: {
      label: 'low-privileged-user-b',
      storageStatePath: '.appsec/auth/userB.storage.json',
    },
    admin: {
      label: 'admin-user',
      storageStatePath: '.appsec/auth/admin.storage.json',
      isPrivileged: true,
    },
  },
  accessControlTests: [
    {
      name: 'User resource ownership',
      type: 'horizontal',
      userAOwns: ['/api/resources/resource-1'],
      userBOwns: ['/api/resources/resource-2'],
      shouldBePrivate: true,
    },
  ],
  maxAuthzRequests: 75,
  requestDelayMs: 150,
  timeoutMs: 10000,
};

function printAuthzFinding(f: AuthzFinding, index: number): void {
  const sev = SEVERITY_CHALK[f.severity](`[${f.severity.toUpperCase()}]`);
  console.log(`  ${chalk.gray(`${index}.`)} ${sev} ${chalk.white.bold(f.title)}`);
  if (f.url) console.log(`     ${chalk.gray('URL:')}     ${chalk.cyan(f.url)}`);
  if (f.profileUsed) console.log(`     ${chalk.gray('Profile:')} ${chalk.yellow(f.profileUsed)}`);
  if (f.targetProfileName) console.log(`     ${chalk.gray('Target:')}  ${chalk.yellow(f.targetProfileName)}`);
  if (f.owasp.length > 0) console.log(`     ${chalk.gray('OWASP:')}   ${chalk.green(f.owasp.join(', '))}`);
  if (f.evidence?.reason) console.log(`     ${chalk.gray('Detail:')}  ${chalk.yellow(f.evidence.reason)}`);
  if (f.staticCorrelation) {
    console.log(`     ${chalk.gray('Static:')}  ${chalk.cyan(f.staticCorrelation.file)} — ${f.staticCorrelation.reason}`);
  }
  console.log(`     ${chalk.gray('Fix:')}     ${f.recommendation.slice(0, 100)}${f.recommendation.length > 100 ? '...' : ''}`);
  console.log('');
}

function printAuthReport(report: AuthScanReport): void {
  const { summary, riskScore, findings, routesTested, resourcePairsTested, durationMs, profilesUsed } = report;

  console.log(`  ${chalk.gray('Target:')}         ${chalk.white(report.targetUrl)}`);
  console.log(`  ${chalk.gray('Profiles used:')}  ${chalk.cyan(profilesUsed.join(', '))}`);
  console.log(`  ${chalk.gray('Routes tested:')}  ${chalk.white(String(routesTested))}`);
  console.log(`  ${chalk.gray('IDOR pairs:')}     ${chalk.white(String(resourcePairsTested))}`);
  console.log(`  ${chalk.gray('Duration:')}       ${chalk.white(`${(durationMs / 1000).toFixed(1)}s`)}`);

  if (report.skippedDestructiveRoutes.length > 0) {
    console.log(`  ${chalk.gray('Skipped (destructive):')} ${chalk.gray(report.skippedDestructiveRoutes.slice(0, 3).join(', '))}${report.skippedDestructiveRoutes.length > 3 ? ' ...' : ''}`);
  }
  console.log('');
  console.log(chalk.gray('  ─────────────────────────────────────────────'));
  console.log('');

  if (findings.length === 0) {
    console.log(chalk.green.bold('  ✅  No access-control issues detected.'));
  } else {
    let idx = 1;
    for (const severity of SEVERITY_ORDER) {
      const group = findings.filter(f => f.severity === severity);
      if (group.length === 0) continue;
      console.log(`  ${SEVERITY_CHALK[severity](`${severity.toUpperCase()} (${group.length})`)}`);
      console.log('');
      for (const f of group) printAuthzFinding(f as AuthzFinding, idx++);
    }
  }

  console.log(chalk.gray('  ─────────────────────────────────────────────'));
  console.log('');

  const scoreColor = riskScore >= 70 ? chalk.green : riskScore >= 40 ? chalk.yellow : chalk.red;
  console.log(`  ${chalk.gray('Risk Score:')} ${scoreColor.bold(String(riskScore))} ${chalk.gray('/ 100')}`);

  const summaryParts = [
    summary.critical > 0 ? chalk.red.bold(`Critical: ${summary.critical}`) : '',
    summary.high > 0 ? chalk.red(`High: ${summary.high}`) : '',
    summary.medium > 0 ? chalk.yellow(`Medium: ${summary.medium}`) : '',
    summary.low > 0 ? chalk.blue(`Low: ${summary.low}`) : '',
    summary.info > 0 ? chalk.gray(`Info: ${summary.info}`) : '',
  ].filter(Boolean).join(chalk.gray(' | '));
  if (summaryParts) console.log(`  ${summaryParts}`);
  console.log('');

  if (report.recommendations.length > 0) {
    console.log(chalk.gray('  Recommended fixes:'));
    report.recommendations.slice(0, 4).forEach((r, i) => {
      console.log(`  ${chalk.gray(`${i + 1}.`)} ${r.slice(0, 100)}${r.length > 100 ? '...' : ''}`);
    });
    console.log('');
  }
}

program
  .command('scan-auth <url>')
  .description('Authenticated access-control scan (IDOR, vertical privilege, anonymous route testing)')
  .option('--config <path>', 'Path to auth config JSON', '.appsec/auth-config.json')
  .option('--json', 'Output full JSON report to stdout')
  .action(async (url: string, opts: { config: string; json?: boolean }) => {
    printBanner();

    try { new URL(url); } catch {
      console.error(chalk.red(`  Error: Invalid URL: ${url}`));
      process.exit(2);
    }

    const isLocal = url.includes('localhost') || url.includes('127.0.0.1') || url.includes('.local');
    if (!isLocal) {
      console.log(chalk.yellow(`  Warning: Target does not appear to be localhost.`));
      console.log(chalk.yellow(`  Only scan applications you own or have explicit permission to test.`));
      console.log('');
    }

    // Load config
    let config: AuthScanConfig;
    const configPath = path.resolve(opts.config);
    if (fs.existsSync(configPath)) {
      config = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as AuthScanConfig;
      config.baseUrl = url;
    } else {
      console.log(chalk.gray(`  No auth-config.json found. Using defaults (storageState files from .appsec/auth/).`));
      console.log(chalk.gray(`  Run "appsec auth init" to create a config template.`));
      console.log('');
      config = { ...AUTH_CONFIG_TEMPLATE, baseUrl: url };
    }

    console.log(chalk.gray(`  Scanning auth/access-control: ${url}`));
    console.log(chalk.gray(`  Safe mode: GET/HEAD only, no brute force, maxRequests=${config.maxAuthzRequests ?? 75}`));
    console.log('');

    try {
      const report = await runAuthScan(config);

      if (opts.json) {
        process.stdout.write(JSON.stringify(report, null, 2));
        return;
      }

      printAuthReport(report);

      // Save report
      const outputDir = path.resolve('.appsec');
      if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
      fs.writeFileSync(path.join(outputDir, 'auth-report.json'), JSON.stringify(report, null, 2));
      console.log(`  ${chalk.gray('Report saved:')} ${chalk.cyan(path.join(outputDir, 'auth-report.json'))}`);
      console.log('');

      process.exit(report.summary.critical > 0 || report.summary.high > 0 ? 1 : 0);
    } catch (err) {
      console.error(chalk.red('  Auth scan failed:'), err);
      process.exit(2);
    }
  });

// ── auth sub-commands ────────────────────────────────────────────────────────

const authCmd = program
  .command('auth')
  .description('Auth profile management for scan-auth');

authCmd
  .command('init')
  .description('Create .appsec/auth-config.json template')
  .action(() => {
    const outputDir = path.resolve('.appsec');
    const configPath = path.join(outputDir, 'auth-config.json');

    if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
    if (fs.existsSync(configPath)) {
      console.log(chalk.yellow(`  auth-config.json already exists: ${configPath}`));
      return;
    }

    fs.writeFileSync(configPath, JSON.stringify(AUTH_CONFIG_TEMPLATE, null, 2));
    console.log('');
    console.log(chalk.green('  ✅  Created .appsec/auth-config.json'));
    console.log('');
    console.log(chalk.gray('  Next steps:'));
    console.log(`  1. Edit ${chalk.cyan(configPath)} to set baseUrl and profile storageState paths`);
    console.log('  2. Export storageState for each user (see docs/auth-access-control-scanning.md)');
    console.log('     OR run: npx tsx --tsconfig scripts/tsconfig.json scripts/setup-auth-profiles.ts');
    console.log('  3. Run: appsec auth test-config');
    console.log('  4. Run: appsec scan-auth <url>');
    console.log('');
  });

authCmd
  .command('test-config')
  .description('Validate auth profiles and test connectivity to the target')
  .option('--config <path>', 'Path to auth config JSON', '.appsec/auth-config.json')
  .option('--url <url>', 'Target URL (overrides config baseUrl)')
  .action(async (opts: { config: string; url?: string }) => {
    console.log('');
    const configPath = path.resolve(opts.config);
    if (!fs.existsSync(configPath)) {
      console.error(chalk.red(`  auth-config.json not found: ${configPath}`));
      console.log(chalk.gray(`  Run "appsec auth init" to create a template.`));
      process.exit(1);
    }

    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as AuthScanConfig;
    const baseUrl = opts.url ?? config.baseUrl;

    console.log(chalk.cyan.bold('  Auth Config Validation'));
    console.log('');
    console.log(`  ${chalk.gray('Target:')} ${baseUrl}`);
    console.log(`  ${chalk.gray('Profiles:')}`);

    let hasErrors = false;

    for (const [name, profile] of Object.entries(config.profiles)) {
      const storagePath = profile.storageStatePath;
      if (storagePath) {
        const resolved = path.resolve(storagePath);
        if (fs.existsSync(resolved)) {
          const state = JSON.parse(fs.readFileSync(resolved, 'utf-8')) as { cookies?: unknown[] };
          const cookieCount = state.cookies?.length ?? 0;
          console.log(`    ${chalk.green('✓')} ${name.padEnd(12)} storageState — ${cookieCount} cookie(s)`);
        } else {
          console.log(`    ${chalk.red('✗')} ${name.padEnd(12)} storageState not found: ${resolved}`);
          hasErrors = true;
        }
      } else if (profile.cookies || profile.headers) {
        console.log(`    ${chalk.green('✓')} ${name.padEnd(12)} headers/cookies profile`);
      } else {
        console.log(`    ${chalk.yellow('~')} ${name.padEnd(12)} no credentials (anonymous)`);
      }
    }

    console.log('');

    // Test connectivity
    try {
      const res = await fetch(`${baseUrl}/api/auth/me`, { signal: AbortSignal.timeout(5000) });
      if (res.status === 401 || res.status === 200) {
        console.log(`  ${chalk.green('✓')} Target is reachable at ${baseUrl}`);
      } else {
        console.log(`  ${chalk.yellow('~')} Target responded with status ${res.status}`);
      }
    } catch {
      console.log(`  ${chalk.red('✗')} Cannot reach ${baseUrl} — make sure the app is running`);
      hasErrors = true;
    }

    console.log('');
    if (hasErrors) {
      console.log(chalk.red('  Validation failed. Fix the errors above before running scan-auth.'));
      process.exit(1);
    } else {
      console.log(chalk.green('  ✅  Auth config is valid. Run: appsec scan-auth <url>'));
    }
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
