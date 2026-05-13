#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import * as childProcess from 'child_process';
import { Worker } from 'worker_threads';
import type {
  ScanReport, Finding, Severity, RuleMetadata, RuleEngine,
  RuntimeScanReport, RuntimeFinding, AuthScanReport, AuthzFinding, AuthScanConfig,
} from '@cybermat/shared';
import {
  runScan, runRuntimeScan, runAuthScan,
  generateSarif, generateMarkdown, writeReports,
  createBaseline, compareToBaseline, saveBaseline, loadBaseline,
} from '@cybermat/core';
import type { BaselineDiff } from '@cybermat/core';
import { allRules, defaultRegistry } from '@cybermat/rules';

// ─── Exit codes ──────────────────────────────────────────────────────────────
// 0 = clean / success
// 1 = critical or high findings detected
// 2 = scan / runtime error
// 3 = config / validation error
// 4 = missing dependency (doctor)
// 5 = new findings compared to baseline (CI mode)

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

function printReport(report: ScanReport, diff?: BaselineDiff): void {
  const { summary, riskScore, detectedStack, findings, filesScanned, filesIgnored } = report;

  const stackStr = [
    ...detectedStack.frameworks,
    ...detectedStack.databases.slice(0, 2),
    ...detectedStack.authProviders.slice(0, 2),
  ].join(', ') || 'Unknown';

  console.log(`  ${chalk.gray('Target:')}  ${chalk.white(report.scannedPath)}`);
  console.log(`  ${chalk.gray('Files:')}   ${chalk.white(String(filesScanned))} scanned, ${chalk.gray(String(filesIgnored))} ignored`);

  const coverage = report.metadata?.coverage;
  if (coverage) {
    const topLangs = Object.entries(coverage.filesByLanguage)
      .filter(([lang]) => lang !== 'unknown')
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([lang, count]) => `${lang} ${count}`)
      .join(chalk.gray(', '));
    if (topLangs) {
      console.log(`  ${chalk.gray('Languages:')} ${chalk.cyan(topLangs)}`);
    }
  }

  console.log(`  ${chalk.gray('Stack:')}   ${chalk.cyan(stackStr)}`);

  if (diff) {
    console.log(`  ${chalk.gray('Baseline:')} ${chalk.green(`${diff.summary.existing} existing`)} ${chalk.red(`${diff.summary.new} new`)} ${chalk.gray(`${diff.summary.fixed} fixed`)}`);
  }

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
        const isNew = diff ? diff.newFindings.some(n => n.id === f.id) : false;
        if (isNew) process.stdout.write(chalk.yellow('  ★ NEW  '));
        printFinding(f, idx++);
      }
    }
  }

  console.log(chalk.gray('  ─────────────────────────────────────────────'));
  console.log('');

  const scoreColor = riskScore >= 70 ? chalk.green : riskScore >= 40 ? chalk.yellow : riskScore >= 20 ? chalk.red : chalk.bgRed.white;
  const scoreLabel = riskScore >= 70 ? chalk.green('Secure') : riskScore >= 40 ? chalk.yellow('Low Risk') : riskScore >= 20 ? chalk.red('High Risk') : chalk.bgRed.white('Critical Risk');
  console.log(`  ${chalk.gray('Risk Score:')} ${scoreColor.bold(String(riskScore))} ${chalk.gray('/ 100')}  ${scoreLabel}`);

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

  const outputDir = path.join(report.scannedPath, '.cybermat');
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
    runtime: 'Runtime Scanner',
    authz: 'Auth/Access Control Scanner',
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

// ─── Progress Spinner (worker-thread based) ──────────────────────────────────
// Runs in a separate thread so it keeps spinning even when the main thread is
// blocked by synchronous rule execution (regex over thousands of files).

const SPINNER_WORKER_CODE = `
const { parentPort } = require('worker_threads');
const FRAMES = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏'];
let frameIdx = 0;
const startMs = Date.now();
let msg = '';
let pct = 0;
let active = false;
setInterval(() => {
  if (!active) return;
  const elapsed = ((Date.now() - startMs) / 1000).toFixed(1);
  const frame = FRAMES[frameIdx++ % FRAMES.length];
  process.stderr.write('\\r  ' + frame + ' ' + msg.padEnd(46) + ' \\x1b[36m' + String(pct).padStart(3) + '%\\x1b[0m   [' + elapsed + 's]');
}, 80);
parentPort.on('message', (m) => {
  if (m.type === 'start') {
    active = true; msg = m.msg; pct = m.pct ?? 0;
  } else if (m.type === 'update') {
    msg = m.msg; if (m.pct !== undefined) pct = m.pct;
  } else if (m.type === 'done') {
    active = false;
    const elapsed = ((Date.now() - startMs) / 1000).toFixed(1);
    process.stderr.write('\\r  \\x1b[32m✓\\x1b[0m ' + (m.msg || msg).padEnd(46) + ' \\x1b[36m' + String(m.pct ?? pct).padStart(3) + '%\\x1b[0m   [' + elapsed + 's]\\n');
  }
});
`;

class ProgressSpinner {
  private readonly worker: Worker;

  constructor() {
    this.worker = new Worker(SPINNER_WORKER_CODE, { eval: true });
    this.worker.unref();
  }

  start(msg: string, pct = 0): void {
    this.worker.postMessage({ type: 'start', msg, pct });
  }

  update(msg: string, pct: number): void {
    this.worker.postMessage({ type: 'update', msg, pct });
  }

  done(msg: string, pct: number): void {
    this.worker.postMessage({ type: 'done', msg, pct });
  }

  async stop(): Promise<void> {
    process.stderr.write('\r' + ' '.repeat(72) + '\r');
    await this.worker.terminate();
  }
}

// ─── CLI setup ────────────────────────────────────────────────────────────

const program = new Command();

program
  .name('cybermat')
  .description('CyberMat Shield — Local-first Application Security Scanner')
  .version(pkg.version);

// ── init command ─────────────────────────────────────────────────────────────
program
  .command('init')
  .description('Initialize CyberMat Shield in the current project')
  .action(() => {
    console.log('');
    console.log(chalk.cyan.bold('  Initializing CyberMat Shield...'));
    console.log('');

    const cybermatDir = path.resolve('.cybermat');
    if (!fs.existsSync(cybermatDir)) {
      fs.mkdirSync(cybermatDir, { recursive: true });
      console.log(`  ${chalk.green('✓')} Created .cybermat/`);
    } else {
      console.log(`  ${chalk.gray('~')} .cybermat/ already exists`);
    }

    // .cybermatignore
    const ignorePath = path.resolve('.cybermatignore');
    if (!fs.existsSync(ignorePath)) {
      fs.writeFileSync(ignorePath, [
        '# CyberMat Shield ignore file',
        '# Paths, rule IDs, or finding fingerprints to suppress',
        '',
        '# Ignore entire directories',
        '# node_modules/',
        '# .next/',
        '',
        '# Ignore specific rule IDs',
        '# rule:secrets/generic-api-key',
        '',
        '# Ignore specific fingerprints (copy from report.json)',
        '# fp:abc123...',
        '',
      ].join('\n'));
      console.log(`  ${chalk.green('✓')} Created .cybermatignore`);
    } else {
      console.log(`  ${chalk.gray('~')} .cybermatignore already exists`);
    }

    // cybermat.config.json
    const configPath = path.resolve('cybermat.config.json');
    if (!fs.existsSync(configPath)) {
      const config = {
        $schema: 'https://raw.githubusercontent.com/Martysunshine/cybermat-shield/main/schema/cybermat-config.schema.json',
        version: 1,
        outputDir: '.cybermat',
        failOn: 'high',
        rules: {
          disabled: [],
          severityOverrides: {},
        },
        scan: {
          maxFileSizeKb: 512,
          skipDirs: ['node_modules', '.git', '.next', 'dist', 'build', 'coverage'],
        },
        runtime: {
          maxPages: 20,
          maxDepth: 3,
          requestDelayMs: 150,
          timeoutMs: 15000,
        },
        baseline: {
          enabled: false,
          failOnNew: true,
        },
      };
      fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
      console.log(`  ${chalk.green('✓')} Created cybermat.config.json`);
    } else {
      console.log(`  ${chalk.gray('~')} cybermat.config.json already exists`);
    }

    // .gitignore entry
    const gitignorePath = path.resolve('.gitignore');
    if (fs.existsSync(gitignorePath)) {
      const content = fs.readFileSync(gitignorePath, 'utf-8');
      const linesToAdd: string[] = [];
      if (!content.includes('.cybermat/auth/')) linesToAdd.push('.cybermat/auth/');
      if (!content.includes('*.storage.json')) linesToAdd.push('*.storage.json');
      if (linesToAdd.length > 0) {
        fs.appendFileSync(gitignorePath, `\n# CyberMat Shield — session tokens (never commit)\n${linesToAdd.join('\n')}\n`);
        console.log(`  ${chalk.green('✓')} Added .cybermat/auth/ to .gitignore`);
      }
    }

    console.log('');
    console.log(chalk.green('  ✅  CyberMat Shield initialized.'));
    console.log('');
    console.log(chalk.gray('  Next steps:'));
    console.log('  1. Run: ' + chalk.cyan('cybermat scan <path>'));
    console.log('  2. Run: ' + chalk.cyan('cybermat doctor') + '  — check environment');
    console.log('  3. Run: ' + chalk.cyan('cybermat rules list') + '  — browse 95 security rules');
    console.log('');
  });

// ── doctor command ────────────────────────────────────────────────────────────
program
  .command('doctor')
  .description('Check environment dependencies and configuration')
  .action(async () => {
    console.log('');
    console.log(chalk.cyan.bold('  CyberMat Shield — Environment Check'));
    console.log('');

    let allOk = true;

    function check(label: string, ok: boolean, detail?: string): void {
      const icon = ok ? chalk.green('✓') : chalk.red('✗');
      const msg = ok ? chalk.white(label) : chalk.red(label);
      console.log(`  ${icon}  ${msg}${detail ? chalk.gray(` — ${detail}`) : ''}`);
      if (!ok) allOk = false;
    }

    function warn(label: string, detail?: string): void {
      console.log(`  ${chalk.yellow('~')}  ${chalk.yellow(label)}${detail ? chalk.gray(` — ${detail}`) : ''}`);
    }

    // Node version
    const nodeVersion = process.version;
    const nodeOk = parseInt(nodeVersion.slice(1)) >= 18;
    check(`Node.js ${nodeVersion}`, nodeOk, nodeOk ? undefined : 'Requires Node 18+');

    // pnpm
    try {
      const pnpmOut = childProcess.execSync('pnpm --version', { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
      check(`pnpm ${pnpmOut}`, true);
    } catch {
      warn('pnpm not found', 'Install with: npm install -g pnpm');
    }

    // Playwright chromium
    try {
      const playwrightOut = childProcess.execSync(
        'node -e "const {chromium}=require(\'playwright\');chromium.executablePath().then(p=>console.log(p)).catch(()=>console.log(\'missing\'))"',
        { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], cwd: path.resolve('.') }
      ).trim();
      const playwrightOk = !playwrightOut.includes('missing') && fs.existsSync(playwrightOut);
      check('Playwright chromium browser', playwrightOk, playwrightOk ? 'Ready for runtime scanning' : 'Run: npx playwright install chromium');
    } catch {
      warn('Playwright check failed', 'Run: npx playwright install chromium');
    }

    // .cybermat dir writable
    const cybermatDir = path.resolve('.cybermat');
    try {
      if (!fs.existsSync(cybermatDir)) fs.mkdirSync(cybermatDir, { recursive: true });
      const testFile = path.join(cybermatDir, '.write-test');
      fs.writeFileSync(testFile, '');
      fs.unlinkSync(testFile);
      check('.cybermat/ is writable', true);
    } catch {
      check('.cybermat/ is writable', false, 'Check directory permissions');
    }

    // Config file
    const configPath = path.resolve('cybermat.config.json');
    if (fs.existsSync(configPath)) {
      try {
        JSON.parse(fs.readFileSync(configPath, 'utf-8'));
        check('cybermat.config.json', true, 'Valid JSON');
      } catch {
        check('cybermat.config.json', false, 'Invalid JSON — run: cybermat config validate');
      }
    } else {
      warn('cybermat.config.json not found', 'Run: cybermat init');
    }

    // .cybermatignore
    const ignorePath = path.resolve('.cybermatignore');
    if (fs.existsSync(ignorePath)) {
      check('.cybermatignore', true, 'Present');
    } else {
      warn('.cybermatignore not found', 'Run: cybermat init');
    }

    // Rule registry
    const ruleCount = defaultRegistry.listRules().length;
    check(`Rule registry — ${ruleCount} rules loaded`, ruleCount > 0);

    // Auth profiles (optional)
    const authDir = path.resolve('.cybermat/auth');
    if (fs.existsSync(authDir)) {
      const storageFiles = fs.readdirSync(authDir).filter(f => f.endsWith('.storage.json'));
      if (storageFiles.length > 0) {
        check(`Auth profiles — ${storageFiles.length} storageState file(s)`, true);
      } else {
        warn('No storageState files in .cybermat/auth/', 'Run: npx tsx scripts/setup-auth-profiles.ts');
      }
    } else {
      warn('.cybermat/auth/ not found', 'Optional — needed for scan-auth');
    }

    // Baseline
    const baseline = loadBaseline(cybermatDir);
    if (baseline) {
      check(`Baseline — ${baseline.entries.length} entries from ${baseline.createdAt.split('T')[0]}`, true);
    } else {
      warn('No baseline found', 'Run: cybermat baseline create');
    }

    console.log('');
    if (allOk) {
      console.log(chalk.green('  ✅  All checks passed. CyberMat Shield is ready.'));
    } else {
      console.log(chalk.red('  ✗  Some checks failed. Fix the issues above.'));
      process.exit(4);
    }
    console.log('');
  });

// ── config validate command ───────────────────────────────────────────────────
program
  .command('config validate')
  .description('Validate cybermat.config.json')
  .option('--config <path>', 'Path to config file', 'cybermat.config.json')
  .action((opts: { config: string }) => {
    console.log('');
    const configPath = path.resolve(opts.config);
    if (!fs.existsSync(configPath)) {
      console.error(chalk.red(`  Config not found: ${configPath}`));
      console.log(chalk.gray('  Run: cybermat init'));
      process.exit(3);
    }

    let config: Record<string, unknown>;
    try {
      config = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as Record<string, unknown>;
    } catch (err) {
      console.error(chalk.red(`  Invalid JSON in ${configPath}: ${(err as Error).message}`));
      process.exit(3);
    }

    const issues: string[] = [];
    const warns: string[] = [];

    if (config['version'] !== 1) issues.push('version must be 1');
    if (config['failOn'] && !['critical', 'high', 'medium', 'low', 'info', 'none'].includes(config['failOn'] as string)) {
      issues.push('failOn must be one of: critical, high, medium, low, info, none');
    }

    const rules = config['rules'] as Record<string, unknown> | undefined;
    if (rules) {
      if (rules['disabled'] && !Array.isArray(rules['disabled'])) issues.push('rules.disabled must be an array');
      if (rules['severityOverrides'] && typeof rules['severityOverrides'] !== 'object') {
        issues.push('rules.severityOverrides must be an object');
      }
    }

    if (issues.length === 0) {
      console.log(chalk.green(`  ✅  ${opts.config} is valid`));
      warns.forEach(w => console.log(`  ${chalk.yellow('~')} ${w}`));
    } else {
      console.log(chalk.red(`  ✗  ${opts.config} has errors:`));
      issues.forEach(i => console.log(`     ${chalk.red('•')} ${i}`));
      process.exit(3);
    }
    console.log('');
  });

// ── scan command ────────────────────────────────────────────────────────────
program
  .command('scan <path>')
  .description('Scan a project directory for security issues')
  .option('--json', 'Output full JSON report to stdout')
  .option('--sarif', 'Write SARIF report to .cybermat/report.sarif')
  .option('--markdown', 'Write Markdown report to .cybermat/report.md')
  .option('--output-dir <dir>', 'Output directory for reports', '.cybermat')
  .option('--fail-on <severity>', 'Exit 1 when findings at or above this severity exist (critical|high|medium|low|info|none)', 'high')
  .option('--baseline', 'Compare to .cybermat/baseline.json and annotate new vs existing findings')
  .option('--ci', 'Exit code 5 if new findings compared to baseline (implies --baseline)')
  .option('--strict-rules', 'Exit 2 if any rule fails internally during execution')
  .option('--debug', 'Print per-rule timing and detailed internal diagnostics')
  .option('--max-files <n>', 'Maximum files to scan (default: unlimited)')
  .option('--rule-timeout <ms>', 'Max milliseconds per rule before it is skipped (default: 30000)')
  .action(async (targetPath: string, opts: {
    json?: boolean; sarif?: boolean; markdown?: boolean;
    outputDir?: string; failOn?: string; baseline?: boolean; ci?: boolean;
    strictRules?: boolean; debug?: boolean; maxFiles?: string; ruleTimeout?: string;
  }) => {
    printBanner();

    const absolutePath = path.resolve(targetPath);
    if (!fs.existsSync(absolutePath)) {
      console.error(chalk.red(`  Error: Path not found: ${absolutePath}`));
      process.exit(2);
    }

    const spinner = opts.json ? null : new ProgressSpinner();
    if (!opts.json) console.log('');

    try {
      const report = await runScan(absolutePath, allRules, {
        outputDir: opts.outputDir,
        strictRuleFailures: opts.strictRules,
        debug: opts.debug,
        maxFiles: opts.maxFiles !== undefined ? parseInt(opts.maxFiles, 10) : undefined,
        ruleTimeoutMs: opts.ruleTimeout !== undefined ? parseInt(opts.ruleTimeout, 10) : undefined,
        onProgress: (phase, detail) => {
          if (!spinner) return;
          switch (phase) {
            case 'inventory':      spinner.start('Building file inventory...', 0); break;
            case 'inventory_done': spinner.done(detail ?? 'File inventory complete', 10); break;
            case 'analysis':       spinner.start('Analyzing code structure...', 10); break;
            case 'analysis_done':  spinner.done(detail ?? 'Code analysis complete', 20); break;
            case 'rules':          spinner.start('Running security rules... [0/?]', 20); break;
            case 'rule_done': {
              const [done, total] = (detail ?? '0/1').split('/').map(Number);
              const pct = 20 + Math.round((done / total) * 80);
              spinner.update(`Running security rules... [${done}/${total}]`, pct);
              break;
            }
            case 'rules_done':     spinner.done(detail ?? 'Rules complete', 100); break;
          }
        },
      });

      // Output dir is relative to the scanned path (where JSON/HTML also go)
      const outputDir = path.join(absolutePath, opts.outputDir ?? '.cybermat');

      // Baseline comparison
      let diff: BaselineDiff | undefined;
      if (opts.ci || opts.baseline) {
        const bl = loadBaseline(outputDir);
        if (bl) {
          diff = compareToBaseline(report, bl);
        } else {
          console.log(chalk.yellow('  No baseline found — skipping comparison. Run: cybermat baseline create'));
          console.log('');
        }
      }

      if (opts.json) {
        process.stdout.write(JSON.stringify(report, null, 2));
        return;
      }

      await spinner?.stop();
      console.log('');
      printReport(report, diff);

      // Engine health diagnostics warning
      const engineHealth = report.metadata?.engineHealth;
      if (engineHealth && engineHealth.rulesFailed > 0) {
        console.log(chalk.yellow(`  ⚠  ${engineHealth.rulesFailed} rule(s) failed internally. Results may be incomplete. See .cybermat/report.json diagnostics.`));
        console.log('');
        if (opts.debug) {
          console.log(chalk.gray('  Failed rules:'));
          engineHealth.failedRules.forEach(r => {
            console.log(`    ${chalk.red('✗')} ${r.ruleId}: ${chalk.gray(r.error)}`);
          });
          console.log('');
        }
      }

      // Debug: per-rule timing
      if (opts.debug && report.metadata?.scanDurationMs !== undefined) {
        console.log(chalk.gray(`  Scan duration: ${report.metadata.scanDurationMs}ms`));
        console.log(chalk.gray(`  Rules executed: ${engineHealth?.rulesTotal ?? 0} (${engineHealth?.rulesSucceeded ?? 0} succeeded, ${engineHealth?.rulesFailed ?? 0} failed)`));
        console.log('');
      }

      // Write extra formats
      if (opts.sarif) {
        const sarifPath = path.join(outputDir, 'report.sarif');
        fs.writeFileSync(sarifPath, generateSarif(report));
        console.log(`    ${chalk.cyan(sarifPath)}`);
      }
      if (opts.markdown) {
        const mdPath = path.join(outputDir, 'report.md');
        fs.writeFileSync(mdPath, generateMarkdown(report));
        console.log(`    ${chalk.cyan(mdPath)}`);
      }

      // Exit code logic
      const failOn = (opts.failOn ?? 'high') as Severity | 'none';
      const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];

      if (opts.strictRules && engineHealth && engineHealth.rulesFailed > 0) {
        console.log(chalk.red(`  ✗  Strict mode: ${engineHealth.rulesFailed} rule(s) failed internally.`));
        process.exit(2);
      }

      if (opts.ci && diff && diff.summary.new > 0) {
        console.log(chalk.red(`  ✗  ${diff.summary.new} new finding(s) vs baseline. CI failed.`));
        console.log('');
        process.exit(5);
      }

      if (failOn !== 'none') {
        const threshold = sevOrder.indexOf(failOn);
        const sum = report.summary as unknown as Record<string, number>;
        const hasFail = SEVERITY_ORDER.slice(0, threshold + 1).some(s => sum[s] > 0);
        if (hasFail) process.exit(1);
      }

      process.exit(0);

    } catch (err) {
      await spinner?.stop();
      console.error(chalk.red('  Scan failed:'), err);
      process.exit(2);
    }
  });

// ── baseline commands ─────────────────────────────────────────────────────────
const baselineCmd = program
  .command('baseline')
  .description('Manage scan baselines for CI diffing');

baselineCmd
  .command('create')
  .description('Create a baseline from the last scan report')
  .option('--output-dir <dir>', 'Directory containing report.json', '.cybermat')
  .action((opts: { outputDir: string }) => {
    console.log('');
    const outputDir = path.resolve(opts.outputDir);
    const reportPath = path.join(outputDir, 'report.json');

    if (!fs.existsSync(reportPath)) {
      console.error(chalk.red(`  report.json not found in ${outputDir}`));
      console.log(chalk.gray('  Run a scan first: cybermat scan <path>'));
      process.exit(3);
    }

    const report = JSON.parse(fs.readFileSync(reportPath, 'utf-8')) as ScanReport;
    const baseline = createBaseline(report);
    const savedPath = saveBaseline(baseline, outputDir);

    console.log(chalk.green(`  ✅  Baseline created: ${savedPath}`));
    console.log(`  ${chalk.gray('Entries:')} ${baseline.entries.length} findings fingerprinted`);
    console.log(`  ${chalk.gray('Tip:')} Commit ${savedPath} to track security regressions in CI.`);
    console.log('');
  });

baselineCmd
  .command('compare')
  .description('Compare the last scan report to the current baseline')
  .option('--output-dir <dir>', 'Directory containing report.json and baseline.json', '.cybermat')
  .action((opts: { outputDir: string }) => {
    console.log('');
    const outputDir = path.resolve(opts.outputDir);
    const reportPath = path.join(outputDir, 'report.json');

    if (!fs.existsSync(reportPath)) {
      console.error(chalk.red(`  report.json not found in ${outputDir}`));
      process.exit(3);
    }

    const baseline = loadBaseline(outputDir);
    if (!baseline) {
      console.error(chalk.red(`  baseline.json not found in ${outputDir}`));
      console.log(chalk.gray('  Run: cybermat baseline create'));
      process.exit(3);
    }

    const report = JSON.parse(fs.readFileSync(reportPath, 'utf-8')) as ScanReport;
    const diff = compareToBaseline(report, baseline);

    console.log(chalk.cyan.bold('  Baseline Comparison'));
    console.log('');
    console.log(`  ${chalk.gray('Baseline date:')} ${baseline.createdAt.split('T')[0]}`);
    console.log(`  ${chalk.gray('Baseline entries:')} ${baseline.entries.length}`);
    console.log('');
    console.log(`  ${chalk.red(`✗ New findings:      ${diff.summary.new}`)}`);
    console.log(`  ${chalk.gray(`~ Existing findings: ${diff.summary.existing}`)}`);
    console.log(`  ${chalk.green(`✓ Fixed findings:    ${diff.summary.fixed}`)}`);
    console.log('');

    if (diff.newFindings.length > 0) {
      console.log(chalk.red('  New findings (not in baseline):'));
      diff.newFindings.forEach((f, i) => {
        const sev = SEVERITY_CHALK[f.severity](`[${f.severity.toUpperCase()}]`);
        const loc = f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : '';
        console.log(`  ${i + 1}. ${sev} ${f.title}${loc ? chalk.gray(` — ${loc}`) : ''}`);
      });
      console.log('');
    }

    if (diff.fixedEntries.length > 0) {
      console.log(chalk.green('  Fixed since baseline:'));
      diff.fixedEntries.forEach((e, i) => {
        console.log(`  ${i + 1}. ${chalk.green('✓')} ${e.ruleId} — ${e.title}`);
      });
      console.log('');
    }
  });

// ── report command ────────────────────────────────────────────────────────────
program
  .command('report')
  .description('Generate additional report formats from the last scan')
  .option('--output-dir <dir>', 'Directory containing report.json', '.cybermat')
  .option('--sarif', 'Write SARIF report')
  .option('--markdown', 'Write Markdown report')
  .option('--all', 'Write all available formats')
  .action((opts: { outputDir: string; sarif?: boolean; markdown?: boolean; all?: boolean }) => {
    console.log('');
    const outputDir = path.resolve(opts.outputDir);
    const reportPath = path.join(outputDir, 'report.json');

    if (!fs.existsSync(reportPath)) {
      console.error(chalk.red(`  report.json not found in ${outputDir}`));
      console.log(chalk.gray('  Run a scan first: cybermat scan <path>'));
      process.exit(3);
    }

    const report = JSON.parse(fs.readFileSync(reportPath, 'utf-8')) as ScanReport;
    const written: string[] = [];

    if (opts.sarif || opts.all) {
      const p = path.join(outputDir, 'report.sarif');
      fs.writeFileSync(p, generateSarif(report));
      written.push(p);
    }
    if (opts.markdown || opts.all) {
      const p = path.join(outputDir, 'report.md');
      fs.writeFileSync(p, generateMarkdown(report));
      written.push(p);
    }

    if (written.length === 0) {
      console.log(chalk.yellow('  Specify a format: --sarif, --markdown, or --all'));
    } else {
      written.forEach(p => console.log(`  ${chalk.green('✓')} ${chalk.cyan(p)}`));
      console.log('');
      console.log(chalk.green('  ✅  Reports generated.'));
    }
    console.log('');
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

    if (opts.owasp) rules = defaultRegistry.getRulesByOwasp(opts.owasp);
    if (opts.engine) rules = rules.filter(r => r.engine === opts.engine);
    if (opts.tag) rules = rules.filter(r => r.tags.some(t => t.toLowerCase() === opts.tag!.toLowerCase()));

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
      console.log(chalk.gray(`  Run "cybermat rules list" to see all available rule IDs.`));
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
    if (rule.owasp2025.length > 0) console.log(`  ${chalk.gray('OWASP 2025:')} ${chalk.green(rule.owasp2025.join(', '))}`);
    if (rule.cwe && rule.cwe.length > 0) console.log(`  ${chalk.gray('CWE:')}        ${rule.cwe.join(', ')}`);
    if (rule.asvs && rule.asvs.length > 0) console.log(`  ${chalk.gray('ASVS:')}       ${rule.asvs.join(', ')}`);
    if (rule.wstg && rule.wstg.length > 0) console.log(`  ${chalk.gray('WSTG:')}       ${rule.wstg.join(', ')}`);
    if (rule.tags.length > 0) console.log(`  ${chalk.gray('Tags:')}       ${rule.tags.join(', ')}`);
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

    if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

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
  .option('--sarif', 'Also write SARIF report to .cybermat/runtime-report.sarif')
  .option('--no-browser', 'Skip Playwright browser crawl (HTTP probes only)')
  .action(async (url: string, opts: {
    maxPages: string; maxDepth: string; delay: string; timeout: string;
    json?: boolean; sarif?: boolean; browser: boolean;
  }) => {
    printBanner();

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

      // Save runtime report
      const outputDir = path.resolve('.cybermat');
      if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
      const rtReportPath = path.join(outputDir, 'runtime-report.json');
      fs.writeFileSync(rtReportPath, JSON.stringify(report, null, 2));
      console.log(`  ${chalk.gray('Report saved:')} ${chalk.cyan(rtReportPath)}`);

      if (opts.sarif) {
        const sarifPath = path.join(outputDir, 'runtime-report.sarif');
        const fakeStaticReport: ScanReport = {
          scannedPath: url, timestamp: new Date().toISOString(),
          findings: report.findings as unknown as Finding[],
          summary: report.summary, riskScore: report.riskScore,
          filesScanned: 0, filesIgnored: 0,
          detectedStack: { languages: [], frameworks: [], databases: [], authProviders: [], aiProviders: [], deploymentTargets: [], packageManagers: [] },
          topRecommendations: report.topRecommendations, owaspCoverage: [], topRiskyFiles: [],
          findingsByLayer: { code: [], runtime: report.findings as unknown as Finding[], authz: [] },
          metadata: { timestamp: new Date().toISOString(), layers: ['runtime'], version: pkg.version },
        };
        fs.writeFileSync(sarifPath, generateSarif(fakeStaticReport, report));
        console.log(`    ${chalk.cyan(sarifPath)}`);
      }

      console.log('');
      process.exit(report.summary.critical > 0 || report.summary.high > 0 ? 1 : 0);
    } catch (err) {
      console.error(chalk.red('  Runtime scan failed:'), err);
      process.exit(2);
    }
  });

// ── scan-auth command ────────────────────────────────────────────────────────

const AUTH_CONFIG_TEMPLATE: AuthScanConfig = {
  baseUrl: 'http://localhost:3000',
  profiles: {
    userA: { label: 'low-privileged-user-a', storageStatePath: '.cybermat/auth/userA.storage.json' },
    userB: { label: 'low-privileged-user-b', storageStatePath: '.cybermat/auth/userB.storage.json' },
    admin: { label: 'admin-user', storageStatePath: '.cybermat/auth/admin.storage.json', isPrivileged: true },
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
  .option('--config <path>', 'Path to auth config JSON', '.cybermat/auth-config.json')
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

    let config: AuthScanConfig;
    const configPath = path.resolve(opts.config);
    if (fs.existsSync(configPath)) {
      config = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as AuthScanConfig;
      config.baseUrl = url;
    } else {
      console.log(chalk.gray(`  No auth-config.json found. Using defaults.`));
      console.log(chalk.gray(`  Run "cybermat auth init" to create a config template.`));
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

      const outputDir = path.resolve('.cybermat');
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
  .description('Create .cybermat/auth-config.json template')
  .action(() => {
    const outputDir = path.resolve('.cybermat');
    const configPath = path.join(outputDir, 'auth-config.json');

    if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
    if (fs.existsSync(configPath)) {
      console.log(chalk.yellow(`  auth-config.json already exists: ${configPath}`));
      return;
    }

    fs.writeFileSync(configPath, JSON.stringify(AUTH_CONFIG_TEMPLATE, null, 2));
    console.log('');
    console.log(chalk.green('  ✅  Created .cybermat/auth-config.json'));
    console.log('');
    console.log(chalk.gray('  Next steps:'));
    console.log(`  1. Edit ${chalk.cyan(configPath)} to set baseUrl and profile paths`);
    console.log('  2. Run: npx tsx --tsconfig scripts/tsconfig.json scripts/setup-auth-profiles.ts');
    console.log('  3. Run: cybermat auth test-config');
    console.log('  4. Run: cybermat scan-auth <url>');
    console.log('');
  });

authCmd
  .command('test-config')
  .description('Validate auth profiles and test connectivity to the target')
  .option('--config <path>', 'Path to auth config JSON', '.cybermat/auth-config.json')
  .option('--url <url>', 'Target URL (overrides config baseUrl)')
  .action(async (opts: { config: string; url?: string }) => {
    console.log('');
    const configPath = path.resolve(opts.config);
    if (!fs.existsSync(configPath)) {
      console.error(chalk.red(`  auth-config.json not found: ${configPath}`));
      console.log(chalk.gray(`  Run "cybermat auth init" to create a template.`));
      process.exit(3);
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
      process.exit(3);
    } else {
      console.log(chalk.green('  ✅  Auth config is valid. Run: cybermat scan-auth <url>'));
    }
    console.log('');
  });

// ── dashboard stub ────────────────────────────────────────────────────────────
program
  .command('dashboard')
  .description('Open the security dashboard')
  .action(() => {
    console.log(chalk.yellow('  Open .cybermat/report.html in your browser for the interactive dashboard.'));
    console.log(chalk.gray('  Or run: cybermat report --markdown --sarif  to generate additional formats.'));
  });

program.parse(process.argv);
