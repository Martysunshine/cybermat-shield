import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { buildFileInventory, SCANNABLE_EXTENSIONS, SCANNABLE_FILENAMES } from '../file-inventory';
import type { ScannerConfig } from '@cybermat/shared';

const CONFIG: ScannerConfig = {
  ignoreDirs: [],
  ignoreFiles: [],
  maxFileSizeBytes: 1_000_000,
  outputDir: '.cybermat',
};

// ─── Extension / filename sets ────────────────────────────────────────────────

describe('SCANNABLE_EXTENSIONS', () => {
  const cases: [string, string][] = [
    ['.py', 'Python'], ['.go', 'Go'], ['.java', 'Java'],
    ['.cs', 'C#'], ['.php', 'PHP'], ['.rb', 'Ruby'], ['.rs', 'Rust'],
    ['.kt', 'Kotlin'], ['.swift', 'Swift'], ['.c', 'C'], ['.cpp', 'C++'],
    ['.tf', 'Terraform'], ['.hcl', 'HCL'], ['.sh', 'Shell'],
    ['.ps1', 'PowerShell'], ['.yaml', 'YAML'], ['.yml', 'YAML'],
    ['.pem', 'PEM cert'], ['.key', 'Key file'], ['.bat', 'Batch'],
    ['.sql', 'SQL'], ['.graphql', 'GraphQL'], ['.prisma', 'Prisma'],
    ['.vue', 'Vue'], ['.svelte', 'Svelte'], ['.astro', 'Astro'],
    ['.ts', 'TypeScript'], ['.tsx', 'TSX'], ['.js', 'JavaScript'],
    ['.md', 'Markdown'], ['.txt', 'Text'], ['.json', 'JSON'],
    ['.toml', 'TOML'], ['.xml', 'XML'], ['.rego', 'OPA Rego'],
    ['.html', 'HTML'], ['.css', 'CSS'], ['.scss', 'SCSS'],
  ];
  for (const [ext, label] of cases) {
    test(`includes ${label} (${ext})`, () => {
      assert.ok(SCANNABLE_EXTENSIONS.has(ext), `Expected ${ext} in SCANNABLE_EXTENSIONS`);
    });
  }
});

describe('SCANNABLE_FILENAMES', () => {
  const cases = [
    'Dockerfile', 'Containerfile', 'Makefile', 'Jenkinsfile',
    'go.mod', 'go.sum', 'Cargo.toml', 'requirements.txt',
    'package.json', 'pnpm-lock.yaml', 'yarn.lock',
    'pyproject.toml', 'pom.xml', 'build.gradle',
    'composer.json', 'Gemfile',
    'next.config.ts', 'vite.config.ts', 'tsconfig.json',
    'vercel.json', 'netlify.toml', 'wrangler.toml',
    'firebase.json', 'firestore.rules', 'storage.rules',
    'nginx.conf', 'Caddyfile',
    '.gitlab-ci.yml', 'azure-pipelines.yml', 'bitbucket-pipelines.yml',
  ];
  for (const name of cases) {
    test(`includes ${name}`, () => {
      assert.ok(SCANNABLE_FILENAMES.has(name), `Expected ${name} in SCANNABLE_FILENAMES`);
    });
  }
});

// ─── buildFileInventory integration tests ────────────────────────────────────

let tmpDir: string;

before(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cybermat-test-'));
});

after(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function write(rel: string, content: string): string {
  const full = path.join(tmpDir, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
  return full;
}

describe('buildFileInventory — file inclusion', () => {
  test('includes Python .py file with correct language/fileKind', () => {
    write('app/main.py', 'print("hello")\n');
    const { files } = buildFileInventory(tmpDir, CONFIG);
    const f = files.find(x => x.relativePath === 'app/main.py');
    assert.ok(f, 'Python file should be included');
    assert.equal(f!.language, 'python');
    assert.equal(f!.fileKind, 'source');
  });

  test('includes Go .go file', () => {
    write('main.go', 'package main\n');
    const { files } = buildFileInventory(tmpDir, CONFIG);
    const f = files.find(x => x.relativePath === 'main.go');
    assert.ok(f, 'Go file should be included');
    assert.equal(f!.language, 'go');
  });

  test('includes Dockerfile (no extension) with language=dockerfile', () => {
    write('Dockerfile', 'FROM node:20\n');
    const { files } = buildFileInventory(tmpDir, CONFIG);
    const f = files.find(x => x.relativePath === 'Dockerfile');
    assert.ok(f, 'Dockerfile should be included');
    assert.equal(f!.language, 'dockerfile');
    assert.equal(f!.fileKind, 'docker');
  });

  test('includes Makefile (no extension) with fileKind=script', () => {
    write('Makefile', 'all:\n\techo done\n');
    const { files } = buildFileInventory(tmpDir, CONFIG);
    const f = files.find(x => x.relativePath === 'Makefile');
    assert.ok(f, 'Makefile should be included');
    assert.equal(f!.fileKind, 'script');
  });

  test('includes Jenkinsfile (no extension) with fileKind=ci_cd', () => {
    write('Jenkinsfile', 'pipeline {}\n');
    const { files } = buildFileInventory(tmpDir, CONFIG);
    const f = files.find(x => x.relativePath === 'Jenkinsfile');
    assert.ok(f, 'Jenkinsfile should be included');
    assert.equal(f!.fileKind, 'ci_cd');
  });

  test('includes .github/workflows/ci.yml with fileKind=ci_cd and ecosystem=github-actions', () => {
    write('.github/workflows/ci.yml', 'on: push\njobs: {}\n');
    const { files } = buildFileInventory(tmpDir, CONFIG);
    const f = files.find(x => x.relativePath === '.github/workflows/ci.yml');
    assert.ok(f, '.github/workflows/ YAML should be included');
    assert.equal(f!.fileKind, 'ci_cd');
    assert.equal(f!.ecosystem, 'github-actions');
  });

  test('includes Terraform .tf file with language=terraform', () => {
    write('infra/main.tf', 'resource "aws_s3_bucket" "b" {}\n');
    const { files } = buildFileInventory(tmpDir, CONFIG);
    const f = files.find(x => x.relativePath === 'infra/main.tf');
    assert.ok(f, '.tf file should be included');
    assert.equal(f!.language, 'terraform');
    assert.equal(f!.fileKind, 'infrastructure');
  });

  test('includes .env.local with language=env and fileKind=env', () => {
    write('.env.local', 'SECRET=abc\n');
    const { files } = buildFileInventory(tmpDir, CONFIG);
    const f = files.find(x => x.relativePath === '.env.local');
    assert.ok(f, '.env.local should be included');
    assert.equal(f!.language, 'env');
    assert.equal(f!.fileKind, 'env');
  });

  test('includes package.json with fileKind=dependency_manifest', () => {
    write('package.json', '{"name":"test"}\n');
    const { files } = buildFileInventory(tmpDir, CONFIG);
    const f = files.find(x => x.relativePath === 'package.json');
    assert.ok(f, 'package.json should be included');
    assert.equal(f!.fileKind, 'dependency_manifest');
    assert.equal(f!.ecosystem, 'node');
  });

  test('includes firestore.rules with fileKind=security_rules', () => {
    write('firestore.rules', 'service cloud.firestore {}\n');
    const { files } = buildFileInventory(tmpDir, CONFIG);
    const f = files.find(x => x.relativePath === 'firestore.rules');
    assert.ok(f, 'firestore.rules should be included');
    assert.equal(f!.fileKind, 'security_rules');
    assert.equal(f!.ecosystem, 'firebase');
  });

  test('includes go.mod with fileKind=dependency_manifest', () => {
    write('go.mod', 'module example.com/app\ngo 1.21\n');
    const { files } = buildFileInventory(tmpDir, CONFIG);
    const f = files.find(x => x.relativePath === 'go.mod');
    assert.ok(f, 'go.mod should be included');
    assert.equal(f!.fileKind, 'dependency_manifest');
    assert.equal(f!.ecosystem, 'go');
  });

  test('includes pom.xml with fileKind=dependency_manifest', () => {
    write('pom.xml', '<project></project>\n');
    const { files } = buildFileInventory(tmpDir, CONFIG);
    const f = files.find(x => x.relativePath === 'pom.xml');
    assert.ok(f, 'pom.xml should be included');
    assert.equal(f!.fileKind, 'dependency_manifest');
    assert.equal(f!.ecosystem, 'java');
  });

  test('includes Cargo.toml with ecosystem=rust', () => {
    write('Cargo.toml', '[package]\nname = "test"\n');
    const { files } = buildFileInventory(tmpDir, CONFIG);
    const f = files.find(x => x.relativePath === 'Cargo.toml');
    assert.ok(f, 'Cargo.toml should be included');
    assert.equal(f!.ecosystem, 'rust');
  });

  test('includes Gemfile with ecosystem=ruby', () => {
    write('Gemfile', "source 'https://rubygems.org'\n");
    const { files } = buildFileInventory(tmpDir, CONFIG);
    const f = files.find(x => x.relativePath === 'Gemfile');
    assert.ok(f, 'Gemfile should be included');
    assert.equal(f!.ecosystem, 'ruby');
  });

  test('includes nginx.conf with language=config', () => {
    write('nginx.conf', 'server { listen 80; }\n');
    const { files } = buildFileInventory(tmpDir, CONFIG);
    const f = files.find(x => x.relativePath === 'nginx.conf');
    assert.ok(f, 'nginx.conf should be included');
    assert.equal(f!.language, 'config');
  });

  test('includes requirements.txt', () => {
    write('requirements.txt', 'django>=4.0\n');
    const { files } = buildFileInventory(tmpDir, CONFIG);
    const f = files.find(x => x.relativePath === 'requirements.txt');
    assert.ok(f, 'requirements.txt should be included');
    assert.equal(f!.ecosystem, 'python');
  });
});

describe('buildFileInventory — binary and large file exclusion', () => {
  test('skips file containing null bytes', () => {
    // Use a scannable extension so it passes the extension check, then hits binary detection
    write('data.conf', 'CONF\x00BINARY\x00CONTENT');
    const { files, skippedByReason } = buildFileInventory(tmpDir, CONFIG);
    const f = files.find(x => x.relativePath === 'data.conf');
    assert.equal(f, undefined, 'Binary file should not appear in results');
    const binarySkipped = (skippedByReason['binary'] ?? 0) > 0;
    assert.ok(binarySkipped, 'Should count at least one binary skip');
  });

  test('skips file over maxFileSizeBytes', () => {
    const bigContent = 'x'.repeat(1_100_000);
    write('huge.txt', bigContent);
    const smallConfig: ScannerConfig = { ...CONFIG, maxFileSizeBytes: 1_000_000 };
    const { files, skippedByReason } = buildFileInventory(tmpDir, smallConfig);
    const f = files.find(x => x.relativePath === 'huge.txt');
    assert.equal(f, undefined, 'Oversized file should not appear in results');
    assert.ok((skippedByReason['too_large'] ?? 0) > 0, 'Should count too_large skip');
  });

  test('skips files matching ignoreFiles config', () => {
    write('src/secret-backup.ts', 'const x = 1;\n');
    const cfg: ScannerConfig = { ...CONFIG, ignoreFiles: ['secret-backup'] };
    const { files, skippedByReason } = buildFileInventory(tmpDir, cfg);
    const f = files.find(x => x.relativePath === 'src/secret-backup.ts');
    assert.equal(f, undefined, 'Ignored file should not appear in results');
    assert.ok((skippedByReason['ignored_file'] ?? 0) > 0, 'Should count ignored_file skip');
  });

  test('skips node_modules directory', () => {
    write('node_modules/lodash/index.js', 'module.exports = {};\n');
    const { files } = buildFileInventory(tmpDir, CONFIG);
    const found = files.find(x => x.relativePath.startsWith('node_modules/'));
    assert.equal(found, undefined, 'node_modules should be ignored');
  });

  test('skips .git directory', () => {
    write('.git/config', '[core]\n\trepositoryformatversion = 0\n');
    const { files } = buildFileInventory(tmpDir, CONFIG);
    const found = files.find(x => x.relativePath.startsWith('.git/'));
    assert.equal(found, undefined, '.git directory should be ignored');
  });

  test('FileInventoryResult includes skipped count and skippedByReason', () => {
    const result = buildFileInventory(tmpDir, CONFIG);
    assert.ok('skipped' in result, 'Result should have skipped field');
    assert.ok('skippedByReason' in result, 'Result should have skippedByReason field');
    assert.ok(typeof result.skipped === 'number', 'skipped should be a number');
    assert.ok(typeof result.skippedByReason === 'object', 'skippedByReason should be an object');
  });
});
