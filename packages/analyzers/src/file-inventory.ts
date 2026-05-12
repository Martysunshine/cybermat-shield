import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import type { ScannedFile, ScannerConfig } from '@cybermat/shared';
import { detectLanguage, detectFileKind, detectEcosystem } from './language-classifier';

// ─── Ignored directories ──────────────────────────────────────────────────────

const IGNORE_DIRS = new Set([
  'node_modules', '.next', 'dist', 'build', '.git',
  'coverage', '.turbo', '.vercel', '.cache', 'out',
  '.svelte-kit', '__pycache__', '.pytest_cache', '.nuxt',
  '.appsec',
]);

// ─── Scannable extensions ─────────────────────────────────────────────────────

const WEB_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.vue', '.svelte', '.astro',
  '.html', '.htm', '.css', '.scss', '.sass', '.less',
]);

const BACKEND_EXTENSIONS = new Set([
  '.py', '.go', '.java', '.cs', '.php', '.rb', '.rs',
  '.kt', '.kts', '.swift',
  '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp',
  '.scala', '.clj', '.ex', '.exs', '.erl', '.hrl',
  '.fs', '.fsx',
]);

const CONFIG_EXTENSIONS = new Set([
  '.json', '.jsonc', '.yaml', '.yml', '.toml',
  '.ini', '.conf', '.config', '.properties', '.xml',
  '.env', '.envrc',
  '.pem', '.key', '.crt', '.cert', '.pub',
  '.rules',
]);

const INFRA_EXTENSIONS = new Set([
  '.tf', '.tfvars', '.hcl', '.nomad', '.rego', '.cue',
]);

const DATABASE_EXTENSIONS = new Set([
  '.sql', '.graphql', '.gql', '.prisma', '.dbml',
]);

const SCRIPT_EXTENSIONS = new Set([
  '.sh', '.bash', '.zsh', '.fish',
  '.ps1', '.bat', '.cmd',
  '.make', '.mk',
]);

const DOC_EXTENSIONS = new Set([
  '.md', '.mdx', '.txt', '.rst',
]);

/** All extensions that the scanner will read. */
export const SCANNABLE_EXTENSIONS: ReadonlySet<string> = new Set([
  ...WEB_EXTENSIONS,
  ...BACKEND_EXTENSIONS,
  ...CONFIG_EXTENSIONS,
  ...INFRA_EXTENSIONS,
  ...DATABASE_EXTENSIONS,
  ...SCRIPT_EXTENSIONS,
  ...DOC_EXTENSIONS,
]);

// ─── Scannable filenames (exact basename match) ───────────────────────────────

export const SCANNABLE_FILENAMES: ReadonlySet<string> = new Set([
  // Build / container
  'Dockerfile', 'Containerfile',
  'Makefile', 'GNUmakefile',
  'Jenkinsfile',
  'Procfile',
  // Package manifests
  'Gemfile', 'Gemfile.lock',
  'Rakefile',
  'Pipfile',
  'requirements.txt', 'requirements-dev.txt',
  'pyproject.toml', 'poetry.lock',
  'go.mod', 'go.sum',
  'pom.xml',
  'build.gradle', 'build.gradle.kts',
  'settings.gradle', 'settings.gradle.kts',
  'gradle.properties',
  'Cargo.toml', 'Cargo.lock',
  'composer.json', 'composer.lock',
  'package.json', 'package-lock.json',
  'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb',
  'deno.json', 'deno.jsonc',
  // Framework config
  'tsconfig.json',
  'next.config.js', 'next.config.mjs', 'next.config.ts',
  'vite.config.ts', 'vite.config.js',
  'nuxt.config.ts',
  'svelte.config.js',
  'astro.config.mjs',
  'vercel.json',
  'netlify.toml',
  'wrangler.toml',
  'firebase.json',
  'firestore.rules', 'storage.rules',
  // Web server
  'nginx.conf', 'httpd.conf', 'apache.conf', 'Caddyfile',
  // CI/CD
  '.gitlab-ci.yml',
  'azure-pipelines.yml',
  'bitbucket-pipelines.yml',
  '.drone.yml', 'drone.yml',
  '.travis.yml',
  // Misc
  'robots.txt', 'sitemap.xml',
]);

// CI/CD directory path patterns (relative path must contain one of these)
const CICD_PATH_PATTERNS = [
  '.github/workflows/',
  '.github/actions/',
  '.circleci/',
];

// ─── FileInventoryResult ─────────────────────────────────────────────────────

export interface FileInventoryResult {
  files: ScannedFile[];
  /** Count of directories that were ignored (IGNORE_DIRS + config.ignoreDirs) */
  ignored: number;
  /** Count of individual files that were skipped (binary, too_large, read errors, symlinks) */
  skipped: number;
  /** Breakdown of skipped files by reason */
  skippedByReason: Record<string, number>;
}

// ─── Binary detection ─────────────────────────────────────────────────────────

const BINARY_SAMPLE_BYTES = 512;
const BINARY_NON_PRINTABLE_THRESHOLD = 0.30;

/**
 * Heuristic binary check: reads the first N bytes and checks the ratio of
 * non-printable characters. More accurate than null-byte check alone.
 * Excludes tab (0x09), LF (0x0A), CR (0x0D) as valid text chars.
 */
function looksLikeBinary(fullPath: string): boolean {
  let fd: number | undefined;
  try {
    fd = fs.openSync(fullPath, 'r');
    const buf = Buffer.alloc(BINARY_SAMPLE_BYTES);
    const bytesRead = fs.readSync(fd, buf, 0, BINARY_SAMPLE_BYTES, 0);
    if (bytesRead === 0) return false;
    let nonPrintable = 0;
    for (let i = 0; i < bytesRead; i++) {
      const b = buf[i];
      if (b === 0x00) return true; // null byte → definitely binary
      if (b < 0x09 || (b > 0x0D && b < 0x20) || b === 0x7F) nonPrintable++;
    }
    return nonPrintable / bytesRead > BINARY_NON_PRINTABLE_THRESHOLD;
  } catch {
    return false;
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch { /* ignore */ }
    }
  }
}

// ─── Main inventory builder ───────────────────────────────────────────────────

export function buildFileInventory(rootPath: string, config: ScannerConfig): FileInventoryResult {
  const files: ScannedFile[] = [];
  let ignored = 0;
  let skipped = 0;
  const skippedByReason: Record<string, number> = {};

  function bumpSkip(reason: string): void {
    skipped++;
    skippedByReason[reason] = (skippedByReason[reason] ?? 0) + 1;
  }

  function scan(dir: string): void {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      const relativePath = path.relative(rootPath, fullPath).replace(/\\/g, '/');

      // Symlink safety: skip symlinked directories to prevent loops
      if (entry.isSymbolicLink()) {
        try {
          const target = fs.statSync(fullPath);
          if (target.isDirectory()) {
            bumpSkip('symlink_skipped');
            continue;
          }
          // Symlinked files are allowed — fall through to normal file handling
        } catch {
          bumpSkip('symlink_skipped');
          continue;
        }
      }

      if (entry.isDirectory()) {
        if (IGNORE_DIRS.has(entry.name) || config.ignoreDirs.includes(entry.name)) {
          ignored++;
          continue;
        }
        scan(fullPath);
        continue;
      }

      if (!entry.isFile() && !entry.isSymbolicLink()) continue;

      if (config.ignoreFiles.some(p => relativePath.includes(p))) {
        bumpSkip('ignored_file');
        continue;
      }

      const ext = path.extname(entry.name).toLowerCase();
      const basename = path.basename(entry.name);
      const lowerRelative = relativePath.toLowerCase();

      // Determine if this file is scannable
      const isEnvFile = basename.startsWith('.env');
      const hasScannableExt = SCANNABLE_EXTENSIONS.has(ext);
      const hasScannableBasename = SCANNABLE_FILENAMES.has(basename);
      const isCiCdPath = CICD_PATH_PATTERNS.some(p => lowerRelative.includes(p));

      if (!hasScannableExt && !isEnvFile && !hasScannableBasename && !isCiCdPath) {
        continue; // unsupported — silently skip (no counter, keeps ignored low)
      }

      // Binary check before stat (fast path for obvious binary extensions)
      if (looksLikeBinary(fullPath)) {
        bumpSkip('binary');
        continue;
      }

      let stat: fs.Stats;
      try {
        stat = fs.statSync(fullPath);
      } catch {
        bumpSkip('read_error');
        continue;
      }

      if (stat.size > config.maxFileSizeBytes) {
        bumpSkip('too_large');
        continue;
      }

      let content: string;
      try {
        content = fs.readFileSync(fullPath, 'utf-8');
      } catch {
        bumpSkip('read_error');
        continue;
      }

      // Belt-and-suspenders null-byte check on the decoded content
      if (content.includes('\0')) {
        bumpSkip('binary');
        continue;
      }

      const sha256 = crypto.createHash('sha256').update(content).digest('hex');

      // Classify language, fileKind, ecosystem
      const language = detectLanguage(relativePath, ext, basename);
      const fileKind = detectFileKind(relativePath, ext, basename);
      const ecosystem = detectEcosystem(relativePath, basename);

      files.push({
        path: fullPath,
        relativePath,
        extension: ext || basename,
        sizeBytes: stat.size,
        content,
        sha256,
        language,
        fileKind,
        ecosystem,
      });
    }
  }

  scan(rootPath);
  return { files, ignored, skipped, skippedByReason };
}
