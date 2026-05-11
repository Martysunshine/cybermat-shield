import * as fs from 'fs';
import * as path from 'path';
import type { ScannedFile, ScannerConfig } from '@cybermat/shared';

const IGNORE_DIRS = new Set([
  'node_modules', '.next', 'dist', 'build', '.git',
  'coverage', '.turbo', '.vercel', '.cache', 'out',
  '.svelte-kit', '__pycache__', '.pytest_cache', '.nuxt',
  '.appsec',
]);

const TEXT_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.json', '.yaml', '.yml', '.toml', '.env',
  '.md', '.mdx', '.txt', '.html', '.css', '.scss',
  '.sql', '.graphql', '.gql', '.prisma', '.sh',
  '.vue', '.svelte', '.astro',
]);

const SENSITIVE_FILENAMES = new Set([
  '.env', '.env.local', '.env.production', '.env.development',
  '.env.staging', '.env.test', '.env.example',
]);

export interface FileInventoryResult {
  files: ScannedFile[];
  ignored: number;
}

export function buildFileInventory(rootPath: string, config: ScannerConfig): FileInventoryResult {
  const files: ScannedFile[] = [];
  let ignored = 0;

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

      if (entry.isDirectory()) {
        if (IGNORE_DIRS.has(entry.name) || config.ignoreDirs.includes(entry.name)) {
          ignored++;
          continue;
        }
        scan(fullPath);
        continue;
      }

      if (!entry.isFile()) continue;

      if (config.ignoreFiles.some(p => relativePath.includes(p))) {
        ignored++;
        continue;
      }

      const ext = path.extname(entry.name).toLowerCase();
      const basename = path.basename(entry.name);
      const isSensitiveFile = SENSITIVE_FILENAMES.has(basename) || basename.startsWith('.env');

      if (!TEXT_EXTENSIONS.has(ext) && !isSensitiveFile) {
        continue;
      }

      let stat: fs.Stats;
      try {
        stat = fs.statSync(fullPath);
      } catch {
        continue;
      }

      if (stat.size > config.maxFileSizeBytes) {
        ignored++;
        continue;
      }

      let content: string;
      try {
        content = fs.readFileSync(fullPath, 'utf-8');
      } catch {
        continue;
      }

      if (content.includes('\0')) continue;

      files.push({
        path: fullPath,
        relativePath,
        extension: ext || basename,
        sizeBytes: stat.size,
        content,
      });
    }
  }

  scan(rootPath);
  return { files, ignored };
}
