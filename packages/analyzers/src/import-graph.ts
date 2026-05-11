import type { ScannedFile, ImportGraph, ImportEdge } from '@cybermat/shared';

const STATIC_IMPORT_RE = /^import\s+(?:type\s+)?(?:\{[^}]*\}|\*\s+as\s+\w+|\w+)(?:\s*,\s*(?:\{[^}]*\}|\*\s+as\s+\w+|\w+))?\s+from\s+['"]([^'"]+)['"]/gm;
const STATIC_IMPORT_BARE_RE = /^import\s+['"]([^'"]+)['"]/gm;
const DYNAMIC_IMPORT_RE = /import\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
const REQUIRE_RE = /(?:require|import)\s*\(\s*['"]([^'"]+)['"]\s*\)/g;

const SERVER_ONLY_MODULES = new Set([
  'fs', 'path', 'crypto', 'child_process', 'os', 'net', 'tls', 'http', 'https',
  'stream', 'buffer', 'process', 'cluster', 'worker_threads',
  'server-only', 'next/server', 'next/headers', 'next/cookies',
]);

const CLIENT_ONLY_MODULES = new Set([
  'client-only', 'react-dom/client',
]);

function extractImports(content: string): Array<{ specifier: string; isDynamic: boolean }> {
  const imports: Array<{ specifier: string; isDynamic: boolean }> = [];
  const seen = new Set<string>();

  const addImport = (spec: string, isDynamic: boolean) => {
    if (!seen.has(spec)) {
      seen.add(spec);
      imports.push({ specifier: spec, isDynamic });
    }
  };

  let match: RegExpExecArray | null;

  STATIC_IMPORT_RE.lastIndex = 0;
  while ((match = STATIC_IMPORT_RE.exec(content)) !== null) addImport(match[1], false);

  STATIC_IMPORT_BARE_RE.lastIndex = 0;
  while ((match = STATIC_IMPORT_BARE_RE.exec(content)) !== null) addImport(match[1], false);

  DYNAMIC_IMPORT_RE.lastIndex = 0;
  while ((match = DYNAMIC_IMPORT_RE.exec(content)) !== null) addImport(match[1], true);

  REQUIRE_RE.lastIndex = 0;
  while ((match = REQUIRE_RE.exec(content)) !== null) {
    if (!match[0].startsWith('import(')) addImport(match[1], false);
  }

  return imports;
}

function isServerOnlyImport(specifier: string): boolean {
  const bare = specifier.split('/')[0];
  return SERVER_ONLY_MODULES.has(bare) || SERVER_ONLY_MODULES.has(specifier);
}

function isClientOnlyImport(specifier: string): boolean {
  return CLIENT_ONLY_MODULES.has(specifier);
}

function isClientFile(relativePath: string, content: string): boolean {
  return /"use client"|'use client'/.test(content) ||
    relativePath.startsWith('components/') ||
    relativePath.startsWith('src/components/') ||
    (relativePath.startsWith('app/') && relativePath.endsWith('page.tsx'));
}

function isServerFile(relativePath: string, content: string): boolean {
  return /"use server"|'use server'/.test(content) ||
    /^(?:src\/)?app\/api\//.test(relativePath) ||
    /^(?:src\/)?pages\/api\//.test(relativePath) ||
    relativePath === 'middleware.ts' ||
    relativePath === 'middleware.js';
}

export function buildImportGraph(files: ScannedFile[]): ImportGraph {
  const nodes: string[] = files.map(f => f.relativePath);
  const edges: ImportEdge[] = [];
  const serverClientLeaks: string[] = [];
  const clientServerLeaks: string[] = [];

  for (const file of files) {
    if (!['.ts', '.tsx', '.js', '.jsx', '.mjs'].includes(file.extension)) continue;

    const imports = extractImports(file.content);
    const fileIsClient = isClientFile(file.relativePath, file.content);
    const fileIsServer = isServerFile(file.relativePath, file.content);

    for (const { specifier, isDynamic } of imports) {
      edges.push({
        from: file.relativePath,
        to: specifier,
        importType: isDynamic ? 'dynamic' : 'static',
      });

      // Detect boundary violations
      if (fileIsClient && isServerOnlyImport(specifier)) {
        serverClientLeaks.push(`${file.relativePath} imports server-only "${specifier}"`);
      }
      if (fileIsServer && isClientOnlyImport(specifier)) {
        clientServerLeaks.push(`${file.relativePath} imports client-only "${specifier}"`);
      }
    }
  }

  return { nodes, edges, serverClientLeaks, clientServerLeaks };
}
