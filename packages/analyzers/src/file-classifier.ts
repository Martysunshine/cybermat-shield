import type { ScannedFile, FileClassification, FileKind } from '@cybermat/shared';

const CONFIG_FILENAMES = new Set([
  'next.config.js', 'next.config.ts', 'next.config.mjs',
  'vite.config.ts', 'vite.config.js', 'vite.config.mjs',
  'vercel.json', 'netlify.toml',
  'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
  'package.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb',
  'tsconfig.json', 'tsconfig.base.json',
  '.eslintrc.js', '.eslintrc.ts', '.eslintrc.json', '.eslintrc.cjs',
  'eslint.config.js', 'eslint.config.ts', 'eslint.config.mjs',
  '.babelrc', 'babel.config.js', 'babel.config.ts',
  'tailwind.config.js', 'tailwind.config.ts',
  'postcss.config.js', 'postcss.config.ts',
  'jest.config.js', 'jest.config.ts',
  'vitest.config.ts', 'vitest.config.js',
  'playwright.config.ts', 'playwright.config.js',
  '.prettierrc', 'prettier.config.js',
  'turbo.json', 'pnpm-workspace.yaml',
]);

const BROWSER_APIS = /\b(?:window|document|localStorage|sessionStorage|navigator|location|history|alert|confirm|prompt|fetch(?!\s*\(.*\bprocess\.env))\b/;
const SERVER_ONLY_APIS = /\b(?:fs\.|child_process\.|path\.resolve|crypto\.createHash|process\.env\.(?!NEXT_PUBLIC_|VITE_))\b/;

function isConfigFile(rel: string): boolean {
  const basename = rel.split('/').pop() ?? '';
  if (CONFIG_FILENAMES.has(basename)) return true;
  if (rel.startsWith('.github/workflows/')) return true;
  if (/\.(config|rc)\.(js|ts|mjs|cjs|json)$/.test(basename)) return true;
  return false;
}

function isTestFile(rel: string): boolean {
  return rel.includes('__tests__/') ||
    rel.includes('__mocks__/') ||
    rel.includes('.test.') ||
    rel.includes('.spec.') ||
    rel.includes('/test/') ||
    rel.includes('/tests/') ||
    rel.includes('/e2e/') ||
    rel.endsWith('.test.ts') ||
    rel.endsWith('.spec.ts') ||
    rel.endsWith('.test.tsx') ||
    rel.endsWith('.spec.tsx');
}

function isServerPath(rel: string): boolean {
  return rel.match(/^app\/api\//) !== null ||
    rel.match(/^src\/app\/api\//) !== null ||
    rel.match(/^pages\/api\//) !== null ||
    rel.match(/^src\/pages\/api\//) !== null ||
    rel.match(/\/server\//) !== null ||
    rel.match(/\/lib\/server\//) !== null ||
    rel.match(/\/services\//) !== null ||
    rel === 'middleware.ts' ||
    rel === 'middleware.js' ||
    rel === 'src/middleware.ts' ||
    rel.match(/\/middleware\.(ts|js)$/) !== null ||
    rel.match(/\/api\/.*\.(ts|js)$/) !== null;
}

function isClientPath(rel: string): boolean {
  return rel.startsWith('components/') ||
    rel.startsWith('src/components/') ||
    rel.startsWith('app/') && rel.endsWith('page.tsx') ||
    rel.startsWith('app/') && rel.endsWith('page.jsx') ||
    rel.startsWith('pages/') && !rel.includes('/api/') ||
    rel.startsWith('src/pages/') && !rel.includes('/api/');
}

function isSharedPath(rel: string): boolean {
  return rel.startsWith('lib/') ||
    rel.startsWith('src/lib/') ||
    rel.startsWith('utils/') ||
    rel.startsWith('src/utils/') ||
    rel.startsWith('hooks/') ||
    rel.startsWith('src/hooks/') ||
    rel.startsWith('shared/') ||
    rel.startsWith('src/shared/') ||
    rel.startsWith('types/') ||
    rel.startsWith('src/types/');
}

function classifyOne(file: ScannedFile): FileClassification {
  const rel = file.relativePath;
  const content = file.content;
  const reasons: string[] = [];

  // Config files (check early — highest priority for structural files)
  if (isConfigFile(rel)) {
    return { file: rel, kind: 'config', confidence: 'high', reasons: ['Configuration file by name/path convention'] };
  }

  // Public / static assets
  if (rel.startsWith('public/') || rel.startsWith('static/') || rel.startsWith('assets/')) {
    return { file: rel, kind: 'public', confidence: 'high', reasons: ['In public/static/assets directory'] };
  }

  // Test files
  if (isTestFile(rel)) {
    return { file: rel, kind: 'test', confidence: 'high', reasons: ['Test file by path pattern (.test., .spec., __tests__)'] };
  }

  // Explicit React / Next.js directives override everything
  if (/"use client"|'use client'/.test(content)) {
    reasons.push('"use client" directive present');
    return { file: rel, kind: 'client', confidence: 'high', reasons };
  }
  if (/"use server"|'use server'/.test(content)) {
    reasons.push('"use server" directive present');
    return { file: rel, kind: 'server', confidence: 'high', reasons };
  }

  // Strong server path signals
  if (isServerPath(rel)) {
    reasons.push('Server path pattern (app/api, pages/api, /server/, middleware)');
    const kind: FileKind = 'server';

    // Check if it has browser APIs mixed in (unusual — lower confidence)
    if (BROWSER_APIS.test(content)) {
      reasons.push('Contains browser APIs despite server path');
      return { file: rel, kind, confidence: 'medium', reasons };
    }
    return { file: rel, kind, confidence: 'high', reasons };
  }

  // Strong client path signals
  if (isClientPath(rel)) {
    reasons.push('Client path pattern (components/, pages/, page.tsx)');
    return { file: rel, kind: 'client', confidence: 'medium', reasons };
  }

  // Content-based classification
  if (SERVER_ONLY_APIS.test(content)) {
    reasons.push('Uses server-only Node.js APIs (fs, child_process, process.env without NEXT_PUBLIC_)');
    return { file: rel, kind: 'server', confidence: 'medium', reasons };
  }

  if (BROWSER_APIS.test(content)) {
    reasons.push('Uses browser-only APIs (window, document, localStorage)');
    return { file: rel, kind: 'client', confidence: 'medium', reasons };
  }

  // Path-based shared heuristic
  if (isSharedPath(rel)) {
    reasons.push('Shared utility path (lib/, utils/, hooks/, types/)');
    return { file: rel, kind: 'shared', confidence: 'low', reasons };
  }

  return { file: rel, kind: 'unknown', confidence: 'low', reasons: ['No clear classification signals found'] };
}

export async function classifyFiles(files: ScannedFile[]): Promise<FileClassification[]> {
  const result: FileClassification[] = [];
  for (let fi = 0; fi < files.length; fi++) {
    result.push(classifyOne(files[fi]));
    // Yield every 100 files so the event loop stays free for the spinner
    if (fi > 0 && fi % 100 === 0) await new Promise<void>(resolve => setImmediate(resolve));
  }
  return result;
}
