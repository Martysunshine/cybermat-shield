import type { ScannedFile } from '@cybermat/shared';

export interface ConfigRisk {
  file: string;
  riskType: string;
  detail: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface ConfigAnalysisResult {
  risks: ConfigRisk[];
}

export function analyzeConfig(files: ScannedFile[]): ConfigAnalysisResult {
  const risks: ConfigRisk[] = [];

  // Firebase security rules: allow read, write: if true
  const firebaseRules = files.filter(f =>
    f.relativePath.includes('firestore.rules') ||
    f.relativePath.includes('database.rules.json') ||
    f.relativePath.includes('storage.rules') ||
    f.relativePath.endsWith('.rules')
  );
  for (const file of firebaseRules) {
    if (/allow\s+(?:read|write)\s*:\s*if\s+true/.test(file.content)) {
      risks.push({
        file: file.relativePath,
        riskType: 'firebase-permissive-rules',
        severity: 'critical',
        detail: 'Firebase security rules allow read/write for all users (if true) — database is publicly readable/writable',
      });
    } else if (/allow\s+(?:read|write)\s*;/.test(file.content)) {
      risks.push({
        file: file.relativePath,
        riskType: 'firebase-permissive-rules',
        severity: 'critical',
        detail: 'Firebase security rules may allow unrestricted access — verify auth conditions',
      });
    }
  }

  // next.config.js: source maps exposed
  const nextConfig = files.find(f =>
    f.relativePath === 'next.config.js' ||
    f.relativePath === 'next.config.ts' ||
    f.relativePath === 'next.config.mjs'
  );
  if (nextConfig && /productionBrowserSourceMaps\s*:\s*true/.test(nextConfig.content)) {
    risks.push({
      file: nextConfig.relativePath,
      riskType: 'source-maps-enabled',
      severity: 'medium',
      detail: 'productionBrowserSourceMaps: true exposes original source to production users',
    });
  }

  // Supabase: no RLS migration files detected
  const hasSupabaseClient = files.some(f =>
    f.content.includes('@supabase/supabase-js') || f.content.includes('createClient')
  );
  const hasMigrations = files.some(f =>
    f.relativePath.includes('/migrations/') || f.relativePath.endsWith('.sql')
  );
  const hasPolicies = files.some(f =>
    f.content.toLowerCase().includes('row level security') ||
    f.content.toLowerCase().includes('enable rls') ||
    f.content.toLowerCase().includes('create policy')
  );
  if (hasSupabaseClient && !hasMigrations && !hasPolicies) {
    risks.push({
      file: 'supabase (project-wide)',
      riskType: 'supabase-missing-rls',
      severity: 'high',
      detail: 'Supabase detected but no Row Level Security (RLS) policies or migrations found. Tables may be publicly accessible.',
    });
  }

  return { risks };
}
