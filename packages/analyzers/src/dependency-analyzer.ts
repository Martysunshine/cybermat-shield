import type { ScannedFile } from '@cybermat/shared';

export interface DependencyRisk {
  name: string;
  version: string;
  riskType: 'wildcard-version' | 'lifecycle-script' | 'no-lockfile';
  severity: 'high' | 'medium' | 'low';
  detail: string;
}

export interface DependencyAnalysisResult {
  risks: DependencyRisk[];
  totalDeps: number;
  directDeps: number;
}

export function analyzeDependencies(
  files: ScannedFile[],
  packageJson?: Record<string, unknown>,
): DependencyAnalysisResult {
  const risks: DependencyRisk[] = [];

  if (!packageJson) return { risks, totalDeps: 0, directDeps: 0 };

  const deps = (packageJson.dependencies as Record<string, string>) ?? {};
  const devDeps = (packageJson.devDependencies as Record<string, string>) ?? {};
  const allDeps = { ...deps, ...devDeps };

  const directDeps = Object.keys(deps).length;
  const totalDeps = Object.keys(allDeps).length;

  // Wildcard or overly broad versions
  for (const [name, version] of Object.entries(allDeps)) {
    if (version === '*' || version === 'x') {
      risks.push({ name, version, riskType: 'wildcard-version', severity: 'high', detail: `Wildcard version "${version}" — any version may be installed including breaking or malicious releases` });
    } else if (version.startsWith('>') || version === 'latest') {
      risks.push({ name, version, riskType: 'wildcard-version', severity: 'medium', detail: `Overly broad version constraint "${version}" — exact version not pinned` });
    }
  }

  // Lifecycle scripts (install/postinstall can run arbitrary code)
  const scripts = (packageJson.scripts as Record<string, string>) ?? {};
  for (const [hook, cmd] of Object.entries(scripts)) {
    if (['install', 'postinstall', 'preinstall'].includes(hook)) {
      risks.push({
        name: 'package.json lifecycle script',
        version: '-',
        riskType: 'lifecycle-script',
        severity: 'medium',
        detail: `"${hook}" script runs on install: ${String(cmd).slice(0, 80)}`,
      });
    }
  }

  // Missing lockfile
  const hasLockfile = files.some(f =>
    f.relativePath === 'package-lock.json' ||
    f.relativePath === 'pnpm-lock.yaml' ||
    f.relativePath === 'yarn.lock' ||
    f.relativePath === 'bun.lockb'
  );
  if (!hasLockfile) {
    risks.push({
      name: 'lockfile',
      version: '-',
      riskType: 'no-lockfile',
      severity: 'medium',
      detail: 'No lockfile found (package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lockb). Dependency versions are not pinned.',
    });
  }

  return { risks, totalDeps, directDeps };
}
