import type { ScannedFile } from '@cybermat/shared';

export interface DependencyRisk {
  name: string;
  version: string;
  riskType: 'known-vuln' | 'wildcard-version' | 'lifecycle-script' | 'deprecated' | 'typosquat';
  severity: 'critical' | 'high' | 'medium' | 'low';
  detail: string;
}

export interface DependencyAnalysisResult {
  risks: DependencyRisk[];
  totalDeps: number;
  directDeps: number;
}

/**
 * Analyzes package.json and lockfiles for dependency risks.
 * Phase 4 implementation: integrates with npm audit / OSV / Trivy adapter.
 */
export function analyzeDependencies(
  _files: ScannedFile[],
  _packageJson?: Record<string, unknown>,
): DependencyAnalysisResult {
  // Phase 4: parse package.json + lockfiles, check for wildcard versions,
  // suspicious lifecycle scripts, and optionally query OSV/npm audit JSON output.
  return { risks: [], totalDeps: 0, directDeps: 0 };
}
