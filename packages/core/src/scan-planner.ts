import type { ScanPlan, ScanMode, ScannerConfig } from '@cybermat/shared';

type ScanCommand = 'scan' | 'scan-runtime' | 'scan-auth' | 'full-scan';

interface PlanOptions {
  targetPath?: string;
  targetUrl?: string;
  authProfiles?: string[];
  config: ScannerConfig;
}

const CODE_MODE: ScanMode = {
  layer: 'code',
  enabled: true,
  requiresTargetUrl: false,
  requiresAuthProfiles: false,
  safeByDefault: true,
};

const RUNTIME_MODE: ScanMode = {
  layer: 'runtime',
  enabled: false,
  requiresTargetUrl: true,
  requiresAuthProfiles: false,
  safeByDefault: true,
};

const AUTHZ_MODE: ScanMode = {
  layer: 'authz',
  enabled: false,
  requiresTargetUrl: true,
  requiresAuthProfiles: true,
  safeByDefault: true,
};

/**
 * Decides which scanner layers run based on the CLI command and available config.
 *
 * cybermat scan .            → code layer only
 * cybermat scan-runtime <u>  → runtime layer (+ code layer context if available)
 * cybermat scan-auth <u>     → authz layer (requires auth profiles)
 * cybermat full-scan .       → code + runtime (if targetUrl) + authz (if profiles)
 */
export function createScanPlan(command: ScanCommand, options: PlanOptions): ScanPlan {
  const { targetPath, targetUrl, authProfiles, config } = options;
  const hasUrl = Boolean(targetUrl);
  const hasProfiles = Boolean(authProfiles && authProfiles.length > 0);

  switch (command) {
    case 'scan':
      return {
        targetPath,
        layers: [{ ...CODE_MODE, enabled: true }],
        config,
      };

    case 'scan-runtime':
      if (!hasUrl) throw new Error('scan-runtime requires a target URL: cybermat scan-runtime <url>');
      return {
        targetUrl,
        layers: [
          { ...CODE_MODE, enabled: false },
          { ...RUNTIME_MODE, enabled: true },
        ],
        config,
      };

    case 'scan-auth':
      if (!hasUrl) throw new Error('scan-auth requires a target URL: cybermat scan-auth <url>');
      if (!hasProfiles) {
        throw new Error(
          'scan-auth requires auth profiles. Run: cybermat auth init — then configure .cybermat/auth/',
        );
      }
      return {
        targetUrl,
        layers: [
          { ...CODE_MODE, enabled: false },
          { ...RUNTIME_MODE, enabled: false },
          { ...AUTHZ_MODE, enabled: true },
        ],
        config,
      };

    case 'full-scan':
      return {
        targetPath,
        targetUrl,
        layers: [
          { ...CODE_MODE, enabled: true },
          { ...RUNTIME_MODE, enabled: hasUrl },
          { ...AUTHZ_MODE, enabled: hasUrl && hasProfiles },
        ],
        config,
      };
  }
}

/** Returns a human-readable summary of what layers will run */
export function describeScanPlan(plan: ScanPlan): string {
  const active = plan.layers
    .filter(m => m.enabled)
    .map(m => m.layer)
    .join(', ');
  const disabled = plan.layers
    .filter(m => !m.enabled)
    .map(m => {
      const reason = m.requiresTargetUrl && !plan.targetUrl
        ? 'no targetUrl'
        : m.requiresAuthProfiles
        ? 'no auth profiles'
        : 'disabled';
      return `${m.layer} (${reason})`;
    });

  const lines = [`Layers: ${active || 'none'}`];
  if (disabled.length) lines.push(`Skipped: ${disabled.join(', ')}`);
  return lines.join(' | ');
}
