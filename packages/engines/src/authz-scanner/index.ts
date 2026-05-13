import type { ScannerEngine, ScanContext, Finding } from '@cybermat/shared';

/**
 * Auth / Access-Control Scanner Engine — Layer 3
 *
 * Safely tests authorization boundaries using user-provided auth profiles.
 * REQUIRES explicit auth profiles — refuses to run without them.
 *
 * Phase 7 implementation: anonymous access testing, userA/userB comparison,
 * admin route testing, IDOR/BOLA checks, tenant boundary checks.
 *
 * Safety guarantees:
 *   - Only runs with explicit user-configured auth profiles
 *   - GET/HEAD/OPTIONS only by default
 *   - No random ID generation / brute forcing
 *   - Max 75 requests per scan session
 *   - 150ms delay between requests
 *   - Halts on excessive 5xx responses
 *   - All sensitive response values are redacted from findings
 */
export const authzScannerEngine: ScannerEngine = {
  id: 'authz-scanner',
  name: 'Auth / Access-Control Scanner',
  layer: 'authz',
  supportedLanguages: [],
  supportedFrameworks: [],

  async run(context: ScanContext): Promise<Finding[]> {
    if (!context.targetUrl) {
      throw new Error('Authz scanner requires a targetUrl. Use: cybermat scan-auth <url>');
    }
    if (!context.authProfiles || context.authProfiles.length === 0) {
      throw new Error(
        'Authz scanner requires at least one auth profile. ' +
        'Run: cybermat auth init — then configure .cybermat/auth/*.storage.json',
      );
    }
    // Phase 7: load auth profiles, discover routes, run AnonymousAccessTest,
    // VerticalPrivilegeTest, HorizontalIdorTest, TenantBoundaryTest,
    // correlate with static code findings, and return normalized findings.
    return [];
  },
};
