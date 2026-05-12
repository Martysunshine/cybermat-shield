import type { AuthScanConfig, AuthScanReport, AuthProfile, RouteInfo } from '@cybermat/shared';
import { AuthProfileLoader } from './auth-profile-loader';
import { HttpAuthClient } from './http-auth-client';
import { discoverCandidates } from './route-discoverer';
import { AuthzFindingBuilder } from './authz-finding-builder';
import { detectTenantBoundaryRisks, tenantSignalsToFindings } from './tests/tenant-boundary';
import { runAnonymousAccessTests } from './tests/anonymous-access';
import { runVerticalPrivilegeTests } from './tests/vertical-privilege';
import { runHorizontalIdorTests } from './tests/horizontal-idor';
import { runMethodAuthorizationTests } from './tests/method-authorization';

const RECOMMENDATIONS = [
  'Enforce authentication server-side on every protected route',
  'Check resource ownership before returning data (do not trust IDs from the client)',
  'Implement role-based access control (RBAC) for admin routes',
  'Never trust user_id or owner_id from the request body or query params',
  'Implement organization/tenant membership checks on multi-tenant routes',
  'Enable Supabase RLS or tighten Firebase security rules',
  'Add audit logging for all access-control decisions',
  'Write automated tests that verify access-control rules across user roles',
];

export class AuthzScanner {
  private readonly config: Required<Omit<AuthScanConfig, 'profiles' | 'accessControlTests'>> & AuthScanConfig;

  constructor(config: AuthScanConfig) {
    this.config = {
      maxAuthzRequests: 75,
      requestDelayMs: 150,
      timeoutMs: 10000,
      ...config,
    };
  }

  async run(staticRoutes: RouteInfo[] = []): Promise<AuthScanReport> {
    const start = Date.now();

    // Load auth profiles
    const profileMap: Record<string, AuthProfile> = {
      anonymous: AuthProfileLoader.anonymous(),
    };

    const warnings: string[] = [];
    for (const [name, cfg] of Object.entries(this.config.profiles)) {
      try {
        profileMap[name] = await AuthProfileLoader.load(name, cfg);
      } catch (err: unknown) {
        warnings.push(`Could not load profile "${name}": ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    if (warnings.length) console.warn('[authz-scanner] Profile warnings:\n' + warnings.join('\n'));

    const profiles = Object.values(profileMap);
    AuthProfileLoader.validate(profiles);

    // Route candidates
    const configRoutes = (this.config.accessControlTests ?? [])
      .flatMap(t => [...(t.userAOwns ?? []), ...(t.userBOwns ?? [])]);
    const candidates = discoverCandidates(staticRoutes, configRoutes);

    const skippedDestructiveRoutes = candidates
      .filter(c => c.destructive)
      .map(c => c.route);

    const client = new HttpAuthClient(this.config.timeoutMs, this.config.requestDelayMs);
    const requestBudget = { remaining: this.config.maxAuthzRequests };

    // Run tests
    const anonymous = profileMap['anonymous'];
    const lowPrivProfiles = profiles.filter(p => p.type !== 'anonymous' && !p.isPrivileged);
    const adminProfile = profiles.find(p => p.isPrivileged);

    const [anonFindings, verticalFindings, methodFindings] = await Promise.all([
      runAnonymousAccessTests(this.config.baseUrl, candidates, anonymous, client, requestBudget),
      runVerticalPrivilegeTests(this.config.baseUrl, candidates, lowPrivProfiles, adminProfile, staticRoutes, client, requestBudget),
      runMethodAuthorizationTests(this.config.baseUrl, candidates, anonymous, client, requestBudget),
    ]);

    const { findings: idorFindings, pairsTested } = await runHorizontalIdorTests(
      this.config.baseUrl,
      this.config.accessControlTests ?? [],
      profileMap,
      client,
      requestBudget,
    );

    // Static tenant boundary detection
    const tenantSignals = detectTenantBoundaryRisks(staticRoutes);
    const tenantFindings = tenantSignalsToFindings(tenantSignals);

    const allFindings = [
      ...anonFindings,
      ...verticalFindings,
      ...idorFindings,
      ...tenantFindings,
      ...methodFindings,
    ];

    const summary = AuthzFindingBuilder.summary(allFindings);
    const riskScore = AuthzFindingBuilder.score(allFindings);

    return {
      targetUrl: this.config.baseUrl,
      profilesUsed: profiles.map(p => p.name),
      routesTested: candidates.filter(c => !c.destructive).length,
      resourcePairsTested: pairsTested,
      durationMs: Date.now() - start,
      findings: allFindings,
      summary,
      riskScore,
      skippedDestructiveRoutes,
      recommendations: allFindings.length > 0 ? RECOMMENDATIONS : [],
    };
  }
}
