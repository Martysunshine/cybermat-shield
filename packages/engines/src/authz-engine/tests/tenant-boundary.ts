import type { AuthzFinding, RouteInfo } from '@cybermat/shared';

// Static detection only — looks for tenant/org ID patterns in route files
// Runtime tenant cross-access requires config-driven resource pairs (handled in horizontal-idor)

const TENANT_ID_PATTERNS = [
  /organizationId|orgId|tenantId|workspaceId|teamId|groupId/,
];

const TENANT_CHECK_PATTERNS = [
  /\.organizationId\s*===\s*user/i,
  /checkMembership/i,
  /verifyTenantAccess/i,
  /assertTenant/i,
];

export interface TenantSignal {
  route: string;
  file: string;
  reason: string;
}

export function detectTenantBoundaryRisks(staticRoutes: RouteInfo[]): TenantSignal[] {
  const signals: TenantSignal[] = [];

  for (const route of staticRoutes) {
    if (!route.isApi) continue;

    // Check if route URL contains tenant-like segments
    const hasTenantInRoute = TENANT_ID_PATTERNS.some(p => p.test(route.route));
    const acceptsUserInput = route.acceptsUserInput;

    if (hasTenantInRoute && acceptsUserInput && !route.hasRoleCheck) {
      signals.push({
        route: route.route,
        file: route.file,
        reason: 'Route accepts tenant/org ID from client without detected membership check',
      });
    }
  }

  return signals;
}

export function tenantSignalsToFindings(signals: TenantSignal[]): AuthzFinding[] {
  return signals.map(signal => ({
    id: `authz-tenant-${Buffer.from(signal.route).toString('hex').slice(0, 8)}`,
    ruleId: 'authz.tenant-boundary-risk',
    title: 'Potential tenant boundary issue detected in route',
    severity: 'medium' as const,
    confidence: 'low' as const,
    owasp: ['A01 Broken Access Control', 'A06 Insecure Design'],
    category: 'Tenant Boundary',
    cwe: ['CWE-284'],
    layer: 'authz' as const,
    url: signal.route,
    file: signal.file,
    evidence: { reason: signal.reason },
    impact: 'Users may be able to access data from other organizations or tenants.',
    recommendation: 'Verify tenant membership server-side on every request. Filter all queries by the authenticated user\'s tenantId.',
    tags: ['authz', 'multi-tenant', 'idor'],
  }));
}
