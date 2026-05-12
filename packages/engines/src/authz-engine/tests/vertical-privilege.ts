import type { AuthzFinding, AuthProfile, AccessRouteCandidate, RouteInfo } from '@cybermat/shared';
import { HttpAuthClient } from '../http-auth-client';
import { analyzeSensitiveResponse } from '../sensitive-response-analyzer';
import { AuthzFindingBuilder } from '../authz-finding-builder';
import { correlateRoute } from '../static-correlation';

const ADMIN_PATTERNS = [/\/admin/i, /\/internal/i, /\/superuser/i, /\/manage/i];

function isAdminRoute(route: string): boolean {
  return ADMIN_PATTERNS.some(p => p.test(route));
}

export async function runVerticalPrivilegeTests(
  baseUrl: string,
  candidates: AccessRouteCandidate[],
  lowPrivProfiles: AuthProfile[],
  adminProfile: AuthProfile | undefined,
  staticRoutes: RouteInfo[],
  client: HttpAuthClient,
  requestBudget: { remaining: number },
): Promise<AuthzFinding[]> {
  const findings: AuthzFinding[] = [];
  const adminCandidates = candidates.filter(c => !c.destructive && isAdminRoute(c.route));

  for (const candidate of adminCandidates) {
    for (const profile of lowPrivProfiles) {
      if (requestBudget.remaining <= 0) break;
      requestBudget.remaining--;

      const url = baseUrl.replace(/\/$/, '') + candidate.route;
      const result = await client.probe(url, profile);

      if (result.status === 0 || result.error) continue;
      // 401/403/3xx = correctly blocked
      if (result.status === 401 || result.status === 403 || (result.status >= 300 && result.status < 400)) continue;

      if (result.status === 200) {
        const signals = analyzeSensitiveResponse(result.body);
        const sensitiveFields = signals.map(s => s.field);
        const correlation = correlateRoute(candidate.route, staticRoutes);
        findings.push(AuthzFindingBuilder.verticalPrivilege(url, profile.name, result.status, sensitiveFields, correlation));
      }
    }
  }

  return findings;
}
