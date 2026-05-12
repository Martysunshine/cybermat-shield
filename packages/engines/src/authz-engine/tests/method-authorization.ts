import type { AuthzFinding, AuthProfile, AccessRouteCandidate } from '@cybermat/shared';
import { HttpAuthClient } from '../http-auth-client';
import { AuthzFindingBuilder } from '../authz-finding-builder';

const UNSAFE_METHODS_IN_ALLOW = ['POST', 'PUT', 'PATCH', 'DELETE'];

export async function runMethodAuthorizationTests(
  baseUrl: string,
  candidates: AccessRouteCandidate[],
  anonymous: AuthProfile,
  client: HttpAuthClient,
  requestBudget: { remaining: number },
): Promise<AuthzFinding[]> {
  const findings: AuthzFinding[] = [];
  const sensitive = candidates.filter(c => !c.destructive && c.riskTags.includes('sensitive'));

  for (const candidate of sensitive) {
    if (requestBudget.remaining <= 0) break;
    requestBudget.remaining--;

    const url = baseUrl.replace(/\/$/, '') + candidate.route;
    const result = await client.head(url, anonymous);

    if (result.status === 0 || result.error) continue;

    // Check Allow header for unsafe methods on anonymous-accessible route
    const allowHeader = result.headers?.['allow'] ?? '';
    const exposedMethods = UNSAFE_METHODS_IN_ALLOW.filter(m =>
      allowHeader.toUpperCase().includes(m),
    );

    // Only flag if the route is accessible without auth AND exposes mutation methods
    if (result.status === 200 && exposedMethods.length > 0) {
      findings.push(AuthzFindingBuilder.methodWithoutAuth(url, exposedMethods));
    }
  }

  return findings;
}
