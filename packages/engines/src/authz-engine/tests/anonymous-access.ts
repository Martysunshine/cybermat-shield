import type { AuthzFinding, AuthProfile, AccessRouteCandidate } from '@cybermat/shared';
import { HttpAuthClient } from '../http-auth-client';
import { analyzeSensitiveResponse, isSensitiveResponse } from '../sensitive-response-analyzer';
import { AuthzFindingBuilder } from '../authz-finding-builder';

export async function runAnonymousAccessTests(
  baseUrl: string,
  candidates: AccessRouteCandidate[],
  anonymous: AuthProfile,
  client: HttpAuthClient,
  requestBudget: { remaining: number },
): Promise<AuthzFinding[]> {
  const findings: AuthzFinding[] = [];
  const testable = candidates.filter(c => !c.destructive && c.requiresAuthExpected);

  for (const candidate of testable) {
    if (requestBudget.remaining <= 0) break;
    requestBudget.remaining--;

    const url = baseUrl.replace(/\/$/, '') + candidate.route;
    const result = await client.probe(url, anonymous);

    if (result.status === 0 || result.error) continue;

    const signals = analyzeSensitiveResponse(result.body);
    const sensitiveFields = signals.map(s => s.field);

    if (result.status === 200 && isSensitiveResponse(signals)) {
      findings.push(AuthzFindingBuilder.sensitiveAnonymousResponse(url, sensitiveFields));
    } else if (result.status === 200) {
      findings.push(AuthzFindingBuilder.anonymousAccess(url, result.status, sensitiveFields));
    }
  }

  return findings;
}
