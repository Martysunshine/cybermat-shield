import type { AuthzFinding, AuthProfile, AccessControlTestConfig } from '@cybermat/shared';
import { HttpAuthClient } from '../http-auth-client';
import { analyzeSensitiveResponse } from '../sensitive-response-analyzer';
import { AuthzFindingBuilder } from '../authz-finding-builder';
import { compareResponses } from '../response-comparator';

export async function runHorizontalIdorTests(
  baseUrl: string,
  tests: AccessControlTestConfig[],
  profiles: Record<string, AuthProfile>,
  client: HttpAuthClient,
  requestBudget: { remaining: number },
): Promise<{ findings: AuthzFinding[]; pairsTested: number }> {
  const findings: AuthzFinding[] = [];
  let pairsTested = 0;

  const userA = profiles['userA'];
  const userB = profiles['userB'];
  if (!userA || !userB) return { findings, pairsTested };

  for (const test of tests) {
    if (test.type !== 'horizontal') continue;

    for (const resource of test.userAOwns ?? []) {
      if (requestBudget.remaining <= 0) break;
      pairsTested++;

      const url = baseUrl.replace(/\/$/, '') + resource;

      // userA should succeed
      const authorizedResult = await client.probe(url, userA);
      requestBudget.remaining--;
      if (requestBudget.remaining <= 0) break;

      // userB should NOT succeed
      const unauthorizedResult = await client.probe(url, userB);
      requestBudget.remaining--;

      const authSnapshot = HttpAuthClient.toSnapshot(authorizedResult);
      const unauthSnapshot = HttpAuthClient.toSnapshot(unauthorizedResult);
      const signals = analyzeSensitiveResponse(unauthorizedResult.body);
      authSnapshot.sensitiveFields = analyzeSensitiveResponse(authorizedResult.body).map(s => s.field);
      unauthSnapshot.sensitiveFields = signals.map(s => s.field);

      const comparison = compareResponses(authSnapshot, unauthSnapshot);

      if (comparison.verdict === 'fail' || comparison.verdict === 'suspicious') {
        findings.push(
          AuthzFindingBuilder.horizontalIdor(url, 'userA', 'userB', unauthorizedResult.status, unauthSnapshot.sensitiveFields),
        );
      }
    }

    for (const resource of test.userBOwns ?? []) {
      if (requestBudget.remaining <= 0) break;
      pairsTested++;

      const url = baseUrl.replace(/\/$/, '') + resource;

      const authorizedResult = await client.probe(url, userB);
      requestBudget.remaining--;
      if (requestBudget.remaining <= 0) break;

      const unauthorizedResult = await client.probe(url, userA);
      requestBudget.remaining--;

      const authSnapshot = HttpAuthClient.toSnapshot(authorizedResult);
      const unauthSnapshot = HttpAuthClient.toSnapshot(unauthorizedResult);
      unauthSnapshot.sensitiveFields = analyzeSensitiveResponse(unauthorizedResult.body).map(s => s.field);

      const comparison = compareResponses(authSnapshot, unauthSnapshot);

      if (comparison.verdict === 'fail' || comparison.verdict === 'suspicious') {
        findings.push(
          AuthzFindingBuilder.horizontalIdor(url, 'userB', 'userA', unauthorizedResult.status, unauthSnapshot.sensitiveFields),
        );
      }
    }
  }

  return { findings, pairsTested };
}
