import type { ResponseSnapshot } from '@cybermat/shared';

export type ComparisonVerdict = 'pass' | 'suspicious' | 'fail';

export interface ComparisonResult {
  sameStatus: boolean;
  similarContentLength: boolean;
  sameJsonKeys: boolean;
  overlappingSensitiveFields: string[];
  verdict: ComparisonVerdict;
  reason: string;
}

export function compareResponses(
  authorized: ResponseSnapshot,
  unauthorized: ResponseSnapshot,
): ComparisonResult {
  const sameStatus = authorized.status === unauthorized.status;
  const lengthDiff = Math.abs(authorized.contentLength - unauthorized.contentLength);
  const similarContentLength = lengthDiff < 100 || lengthDiff / Math.max(authorized.contentLength, 1) < 0.15;

  const authKeys = new Set(authorized.jsonKeys);
  const sameJsonKeys =
    unauthorized.jsonKeys.length > 0 &&
    unauthorized.jsonKeys.every(k => authKeys.has(k));

  const authFields = new Set(authorized.sensitiveFields);
  const overlappingSensitiveFields = unauthorized.sensitiveFields.filter(f => authFields.has(f));

  // The unauthorized response should get 401/403/redirect (3xx)
  const isGatedStatus = [401, 403].includes(unauthorized.status) || (unauthorized.status >= 300 && unauthorized.status < 400);

  if (isGatedStatus) {
    return { sameStatus, similarContentLength, sameJsonKeys, overlappingSensitiveFields, verdict: 'pass', reason: 'Access correctly denied' };
  }

  if (unauthorized.status === 0 || unauthorized.status >= 500) {
    return { sameStatus, similarContentLength, sameJsonKeys, overlappingSensitiveFields, verdict: 'pass', reason: 'Server error or unreachable' };
  }

  if (unauthorized.status === 200 && sameJsonKeys && overlappingSensitiveFields.length > 0) {
    return { sameStatus, similarContentLength, sameJsonKeys, overlappingSensitiveFields, verdict: 'fail', reason: 'Same sensitive fields returned to unauthorized profile' };
  }

  if (unauthorized.status === 200 && (sameJsonKeys || similarContentLength)) {
    return { sameStatus, similarContentLength, sameJsonKeys, overlappingSensitiveFields, verdict: 'suspicious', reason: 'Similar response returned to unauthorized profile' };
  }

  if (unauthorized.status === 200) {
    return { sameStatus, similarContentLength, sameJsonKeys, overlappingSensitiveFields, verdict: 'suspicious', reason: 'Route returned 200 to unauthorized profile' };
  }

  return { sameStatus, similarContentLength, sameJsonKeys, overlappingSensitiveFields, verdict: 'pass', reason: `Status ${unauthorized.status}` };
}
