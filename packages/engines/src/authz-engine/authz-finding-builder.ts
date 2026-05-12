import { randomBytes } from 'crypto';
import type { AuthzFinding, Severity, StaticCorrelation } from '@cybermat/shared';

function id(): string {
  return randomBytes(4).toString('hex');
}

function summary(findings: AuthzFinding[]) {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  for (const f of findings) { c[f.severity]++; c.total++; }
  return c;
}

function scoreFindings(findings: AuthzFinding[]): number {
  const weights: Record<string, number> = { critical: 25, high: 12, medium: 5, low: 2, info: 0 };
  const deduction = findings.reduce((acc, f) => acc + (weights[f.severity] ?? 0), 0);
  return Math.max(0, 100 - deduction);
}

export const AuthzFindingBuilder = {
  anonymousAccess(url: string, status: number, sensitiveFields: string[], correlation?: StaticCorrelation): AuthzFinding {
    const hasSensitive = sensitiveFields.length > 0;
    return {
      id: `authz-anon-${id()}`,
      ruleId: 'authz.anonymous-protected-route-accessible',
      title: 'Protected route accessible without authentication',
      severity: hasSensitive ? 'high' : 'medium',
      confidence: 'high',
      owasp: ['A01 Broken Access Control', 'A07 Authentication Failures'],
      category: 'Broken Access Control',
      cwe: ['CWE-284', 'CWE-306'],
      layer: 'authz',
      url,
      statusCode: status,
      profileUsed: 'anonymous',
      sensitiveFields,
      staticCorrelation: correlation,
      evidence: {
        reason: `Route returned HTTP ${status} to an unauthenticated request${hasSensitive ? ` and included sensitive fields: ${sensitiveFields.join(', ')}` : ''}`,
      },
      impact: 'Unauthenticated users can access data or functionality that should require login.',
      recommendation: 'Enforce authentication server-side on every protected route. Do not rely on client-side redirects.',
      tags: ['authz', 'authentication', 'anonymous-access'],
    };
  },

  verticalPrivilege(url: string, profileName: string, status: number, sensitiveFields: string[], correlation?: StaticCorrelation): AuthzFinding {
    return {
      id: `authz-vpriv-${id()}`,
      ruleId: 'authz.low-priv-user-admin-route',
      title: 'Low-privilege user can access admin/privileged route',
      severity: 'high',
      confidence: 'high',
      owasp: ['A01 Broken Access Control'],
      category: 'Broken Access Control',
      cwe: ['CWE-284', 'CWE-269'],
      layer: 'authz',
      url,
      statusCode: status,
      profileUsed: profileName,
      sensitiveFields,
      staticCorrelation: correlation,
      evidence: {
        reason: `Route returned HTTP ${status} to profile "${profileName}" (low-privilege user)${sensitiveFields.length ? `. Sensitive fields: ${sensitiveFields.join(', ')}` : ''}`,
      },
      impact: 'A regular user can access admin functionality or data, leading to privilege escalation.',
      recommendation: 'Implement role-based access control (RBAC). Check the user\'s role server-side on every admin route.',
      tags: ['authz', 'privilege-escalation', 'vertical-idor'],
    };
  },

  horizontalIdor(url: string, ownerProfile: string, accessorProfile: string, status: number, sensitiveFields: string[]): AuthzFinding {
    return {
      id: `authz-idor-${id()}`,
      ruleId: 'authz.horizontal-idor-configured-resource',
      title: `IDOR: ${accessorProfile} can access ${ownerProfile}'s resource`,
      severity: 'high',
      confidence: 'high',
      owasp: ['A01 Broken Access Control'],
      category: 'IDOR / BOLA',
      cwe: ['CWE-284', 'CWE-639'],
      layer: 'authz',
      url,
      statusCode: status,
      profileUsed: accessorProfile,
      targetProfileName: ownerProfile,
      sensitiveFields,
      evidence: {
        reason: `Profile "${accessorProfile}" retrieved HTTP ${status} from a resource owned by "${ownerProfile}". No ownership check detected.`,
      },
      impact: 'Any authenticated user can read or modify other users\' private data by guessing or incrementing IDs.',
      recommendation: 'Verify resource ownership server-side. Never trust user-supplied IDs to determine access — always compare against the authenticated user\'s identity.',
      tags: ['authz', 'idor', 'bola', 'horizontal'],
    };
  },

  sensitiveAnonymousResponse(url: string, sensitiveFields: string[]): AuthzFinding {
    return {
      id: `authz-sens-${id()}`,
      ruleId: 'authz.sensitive-response-to-anonymous',
      title: 'Sensitive data returned to anonymous request',
      severity: 'high',
      confidence: 'medium',
      owasp: ['A01 Broken Access Control', 'A07 Authentication Failures'],
      category: 'Data Exposure',
      cwe: ['CWE-200', 'CWE-284'],
      layer: 'authz',
      url,
      profileUsed: 'anonymous',
      sensitiveFields,
      evidence: {
        reason: `Anonymous request received a response containing sensitive fields: ${sensitiveFields.join(', ')}`,
      },
      impact: 'Private user data is exposed without any authentication requirement.',
      recommendation: 'Add server-side authentication enforcement. Return minimal data in error/unauthorized responses.',
      tags: ['authz', 'data-exposure', 'anonymous'],
    };
  },

  methodWithoutAuth(url: string, methods: string[]): AuthzFinding {
    return {
      id: `authz-meth-${id()}`,
      ruleId: 'authz.mutation-methods-without-auth',
      title: 'Sensitive route exposes mutation methods without authentication',
      severity: 'medium',
      confidence: 'medium',
      owasp: ['A01 Broken Access Control'],
      category: 'Broken Access Control',
      cwe: ['CWE-284'],
      layer: 'authz',
      url,
      profileUsed: 'anonymous',
      evidence: {
        reason: `Route ${url} allows ${methods.join(', ')} without authentication`,
      },
      impact: 'Unauthenticated users may be able to modify or delete data.',
      recommendation: 'Restrict mutation methods (POST, PUT, PATCH, DELETE) to authenticated users only.',
      tags: ['authz', 'method-authorization'],
    };
  },

  summary,
  score: scoreFindings,
};

export type { Severity };
