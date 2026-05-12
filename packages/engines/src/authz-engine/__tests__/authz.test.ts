import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { AuthProfileLoader } from '../auth-profile-loader';
import { analyzeSensitiveResponse, isSensitiveResponse } from '../sensitive-response-analyzer';
import { compareResponses } from '../response-comparator';
import { discoverCandidates } from '../route-discoverer';
import { AuthzFindingBuilder } from '../authz-finding-builder';
import { detectTenantBoundaryRisks } from '../tests/tenant-boundary';
import { correlateRoute } from '../static-correlation';
import type { AuthProfile, RouteInfo, ResponseSnapshot } from '@cybermat/shared';

// ─── AuthProfileLoader ────────────────────────────────────────────────────────

describe('AuthProfileLoader.anonymous', () => {
  it('returns anonymous profile with empty headers', () => {
    const p = AuthProfileLoader.anonymous();
    assert.equal(p.name, 'anonymous');
    assert.equal(p.type, 'anonymous');
    assert.deepEqual(p.headers, {});
  });
});

describe('AuthProfileLoader.validate', () => {
  it('warns when fewer than 2 non-anonymous profiles', () => {
    const profiles: AuthProfile[] = [
      { name: 'anonymous', label: 'Anonymous', type: 'anonymous', headers: {} },
      { name: 'userA', label: 'User A', type: 'cookies', headers: { cookie: 'session=abc' } },
    ];
    const warnings = AuthProfileLoader.validate(profiles);
    assert.ok(warnings.length > 0);
    assert.ok(warnings[0].includes('Horizontal IDOR'));
  });

  it('no warnings when 2 non-anonymous profiles exist', () => {
    const profiles: AuthProfile[] = [
      { name: 'anonymous', label: 'Anonymous', type: 'anonymous', headers: {} },
      { name: 'userA', label: 'User A', type: 'cookies', headers: { cookie: 'session=abc' } },
      { name: 'userB', label: 'User B', type: 'cookies', headers: { cookie: 'session=def' } },
    ];
    assert.deepEqual(AuthProfileLoader.validate(profiles), []);
  });

  it('warns on duplicate profile names', () => {
    const profiles: AuthProfile[] = [
      { name: 'userA', label: 'User A', type: 'cookies', headers: {} },
      { name: 'userA', label: 'User A dup', type: 'cookies', headers: {} },
      { name: 'userB', label: 'User B', type: 'cookies', headers: {} },
    ];
    const warnings = AuthProfileLoader.validate(profiles);
    assert.ok(warnings.some(w => w.includes('Duplicate')));
  });
});

// ─── SensitiveResponseAnalyzer ────────────────────────────────────────────────

describe('analyzeSensitiveResponse', () => {
  it('returns empty for empty body', () => {
    assert.deepEqual(analyzeSensitiveResponse(''), []);
  });

  it('detects email in JSON response', () => {
    const body = JSON.stringify({ email: 'test@example.com', name: 'Test' });
    const signals = analyzeSensitiveResponse(body);
    assert.ok(signals.some(s => s.field === 'email'));
    assert.equal(signals[0].confidence, 'high');
  });

  it('detects nested sensitive fields', () => {
    const body = JSON.stringify({ user: { role: 'admin', passwordHash: 'abc123' } });
    const signals = analyzeSensitiveResponse(body);
    assert.ok(signals.some(s => s.field === 'role'));
    assert.ok(signals.some(s => s.field === 'passwordHash'));
  });

  it('detects fields in arrays', () => {
    const body = JSON.stringify([{ user_id: '1', email: 'a@b.com' }]);
    const signals = analyzeSensitiveResponse(body);
    assert.ok(signals.some(s => s.field === 'email'));
  });

  it('falls back to string matching for non-JSON', () => {
    const body = '<html>{"email": "x@y.com"}</html>';
    const signals = analyzeSensitiveResponse(body);
    assert.ok(signals.some(s => s.field === 'email'));
  });

  it('returns no signals for safe body', () => {
    const body = JSON.stringify({ id: 1, name: 'Widget', price: 9.99 });
    assert.deepEqual(analyzeSensitiveResponse(body), []);
  });
});

describe('isSensitiveResponse', () => {
  it('returns true for high-confidence signal', () => {
    const signals = [{ field: 'email', confidence: 'high' as const, redactedEvidence: '' }];
    assert.ok(isSensitiveResponse(signals));
  });

  it('returns true for 2+ signals regardless of confidence', () => {
    const signals = [
      { field: 'role', confidence: 'medium' as const, redactedEvidence: '' },
      { field: 'token', confidence: 'medium' as const, redactedEvidence: '' },
    ];
    assert.ok(isSensitiveResponse(signals));
  });

  it('returns false for single low-confidence signal', () => {
    const signals = [{ field: 'name', confidence: 'low' as const, redactedEvidence: '' }];
    assert.ok(!isSensitiveResponse(signals));
  });
});

// ─── ResponseComparator ───────────────────────────────────────────────────────

function snap(overrides: Partial<ResponseSnapshot> = {}): ResponseSnapshot {
  return { status: 200, contentLength: 500, jsonKeys: ['id', 'email'], sensitiveFields: ['email'], body: '', ...overrides };
}

describe('compareResponses', () => {
  it('passes when unauthorized gets 401', () => {
    const result = compareResponses(snap(), snap({ status: 401, contentLength: 10, jsonKeys: [], sensitiveFields: [] }));
    assert.equal(result.verdict, 'pass');
  });

  it('passes when unauthorized gets 403', () => {
    const result = compareResponses(snap(), snap({ status: 403 }));
    assert.equal(result.verdict, 'pass');
  });

  it('passes when unauthorized gets 302 redirect', () => {
    const result = compareResponses(snap(), snap({ status: 302, jsonKeys: [], sensitiveFields: [] }));
    assert.equal(result.verdict, 'pass');
  });

  it('fails when unauthorized gets same status + sensitive fields', () => {
    const result = compareResponses(snap(), snap({ status: 200, sensitiveFields: ['email'], jsonKeys: ['id', 'email'] }));
    assert.equal(result.verdict, 'fail');
  });

  it('suspicious when unauthorized gets 200 with matching keys', () => {
    const result = compareResponses(snap(), snap({ status: 200, sensitiveFields: [], jsonKeys: ['id', 'email'] }));
    assert.equal(result.verdict, 'suspicious');
  });

  it('suspicious when unauthorized gets 200 with similar length', () => {
    const result = compareResponses(snap({ contentLength: 500 }), snap({ status: 200, contentLength: 510, jsonKeys: [], sensitiveFields: [] }));
    assert.equal(result.verdict, 'suspicious');
  });

  it('passes when server errors', () => {
    const result = compareResponses(snap(), snap({ status: 500, jsonKeys: [], sensitiveFields: [] }));
    assert.equal(result.verdict, 'pass');
  });
});

// ─── RouteDiscoverer ──────────────────────────────────────────────────────────

describe('discoverCandidates', () => {
  it('includes heuristic known protected paths', () => {
    const candidates = discoverCandidates();
    assert.ok(candidates.some(c => c.route === '/api/admin'));
    assert.ok(candidates.some(c => c.route === '/dashboard'));
  });

  it('includes static routes', () => {
    const routes: RouteInfo[] = [{
      route: '/api/custom',
      file: 'app/api/custom/route.ts',
      framework: 'nextjs',
      isApi: true,
      isPage: false,
      riskTags: [],
    }];
    const candidates = discoverCandidates(routes);
    assert.ok(candidates.some(c => c.route === '/api/custom' && c.source === 'static'));
  });

  it('marks destructive routes correctly', () => {
    const routes: RouteInfo[] = [{
      route: '/api/delete-account',
      file: 'app/api/delete-account/route.ts',
      framework: 'nextjs',
      isApi: true,
      isPage: false,
      riskTags: [],
    }];
    const candidates = discoverCandidates(routes);
    const cand = candidates.find(c => c.route === '/api/delete-account');
    assert.ok(cand?.destructive);
  });

  it('deduplicates routes', () => {
    const routes: RouteInfo[] = [
      { route: '/api/admin', file: 'f.ts', framework: 'nextjs', isApi: true, isPage: false, riskTags: [] },
      { route: '/api/admin', file: 'f.ts', framework: 'nextjs', isApi: true, isPage: false, riskTags: [] },
    ];
    const candidates = discoverCandidates(routes);
    const count = candidates.filter(c => c.route === '/api/admin').length;
    assert.equal(count, 1);
  });

  it('adds riskTags for admin routes', () => {
    const candidates = discoverCandidates();
    const admin = candidates.find(c => c.route === '/api/admin');
    assert.ok(admin?.riskTags.includes('admin'));
  });
});

// ─── AuthzFindingBuilder ──────────────────────────────────────────────────────

describe('AuthzFindingBuilder.anonymousAccess', () => {
  it('creates finding with correct ruleId and owasp', () => {
    const f = AuthzFindingBuilder.anonymousAccess('http://localhost/api/admin', 200, []);
    assert.equal(f.ruleId, 'authz.anonymous-protected-route-accessible');
    assert.ok(f.owasp.includes('A01 Broken Access Control'));
    assert.equal(f.layer, 'authz');
  });

  it('upgrades severity to high when sensitive fields present', () => {
    const f = AuthzFindingBuilder.anonymousAccess('http://localhost/api/admin', 200, ['email', 'role']);
    assert.equal(f.severity, 'high');
  });

  it('uses medium severity for no sensitive fields', () => {
    const f = AuthzFindingBuilder.anonymousAccess('http://localhost/api/test', 200, []);
    assert.equal(f.severity, 'medium');
  });
});

describe('AuthzFindingBuilder.horizontalIdor', () => {
  it('creates IDOR finding with correct profiles', () => {
    const f = AuthzFindingBuilder.horizontalIdor('http://localhost/api/resources/1', 'userA', 'userB', 200, []);
    assert.equal(f.ruleId, 'authz.horizontal-idor-configured-resource');
    assert.equal(f.profileUsed, 'userB');
    assert.equal(f.targetProfileName, 'userA');
    assert.ok(f.owasp.includes('A01 Broken Access Control'));
  });
});

describe('AuthzFindingBuilder.verticalPrivilege', () => {
  it('creates privilege escalation finding', () => {
    const f = AuthzFindingBuilder.verticalPrivilege('http://localhost/api/admin', 'userA', 200, []);
    assert.equal(f.ruleId, 'authz.low-priv-user-admin-route');
    assert.equal(f.severity, 'high');
    assert.equal(f.layer, 'authz');
  });
});

describe('AuthzFindingBuilder.summary', () => {
  it('counts findings by severity', () => {
    const findings = [
      AuthzFindingBuilder.anonymousAccess('http://a', 200, ['email']),
      AuthzFindingBuilder.horizontalIdor('http://b', 'userA', 'userB', 200, []),
    ];
    const s = AuthzFindingBuilder.summary(findings);
    assert.equal(s.total, 2);
    assert.equal(s.high, 2);
  });
});

describe('AuthzFindingBuilder.score', () => {
  it('returns 100 for no findings', () => {
    assert.equal(AuthzFindingBuilder.score([]), 100);
  });

  it('deducts correctly for high findings', () => {
    const findings = [AuthzFindingBuilder.horizontalIdor('http://a', 'userA', 'userB', 200, [])];
    assert.equal(AuthzFindingBuilder.score(findings), 88); // 100 - 12
  });

  it('clamps to 0', () => {
    const findings = Array.from({ length: 10 }, (_, i) =>
      AuthzFindingBuilder.anonymousAccess(`http://a/${i}`, 200, ['email']),
    );
    assert.equal(AuthzFindingBuilder.score(findings), 0);
  });
});

// ─── TenantBoundaryDetection ──────────────────────────────────────────────────

describe('detectTenantBoundaryRisks', () => {
  it('flags route with organizationId param and no role check', () => {
    const routes: RouteInfo[] = [{
      route: '/api/organizationId/members',
      file: 'app/api/[organizationId]/members/route.ts',
      framework: 'nextjs',
      isApi: true,
      isPage: false,
      hasRoleCheck: false,
      acceptsUserInput: true,
      riskTags: [],
    }];
    const signals = detectTenantBoundaryRisks(routes);
    assert.ok(signals.length > 0);
  });

  it('does not flag non-API routes', () => {
    const routes: RouteInfo[] = [{
      route: '/organizationId/members',
      file: 'app/[organizationId]/members/page.tsx',
      framework: 'nextjs',
      isApi: false,
      isPage: true,
      riskTags: [],
    }];
    assert.deepEqual(detectTenantBoundaryRisks(routes), []);
  });
});

// ─── StaticCorrelation ────────────────────────────────────────────────────────

describe('correlateRoute', () => {
  it('returns correlation for admin route with no role check', () => {
    const routes: RouteInfo[] = [{
      route: '/api/admin',
      file: 'app/api/admin/route.ts',
      framework: 'nextjs',
      isApi: true,
      isPage: false,
      requiresAuth: false,
      hasRoleCheck: false,
      riskTags: [],
    }];
    const corr = correlateRoute('/api/admin', routes);
    assert.ok(corr !== undefined);
    assert.ok(corr!.reason.includes('role check'));
  });

  it('returns undefined when route not found in static routes', () => {
    assert.equal(correlateRoute('/api/missing', []), undefined);
  });
});
