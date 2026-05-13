import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { ScopeManager } from '../scope-manager';
import { isDestructiveUrl, isDestructiveForm, isDestructiveUrlOrForm } from '../destructive-guard';
import { analyzeHeaders } from '../header-analyzer';
import { analyzeCookies } from '../cookie-analyzer';
import { analyzeCorsResults } from '../cors-analyzer';
import { analyzeRedirectResults, buildRedirectTestUrls, SAFE_REDIRECT_TARGET } from '../redirect-analyzer';
import { EXPOSED_FILE_CHECKS, analyzeExposedFiles } from '../exposed-file-analyzer';
import { generateMarker, classifyReflectionContext } from '../reflection-analyzer';
import type { CrawledCookie } from '@cybermat/shared';

// ─── ScopeManager ────────────────────────────────────────────────────────────

describe('ScopeManager', () => {
  const scope = new ScopeManager({ baseUrl: 'http://localhost:3000' });

  test('allows same-origin URLs', () => {
    assert.equal(scope.isInScope('http://localhost:3000/api/users'), true);
  });

  test('blocks cross-origin URLs', () => {
    assert.equal(scope.isInScope('https://evil.example/steal'), false);
  });

  test('blocks invalid URLs', () => {
    assert.equal(scope.isInScope('not-a-url'), false);
  });

  test('respects disallowedPaths', () => {
    const s = new ScopeManager({
      baseUrl: 'http://localhost:3000',
      disallowedPaths: ['/admin'],
    });
    assert.equal(s.isInScope('http://localhost:3000/admin/users'), false);
    assert.equal(s.isInScope('http://localhost:3000/users'), true);
  });

  test('withinLimits returns false when pages exceeded', () => {
    const s = new ScopeManager({ baseUrl: 'http://localhost:3000', maxPages: 5 });
    assert.equal(s.withinLimits(5, 0), false);
    assert.equal(s.withinLimits(4, 0), true);
  });

  test('withinDepth enforces maxDepth', () => {
    const s = new ScopeManager({ baseUrl: 'http://localhost:3000', maxDepth: 2 });
    assert.equal(s.withinDepth(2), true);
    assert.equal(s.withinDepth(3), false);
  });
});

// ─── Destructive guard ───────────────────────────────────────────────────────

describe('isDestructiveUrl', () => {
  test('blocks /delete path', () => {
    assert.equal(isDestructiveUrl('http://localhost:3000/api/delete'), true);
  });

  test('blocks /logout path', () => {
    assert.equal(isDestructiveUrl('http://localhost:3000/logout'), true);
  });

  test('blocks /checkout path', () => {
    assert.equal(isDestructiveUrl('http://localhost:3000/checkout'), true);
  });

  test('allows safe paths', () => {
    assert.equal(isDestructiveUrl('http://localhost:3000/api/users'), false);
    assert.equal(isDestructiveUrl('http://localhost:3000/dashboard'), false);
  });

  test('treats invalid URL as destructive', () => {
    assert.equal(isDestructiveUrl('not-a-url'), true);
  });
});

describe('isDestructiveForm', () => {
  test('blocks forms with password fields', () => {
    assert.equal(
      isDestructiveForm({ fields: [{ type: 'password', name: 'pass' }] }),
      true,
    );
  });

  test('blocks forms with file upload fields', () => {
    assert.equal(
      isDestructiveForm({ fields: [{ type: 'file', name: 'upload' }] }),
      true,
    );
  });

  test('blocks forms posting to destructive actions', () => {
    assert.equal(
      isDestructiveForm({ action: 'http://localhost/delete', fields: [] }),
      true,
    );
  });

  test('allows safe forms', () => {
    assert.equal(
      isDestructiveForm({ method: 'GET', fields: [{ type: 'text', name: 'q' }] }),
      false,
    );
  });
});

describe('isDestructiveUrlOrForm', () => {
  test('returns true if URL is destructive even with safe form', () => {
    assert.equal(
      isDestructiveUrlOrForm('http://localhost/logout', { fields: [] }),
      true,
    );
  });

  test('returns true if form is destructive with safe URL', () => {
    assert.equal(
      isDestructiveUrlOrForm('http://localhost/search', { fields: [{ type: 'password' }] }),
      true,
    );
  });
});

// ─── Header analyzer ─────────────────────────────────────────────────────────

describe('analyzeHeaders', () => {
  test('flags missing CSP', () => {
    const findings = analyzeHeaders('http://localhost:3000', {}, false);
    assert.ok(findings.some(f => f.ruleId === 'runtime.missing-csp'));
  });

  test('flags weak CSP with unsafe-inline', () => {
    const findings = analyzeHeaders(
      'http://localhost:3000',
      { 'content-security-policy': "default-src 'self'; script-src 'unsafe-inline'" },
      false,
    );
    assert.ok(findings.some(f => f.ruleId === 'runtime.weak-csp'));
  });

  test('no CSP finding when strong CSP present', () => {
    const findings = analyzeHeaders(
      'http://localhost:3000',
      { 'content-security-policy': "default-src 'self'" },
      false,
    );
    assert.ok(!findings.some(f => f.ruleId === 'runtime.missing-csp'));
    assert.ok(!findings.some(f => f.ruleId === 'runtime.weak-csp'));
  });

  test('flags missing HSTS on HTTPS only', () => {
    const http = analyzeHeaders('http://localhost:3000', {}, false);
    assert.ok(!http.some(f => f.ruleId === 'runtime.missing-hsts'));

    const https = analyzeHeaders('https://localhost:3000', {}, true);
    assert.ok(https.some(f => f.ruleId === 'runtime.missing-hsts'));
  });

  test('no HSTS finding when header present', () => {
    const findings = analyzeHeaders(
      'https://localhost:3000',
      { 'strict-transport-security': 'max-age=31536000' },
      true,
    );
    assert.ok(!findings.some(f => f.ruleId === 'runtime.missing-hsts'));
  });

  test('flags missing X-Frame-Options', () => {
    const findings = analyzeHeaders('http://localhost:3000', {}, false);
    assert.ok(findings.some(f => f.ruleId === 'runtime.missing-x-frame-options'));
  });

  test('no X-Frame-Options finding when frame-ancestors in CSP', () => {
    const findings = analyzeHeaders(
      'http://localhost:3000',
      { 'content-security-policy': "frame-ancestors 'none'" },
      false,
    );
    assert.ok(!findings.some(f => f.ruleId === 'runtime.missing-x-frame-options'));
  });
});

// ─── Cookie analyzer ─────────────────────────────────────────────────────────

describe('analyzeCookies', () => {
  const base: CrawledCookie = {
    name: 'session',
    value: 'abc123xyz',
    secure: true,
    httpOnly: true,
    sameSite: 'Lax',
  };

  test('flags missing HttpOnly on auth cookie', () => {
    const findings = analyzeCookies('http://localhost', [{ ...base, httpOnly: false }], false);
    assert.ok(findings.some(f => f.ruleId === 'runtime.cookie-missing-httponly'));
  });

  test('flags missing Secure on HTTPS for auth cookie', () => {
    const findings = analyzeCookies('https://localhost', [{ ...base, secure: false }], true);
    assert.ok(findings.some(f => f.ruleId === 'runtime.cookie-missing-secure'));
  });

  test('no Secure finding on HTTP', () => {
    const findings = analyzeCookies('http://localhost', [{ ...base, secure: false }], false);
    assert.ok(!findings.some(f => f.ruleId === 'runtime.cookie-missing-secure'));
  });

  test('flags missing SameSite', () => {
    const findings = analyzeCookies('http://localhost', [{ ...base, sameSite: undefined }], false);
    assert.ok(findings.some(f => f.ruleId === 'runtime.cookie-missing-samesite'));
  });

  test('flags JWT-like cookie value', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const findings = analyzeCookies('http://localhost', [{ ...base, value: jwt }], false);
    assert.ok(findings.some(f => f.ruleId === 'runtime.cookie-jwt-value'));
  });

  test('flags long-expiry cookie', () => {
    const farFuture = Math.floor(Date.now() / 1000) + 100 * 86400; // 100 days
    const findings = analyzeCookies('http://localhost', [{ ...base, expires: farFuture }], false);
    assert.ok(findings.some(f => f.ruleId === 'runtime.cookie-long-expiry'));
  });

  test('clean cookie produces no findings', () => {
    const findings = analyzeCookies('https://localhost', [base], true);
    assert.equal(findings.length, 0);
  });
});

// ─── CORS analyzer ───────────────────────────────────────────────────────────

describe('analyzeCorsResults', () => {
  test('flags reflected arbitrary origin', () => {
    const findings = analyzeCorsResults('https://api.example.com', [{
      testOrigin: 'https://evil.example',
      allowOrigin: 'https://evil.example',
      allowCredentials: undefined,
      statusCode: 200,
    }]);
    assert.ok(findings.some(f => f.ruleId === 'runtime.cors-reflected-origin'));
  });

  test('flags reflected origin with credentials as critical', () => {
    const findings = analyzeCorsResults('https://api.example.com', [{
      testOrigin: 'https://evil.example',
      allowOrigin: 'https://evil.example',
      allowCredentials: 'true',
      statusCode: 200,
    }]);
    const f = findings.find(f => f.ruleId === 'runtime.cors-reflected-origin');
    assert.ok(f);
    assert.equal(f!.severity, 'critical');
  });

  test('flags wildcard with credentials', () => {
    const findings = analyzeCorsResults('https://api.example.com', [{
      testOrigin: 'https://evil.example',
      allowOrigin: '*',
      allowCredentials: 'true',
      statusCode: 200,
    }]);
    assert.ok(findings.some(f => f.ruleId === 'runtime.cors-wildcard-credentials'));
  });

  test('no findings for non-reflected origin', () => {
    const findings = analyzeCorsResults('https://api.example.com', [{
      testOrigin: 'https://evil.example',
      allowOrigin: 'https://trusted.example.com',
      allowCredentials: undefined,
      statusCode: 200,
    }]);
    assert.equal(findings.length, 0);
  });
});

// ─── Redirect analyzer ───────────────────────────────────────────────────────

describe('analyzeRedirectResults', () => {
  test('flags open redirect when location points to safe target', () => {
    const findings = analyzeRedirectResults([{
      url: 'http://localhost/login?next=' + encodeURIComponent(SAFE_REDIRECT_TARGET),
      param: 'next',
      statusCode: 302,
      locationHeader: SAFE_REDIRECT_TARGET,
    }]);
    assert.ok(findings.some(f => f.ruleId === 'runtime.open-redirect'));
  });

  test('no finding when location is internal', () => {
    const findings = analyzeRedirectResults([{
      url: 'http://localhost/login?next=/dashboard',
      param: 'next',
      statusCode: 302,
      locationHeader: '/dashboard',
    }]);
    assert.equal(findings.length, 0);
  });

  test('no finding when no location header', () => {
    const findings = analyzeRedirectResults([{
      url: 'http://localhost/login?next=anything',
      param: 'next',
      statusCode: 200,
      locationHeader: undefined,
    }]);
    assert.equal(findings.length, 0);
  });

  test('buildRedirectTestUrls generates URLs for all redirect params', () => {
    const urls = buildRedirectTestUrls('http://localhost:3000');
    assert.ok(urls.length > 0);
    assert.ok(urls.every(u => u.url.includes(encodeURIComponent(SAFE_REDIRECT_TARGET))));
    assert.ok(urls.some(u => u.param === 'next'));
    assert.ok(urls.some(u => u.param === 'returnUrl'));
  });
});

// ─── Exposed file analyzer ───────────────────────────────────────────────────

describe('analyzeExposedFiles', () => {
  test('EXPOSED_FILE_CHECKS contains /.env as critical', () => {
    const envCheck = EXPOSED_FILE_CHECKS.find(c => c.path === '/.env');
    assert.ok(envCheck);
    assert.equal(envCheck!.severity, 'critical');
  });

  test('flags 200 response for known sensitive path', () => {
    const findings = analyzeExposedFiles('http://localhost:3000', [{
      path: '/.env',
      statusCode: 200,
      bodyPreview: 'NEXT_PUBLIC_API_KEY=abc123',
    }]);
    assert.ok(findings.some(f => f.severity === 'critical'));
  });

  test('ignores 404 responses', () => {
    const findings = analyzeExposedFiles('http://localhost:3000', [{
      path: '/.env',
      statusCode: 404,
    }]);
    assert.equal(findings.length, 0);
  });

  test('ignores 403 responses', () => {
    const findings = analyzeExposedFiles('http://localhost:3000', [{
      path: '/.git/config',
      statusCode: 403,
    }]);
    assert.equal(findings.length, 0);
  });
});

// ─── Reflection analyzer ─────────────────────────────────────────────────────

describe('classifyReflectionContext', () => {
  test('returns none when marker not present', () => {
    assert.equal(classifyReflectionContext('<html>hello</html>', 'cybermat_marker_abc'), 'none');
  });

  test('detects script-block context', () => {
    const marker = generateMarker();
    const body = `<html><script>var q = "${marker}";</script></html>`;
    assert.equal(classifyReflectionContext(body, marker), 'script-block');
  });

  test('detects html-attribute context', () => {
    const marker = generateMarker();
    const body = `<html><input value="${marker}" /></html>`;
    assert.equal(classifyReflectionContext(body, marker), 'html-attribute');
  });

  test('detects html-text context as default', () => {
    const marker = generateMarker();
    const body = `<html><body><p>Hello ${marker} world</p></body></html>`;
    assert.equal(classifyReflectionContext(body, marker), 'html-text');
  });

  test('generateMarker produces unique values', () => {
    const m1 = generateMarker();
    const m2 = generateMarker();
    assert.notEqual(m1, m2);
    assert.ok(m1.startsWith('cybermat_marker_'));
  });
});
