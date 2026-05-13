import { randomBytes } from 'crypto';
import type { RuntimeFinding, Severity } from '@cybermat/shared';

function makeId(ruleId: string): string {
  return `${ruleId}-${randomBytes(4).toString('hex')}`;
}

export const RuntimeFindingBuilder = {
  header(
    ruleId: string,
    title: string,
    severity: Severity,
    url: string,
    headerName: string,
    description: string,
    recommendation: string,
    owasp: string[],
    headerValue?: string,
  ): RuntimeFinding {
    return {
      id: makeId(ruleId),
      ruleId,
      title,
      severity,
      confidence: 'high',
      owasp,
      category: 'Security Headers',
      evidence: {
        reason: description,
        snippet: headerValue
          ? `${headerName}: ${headerValue.slice(0, 200)}`
          : `Header "${headerName}" not present`,
      },
      impact: description,
      recommendation,
      tags: ['headers', 'runtime'],
      layer: 'runtime',
      url,
      headerName,
    };
  },

  cookie(
    ruleId: string,
    title: string,
    severity: Severity,
    url: string,
    cookieName: string,
    description: string,
    recommendation: string,
    owasp: string[],
  ): RuntimeFinding {
    return {
      id: makeId(ruleId),
      ruleId,
      title,
      severity,
      confidence: 'high',
      owasp,
      category: 'Cookies',
      evidence: { reason: description, snippet: `Set-Cookie: ${cookieName}=...` },
      impact: description,
      recommendation,
      tags: ['cookies', 'runtime'],
      layer: 'runtime',
      url,
      cookieName,
    };
  },

  cors(
    ruleId: string,
    title: string,
    severity: Severity,
    url: string,
    testOrigin: string,
    description: string,
    recommendation: string,
  ): RuntimeFinding {
    return {
      id: makeId(ruleId),
      ruleId,
      title,
      severity,
      confidence: 'high',
      owasp: ['A01 Broken Access Control'],
      category: 'CORS',
      evidence: { reason: description, snippet: `Origin: ${testOrigin}` },
      impact: description,
      recommendation,
      tags: ['cors', 'runtime'],
      layer: 'runtime',
      url,
      method: 'GET',
      requestEvidence: `Origin: ${testOrigin}`,
    };
  },

  reflection(
    ruleId: string,
    title: string,
    severity: Severity,
    url: string,
    param: string,
    context: string,
    description: string,
    recommendation: string,
    owasp: string[],
  ): RuntimeFinding {
    return {
      id: makeId(ruleId),
      ruleId,
      title,
      severity,
      confidence: 'medium',
      owasp,
      category: 'Injection',
      evidence: { reason: description, snippet: `param="${param}" reflected in ${context}` },
      impact: description,
      recommendation,
      tags: ['xss', 'reflection', 'runtime'],
      layer: 'runtime',
      url,
      requestEvidence: `?${param}=<marker>`,
    };
  },

  redirect(
    ruleId: string,
    title: string,
    severity: Severity,
    url: string,
    param: string,
    description: string,
    recommendation: string,
    owasp: string[],
  ): RuntimeFinding {
    return {
      id: makeId(ruleId),
      ruleId,
      title,
      severity,
      confidence: 'high',
      owasp,
      category: 'Open Redirect',
      evidence: {
        reason: description,
        snippet: `?${param}=https://example.com/cybermat-redirect-test → 3xx`,
      },
      impact: description,
      recommendation,
      tags: ['redirect', 'runtime'],
      layer: 'runtime',
      url,
      method: 'GET',
      requestEvidence: `?${param}=${encodeURIComponent('https://example.com/cybermat-redirect-test')}`,
    };
  },

  exposedFile(
    ruleId: string,
    title: string,
    severity: Severity,
    url: string,
    filePath: string,
    description: string,
    recommendation: string,
    owasp: string[],
    statusCode: number,
  ): RuntimeFinding {
    return {
      id: makeId(ruleId),
      ruleId,
      title,
      severity,
      confidence: 'high',
      owasp,
      category: 'Exposed Files',
      evidence: { reason: description, snippet: `GET ${filePath} → ${statusCode} OK` },
      impact: description,
      recommendation,
      tags: ['exposure', 'runtime'],
      layer: 'runtime',
      url,
      method: 'GET',
      statusCode,
    };
  },
};
