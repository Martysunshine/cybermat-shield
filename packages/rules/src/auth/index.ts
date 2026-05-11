import type { Rule, Finding, RuleContext, ScannedFile } from '@cybermat/shared';
import { makeFindingId } from '../utils';

// Patterns that indicate auth is present in a route file
const AUTH_GUARD_PATTERNS = [
  /auth\s*\(\s*\)/,
  /getServerSession\s*\(/,
  /currentUser\s*\(\s*\)/,
  /requireAuth\s*\(/,
  /verifyToken\s*\(/,
  /supabase\.auth\.getUser/,
  /clerkClient/,
  /withAuth/,
  /requireAdmin\s*\(/,
  /checkRole\s*\(/,
  /isAuthenticated/,
  /const\s+\{\s*userId\s*\}\s*=\s*await\s+auth\s*\(/,
  /session\s*=\s*await\s+getServerSession/,
  /getAuth\s*\(/,
  /authGuard/,
  /bearerToken/,
  /verifyJwt/,
  /validateToken/,
];

const ROLE_CHECK_PATTERNS = [
  /\.role\s*===\s*['"]admin/i,
  /isAdmin\s*[=:]/i,
  /requireAdmin/i,
  /checkRole\s*\(/i,
  /hasRole\s*\(/i,
  /role.*admin/i,
  /admin.*role/i,
  /org\.role/i,
  /user\.isAdmin/i,
];

function hasAuthGuard(content: string): boolean {
  return AUTH_GUARD_PATTERNS.some(p => p.test(content));
}

function hasRoleCheck(content: string): boolean {
  return ROLE_CHECK_PATTERNS.some(p => p.test(content));
}

function isAdminRoute(relativePath: string): boolean {
  return /\/admin[/\.]|\/api\/admin/i.test(relativePath);
}

function isProtectedLookingRoute(relativePath: string): boolean {
  return /\/(?:dashboard|settings|account|profile|billing|payment|subscription|user|me|private|internal)[/\.]/.test(relativePath);
}

function isApiRoute(relativePath: string): boolean {
  return relativePath.includes('/api/') || relativePath.includes('/pages/api/');
}

export const authRule: Rule = {
  id: 'auth',
  name: 'Authentication & Access Control',
  description: 'Detects missing authentication checks in API routes and other access control issues',
  category: 'Authentication',
  owasp: ['A01 Broken Access Control', 'A07 Authentication Failures'],
  severity: 'high',
  run: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    // Check for missing middleware.ts in Next.js projects
    const isNextJs = context.detectedStack.frameworks.includes('Next.js');
    if (isNextJs) {
      const hasMiddleware = context.files.some(f =>
        f.relativePath === 'middleware.ts' ||
        f.relativePath === 'middleware.js' ||
        f.relativePath === 'src/middleware.ts'
      );
      if (!hasMiddleware) {
        findings.push({
          id: makeFindingId('auth.missing-middleware', 'root', 0),
          title: 'Missing Next.js Middleware',
          severity: 'medium',
          confidence: 'medium',
          owasp: ['A01 Broken Access Control', 'A07 Authentication Failures'],
          category: 'Authentication',
          evidence: 'No middleware.ts found in Next.js project',
          impact: 'Without middleware, authentication is not enforced at the routing layer, making it easy to miss protecting routes.',
          recommendation: 'Add middleware.ts to enforce authentication at the edge. Use Clerk, NextAuth, or custom JWT validation.',
        });
      }
    }

    // Check API route files for missing auth
    const routeFiles = context.files.filter(f => {
      const ext = f.extension;
      if (!['.ts', '.js'].includes(ext)) return false;
      return isApiRoute(f.relativePath) && (
        f.relativePath.includes('/route.') ||
        f.relativePath.includes('/pages/api/')
      );
    });

    for (const file of routeFiles) {
      const hasAuth = hasAuthGuard(file.content);
      const isAdmin = isAdminRoute(file.relativePath);
      const isProtected = isProtectedLookingRoute(file.relativePath);

      if (isAdmin && !hasAuth) {
        findings.push({
          id: makeFindingId('auth.admin-route-no-auth', file.relativePath, 0),
          title: 'Admin Route Without Authentication Check',
          severity: 'critical',
          confidence: 'medium',
          owasp: ['A01 Broken Access Control', 'A07 Authentication Failures'],
          category: 'Authentication',
          file: file.relativePath,
          evidence: `Admin route with no detectable auth guard: ${file.relativePath}`,
          impact: 'Unauthenticated users may access administrative functionality.',
          recommendation: 'Add authentication and role/admin check at the start of every admin route handler.',
        });
      } else if (isProtected && !hasAuth) {
        findings.push({
          id: makeFindingId('auth.protected-route-no-auth', file.relativePath, 0),
          title: 'Protected-Looking Route Without Authentication',
          severity: 'high',
          confidence: 'low',
          owasp: ['A01 Broken Access Control', 'A07 Authentication Failures'],
          category: 'Authentication',
          file: file.relativePath,
          evidence: `Route path suggests auth is required but no guard found: ${file.relativePath}`,
          impact: 'Sensitive functionality may be accessible without authentication.',
          recommendation: 'Verify authentication is enforced. Add an explicit auth check at the top of the route handler.',
        });
      } else if (isAdmin && hasAuth && !hasRoleCheck(file.content)) {
        findings.push({
          id: makeFindingId('auth.admin-route-no-role-check', file.relativePath, 0),
          title: 'Admin Route Missing Role Check',
          severity: 'high',
          confidence: 'low',
          owasp: ['A01 Broken Access Control'],
          category: 'Authentication',
          file: file.relativePath,
          evidence: `Admin route authenticated but no role/admin check detected: ${file.relativePath}`,
          impact: 'Any authenticated user (not just admins) may access admin functionality.',
          recommendation: 'Add a role check after authentication: verify the user has an admin role before proceeding.',
        });
      }

      // Flag user_id accepted from request body (IDOR risk)
      const lines = file.content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/(?:req\.body|request\.json\(\)|formData\(\)).*(?:user_id|userId|ownerId|owner_id)/i.test(line) ||
            /(?:user_id|userId|ownerId)\s*[:=].*(?:req\.body|body\.|params\.|query\.)/i.test(line)) {
          findings.push({
            id: makeFindingId('auth.user-id-from-body', file.relativePath, i + 1),
            title: 'user_id Accepted from Request Body',
            severity: 'high',
            confidence: 'medium',
            owasp: ['A01 Broken Access Control'],
            category: 'Authentication',
            file: file.relativePath,
            line: i + 1,
            evidence: line.trim(),
            impact: 'IDOR/BOLA vulnerability: attackers can manipulate user IDs to access or modify other users\' data.',
            recommendation: 'Never trust user_id from the client. Extract it from the authenticated session server-side.',
          });
        }
      }
    }

    return findings;
  },
};
