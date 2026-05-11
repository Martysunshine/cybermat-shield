import type { Rule, Finding, RuleContext } from '@cybermat/shared';
import { makeFindingId } from '../utils';

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
  return /\/admin[/.]|\/api\/admin/i.test(relativePath);
}

function isProtectedLookingRoute(relativePath: string): boolean {
  return /\/(?:dashboard|settings|account|profile|billing|payment|subscription|user|me|private|internal)[/.]/.test(relativePath);
}

function isApiRoute(relativePath: string): boolean {
  return relativePath.includes('/api/') || relativePath.includes('/pages/api/');
}

function isWebhookRoute(relativePath: string): boolean {
  return /\/webhook[s]?[/.]/.test(relativePath);
}

export const authRule: Rule = {
  id: 'auth',
  name: 'Authentication & Access Control',
  description: 'Detects missing authentication, broken access control, and insecure webhook handling',
  category: 'Authentication',
  owasp: ['A01 Broken Access Control', 'A07 Authentication Failures'],
  severity: 'high',
  run: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    const isNextJs = context.detectedStack.frameworks.includes('Next.js');
    const hasClerk = context.detectedStack.authProviders.includes('Clerk');
    const hasStripe = context.detectedStack.databases.includes('Stripe') ||
      context.files.some(f => f.content.includes('stripe'));

    // ── Missing Next.js middleware ──────────────────────────────────────────
    if (isNextJs) {
      const hasMiddleware = context.files.some(f =>
        f.relativePath === 'middleware.ts' ||
        f.relativePath === 'middleware.js' ||
        f.relativePath === 'src/middleware.ts'
      );
      if (!hasMiddleware) {
        findings.push({
          id: makeFindingId('auth.missing-middleware', 'root', 0),
          ruleId: 'auth.missing-middleware',
          title: 'Missing Next.js Middleware',
          severity: 'medium',
          confidence: 'medium',
          owasp: ['A01 Broken Access Control', 'A07 Authentication Failures'],
          cwe: ['CWE-284'],
          category: 'Authentication',
          evidence: {
            reason: 'No middleware.ts found in Next.js project — authentication is not enforced at the routing layer.',
          },
          impact: 'Without middleware, authentication is not enforced at the routing layer, making it easy to miss protecting routes.',
          recommendation: 'Add middleware.ts to enforce authentication at the edge. Use Clerk, NextAuth, or custom JWT validation.',
          tags: ['nextjs', 'middleware', 'auth'],
        });
      }
    }

    // ── Per-route checks ────────────────────────────────────────────────────
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
      const isWebhook = isWebhookRoute(file.relativePath);

      if (isAdmin && !hasAuth) {
        findings.push({
          id: makeFindingId('auth.admin-route-no-auth', file.relativePath, 0),
          ruleId: 'auth.admin-route-no-auth',
          title: 'Admin Route Without Authentication Check',
          severity: 'critical',
          confidence: 'medium',
          owasp: ['A01 Broken Access Control', 'A07 Authentication Failures'],
          cwe: ['CWE-284', 'CWE-306'],
          category: 'Authentication',
          file: file.relativePath,
          evidence: {
            reason: `Admin route with no detectable auth guard: ${file.relativePath}`,
          },
          impact: 'Unauthenticated users may access administrative functionality.',
          recommendation: 'Add authentication and role/admin check at the start of every admin route handler.',
          tags: ['admin', 'auth', 'access-control'],
        });
      } else if (isProtected && !hasAuth) {
        findings.push({
          id: makeFindingId('auth.protected-route-no-auth', file.relativePath, 0),
          ruleId: 'auth.protected-route-no-auth',
          title: 'Protected-Looking Route Without Authentication',
          severity: 'high',
          confidence: 'low',
          owasp: ['A01 Broken Access Control', 'A07 Authentication Failures'],
          cwe: ['CWE-284'],
          category: 'Authentication',
          file: file.relativePath,
          evidence: {
            reason: `Route path suggests auth is required but no guard found: ${file.relativePath}`,
          },
          impact: 'Sensitive functionality may be accessible without authentication.',
          recommendation: 'Verify authentication is enforced. Add an explicit auth check at the top of the route handler.',
          tags: ['auth', 'access-control'],
        });
      } else if (isAdmin && hasAuth && !hasRoleCheck(file.content)) {
        findings.push({
          id: makeFindingId('auth.admin-route-no-role-check', file.relativePath, 0),
          ruleId: 'auth.admin-route-no-role-check',
          title: 'Admin Route Missing Role Check',
          severity: 'high',
          confidence: 'low',
          owasp: ['A01 Broken Access Control'],
          cwe: ['CWE-284', 'CWE-285'],
          category: 'Authentication',
          file: file.relativePath,
          evidence: {
            reason: `Admin route authenticated but no role/admin check detected: ${file.relativePath}`,
          },
          impact: 'Any authenticated user (not just admins) may access admin functionality.',
          recommendation: 'Add a role check after authentication: verify the user has an admin role before proceeding.',
          tags: ['admin', 'rbac', 'access-control'],
        });
      }

      // Webhook missing signature verification
      if (isWebhook && !file.content.includes('constructEvent') && !file.content.includes('verifyWebhookSignature') &&
          !file.content.includes('svix') && !file.content.includes('x-hub-signature') &&
          !file.content.includes('stripe-signature')) {
        findings.push({
          id: makeFindingId('auth.webhook-missing-signature', file.relativePath, 0),
          ruleId: 'auth.webhook-missing-signature',
          title: 'Webhook Route Missing Signature Verification',
          severity: 'high',
          confidence: 'medium',
          owasp: ['A08 Software or Data Integrity Failures'],
          cwe: ['CWE-347'],
          category: 'Authentication',
          file: file.relativePath,
          evidence: {
            reason: 'Webhook route has no detectable signature verification (constructEvent, verifyWebhookSignature, svix, x-hub-signature)',
          },
          impact: 'Attackers can forge webhook payloads to trigger actions like payments, account changes, or data deletion.',
          recommendation: 'Verify webhook signatures using the provider SDK: stripe.webhooks.constructEvent(), Svix, or x-hub-signature for GitHub/GitLab.',
          tags: ['webhook', 'auth', 'integrity'],
        });
      }

      // Stripe: webhook endpoint trusting query params for payment success
      if (hasStripe && file.relativePath.includes('/payment') &&
          /(?:searchParams|query\.)(?:get\()?['"]?(?:success|status|paid)/.test(file.content)) {
        findings.push({
          id: makeFindingId('auth.stripe-payment-success-query-param', file.relativePath, 0),
          ruleId: 'auth.stripe-payment-success-query-param',
          title: 'Payment Success Logic Trusting Query Parameters',
          severity: 'high',
          confidence: 'medium',
          owasp: ['A08 Software or Data Integrity Failures'],
          cwe: ['CWE-807'],
          category: 'Authentication',
          file: file.relativePath,
          evidence: {
            reason: 'Payment success/status read from query parameter — attacker can craft a ?success=true URL',
          },
          impact: 'Attacker can bypass payment by directly navigating to ?success=true or ?status=paid.',
          recommendation: 'Verify payment status via Stripe webhook events or server-side Stripe API, never from client query params.',
          tags: ['stripe', 'payment', 'integrity'],
        });
      }

      // Clerk: API route with no auth() call
      if (hasClerk && isApiRoute(file.relativePath) && !hasAuth) {
        const isPublicLooking = /\/sign-in|\/sign-up|\/public/.test(file.relativePath);
        if (!isPublicLooking) {
          findings.push({
            id: makeFindingId('auth.clerk-api-route-no-auth', file.relativePath, 0),
            ruleId: 'auth.clerk-api-route-no-auth',
            title: 'Clerk API Route Missing auth() Call',
            severity: 'high',
            confidence: 'low',
            owasp: ['A01 Broken Access Control', 'A07 Authentication Failures'],
            cwe: ['CWE-306'],
            category: 'Authentication',
            file: file.relativePath,
            evidence: {
              reason: `Clerk is used in this project but no auth() or currentUser() call found in API route: ${file.relativePath}`,
            },
            impact: 'API route may be publicly accessible when it should require authentication.',
            recommendation: 'Call auth() or currentUser() from @clerk/nextjs at the top of every protected API route.',
            tags: ['clerk', 'auth', 'nextjs'],
          });
        }
      }

      // User ID from request body (IDOR)
      const lines = file.content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/(?:req\.body|request\.json\(\)|formData\(\)).*(?:user_id|userId|ownerId|owner_id)/i.test(line) ||
            /(?:user_id|userId|ownerId)\s*[:=].*(?:req\.body|body\.|params\.|query\.)/i.test(line)) {
          findings.push({
            id: makeFindingId('auth.user-id-from-body', file.relativePath, i + 1),
            ruleId: 'auth.user-id-from-body',
            title: 'user_id Accepted from Request Body',
            severity: 'high',
            confidence: 'medium',
            owasp: ['A01 Broken Access Control'],
            cwe: ['CWE-639'],
            category: 'Authentication',
            file: file.relativePath,
            line: i + 1,
            evidence: {
              snippet: line.trim(),
              reason: 'user_id or ownerId read from client-controlled request body',
            },
            impact: 'IDOR/BOLA vulnerability: attackers can manipulate user IDs to access or modify other users\' data.',
            recommendation: 'Never trust user_id from the client. Extract it from the authenticated session server-side.',
            tags: ['idor', 'bola', 'auth', 'access-control'],
          });
        }
      }
    }

    // ── Supabase service role key in client files ──────────────────────────
    if (context.detectedStack.databases.includes('Supabase')) {
      const clientFiles = (context.fileClassifications ?? [])
        .filter(fc => fc.kind === 'client')
        .map(fc => fc.file);

      for (const file of context.files) {
        const isClient = clientFiles.includes(file.relativePath) ||
          file.relativePath.startsWith('components/') ||
          file.relativePath.startsWith('src/components/');

        if (isClient && /supabase.*serviceRole|service_role.*supabase|SUPABASE_SERVICE_ROLE/i.test(file.content)) {
          findings.push({
            id: makeFindingId('auth.supabase-service-role-in-client', file.relativePath, 0),
            ruleId: 'auth.supabase-service-role-in-client',
            title: 'Supabase Service Role Key in Client File',
            severity: 'critical',
            confidence: 'high',
            owasp: ['A04 Cryptographic Failures', 'A01 Broken Access Control'],
            cwe: ['CWE-312', 'CWE-284'],
            category: 'Authentication',
            file: file.relativePath,
            evidence: {
              reason: 'Supabase service role key referenced in a client-side file — bypasses Row Level Security completely',
            },
            impact: 'The service role key bypasses all RLS policies, exposing the entire database to the client.',
            recommendation: 'Never use the service role key on the client. Use the anon key for client-side, service role only in server-side code.',
            tags: ['supabase', 'service-role', 'rls', 'critical'],
          });
        }
      }
    }

    // ── Stripe secret key in client files ──────────────────────────────────
    if (hasStripe) {
      const clientFiles = (context.fileClassifications ?? [])
        .filter(fc => fc.kind === 'client')
        .map(fc => fc.file);

      for (const file of context.files) {
        const isClient = clientFiles.includes(file.relativePath) ||
          file.relativePath.startsWith('components/') ||
          file.relativePath.startsWith('src/components/');

        if (isClient && /STRIPE_SECRET|stripe.*secret(?!Key.*publishable)/i.test(file.content)) {
          findings.push({
            id: makeFindingId('auth.stripe-secret-in-client', file.relativePath, 0),
            ruleId: 'auth.stripe-secret-in-client',
            title: 'Stripe Secret Key Referenced in Client File',
            severity: 'critical',
            confidence: 'medium',
            owasp: ['A04 Cryptographic Failures'],
            cwe: ['CWE-312'],
            category: 'Authentication',
            file: file.relativePath,
            evidence: {
              reason: 'STRIPE_SECRET or stripe secret key pattern found in client-side file',
            },
            impact: 'Exposing the Stripe secret key allows attackers to make charges, issue refunds, and access customer data.',
            recommendation: 'Only use NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY on the client. Keep STRIPE_SECRET_KEY server-side only.',
            tags: ['stripe', 'secret', 'client'],
          });
        }
      }
    }

    return findings;
  },
};
