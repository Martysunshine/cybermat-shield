import type { ScannedFile, RouteInfo } from '@cybermat/shared';

export interface RouteDiscoveryResult {
  routes: RouteInfo[];
  framework: string;
}

const AUTH_GUARD_PATTERNS = [
  /auth\s*\(\s*\)/,
  /getServerSession\s*\(/,
  /currentUser\s*\(\s*\)/,
  /requireAuth\s*\(/,
  /verifyToken\s*\(/,
  /supabase\.auth\.getUser/,
  /clerkClient/,
  /withAuth/,
  /getAuth\s*\(/,
  /bearerToken/,
  /validateToken/,
  /verifyJwt/,
  /const\s+\{\s*userId\s*\}\s*=\s*await\s+auth/,
  /session\s*=\s*await\s+getServerSession/,
];

const ROLE_CHECK_PATTERNS = [
  /\.role\s*===\s*['"]admin/i,
  /isAdmin/i,
  /requireAdmin/i,
  /checkRole\s*\(/i,
  /hasRole\s*\(/i,
  /org\.role/i,
  /user\.isAdmin/i,
];

const USER_INPUT_PATTERNS = [
  /req\.(body|query|params|headers|cookies)/,
  /request\.(json|formData|text)\s*\(\s*\)/,
  /searchParams/,
  /params\./,
  /body\./,
];

function hasPattern(content: string, patterns: RegExp[]): boolean {
  return patterns.some(p => p.test(content));
}

function buildRiskTags(route: string, content: string, isApi: boolean): string[] {
  const tags: string[] = [];

  if (isApi) tags.push('api-route');
  if (/\/admin[/.]|\/api\/admin/.test(route)) tags.push('admin-route');
  if (/\/webhook[/.]|\/webhooks?[/.]/.test(route)) tags.push('webhook');
  if (/\/pay(ment)?s?|\/checkout|\/stripe|\/billing/.test(route)) tags.push('payment');
  if (/\/auth[/.]|\/login|\/register|\/signup|\/oauth|\/callback/.test(route)) tags.push('auth-route');
  if (/\/upload|\/file/.test(route)) tags.push('accepts-file');
  if (/\/ai|\/chat|\/completion|\/generate/.test(route)) tags.push('ai-tool');
  if (/\/debug|\/test|\/ping|\/health/.test(route)) tags.push('debug-route');
  if (/req\.body\.url|request\.url|searchParams\.get\(['"](?:next|redirect|returnUrl|url)/i.test(content)) {
    tags.push('accepts-url');
  }
  if (/userId|user_id|ownerId/.test(content) && USER_INPUT_PATTERNS.some(p => p.test(content))) {
    tags.push('accepts-user-id');
  }
  if (['POST', 'PUT', 'PATCH', 'DELETE'].some(m => new RegExp(`export\\s+async\\s+function\\s+${m}`).test(content))) {
    tags.push('state-changing-method');
  }
  if (!hasPattern(content, AUTH_GUARD_PATTERNS) && isApi) tags.push('missing-auth');

  return tags;
}

/** Convert a Next.js app router file path to a URL route */
function appPathToRoute(relativePath: string): string {
  // e.g. app/api/users/[id]/route.ts → /api/users/[id]
  let route = relativePath
    .replace(/^(?:src\/)?app/, '')
    .replace(/\/route\.(ts|js|tsx|jsx)$/, '')
    .replace(/\/page\.(tsx|jsx|ts|js)$/, '')
    || '/';
  if (!route.startsWith('/')) route = '/' + route;
  return route;
}

/** Convert a Next.js pages router file path to a URL route */
function pagesPathToRoute(relativePath: string): string {
  // e.g. pages/api/users.ts → /api/users
  let route = relativePath
    .replace(/^(?:src\/)?pages/, '')
    .replace(/\.(ts|js|tsx|jsx)$/, '')
    .replace(/\/index$/, '');
  if (!route.startsWith('/')) route = '/' + route;
  return route;
}

/** Extract exported HTTP method names from a Next.js app router route file */
function extractNextMethods(content: string): Array<'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'> {
  const methods: Array<'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'> = [];
  const methodNames = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;
  for (const m of methodNames) {
    if (new RegExp(`export\\s+(?:async\\s+)?function\\s+${m}\\b`).test(content)) {
      methods.push(m);
    }
  }
  return methods.length > 0 ? methods : ['ANY' as any];
}

function discoverNextJsRoutes(files: ScannedFile[]): RouteInfo[] {
  const routes: RouteInfo[] = [];

  // App router: app/**/route.ts
  for (const file of files) {
    const rel = file.relativePath;
    if (!rel.match(/^(?:src\/)?app\/.*\/route\.(ts|js)$/)) continue;

    const routePath = appPathToRoute(rel);
    const methods = extractNextMethods(file.content);
    const riskTags = buildRiskTags(routePath, file.content, true);

    for (const method of methods) {
      routes.push({
        route: routePath,
        method,
        file: rel,
        framework: 'nextjs',
        isApi: true,
        isPage: false,
        requiresAuth: hasPattern(file.content, AUTH_GUARD_PATTERNS),
        hasRoleCheck: hasPattern(file.content, ROLE_CHECK_PATTERNS),
        acceptsUserInput: hasPattern(file.content, USER_INPUT_PATTERNS),
        riskTags,
      });
    }
  }

  // App router: app/**/page.tsx (UI routes)
  for (const file of files) {
    const rel = file.relativePath;
    if (!rel.match(/^(?:src\/)?app\/.*\/page\.(tsx|jsx)$/)) continue;

    const routePath = appPathToRoute(rel);
    routes.push({
      route: routePath,
      file: rel,
      framework: 'nextjs',
      isApi: false,
      isPage: true,
      riskTags: buildRiskTags(routePath, file.content, false),
    });
  }

  // Pages router: pages/api/**
  for (const file of files) {
    const rel = file.relativePath;
    if (!rel.match(/^(?:src\/)?pages\/api\//) || !['.ts', '.js'].includes(file.extension)) continue;

    const routePath = pagesPathToRoute(rel);
    routes.push({
      route: routePath,
      method: 'ANY',
      file: rel,
      framework: 'nextjs',
      isApi: true,
      isPage: false,
      requiresAuth: hasPattern(file.content, AUTH_GUARD_PATTERNS),
      hasRoleCheck: hasPattern(file.content, ROLE_CHECK_PATTERNS),
      acceptsUserInput: hasPattern(file.content, USER_INPUT_PATTERNS),
      riskTags: buildRiskTags(routePath, file.content, true),
    });
  }

  // Pages router: pages/** (non-api)
  for (const file of files) {
    const rel = file.relativePath;
    if (!rel.match(/^(?:src\/)?pages\//) || rel.includes('/api/')) continue;
    if (!['.tsx', '.jsx', '.ts', '.js'].includes(file.extension)) continue;
    if (rel.match(/^(?:src\/)?pages\/_(?:app|document)/)) continue;

    const routePath = pagesPathToRoute(rel);
    routes.push({
      route: routePath,
      file: rel,
      framework: 'nextjs',
      isApi: false,
      isPage: true,
      riskTags: buildRiskTags(routePath, file.content, false),
    });
  }

  return routes;
}

function discoverExpressRoutes(files: ScannedFile[]): RouteInfo[] {
  const routes: RouteInfo[] = [];
  const METHOD_RE = /(?:app|router)\.(?<method>get|post|put|patch|delete|use)\s*\(\s*['"`](?<path>[^'"`]+)['"`]/gi;

  for (const file of files) {
    if (!['.ts', '.js', '.mjs'].includes(file.extension)) continue;
    if (!file.content.includes('express')) continue;

    let match: RegExpExecArray | null;
    while ((match = METHOD_RE.exec(file.content)) !== null) {
      const { method, path: routePath } = match.groups!;
      const isApi = routePath.includes('/api/') || file.relativePath.includes('/api/');
      routes.push({
        route: routePath,
        method: method.toUpperCase() as any,
        file: file.relativePath,
        framework: 'express',
        isApi,
        isPage: false,
        requiresAuth: hasPattern(file.content, AUTH_GUARD_PATTERNS),
        hasRoleCheck: hasPattern(file.content, ROLE_CHECK_PATTERNS),
        acceptsUserInput: hasPattern(file.content, USER_INPUT_PATTERNS),
        riskTags: buildRiskTags(routePath, file.content, isApi),
      });
    }
  }

  return routes;
}

export function discoverRoutes(files: ScannedFile[], framework: string): RouteDiscoveryResult {
  const routes: RouteInfo[] = [];

  if (framework === 'Next.js' || files.some(f => f.relativePath.match(/^(?:src\/)?app\//) || f.relativePath.match(/^(?:src\/)?pages\//))) {
    routes.push(...discoverNextJsRoutes(files));
  }

  if (framework === 'Express' || files.some(f => f.content.includes('express'))) {
    routes.push(...discoverExpressRoutes(files));
  }

  // De-duplicate by route + method + file
  const seen = new Set<string>();
  const deduped = routes.filter(r => {
    const key = `${r.route}:${r.method ?? 'ANY'}:${r.file}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return { routes: deduped, framework };
}
