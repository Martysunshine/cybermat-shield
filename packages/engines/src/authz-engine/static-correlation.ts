import type { StaticCorrelation, RouteInfo } from '@cybermat/shared';

const AUTH_GUARD_PATTERNS = [
  /getServerSession/,
  /currentUser\(\)/,
  /auth\(\)/,
  /requireAuth/,
  /withAuth/,
  /checkRole/,
  /requireAdmin/,
  /verifyToken/,
  /isAuthenticated/,
];

const IDOR_PATTERNS = [
  /user_id.*request|request.*user_id/i,
  /userId.*body|body.*userId/i,
  /\.params\.id/,
  /searchParams\.get\(['"]id['"]\)/,
];

const ADMIN_ROUTE_PATTERN = /\/admin/i;

export function correlateRoute(route: string, staticRoutes: RouteInfo[]): StaticCorrelation | undefined {
  const match = staticRoutes.find(r => {
    const normalized = r.route.replace(/\[.*?\]/g, '<id>');
    return normalized === route || r.route === route;
  });
  if (!match) return undefined;

  if (ADMIN_ROUTE_PATTERN.test(route) && !match.hasRoleCheck) {
    return { file: match.file, reason: 'Admin route has no detected role check' };
  }
  if (!match.requiresAuth) {
    return { file: match.file, reason: 'Route has no detected auth guard' };
  }
  return undefined;
}

export function hasIdorSignal(routeFile?: string): boolean {
  if (!routeFile) return false;
  return IDOR_PATTERNS.some(p => p.test(routeFile));
}

export function hasAuthGuard(source?: string): boolean {
  if (!source) return false;
  return AUTH_GUARD_PATTERNS.some(p => p.test(source));
}
