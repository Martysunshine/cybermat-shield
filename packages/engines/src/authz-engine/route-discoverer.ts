import type { AccessRouteCandidate, RouteInfo } from '@cybermat/shared';

const KNOWN_PROTECTED_PATHS = [
  '/dashboard', '/settings', '/account', '/profile', '/me',
  '/admin', '/api/admin', '/api/users', '/api/profile', '/api/settings',
  '/api/posts', '/api/events', '/api/messages', '/api/conversations',
  '/api/payments', '/api/billing', '/api/subscriptions',
  '/api/organizations', '/api/workspaces', '/api/tenants',
];

const SENSITIVE_KEYWORDS = [
  'admin', 'private', 'settings', 'account', 'billing', 'payment',
  'subscription', 'message', 'conversation', 'user', 'profile',
  'organization', 'workspace', 'tenant', 'internal', 'debug',
];

const DESTRUCTIVE_SEGMENTS = [
  'delete', 'remove', 'destroy', 'revoke', 'logout', 'reset', 'transfer',
  'withdraw', 'checkout', 'subscribe', 'unsubscribe', 'cancel',
];

function isDestructive(route: string): boolean {
  const lower = route.toLowerCase();
  return DESTRUCTIVE_SEGMENTS.some(seg => lower.includes(seg));
}

function riskTags(route: string): string[] {
  const tags: string[] = [];
  const lower = route.toLowerCase();
  if (lower.includes('/admin') || lower.includes('/internal')) tags.push('admin');
  if (lower.includes('/api/')) tags.push('api');
  if (SENSITIVE_KEYWORDS.some(k => lower.includes(k))) tags.push('sensitive');
  if (/\/[0-9a-f-]{8,}/.test(lower) || /\/\d+/.test(lower)) tags.push('resource-id');
  return tags;
}

export function discoverCandidates(
  staticRoutes: RouteInfo[] = [],
  configRoutes: string[] = [],
): AccessRouteCandidate[] {
  const seen = new Set<string>();
  const candidates: AccessRouteCandidate[] = [];

  function add(route: string, source: AccessRouteCandidate['source'], file?: string) {
    if (seen.has(route)) return;
    seen.add(route);
    candidates.push({
      route,
      method: 'GET',
      source,
      file,
      riskTags: riskTags(route),
      requiresAuthExpected: SENSITIVE_KEYWORDS.some(k => route.toLowerCase().includes(k)),
      destructive: isDestructive(route),
    });
  }

  for (const path of KNOWN_PROTECTED_PATHS) add(path, 'heuristic');
  for (const r of staticRoutes) if (r.isApi || r.isPage) add(r.route, 'static', r.file);
  for (const r of configRoutes) add(r, 'config');

  return candidates;
}
