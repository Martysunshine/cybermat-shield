import type { ScannedFile, RouteInfo } from '@cybermat/shared';

export interface RouteDiscoveryResult {
  routes: RouteInfo[];
  framework: string;
}

/**
 * Discovers HTTP routes from Next.js (app router + pages router) and Express.
 * Phase 4 implementation: parses file-system conventions and route handler exports.
 */
export function discoverRoutes(_files: ScannedFile[], _framework: string): RouteDiscoveryResult {
  // Phase 4: implement Next.js app router (app/*/route.ts), pages router (/pages/api/*),
  // and Express router (app.get/post/put/delete patterns).
  return { routes: [], framework: _framework };
}
