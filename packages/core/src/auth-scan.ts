import type { AuthScanConfig, AuthScanReport, RouteInfo } from '@cybermat/shared';
import { AuthzScanner } from '@cybermat/engines';

export async function runAuthScan(
  config: AuthScanConfig,
  staticRoutes: RouteInfo[] = [],
): Promise<AuthScanReport> {
  const scanner = new AuthzScanner(config);
  return scanner.run(staticRoutes);
}
