import type { RuntimeConfig, RuntimeScanReport } from '@cybermat/shared';
import { RuntimeScanner } from '@cybermat/engines';

export async function runRuntimeScan(config: RuntimeConfig): Promise<RuntimeScanReport> {
  const scanner = new RuntimeScanner(config);
  return scanner.run();
}
