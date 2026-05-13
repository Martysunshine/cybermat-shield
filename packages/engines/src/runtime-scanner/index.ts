import type { ScannerEngine, ScanContext, Finding } from '@cybermat/shared';
import { RuntimeScanner } from '../runtime-engine';

export const runtimeScannerEngine: ScannerEngine = {
  id: 'runtime-scanner',
  name: 'Runtime Scanner',
  layer: 'runtime',
  supportedLanguages: [],
  supportedFrameworks: [],

  async run(context: ScanContext): Promise<Finding[]> {
    if (!context.targetUrl) {
      throw new Error('Runtime scanner requires a targetUrl. Use: cybermat scan-runtime <url>');
    }
    const scanner = new RuntimeScanner({ baseUrl: context.targetUrl });
    const report = await scanner.run();
    return report.findings;
  },
};
