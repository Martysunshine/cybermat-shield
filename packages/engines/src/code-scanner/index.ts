import type { ScannerEngine, ScanContext, Finding } from '@cybermat/shared';
import { scanFilesForSecrets, secretFindingToFinding } from '../secrets-engine';

/**
 * Code Scanner Engine — Layer 1
 *
 * Orchestrates all static analysis engines (secrets, static-code, dependency,
 * config, AI security). Runs against the project's source files without
 * starting a browser or making network requests.
 *
 * Currently active sub-engines:
 *   - secrets-engine (66 detectors)
 *
 * Planned sub-engines (Phase 4):
 *   - static-code-engine (AST-based sink/source detection)
 *   - dependency-engine (lockfile + audit integration)
 *   - config-engine (framework config misconfigurations)
 *   - ai-security-engine (LLM output sinks, tool-call approval)
 */
export const codeScannerEngine: ScannerEngine = {
  id: 'code-scanner',
  name: 'Code Scanner',
  layer: 'code',
  supportedLanguages: ['TypeScript', 'JavaScript'],
  supportedFrameworks: ['Next.js', 'React', 'Express', 'Fastify', 'NestJS'],

  async run(context: ScanContext): Promise<Finding[]> {
    const secretFindings = scanFilesForSecrets(context.files).map(sf => ({
      ...secretFindingToFinding(sf),
      layer: 'code' as const,
    }));

    // Phase 4: add static-code, dependency, config, ai-security engines here
    return secretFindings;
  },
};
