import type { ScannerEngine, ScanContext, Finding } from '@cybermat/shared';
import { scanFilesForSecrets, secretFindingToFinding } from '../secrets-engine';
import { scanFilesForPatterns, multilangFindingToFinding } from '../multilang-engine';

/**
 * Code Scanner Engine — Layer 1
 *
 * Orchestrates all static analysis engines (secrets, static-code, dependency,
 * config, AI security). Runs against the project's source files without
 * starting a browser or making network requests.
 *
 * Currently active sub-engines:
 *   - secrets-engine (60+ detectors)
 *   - multilang-engine (dangerous patterns for Docker, Shell, Terraform, K8s, Python, PHP, CI/CD)
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
  supportedLanguages: [
    'TypeScript', 'JavaScript', 'Python', 'Go', 'Java', 'PHP', 'Ruby',
    'Rust', 'Shell', 'Dockerfile', 'Terraform', 'YAML',
  ],
  supportedFrameworks: ['Next.js', 'React', 'Express', 'Fastify', 'NestJS', 'Docker', 'Kubernetes'],

  async run(context: ScanContext): Promise<Finding[]> {
    const secretFindings = scanFilesForSecrets(context.files).map(sf => ({
      ...secretFindingToFinding(sf),
      layer: 'code' as const,
    }));

    const patternFindings = scanFilesForPatterns(context.files).map(mf => ({
      ...multilangFindingToFinding(mf),
      layer: 'code' as const,
    }));

    return [...secretFindings, ...patternFindings];
  },
};
