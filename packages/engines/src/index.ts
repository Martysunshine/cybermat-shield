// Layer facades — use these when building the scan plan
export { codeScannerEngine } from './code-scanner';
export { runtimeScannerEngine } from './runtime-scanner';
export { authzScannerEngine } from './authz-scanner';

// Direct engine exports (used by rules and the code-scanner facade)
export * from './secrets-engine';
export { scanFilesForPatterns, multilangFindingToFinding, MULTILANG_DETECTORS } from './multilang-engine';
export type { MultiLangFinding, MultiLangDetector } from './multilang-engine';

// Runtime engine — public API for Phase 6
export { RuntimeScanner } from './runtime-engine';

// Authz engine — public API for Phase 7
export { AuthzScanner } from './authz-engine';
