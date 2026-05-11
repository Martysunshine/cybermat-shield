export { RuntimeScanner } from './runtime-scanner';
export { ScopeManager, DEFAULT_RUNTIME_CONFIG } from './scope-manager';
export { isDestructiveUrl, isDestructiveForm, isDestructiveUrlOrForm } from './destructive-guard';
export type { FormSnapshot } from './destructive-guard';
export { analyzeHeaders } from './header-analyzer';
export { analyzeCookies } from './cookie-analyzer';
export { analyzeCorsResults, CORS_TEST_ORIGINS } from './cors-analyzer';
export type { CorsProbeResult } from './cors-analyzer';
export { generateMarker, classifyReflectionContext, buildReflectionFinding } from './reflection-analyzer';
export type { ReflectionContext, ReflectionResult } from './reflection-analyzer';
export { buildRedirectTestUrls, analyzeRedirectResults, REDIRECT_PARAMS, SAFE_REDIRECT_TARGET } from './redirect-analyzer';
export type { RedirectProbeResult } from './redirect-analyzer';
export { analyzeExposedFiles, EXPOSED_FILE_CHECKS } from './exposed-file-analyzer';
export type { ExposedFileCheck, ExposedFileProbeResult } from './exposed-file-analyzer';
export { RuntimeFindingBuilder } from './runtime-finding-builder';
export { HttpProbeEngine } from './http-probe-engine';
export { BrowserCrawler } from './browser-crawler';

export const RUNTIME_ENGINE_VERSION = '0.6.0';
