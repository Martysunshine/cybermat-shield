import type { Rule } from '@cybermat/shared';

/**
 * Runtime rule pack — Layer 2 (Phase 6)
 *
 * Rules in this pack run only when the runtime scanner is active.
 * They consume findings from the BrowserCrawler and HTTP probe engine,
 * not from static file analysis.
 *
 * Planned rules:
 *   - runtime.missing-csp-header
 *   - runtime.missing-hsts
 *   - runtime.cors-reflected-origin
 *   - runtime.cors-wildcard-credentials
 *   - runtime.insecure-cookie-flags
 *   - runtime.open-redirect
 *   - runtime.reflected-input-html
 *   - runtime.exposed-env-file
 *   - runtime.exposed-git-config
 *   - runtime.exposed-swagger
 */
export const runtimeRules: Rule[] = [];
