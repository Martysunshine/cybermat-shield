import type { RuntimeConfig } from '@cybermat/shared';

export const DEFAULT_RUNTIME_CONFIG = {
  allowedHosts: [] as string[],
  disallowedHosts: [] as string[],
  disallowedPaths: [] as string[],
  maxPages: 100,
  maxDepth: 3,
  maxRequests: 300,
  requestDelayMs: 100,
  timeoutMs: 30_000,
  safeMode: true,
  userAgent: 'CyberMat-Shield/0.6.0 (cybermat-scanner; safe-mode)',
} as const;

export class ScopeManager {
  private readonly cfg: Required<RuntimeConfig>;
  private readonly baseHost: string;

  constructor(config: RuntimeConfig) {
    const url = new URL(config.baseUrl);
    this.baseHost = url.hostname;
    this.cfg = {
      baseUrl: config.baseUrl,
      allowedHosts: config.allowedHosts ?? [],
      disallowedHosts: config.disallowedHosts ?? [],
      disallowedPaths: config.disallowedPaths ?? [],
      maxPages: config.maxPages ?? DEFAULT_RUNTIME_CONFIG.maxPages,
      maxDepth: config.maxDepth ?? DEFAULT_RUNTIME_CONFIG.maxDepth,
      maxRequests: config.maxRequests ?? DEFAULT_RUNTIME_CONFIG.maxRequests,
      requestDelayMs: config.requestDelayMs ?? DEFAULT_RUNTIME_CONFIG.requestDelayMs,
      timeoutMs: config.timeoutMs ?? DEFAULT_RUNTIME_CONFIG.timeoutMs,
      safeMode: config.safeMode ?? DEFAULT_RUNTIME_CONFIG.safeMode,
      userAgent: config.userAgent ?? DEFAULT_RUNTIME_CONFIG.userAgent,
    };
  }

  isInScope(url: string): boolean {
    let parsed: URL;
    try { parsed = new URL(url); } catch { return false; }

    const allowed = this.cfg.allowedHosts.length > 0
      ? [this.baseHost, ...this.cfg.allowedHosts]
      : [this.baseHost];

    if (!allowed.includes(parsed.hostname)) return false;
    if (this.cfg.disallowedHosts.includes(parsed.hostname)) return false;

    const p = parsed.pathname.toLowerCase();
    if (this.cfg.disallowedPaths.some(dp => p.startsWith(dp.toLowerCase()))) return false;

    return true;
  }

  withinLimits(pagesVisited: number, requestsMade: number): boolean {
    return pagesVisited < this.cfg.maxPages && requestsMade < this.cfg.maxRequests;
  }

  withinDepth(depth: number): boolean {
    return depth <= this.cfg.maxDepth;
  }

  get baseUrl(): string { return this.cfg.baseUrl; }
  get requestDelayMs(): number { return this.cfg.requestDelayMs; }
  get timeoutMs(): number { return this.cfg.timeoutMs; }
  get userAgent(): string { return this.cfg.userAgent; }
  get safeMode(): boolean { return this.cfg.safeMode; }
}
