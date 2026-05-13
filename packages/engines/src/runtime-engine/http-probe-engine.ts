import type { ScopeManager } from './scope-manager';

export interface ProbeResponse {
  url: string;
  method: string;
  statusCode: number;
  headers: Record<string, string>;
  body: string;
}

const SAFE_REDIRECT_TARGET_PREFIX = 'https://example.com/cybermat-redirect-test';

export class HttpProbeEngine {
  constructor(private readonly scope: ScopeManager) {}

  async get(url: string, extraHeaders: Record<string, string> = {}): Promise<ProbeResponse | null> {
    if (!this.scope.isInScope(url) && !url.startsWith(SAFE_REDIRECT_TARGET_PREFIX)) return null;
    return this.probe('GET', url, extraHeaders);
  }

  async head(url: string): Promise<ProbeResponse | null> {
    if (!this.scope.isInScope(url)) return null;
    return this.probe('HEAD', url);
  }

  private async probe(
    method: string,
    url: string,
    extraHeaders: Record<string, string> = {},
  ): Promise<ProbeResponse | null> {
    try {
      const response = await fetch(url, {
        method,
        headers: { 'User-Agent': this.scope.userAgent, ...extraHeaders },
        redirect: 'manual',
        signal: AbortSignal.timeout(this.scope.timeoutMs),
      });

      const headers: Record<string, string> = {};
      response.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });

      let body = '';
      if (method === 'GET') {
        try { body = await response.text(); } catch { /* ignore */ }
      }

      return { url, method, statusCode: response.status, headers, body };
    } catch {
      return null;
    }
  }
}
