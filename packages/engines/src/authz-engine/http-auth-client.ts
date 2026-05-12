import type { AuthProfile, ResponseSnapshot } from '@cybermat/shared';

export interface ProbeResult {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  contentLength: number;
  error?: string;
}

export class HttpAuthClient {
  constructor(
    private readonly timeoutMs: number = 10000,
    private readonly delayMs: number = 150,
  ) {}

  async probe(url: string, profile: AuthProfile): Promise<ProbeResult> {
    if (this.delayMs > 0) await new Promise(r => setTimeout(r, this.delayMs));
    try {
      const res = await fetch(url, {
        method: 'GET',
        headers: { 'user-agent': 'CyberMat-Shield/0.7.0 (authz-scanner)', ...profile.headers },
        redirect: 'manual',
        signal: AbortSignal.timeout(this.timeoutMs),
      });

      const body = await res.text().catch(() => '');
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });

      return {
        url,
        status: res.status,
        headers,
        body,
        contentLength: body.length,
      };
    } catch (err: unknown) {
      return { url, status: 0, headers: {}, body: '', contentLength: 0, error: String(err) };
    }
  }

  async head(url: string, profile: AuthProfile): Promise<ProbeResult> {
    if (this.delayMs > 0) await new Promise(r => setTimeout(r, this.delayMs));
    try {
      const res = await fetch(url, {
        method: 'HEAD',
        headers: { 'user-agent': 'CyberMat-Shield/0.7.0 (authz-scanner)', ...profile.headers },
        redirect: 'manual',
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      return { url, status: res.status, headers: {}, body: '', contentLength: 0 };
    } catch (err: unknown) {
      return { url, status: 0, headers: {}, body: '', contentLength: 0, error: String(err) };
    }
  }

  static toSnapshot(result: ProbeResult): ResponseSnapshot {
    let jsonKeys: string[] = [];
    try {
      const parsed = JSON.parse(result.body);
      if (parsed && typeof parsed === 'object') {
        jsonKeys = Object.keys(parsed as Record<string, unknown>);
      }
    } catch { /* not JSON */ }

    return {
      status: result.status,
      contentLength: result.contentLength,
      jsonKeys,
      sensitiveFields: [],
      body: result.body,
    };
  }
}
