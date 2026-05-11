import type { CrawledPage, CrawledCookie, CrawledForm, NetworkRequest } from '@cybermat/shared';
import type { ScopeManager } from './scope-manager';
import { isDestructiveUrlOrForm } from './destructive-guard';

export class BrowserCrawler {
  private pagesVisited = 0;
  private requestsMade = 0;

  constructor(private readonly scope: ScopeManager) {}

  async crawl(): Promise<CrawledPage[]> {
    // Dynamic import so the package still builds if playwright isn't installed
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { chromium } = require('playwright') as typeof import('playwright');

    const browser = await chromium.launch({ headless: true });
    try {
      const context = await browser.newContext({ userAgent: this.scope.userAgent });
      const pages: CrawledPage[] = [];
      const visited = new Set<string>();
      const queue: Array<{ url: string; depth: number }> = [
        { url: this.scope.baseUrl, depth: 0 },
      ];

      while (queue.length > 0 && this.scope.withinLimits(this.pagesVisited, this.requestsMade)) {
        const item = queue.shift();
        if (!item) break;
        const { url, depth } = item;

        if (visited.has(url)) continue;
        if (!this.scope.isInScope(url)) continue;
        if (!this.scope.withinDepth(depth)) continue;
        if (isDestructiveUrlOrForm(url)) continue;

        visited.add(url);
        const crawled = await this.visitPage(context, url, depth);
        if (crawled) {
          pages.push(crawled);
          this.pagesVisited++;
          for (const link of crawled.links) {
            if (!visited.has(link) && this.scope.isInScope(link)) {
              queue.push({ url: link, depth: depth + 1 });
            }
          }
        }

        if (this.scope.requestDelayMs > 0) {
          await new Promise(r => setTimeout(r, this.scope.requestDelayMs));
        }
      }

      await context.close();
      return pages;
    } finally {
      await browser.close();
    }
  }

  private async visitPage(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    context: any,
    url: string,
    depth: number,
  ): Promise<CrawledPage | null> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const page: any = await context.newPage();
    const networkRequests: NetworkRequest[] = [];
    const consoleErrors: string[] = [];

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    page.on('request', (req: any) => {
      this.requestsMade++;
      networkRequests.push({ url: req.url(), method: req.method() });
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    page.on('console', (msg: any) => {
      if (msg.type() === 'error') consoleErrors.push(String(msg.text()));
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    page.on('pageerror', (err: any) => consoleErrors.push(String(err?.message ?? err)));

    try {
      const response = await page.goto(url, {
        waitUntil: 'domcontentloaded',
        timeout: this.scope.timeoutMs,
      });
      if (!response) return null;

      const headers: Record<string, string> = {};
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      Object.entries(response.headers() as Record<string, any>).forEach(([k, v]) => {
        headers[k.toLowerCase()] = String(v);
      });

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const rawCookies: any[] = await context.cookies(url);
      const cookies: CrawledCookie[] = rawCookies.map((c: any) => ({
        name: String(c.name),
        value: String(c.value),
        domain: c.domain,
        path: c.path,
        secure: Boolean(c.secure),
        httpOnly: Boolean(c.httpOnly),
        sameSite: c.sameSite,
        expires: typeof c.expires === 'number' ? c.expires : undefined,
      }));

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const links: string[] = await page.$$eval('a[href]', (anchors: any[]) =>
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        anchors.map((a: any) => a.href as string).filter((href: string) => href.startsWith('http')),
      );

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const forms: CrawledForm[] = await page.$$eval('form', (formEls: any[]) =>
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        formEls.map((form: any) => ({
          action: (form.action as string) || undefined,
          method: (form.method as string) || 'GET',
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          fields: Array.from(form.elements as any[]).map((el: any) => ({
            name: (el.name as string) || undefined,
            type: (el.type as string) || undefined,
            value: (el.value as string) || undefined,
          })),
        })),
      );

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const scripts: string[] = await page.$$eval('script[src]', (els: any[]) =>
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        els.map((s: any) => s.src as string).filter(Boolean),
      );

      return {
        url,
        depth,
        statusCode: response.status(),
        headers,
        cookies,
        links: [...new Set(links)],
        forms,
        scripts,
        networkRequests,
        consoleErrors,
        redirectChain: [],
      };
    } catch {
      return null;
    } finally {
      await page.close();
    }
  }
}
