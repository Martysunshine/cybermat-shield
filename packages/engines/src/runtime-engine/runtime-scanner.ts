import type { RuntimeConfig, RuntimeFinding, RuntimeScanReport, ScanSummary } from '@cybermat/shared';
import { ScopeManager } from './scope-manager';
import { HttpProbeEngine } from './http-probe-engine';
import { BrowserCrawler } from './browser-crawler';
import { analyzeHeaders } from './header-analyzer';
import { analyzeCookies } from './cookie-analyzer';
import { analyzeCorsResults, CORS_TEST_ORIGINS } from './cors-analyzer';
import { analyzeExposedFiles, EXPOSED_FILE_CHECKS } from './exposed-file-analyzer';
import { buildRedirectTestUrls, analyzeRedirectResults } from './redirect-analyzer';
import { generateMarker, classifyReflectionContext, buildReflectionFinding } from './reflection-analyzer';
import type { CrawledForm } from '@cybermat/shared';

const SEVERITY_WEIGHTS = { critical: 25, high: 12, medium: 5, low: 2, info: 0 } as const;

export class RuntimeScanner {
  private readonly scope: ScopeManager;
  private readonly http: HttpProbeEngine;

  constructor(private readonly config: RuntimeConfig) {
    this.scope = new ScopeManager(config);
    this.http = new HttpProbeEngine(this.scope);
  }

  async run(): Promise<RuntimeScanReport> {
    const startTime = Date.now();
    const findings: RuntimeFinding[] = [];
    const isHttps = this.config.baseUrl.startsWith('https://');

    // 1. Probe main URL headers
    const mainProbe = await this.http.get(this.config.baseUrl);
    if (mainProbe) {
      findings.push(...analyzeHeaders(this.config.baseUrl, mainProbe.headers, isHttps));
    }

    // 2. CORS probes
    const corsResults = await Promise.all(
      CORS_TEST_ORIGINS.map(async origin => {
        const r = await this.http.get(this.config.baseUrl, { Origin: origin });
        return {
          testOrigin: origin,
          allowOrigin: r?.headers['access-control-allow-origin'],
          allowCredentials: r?.headers['access-control-allow-credentials'],
          statusCode: r?.statusCode ?? 0,
        };
      }),
    );
    findings.push(...analyzeCorsResults(this.config.baseUrl, corsResults));

    // 3. Open redirect probes
    const redirectTests = buildRedirectTestUrls(this.config.baseUrl);
    const redirectResults = await Promise.all(
      redirectTests.map(async ({ url, param }) => {
        const r = await this.http.get(url);
        return { url, param, statusCode: r?.statusCode ?? 0, locationHeader: r?.headers['location'] };
      }),
    );
    findings.push(...analyzeRedirectResults(redirectResults));

    // 4. Exposed file probes
    const exposedResults = await Promise.all(
      EXPOSED_FILE_CHECKS.map(async check => {
        const base = this.config.baseUrl.replace(/\/$/, '');
        const r = await this.http.get(`${base}${check.path}`);
        return {
          path: check.path,
          statusCode: r?.statusCode ?? 0,
          contentType: r?.headers['content-type'],
          bodyPreview: r?.body?.slice(0, 100),
        };
      }),
    );
    findings.push(...analyzeExposedFiles(this.config.baseUrl, exposedResults));

    // 5. Browser crawl — cookies, forms, reflection
    let pagesVisited = 0;
    let requestsMade = 0;
    try {
      const crawler = new BrowserCrawler(this.scope);
      const pages = await crawler.crawl();
      pagesVisited = pages.length;
      requestsMade = pages.reduce((n, p) => n + p.networkRequests.length, 0);

      for (const page of pages) {
        findings.push(...analyzeCookies(page.url, page.cookies, isHttps));
        const reflectionFindings = await this.reflectionScan(page.url, page.forms);
        findings.push(...reflectionFindings);
      }
    } catch {
      // Playwright unavailable or timed out — skip browser checks
    }

    return this.buildReport(findings, pagesVisited, requestsMade, Date.now() - startTime);
  }

  private async reflectionScan(pageUrl: string, forms: CrawledForm[]): Promise<RuntimeFinding[]> {
    const findings: RuntimeFinding[] = [];

    // Only test query params that already exist on the page (no guessing)
    const params = new URL(pageUrl).searchParams;
    for (const [param] of params.entries()) {
      const marker = generateMarker();
      const testUrl = new URL(pageUrl);
      testUrl.searchParams.set(param, marker);
      const r = await this.http.get(testUrl.toString());
      if (r) {
        const context = classifyReflectionContext(r.body, marker);
        const finding = buildReflectionFinding({ url: testUrl.toString(), param, marker, context });
        if (finding) findings.push(finding);
      }
    }

    // Test safe GET forms that don't look destructive
    for (const form of forms) {
      if ((form.method ?? 'GET').toUpperCase() !== 'GET') continue;
      const action = form.action ?? pageUrl;
      if (!this.scope.isInScope(action)) continue;

      for (const field of form.fields) {
        if (!field.name || field.type === 'hidden' || field.type === 'submit') continue;
        const marker = generateMarker();
        const testUrl = new URL(action, pageUrl);
        testUrl.searchParams.set(field.name, marker);
        const r = await this.http.get(testUrl.toString());
        if (r) {
          const context = classifyReflectionContext(r.body, marker);
          const finding = buildReflectionFinding({ url: testUrl.toString(), param: field.name, marker, context });
          if (finding) findings.push(finding);
        }
      }
    }

    return findings;
  }

  private buildReport(
    findings: RuntimeFinding[],
    pagesVisited: number,
    requestsMade: number,
    durationMs: number,
  ): RuntimeScanReport {
    const summary: ScanSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    const owaspSet = new Set<string>();

    for (const f of findings) {
      summary[f.severity]++;
      summary.total++;
      f.owasp.forEach(o => owaspSet.add(o));
    }

    const deduction = findings.reduce((n, f) => n + SEVERITY_WEIGHTS[f.severity], 0);
    const riskScore = Math.max(0, 100 - deduction);

    const sevOrder = ['critical', 'high', 'medium', 'low', 'info'] as const;
    const sorted = [...findings].sort(
      (a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity),
    );
    const seenRecs = new Set<string>();
    const topRecommendations: string[] = [];
    for (const f of sorted) {
      const key = f.recommendation.slice(0, 60);
      if (!seenRecs.has(key)) {
        seenRecs.add(key);
        topRecommendations.push(f.recommendation);
      }
      if (topRecommendations.length >= 5) break;
    }

    return {
      targetUrl: this.config.baseUrl,
      pagesVisited,
      requestsMade,
      durationMs,
      findings,
      summary,
      riskScore,
      owaspCoverage: Array.from(owaspSet),
      topRecommendations,
    };
  }
}
