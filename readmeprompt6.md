Continue from the static scanner and rule-pack architecture.

Now design and implement the runtime scanning engine in a safe, non-destructive way.

Goal:
The scanner should be able to test a running local or staging application through HTTP and browser automation while staying strictly within user-defined scope.

1. Runtime architecture

Create:

- RuntimeScanner
- ScopeManager
- BrowserCrawler
- HttpProbeEngine
- FormAnalyzer
- HeaderAnalyzer
- CookieAnalyzer
- CorsAnalyzer
- RedirectAnalyzer
- ReflectionAnalyzer
- ExposedFileAnalyzer
- RuntimeFindingBuilder

2. ScopeManager

Implement strict scope rules.

Config:

runtime: {
  baseUrl: string;
  allowedHosts: string[];
  disallowedHosts: string[];
  disallowedPaths: string[];
  maxPages: number;
  maxDepth: number;
  maxRequests: number;
  requestDelayMs: number;
  timeoutMs: number;
  safeMode: true;
  userAgent: string;
}

Defaults:
- same-origin only
- safeMode true
- maxPages 100
- maxDepth 3
- maxRequests 300
- delay 100ms
- no external links
- no destructive form submission

3. Destructive action guard

Create isDestructiveUrlOrForm().

Block by default when path/form contains:

- delete
- remove
- destroy
- logout
- payment
- checkout
- subscribe
- unsubscribe
- reset
- transfer
- withdraw
- admin/delete
- billing
- password
- token
- revoke

Also avoid forms with:
- password fields
- card/payment fields
- file upload fields initially
- delete confirmation fields

4. BrowserCrawler

Use Playwright.

Collect:
- pages visited
- links
- forms
- scripts
- network requests
- response status
- response headers
- cookies
- console errors
- page errors
- redirects
- API calls observed

Respect ScopeManager.

5. HTTP probe engine

Perform safe GET/HEAD/OPTIONS probes only by default.

Check:
- security headers
- CORS
- cookies
- exposed files
- source maps
- admin/debug route exposure
- robots.txt
- sitemap.xml
- OpenAPI/Swagger/GraphQL exposure

6. Header analyzer

Check:
- missing Content-Security-Policy
- weak CSP with unsafe-inline/unsafe-eval
- missing HSTS on HTTPS
- missing X-Frame-Options or CSP frame-ancestors
- missing X-Content-Type-Options
- missing Referrer-Policy
- broad Permissions-Policy

7. Cookie analyzer

Check:
- auth/session cookies missing HttpOnly
- auth/session cookies missing Secure on HTTPS
- auth/session cookies missing SameSite
- JWT-like cookie value
- long expiry
- insecure domain scope

8. CORS analyzer

Send controlled Origin headers:
- https://evil.example
- null
- http://localhost:9999

Flag:
- reflected arbitrary origin
- wildcard origin with credentials
- credentials true with broad origin
- dev origins allowed on production-looking target

9. Reflection analyzer

Use harmless markers only:

appsecscanner_marker_<random>

Test:
- safe GET parameters
- search fields
- non-sensitive forms

Detect context:
- reflected in raw HTML text
- reflected in HTML attribute
- reflected inside script block
- reflected in JSON
- reflected in URL

Report as potential reflected injection/XSS candidate based on context.

Do not use exploit payloads in this phase.

10. Open redirect analyzer

Test only known redirect parameters:

- next
- redirect
- redirect_url
- returnUrl
- callbackUrl
- continue
- url

Use safe target:
https://example.com/appsecscanner-redirect-test

Flag if Location header points to the external test URL.

11. Exposed file analyzer

Check safe GET requests for:

- /.env
- /.git/config
- /package.json
- /pnpm-lock.yaml
- /yarn.lock
- /package-lock.json
- /tsconfig.json
- /next.config.js
- /vite.config.ts
- /swagger.json
- /openapi.json
- /api-docs
- /graphql
- /metrics
- /debug

12. Runtime findings

Runtime findings must include:

- URL
- method
- status code
- request evidence
- response evidence
- header/cookie name if relevant
- redacted values
- OWASP mapping
- confidence
- recommendation

13. Runtime report section

In HTML/JSON report, separate:

- Static Findings
- Secret Findings
- Supply Chain Findings
- Config Findings
- Runtime Findings

14. Tests

Add mocked tests for:
- scope enforcement
- destructive action guard
- header analysis
- cookie analysis
- CORS analysis
- redirect analysis
- exposed file path generation
- reflection context classifier
