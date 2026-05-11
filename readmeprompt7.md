Continue from the existing local-first Application Security Scanner.

The static scanner, rule-pack system, and safe runtime scanner architecture should already exist or be in progress. Now add a controlled authenticated access-control testing module.

Goal:
Build a safe, permission-based access-control scanner that detects Broken Access Control, IDOR/BOLA, missing authorization checks, role bypasses, tenant boundary issues, and protected route exposure.

This module must only run against applications the user owns or has explicit permission to test. It must never perform brute force, account takeover, password guessing, destructive actions, payment actions, deletion actions, or aggressive ID fuzzing.

This is a defensive AppSec scanner, not an exploit tool.

1. Add commands

Add one of these depending on the current CLI naming:

appsec scan-auth <url>

or integrate it into runtime scanning:

appsec scan-runtime <url> --auth

Also support:

appsec auth init
appsec auth test-config

The auth init command should create a config template for authenticated scans.

2. Auth profile configuration

Extend appsec.config.json with:

{
  "authProfiles": {
    "anonymous": {},
    "userA": {
      "label": "low-privileged-user-a",
      "storageStatePath": ".appsec/auth/userA.storage.json",
      "headers": {},
      "cookies": ""
    },
    "userB": {
      "label": "low-privileged-user-b",
      "storageStatePath": ".appsec/auth/userB.storage.json",
      "headers": {},
      "cookies": ""
    },
    "admin": {
      "label": "admin-user",
      "storageStatePath": ".appsec/auth/admin.storage.json",
      "headers": {},
      "cookies": ""
    }
  },
  "accessControlTests": []
}

Important:
- storageStatePath should be preferred for Playwright-authenticated scans.
- Cookies/headers are allowed but should be stored carefully.
- Warn the user that auth files may contain sensitive session data.
- Do not print raw cookies or tokens.
- Redact auth evidence in all reports.

3. Auth profile loader

Create AuthProfileLoader.

It should support:

- anonymous profile
- Playwright storageState JSON
- raw Cookie header
- custom Authorization header
- custom headers

Normalize all profiles into:

type AuthProfile = {
  name: string;
  label: string;
  type: "anonymous" | "storageState" | "headers" | "cookies";
  headers: Record<string, string>;
  cookies?: string;
  storageStatePath?: string;
  isPrivileged?: boolean;
};

Add validation:
- userA and userB should be different profiles.
- admin is optional.
- anonymous always exists.
- warn if only one user profile exists because horizontal authorization tests need two comparable users.

4. Route and resource discovery

Use both static routeMap and runtime crawl results.

Identify candidate protected routes:

- /dashboard
- /settings
- /account
- /profile
- /me
- /admin
- /api/admin
- /api/users
- /api/profile
- /api/settings
- /api/posts
- /api/events
- /api/messages
- /api/conversations
- /api/payments
- /api/billing
- /api/subscriptions
- /api/organizations
- /api/workspaces
- /api/tenants

Identify sensitive route keywords:

- admin
- private
- settings
- account
- billing
- payment
- subscription
- message
- conversation
- user
- profile
- organization
- workspace
- tenant
- internal
- debug

Create:

type AccessRouteCandidate = {
  route: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "HEAD";
  source: "static" | "runtime" | "config";
  file?: string;
  riskTags: string[];
  requiresAuthExpected: boolean;
  destructive: boolean;
};

5. Safe method policy

Default safe mode:

Allowed:
- GET
- HEAD
- OPTIONS

Limited:
- POST only for explicitly configured safe test endpoints
- PUT/PATCH/DELETE disabled by default

Never automatically send destructive requests to paths containing:

- delete
- remove
- destroy
- revoke
- logout
- reset
- transfer
- withdraw
- payment
- checkout
- subscribe
- unsubscribe
- billing
- cancel
- admin/delete

6. Access-control test types

Implement these test classes:

A. Anonymous Access Test

Purpose:
Check if protected-looking pages/API routes are accessible without authentication.

Logic:
- Request candidate protected route as anonymous.
- If status is 200 and response contains sensitive-looking data or protected UI, flag.
- If status is 401/403/redirect-to-login, pass.
- If status is 3xx to login/auth page, pass.

Finding:
- A01 Broken Access Control
- A07 Authentication Failures if authentication enforcement seems missing

B. Vertical Privilege Test

Purpose:
Check if a low-privileged user can access admin/internal routes.

Logic:
- Request admin-looking routes as userA.
- If status is 200 and response looks successful, flag.
- Compare with admin profile if provided.
- If userA receives same/similar response as admin on admin route, flag higher severity.

Finding:
- A01 Broken Access Control

C. Horizontal Access / IDOR Test

Purpose:
Check if userA can access userB’s private resources.

Safe implementation:
- Do not brute force IDs.
- Use explicitly configured resource pairs first.
- Use discovered resource IDs only from userA/userB authenticated sessions.
- Test only limited number of requests.

Config example:

"accessControlTests": [
  {
    "name": "private profile ownership",
    "type": "horizontal",
    "userAOwns": ["/api/profiles/user-a-profile-id"],
    "userBOwns": ["/api/profiles/user-b-profile-id"],
    "shouldBePrivate": true
  },
  {
    "name": "private messages",
    "type": "horizontal",
    "userAOwns": ["/api/messages/thread-owned-by-user-a"],
    "userBOwns": ["/api/messages/thread-owned-by-user-b"],
    "shouldBePrivate": true
  }
]

Test:
- userA can access userAOwns.
- userB can access userBOwns.
- userA cannot access userBOwns.
- userB cannot access userAOwns.
- anonymous cannot access either if shouldBePrivate is true.

D. Tenant Boundary Test

Purpose:
Detect multi-tenant authorization issues.

Look for:
- organizationId
- orgId
- tenantId
- workspaceId
- teamId
- groupId

Static signals:
- API route accepts tenant/org/workspace ID from body/query.
- No obvious membership/role check in route.
- No tenant filter in DB query.

Runtime config-driven test:
- userA belongs to tenant A.
- userB belongs to tenant B.
- Try configured tenant-specific resources across profiles.

E. Method Authorization Test

Purpose:
Check whether route authorization differs by HTTP method.

Safe mode:
- Send OPTIONS.
- Send GET/HEAD.
- Do not send mutation methods unless explicitly configured.

Flag:
- sensitive route exposes unsafe methods without auth.
- API route lists broad methods unexpectedly.

7. Response sensitivity analyzer

Create SensitiveResponseAnalyzer.

It should inspect response body safely and detect sensitive fields:

- email
- phone
- address
- user_id
- owner_id
- role
- isAdmin
- admin
- token
- secret
- apiKey
- session
- jwt
- stripe
- payment
- subscription
- private
- message
- conversation
- internalNote
- passwordHash
- resetToken

Redact all values.

Create:

type SensitiveSignal = {
  field: string;
  confidence: "high" | "medium" | "low";
  redactedEvidence: string;
};

8. Response comparison engine

Create ResponseComparator.

Purpose:
Compare anonymous/userA/userB/admin responses.

Signals:
- same status code
- similar content length
- same JSON keys
- same sensitive fields
- same object IDs
- same user IDs
- same admin-only markers
- same page title or protected layout marker

Use this for:
- anonymous vs userA
- userA vs admin
- userA vs userB
- userB vs userA

Do not rely only on status code. Some apps return 200 with an error message.

9. Static/runtime correlation

When a runtime access-control issue is found, attempt to link it to static evidence:

Examples:
- route file has no auth guard
- route accepts user_id from request body
- route has no role check
- route uses admin keyword but no requireAdmin/currentUser/checkRole
- Supabase query does not filter by owner_id/user_id
- Firebase rules are permissive
- middleware is missing or does not cover route

Add to finding evidence:

evidence: {
  runtime: {...},
  staticCorrelation: {
    file: "...",
    reason: "Route has no obvious auth guard"
  }
}

10. Access-control finding types

Create rules/findings for:

- authz.anonymous-protected-route-accessible
- authz.low-priv-user-admin-route
- authz.horizontal-idor-configured-resource
- authz.tenant-boundary-risk
- authz.route-accepts-user-id-from-client
- authz.missing-role-check-admin-route
- authz.mutation-methods-without-auth
- authz.sensitive-response-to-anonymous

Map to:
- A01 Broken Access Control
- A07 Authentication Failures
- A06 Insecure Design
- A09 Logging and Alerting Failures when lack of audit logging is also detected

11. Rate limits and safety

Defaults:
- maxAuthzRequests: 75
- requestDelayMs: 150
- same-origin only
- safe methods only unless explicitly configured
- no brute force
- no random ID generation by default
- no destructive requests
- stop if target returns many 5xx errors
- stop if user scope is violated

12. Auth scan report section

Add report section:

Access Control Testing

Include:
- profiles used, redacted
- routes tested
- resource pairs tested
- issues found
- skipped destructive routes
- static/runtime correlations
- recommended fixes

Recommended fixes should include:
- enforce authentication server-side
- check ownership server-side
- do not trust user_id from client
- implement role-based access control
- implement organization/tenant membership checks
- enable Supabase RLS
- tighten Firebase rules
- add audit logging
- add tests for access control

13. Tests

Add unit/integration tests for:

- auth profile loading
- cookie/header redaction
- protected route candidate detection
- destructive route filtering
- sensitive response analyzer
- response comparator
- anonymous access finding
- vertical privilege finding
- horizontal IDOR configured test
- tenant boundary static detection
- static/runtime correlation
- max request safety limit

14. Documentation

Create docs/auth-access-control-scanning.md.

Explain:
- what this module tests
- required user permission
- how to create userA/userB test accounts
- how to export Playwright storageState
- how to configure resource pairs
- what the scanner will not do
- safety limits
- example findings
- remediation guidance
