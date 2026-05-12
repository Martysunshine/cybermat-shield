# Auth / Access-Control Scanning

CyberMat Shield's `scan-auth` command tests for Broken Access Control (OWASP A01) by making HTTP requests as different users and comparing the responses.

---

## What it tests

| Test Type | Description | OWASP |
|---|---|---|
| **Anonymous Access** | Checks if protected routes return data without any auth | A01, A07 |
| **Vertical Privilege** | Checks if a low-privilege user can reach admin routes | A01 |
| **Horizontal IDOR** | Checks if userA can read userB's private resources | A01 |
| **Tenant Boundary** (static) | Checks static code for routes that accept org/tenant IDs without membership checks | A01, A06 |
| **Method Authorization** | Checks if sensitive routes expose mutation methods without auth | A01 |

---

## What it will NOT do

- Brute-force IDs or accounts
- Generate random IDs to guess resources
- Send POST/PUT/PATCH/DELETE requests unless explicitly configured
- Make requests to destructive paths (`/delete`, `/logout`, `/reset`, etc.)
- Exceed `maxAuthzRequests` (default: 75) per scan
- Make requests outside the configured origin

---

## Requirements

1. A running web application you own or have explicit permission to test
2. Two test user accounts with different permissions
3. Playwright storageState files for each user (see below)

---

## Quick setup (for the built-in test target)

The `examples/vulnerable-next-app` already has hardcoded test accounts. Run these two commands:

```bash
# Terminal 1 — start the test app
cd examples/vulnerable-next-app
npx next dev

# Terminal 2 — save sessions, then scan
npx tsx --tsconfig scripts/tsconfig.json scripts/setup-auth-profiles.ts
node packages/cli/dist/index.js scan-auth http://localhost:3000
```

> **Session reset warning:** The test app stores sessions in-memory. They reset every time the dev server restarts. Run `setup-auth-profiles.ts` again any time you restart the server, and run the scan immediately after — before Next.js performs a hot reload.

---

## Setting up auth profiles for your own app

### Step 1 — Create config

```bash
node packages/cli/dist/index.js auth init
```

This creates `.appsec/auth-config.json`:

```json
{
  "baseUrl": "http://localhost:3000",
  "profiles": {
    "userA": {
      "label": "low-privileged-user-a",
      "storageStatePath": ".appsec/auth/userA.storage.json"
    },
    "userB": {
      "label": "low-privileged-user-b",
      "storageStatePath": ".appsec/auth/userB.storage.json"
    },
    "admin": {
      "label": "admin-user",
      "storageStatePath": ".appsec/auth/admin.storage.json",
      "isPrivileged": true
    }
  },
  "accessControlTests": [
    {
      "name": "User resource ownership",
      "type": "horizontal",
      "userAOwns": ["/api/resources/resource-id-owned-by-user-a"],
      "userBOwns": ["/api/resources/resource-id-owned-by-user-b"],
      "shouldBePrivate": true
    }
  ],
  "maxAuthzRequests": 75,
  "requestDelayMs": 150
}
```

### Step 2 — Export storageState for each user

**Option A: Using the automated setup script**

Adapt `scripts/setup-auth-profiles.ts` to your app's login page URL and credentials.

**Option B: Manually with Playwright**

```typescript
import { chromium } from 'playwright';
import { mkdir } from 'fs/promises';

const browser = await chromium.launch({ headless: false });
const context = await browser.newContext();
const page = await context.newPage();

// Log in as userA
await page.goto('http://localhost:3000/login');
await page.fill('[name=email]', 'usera@yourapp.com');
await page.fill('[name=password]', 'userA-password');
await page.click('button[type=submit]');
await page.waitForURL('**/dashboard');

// Save session
await mkdir('.appsec/auth', { recursive: true });
await context.storageState({ path: '.appsec/auth/userA.storage.json' });
await browser.close();
```

**Option C: Cookie/Authorization header (no Playwright)**

```json
"userA": {
  "label": "user-a",
  "cookies": "session=<your-session-cookie>",
  "headers": {
    "Authorization": "Bearer <your-jwt>"
  }
}
```

> **Security:** storageState files contain real session cookies. Add `.appsec/auth/` to your `.gitignore` immediately. Never commit these files.

### Step 3 — Validate

```bash
node packages/cli/dist/index.js auth test-config
```

### Step 4 — Scan

```bash
node packages/cli/dist/index.js scan-auth http://localhost:3000
```

---

## Configuring IDOR tests

Horizontal IDOR tests require you to specify which resources belong to which user:

```json
"accessControlTests": [
  {
    "name": "Private profile",
    "type": "horizontal",
    "userAOwns": ["/api/profiles/123"],
    "userBOwns": ["/api/profiles/456"],
    "shouldBePrivate": true
  },
  {
    "name": "Private messages",
    "type": "horizontal",
    "userAOwns": ["/api/messages/thread-aaa"],
    "userBOwns": ["/api/messages/thread-bbb"],
    "shouldBePrivate": true
  }
]
```

The scanner will:
1. Verify userA can access `userAOwns` (baseline)
2. Verify userB can access `userBOwns` (baseline)
3. Try userB accessing `userAOwns` — should be blocked (401/403/redirect)
4. Try userA accessing `userBOwns` — should be blocked

---

## Example findings

### Anonymous route access
```
[HIGH] Sensitive data returned to anonymous request
URL: /api/admin
Detail: Anonymous request received sensitive fields: email, role, passwordHash
Fix: Enforce authentication server-side on every protected route.
```

### Vertical privilege escalation
```
[HIGH] Low-privilege user can access admin/privileged route
URL: /api/admin
Profile: userA
Detail: Route returned HTTP 200 to profile "userA". Sensitive fields: email, role, passwordHash
Fix: Implement RBAC. Check user role server-side on every admin route.
```

### Horizontal IDOR
```
[HIGH] IDOR: userB can access userA's resource
URL: /api/resources/resource-1
Profile: userB
Target: userA
Detail: Profile "userB" retrieved HTTP 200 from a resource owned by "userA". No ownership check detected.
Fix: Verify resource ownership server-side. Never trust IDs from the client.
```

---

## Safety limits

| Setting | Default | Purpose |
|---|---|---|
| `maxAuthzRequests` | 75 | Total request budget per scan |
| `requestDelayMs` | 150 | Delay between requests (ms) |
| `timeoutMs` | 10000 | Per-request timeout (ms) |
| Allowed methods | GET, HEAD | No mutation by default |
| Destructive paths | Blocked | `/delete`, `/logout`, `/reset`, etc. |

---

## Remediation guidance

| Issue | Fix |
|---|---|
| Anonymous route access | Enforce auth server-side. Redirects on the client are not auth. |
| Vertical privilege | Check user role on every admin endpoint. |
| IDOR | Compare `resource.ownerId === currentUser.id` before returning data. |
| Tenant boundary | Filter all queries by `tenantId` from the authenticated session, not from request params. |
| Supabase | Enable Row-Level Security (RLS) on all tables. |
| Firebase | Set security rules to require `auth.uid === userId` on user-specific paths. |

---

## Security of the scanner itself

- All session tokens are loaded from storageState files and never logged or stored in reports
- Report files (`auth-report.json`) contain finding descriptions but not raw session tokens
- The scanner never stores credentials in memory beyond the duration of the scan
- Add `.appsec/auth/` to `.gitignore` to prevent accidentally committing session files
