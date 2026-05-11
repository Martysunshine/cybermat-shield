import type { Rule, Finding, RuleContext } from '@cybermat/shared';
import { redactSecret, redactLine, truncate, makeFindingId, isClientFile } from '../utils';

interface SecretPattern {
  id: string;
  name: string;
  pattern: RegExp;
  valueGroup?: number;
  severity: 'critical' | 'high' | 'medium';
  owasp: string[];
  impact: string;
  recommendation: string;
  frontendUpgrade?: boolean;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: 'secrets.supabase-service-role-key',
    name: 'Supabase Service Role Key',
    pattern: /SUPABASE_SERVICE_ROLE_KEY\s*[=:]\s*["']?(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)["']?/,
    valueGroup: 1,
    severity: 'critical',
    owasp: ['A04 Cryptographic Failures', 'A07 Authentication Failures'],
    impact: 'Full database access bypassing Row Level Security. Anyone with this key can read, write, or delete all data.',
    recommendation: 'Rotate this key immediately in the Supabase dashboard. Never use service role key in frontend code.',
    frontendUpgrade: true,
  },
  {
    id: 'secrets.stripe-secret-key',
    name: 'Stripe Secret Key',
    pattern: /(?:STRIPE_SECRET_KEY\s*[=:]\s*["']?|['"])(sk_(?:live|test)_[a-zA-Z0-9]{24,})["']?/,
    valueGroup: 1,
    severity: 'critical',
    owasp: ['A04 Cryptographic Failures'],
    impact: 'Unauthorized payment processing, customer data access, and financial fraud.',
    recommendation: 'Rotate the Stripe secret key immediately. Use it only in server-side environment variables.',
  },
  {
    id: 'secrets.openai-api-key',
    name: 'OpenAI API Key',
    pattern: /(?:OPENAI_API_KEY\s*[=:]\s*["']?|['"])(sk-(?:proj-)?[a-zA-Z0-9\-_]{32,})["']?/,
    valueGroup: 1,
    severity: 'high',
    owasp: ['A04 Cryptographic Failures'],
    impact: 'Unauthorized API usage leading to unexpected billing charges.',
    recommendation: 'Rotate the OpenAI API key. Store in server-only environment variables.',
  },
  {
    id: 'secrets.anthropic-api-key',
    name: 'Anthropic API Key',
    pattern: /(?:ANTHROPIC_API_KEY\s*[=:]\s*["']?|['"])(sk-ant-[a-zA-Z0-9\-_]{20,})["']?/,
    valueGroup: 1,
    severity: 'high',
    owasp: ['A04 Cryptographic Failures'],
    impact: 'Unauthorized Anthropic API usage and unexpected billing.',
    recommendation: 'Rotate the Anthropic API key. Store in server-only environment variables.',
  },
  {
    id: 'secrets.clerk-secret-key',
    name: 'Clerk Secret Key',
    pattern: /CLERK_SECRET_KEY\s*[=:]\s*["']?(sk_(?:live|test)_[a-zA-Z0-9]+)["']?/,
    valueGroup: 1,
    severity: 'critical',
    owasp: ['A04 Cryptographic Failures', 'A07 Authentication Failures'],
    impact: 'Full authentication system compromise, token forgery, and user impersonation.',
    recommendation: 'Rotate Clerk secret key immediately in the Clerk dashboard. Never expose in client code.',
  },
  {
    id: 'secrets.database-url',
    name: 'Database Connection String',
    pattern: /(?:DATABASE_URL|POSTGRES_URL|MONGODB_URI|REDIS_URL|SUPABASE_DB_URL)\s*[=:]\s*["']?((?:postgresql|postgres|mysql|mongodb(?:\+srv)?|redis|rediss):\/\/[^\s"'\n]+)["']?/,
    valueGroup: 1,
    severity: 'critical',
    owasp: ['A04 Cryptographic Failures'],
    impact: 'Direct database access with full credentials, enabling data exfiltration or destruction.',
    recommendation: 'Rotate database credentials immediately. Never commit connection strings to source control.',
  },
  {
    id: 'secrets.jwt-auth-secret',
    name: 'JWT / Auth Secret',
    pattern: /(?:JWT_SECRET|NEXTAUTH_SECRET|AUTH_SECRET|SESSION_SECRET|BETTER_AUTH_SECRET)\s*[=:]\s*["']?([^\s"'\n]{8,})["']?/,
    valueGroup: 1,
    severity: 'high',
    owasp: ['A04 Cryptographic Failures', 'A07 Authentication Failures'],
    impact: 'Session and token forgery. Attackers can impersonate any user.',
    recommendation: 'Rotate the secret. Use a cryptographically random value of at least 32 characters.',
  },
  {
    id: 'secrets.private-key',
    name: 'Private Key Material',
    pattern: /-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|PGP\s+)?PRIVATE KEY-----/,
    severity: 'critical',
    owasp: ['A04 Cryptographic Failures'],
    impact: 'Cryptographic material exposed. Attackers can impersonate servers or decrypt communications.',
    recommendation: 'Remove private key from source. Revoke and rotate the key pair immediately.',
  },
  {
    id: 'secrets.stripe-webhook-secret',
    name: 'Stripe Webhook Secret',
    pattern: /(?:STRIPE_WEBHOOK_SECRET)\s*[=:]\s*["']?(whsec_[a-zA-Z0-9]+)["']?/,
    valueGroup: 1,
    severity: 'high',
    owasp: ['A08 Software or Data Integrity Failures'],
    impact: 'Attackers can forge Stripe webhook events, triggering unauthorized payment flows.',
    recommendation: 'Rotate the webhook signing secret in the Stripe dashboard.',
  },
  {
    id: 'secrets.github-token',
    name: 'GitHub Personal Access Token',
    pattern: /(?:GITHUB_TOKEN|GITHUB_PAT|GH_TOKEN)\s*[=:]\s*["']?((?:ghp|ghs|gho|ghu|github_pat)_[a-zA-Z0-9_]+)["']?/,
    valueGroup: 1,
    severity: 'high',
    owasp: ['A04 Cryptographic Failures'],
    impact: 'Unauthorized access to GitHub repositories, CI/CD pipelines, and organization secrets.',
    recommendation: 'Revoke the token immediately in GitHub settings and rotate.',
  },
  {
    id: 'secrets.sendgrid-api-key',
    name: 'SendGrid / Email API Key',
    pattern: /(?:SENDGRID_API_KEY|RESEND_API_KEY|MAILGUN_API_KEY)\s*[=:]\s*["']?([a-zA-Z0-9.\-_]{20,})["']?/,
    valueGroup: 1,
    severity: 'high',
    owasp: ['A04 Cryptographic Failures'],
    impact: 'Unauthorized email sending, phishing campaigns, or spam from your domain.',
    recommendation: 'Rotate the API key and store in server-only environment variables.',
  },
  {
    id: 'secrets.firebase-private-key',
    name: 'Firebase / GCP Private Key',
    pattern: /(?:FIREBASE_PRIVATE_KEY|GOOGLE_PRIVATE_KEY|GCP_PRIVATE_KEY)\s*[=:]\s*["']?(-----BEGIN[^"']+)["']?/,
    valueGroup: 1,
    severity: 'critical',
    owasp: ['A04 Cryptographic Failures'],
    impact: 'Full Firebase / GCP service account access. Can read/write all Firebase data.',
    recommendation: 'Revoke the service account key in GCP console and rotate immediately.',
  },
];

export const secretsRule: Rule = {
  id: 'secrets',
  name: 'Secret Detection',
  description: 'Detects API keys, credentials, and secrets in source code and config files',
  category: 'Secrets',
  owasp: ['A04 Cryptographic Failures'],
  severity: 'critical',
  run: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    for (const file of context.files) {
      const lines = file.content.split('\n');
      const isClient = isClientFile(file.relativePath, file.content);

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!line.trim() || line.trim().startsWith('//') || line.trim().startsWith('#')) continue;

        for (const sp of SECRET_PATTERNS) {
          const match = sp.pattern.exec(line);
          if (!match) continue;

          const secretValue = sp.valueGroup ? match[sp.valueGroup] : match[0];
          if (!secretValue) continue;

          // Redact BEFORE truncating so the secret isn't visible in trimmed output
          const redactedLine = truncate(redactLine(line, secretValue));

          // Escalate to critical if secret found in frontend/client file
          const severity = sp.frontendUpgrade && isClient ? 'critical' : sp.severity;

          findings.push({
            id: makeFindingId(sp.id, file.relativePath, i + 1),
            title: sp.name,
            severity,
            confidence: 'high',
            owasp: sp.owasp,
            category: 'Secrets',
            file: file.relativePath,
            line: i + 1,
            evidence: redactedLine,
            impact: sp.impact,
            recommendation: sp.recommendation,
          });
        }
      }
    }

    return findings;
  },
};
