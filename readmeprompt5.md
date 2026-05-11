Continue from the deeper scanner architecture.

Now implement a professional rule-pack system and OWASP/ASVS/WSTG mapping layer.

Goal:
Rules should not be random checks. Every rule must have metadata, category, OWASP mapping, CWE mapping where possible, confidence logic, examples, and remediation text.

1. Rule pack architecture

Create rule packs:

- rules/core
- rules/secrets
- rules/javascript-typescript
- rules/react
- rules/nextjs
- rules/node-express
- rules/supabase
- rules/firebase
- rules/clerk
- rules/stripe
- rules/ai-security
- rules/config
- rules/supply-chain
- rules/runtime-placeholder
- rules/authz-placeholder

Each rule pack should export:

const rulePack = {
  id: string;
  name: string;
  description: string;
  rules: Rule[];
};

2. Rule metadata

Every rule must include:

type RuleMetadata = {
  id: string;
  name: string;
  description: string;
  engine: "secrets" | "static" | "dependency" | "config" | "runtime" | "authz" | "ai";
  category: string;
  severity: Severity;
  confidence: Confidence;
  owasp2025: string[];
  cwe?: string[];
  asvs?: string[];
  wstg?: string[];
  tags: string[];
  enabledByDefault: boolean;
  safeForCI: boolean;
  requiresRuntime: boolean;
  requiresAuth: boolean;
  falsePositiveNotes?: string;
  remediation: string;
  fixExample?: string;
};

3. OWASP Top 10:2025 mapping

Use these categories:

A01 Broken Access Control
A02 Security Misconfiguration
A03 Software Supply Chain Failures
A04 Cryptographic Failures
A05 Injection
A06 Insecure Design
A07 Authentication Failures
A08 Software or Data Integrity Failures
A09 Security Logging and Alerting Failures
A10 Mishandling of Exceptional Conditions

Create mapping helper:

mapFindingToOwasp(finding): string[]

A finding can map to multiple categories.

Examples:
- IDOR → A01
- CSRF → A01/A07 depending context
- SSRF → A01/A05 depending context
- CORS misconfig → A02
- exposed secret → A04/A02
- raw SQL injection → A05
- no rate limiting → A06/A07
- missing webhook signature → A08
- no audit logs → A09
- swallowed auth exception → A10/A01
- vulnerable dependency → A03
- unsafe LLM output rendered as HTML → A05/A06
- AI agent destructive action without approval → A06/A08

4. ASVS/WSTG placeholders

Add optional fields for ASVS and WSTG IDs but do not require complete mapping yet.

The architecture should support adding ASVS and WSTG references later.

5. Rule examples

Each rule should have:
- insecure example
- safer example
- explanation

Store examples as strings or markdown.

6. Rule registry

Create RuleRegistry:

- registerRulePack()
- listRules()
- getRuleById()
- getRulesByEngine()
- getRulesByOwasp()
- enableRule()
- disableRule()
- applySeverityOverride()

7. CLI rule commands

Add:

appsec rules list
appsec rules show <ruleId>
appsec rules list --owasp A05
appsec rules list --engine secrets
appsec rules list --tag nextjs

8. Config overrides

Support in config:

{
  "rules": {
    "disabled": ["nextjs.missing-auth-route"],
    "enabled": [],
    "severityOverrides": {
      "secrets.firebase-api-key-public": "info"
    }
  }
}

9. Rule documentation generator

Generate docs/rules.md automatically from rule metadata.

Include:
- rule id
- title
- severity
- OWASP mapping
- description
- insecure example
- safer example
- remediation
- false positive notes

10. Tests

Add tests for:
- rule registry
- rule metadata validation
- config overrides
- OWASP mapping helper
- docs generation
