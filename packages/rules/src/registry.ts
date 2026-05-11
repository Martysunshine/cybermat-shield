import type { RuleMetadata, RulePack, RuleEngine, Severity, RulesConfig } from '@cybermat/shared';

export class RuleRegistry {
  private readonly rules = new Map<string, RuleMetadata>();
  private readonly disabledSet = new Set<string>();
  private readonly overrides = new Map<string, Severity>();

  registerRulePack(pack: RulePack): void {
    for (const rule of pack.rules) {
      this.rules.set(rule.id, rule);
    }
  }

  listRules(): RuleMetadata[] {
    return Array.from(this.rules.values());
  }

  getRuleById(id: string): RuleMetadata | undefined {
    return this.rules.get(id);
  }

  getRulesByEngine(engine: RuleEngine): RuleMetadata[] {
    return this.listRules().filter(r => r.engine === engine);
  }

  getRulesByOwasp(owaspCode: string): RuleMetadata[] {
    const q = owaspCode.toUpperCase();
    return this.listRules().filter(r =>
      r.owasp2025.some(o => o.toUpperCase().startsWith(q))
    );
  }

  getRulesByTag(tag: string): RuleMetadata[] {
    const q = tag.toLowerCase();
    return this.listRules().filter(r => r.tags.some(t => t.toLowerCase() === q));
  }

  enableRule(id: string): void {
    this.disabledSet.delete(id);
  }

  disableRule(id: string): void {
    this.disabledSet.add(id);
  }

  applySeverityOverride(id: string, severity: Severity): void {
    this.overrides.set(id, severity);
  }

  isEnabled(id: string): boolean {
    return !this.disabledSet.has(id);
  }

  getEffectiveSeverity(id: string, defaultSeverity: Severity): Severity {
    return this.overrides.get(id) ?? defaultSeverity;
  }

  applyConfig(config: RulesConfig): void {
    for (const id of config.disabled ?? []) this.disableRule(id);
    for (const id of config.enabled ?? []) this.enableRule(id);
    for (const [id, sev] of Object.entries(config.severityOverrides ?? {})) {
      this.applySeverityOverride(id, sev);
    }
  }
}
