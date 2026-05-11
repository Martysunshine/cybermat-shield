import type { Rule } from '@cybermat/shared';

/**
 * Auth / Access-Control rule pack — Layer 3 (Phase 7)
 *
 * Rules in this pack only run when the authz scanner is active AND
 * auth profiles have been configured by the user.
 *
 * Planned rules:
 *   - authz.anonymous-access-to-protected-route
 *   - authz.vertical-privilege-escalation
 *   - authz.horizontal-idor-resource-access
 *   - authz.tenant-boundary-violation
 *   - authz.admin-route-accessible-to-user
 *   - authz.sensitive-data-in-response-without-auth
 */
export const authzRules: Rule[] = [];
