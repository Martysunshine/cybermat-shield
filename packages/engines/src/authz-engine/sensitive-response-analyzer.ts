import type { SensitiveSignal } from '@cybermat/shared';

const SENSITIVE_FIELDS = [
  'email', 'phone', 'address', 'user_id', 'userId', 'owner_id', 'ownerId',
  'role', 'isAdmin', 'admin', 'token', 'secret', 'apiKey', 'session', 'jwt',
  'stripe', 'payment', 'subscription', 'private', 'message', 'conversation',
  'internalNote', 'passwordHash', 'resetToken',
];

function hasField(obj: unknown, field: string): boolean {
  if (Array.isArray(obj)) return obj.some(item => hasField(item, field));
  if (obj && typeof obj === 'object') {
    const rec = obj as Record<string, unknown>;
    if (field in rec) return true;
    return Object.values(rec).some(v => hasField(v, field));
  }
  return false;
}

export function analyzeSensitiveResponse(body: string): SensitiveSignal[] {
  if (!body) return [];

  let parsed: unknown = null;
  try { parsed = JSON.parse(body); } catch { /* not JSON */ }

  const signals: SensitiveSignal[] = [];

  if (parsed !== null) {
    for (const field of SENSITIVE_FIELDS) {
      if (hasField(parsed, field)) {
        signals.push({ field, confidence: 'high', redactedEvidence: `"${field}": "[REDACTED]"` });
      }
    }
  } else {
    for (const field of SENSITIVE_FIELDS) {
      const pattern = new RegExp(`"${field}"\\s*:`, 'i');
      if (pattern.test(body)) {
        signals.push({ field, confidence: 'medium', redactedEvidence: `"${field}": "[REDACTED]"` });
      }
    }
  }

  return signals;
}

export function isSensitiveResponse(signals: SensitiveSignal[]): boolean {
  return signals.some(s => s.confidence === 'high') || signals.length >= 2;
}
