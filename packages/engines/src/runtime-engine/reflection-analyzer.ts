import { randomBytes } from 'crypto';
import type { RuntimeFinding } from '@cybermat/shared';
import { RuntimeFindingBuilder } from './runtime-finding-builder';

export type ReflectionContext = 'html-text' | 'html-attribute' | 'script-block' | 'json' | 'url' | 'none';

export function generateMarker(): string {
  return `cybermat_marker_${randomBytes(6).toString('hex')}`;
}

export function classifyReflectionContext(body: string, marker: string): ReflectionContext {
  const idx = body.indexOf(marker);
  if (idx === -1) return 'none';

  const before = body.slice(Math.max(0, idx - 300), idx);

  // Inside <script> block
  const lastScriptOpen = before.lastIndexOf('<script');
  const lastScriptClose = before.lastIndexOf('</script');
  if (lastScriptOpen !== -1 && lastScriptOpen > lastScriptClose) return 'script-block';

  // Inside JSON response (marker appears as a JSON string value)
  if (/:\s*"[^"]*$/.test(before) || /^\s*"/.test(body.slice(idx - 1, idx + 1))) {
    const trimmed = body.trim();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) return 'json';
  }

  // Inside HTML attribute
  if (/(?:href|src|action|value|data-[\w-]+|placeholder)=["'][^"']*$/.test(before)) {
    return 'html-attribute';
  }

  // URL redirect context
  if (/(?:location|redirect|url|href)=[^&\s"']*$/.test(before)) return 'url';

  return 'html-text';
}

export interface ReflectionResult {
  url: string;
  param: string;
  marker: string;
  context: ReflectionContext;
}

const SEVERITY_BY_CONTEXT: Record<ReflectionContext, 'high' | 'medium' | 'low'> = {
  'script-block': 'high',
  'html-attribute': 'high',
  'html-text': 'medium',
  'json': 'medium',
  'url': 'low',
  'none': 'low',
};

export function buildReflectionFinding(result: ReflectionResult): RuntimeFinding | null {
  if (result.context === 'none') return null;

  const isXss = result.context === 'script-block' || result.context === 'html-attribute';
  const severity = SEVERITY_BY_CONTEXT[result.context];

  return RuntimeFindingBuilder.reflection(
    'runtime.reflected-input',
    `Reflected Input — Potential ${isXss ? 'XSS' : 'Injection'} (${result.context})`,
    severity,
    result.url,
    result.param,
    result.context,
    `Parameter "${result.param}" reflects user input in the ${result.context} context without encoding. Harmless marker used — no exploit payload.`,
    `Encode all reflected user input for the output context: HTML entities for text, attribute encoding, JSON escaping, or URL encoding as appropriate.`,
    ['A05 Injection'],
  );
}
