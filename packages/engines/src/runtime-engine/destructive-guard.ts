const DESTRUCTIVE_SEGMENTS = [
  'delete', 'remove', 'destroy', 'logout', 'payment', 'checkout',
  'subscribe', 'unsubscribe', 'reset', 'transfer', 'withdraw',
  'admin/delete', 'billing', 'password', 'token', 'revoke',
];

const DESTRUCTIVE_FIELD_TYPES = new Set(['password', 'file']);
const DESTRUCTIVE_FIELD_NAME_PATTERNS = ['card', 'payment', 'delete', 'confirm', 'cvv', 'ccv'];

export interface FormSnapshot {
  action?: string;
  method?: string;
  fields: Array<{ name?: string; type?: string }>;
}

export function isDestructivePath(urlPath: string): boolean {
  const lower = urlPath.toLowerCase();
  return DESTRUCTIVE_SEGMENTS.some(s => lower.includes(s));
}

export function isDestructiveUrl(url: string): boolean {
  try { return isDestructivePath(new URL(url).pathname); } catch { return true; }
}

export function isDestructiveForm(form: FormSnapshot): boolean {
  if (form.action && isDestructiveUrl(form.action)) return true;
  if ((form.method ?? 'GET').toUpperCase() !== 'GET') {
    if (form.action && isDestructivePath(form.action)) return true;
  }
  return form.fields.some(f => {
    const type = (f.type ?? '').toLowerCase();
    const name = (f.name ?? '').toLowerCase();
    if (DESTRUCTIVE_FIELD_TYPES.has(type)) return true;
    if (DESTRUCTIVE_FIELD_NAME_PATTERNS.some(p => name.includes(p))) return true;
    return false;
  });
}

export function isDestructiveUrlOrForm(url: string, form?: FormSnapshot): boolean {
  return isDestructiveUrl(url) || (form != null && isDestructiveForm(form));
}
