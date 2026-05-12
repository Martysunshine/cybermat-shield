import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import type { AuthProfile, AuthProfileConfig } from '@cybermat/shared';

interface StorageStateCookie {
  name: string;
  value: string;
  domain?: string;
  path?: string;
}

interface StorageState {
  cookies: StorageStateCookie[];
}

export class AuthProfileLoader {
  static anonymous(): AuthProfile {
    return { name: 'anonymous', label: 'Anonymous', type: 'anonymous', headers: {} };
  }

  static async load(name: string, config: AuthProfileConfig): Promise<AuthProfile> {
    const label = config.label ?? name;

    if (config.storageStatePath) {
      if (!existsSync(config.storageStatePath)) {
        throw new Error(
          `storageState file not found: ${config.storageStatePath}\n` +
            `Run: npx tsx --tsconfig scripts/tsconfig.json scripts/setup-auth-profiles.ts`,
        );
      }
      const raw = await readFile(config.storageStatePath, 'utf-8');
      const state: StorageState = JSON.parse(raw);
      const cookieStr = state.cookies.map(c => `${c.name}=${c.value}`).join('; ');
      return {
        name,
        label,
        type: 'storageState',
        storageStatePath: config.storageStatePath,
        headers: { cookie: cookieStr, ...(config.headers ?? {}) },
        isPrivileged: config.isPrivileged,
      };
    }

    const headers: Record<string, string> = { ...(config.headers ?? {}) };
    if (config.cookies) {
      headers['cookie'] = config.cookies;
    }
    return {
      name,
      label,
      type: config.cookies ? 'cookies' : 'headers',
      headers,
      cookies: config.cookies,
      isPrivileged: config.isPrivileged,
    };
  }

  static validate(profiles: AuthProfile[]): string[] {
    const warnings: string[] = [];
    const nonAnon = profiles.filter(p => p.type !== 'anonymous');
    if (nonAnon.length < 2) {
      warnings.push(
        'Only one non-anonymous profile found. Horizontal IDOR tests require at least two user profiles.',
      );
    }
    const names = profiles.map(p => p.name);
    const unique = new Set(names);
    if (unique.size !== names.length) {
      warnings.push('Duplicate profile names detected.');
    }
    return warnings;
  }
}
