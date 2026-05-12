// Simple in-memory session store — resets when the dev server restarts
import { randomBytes } from 'crypto';
import { users } from './db';

const sessions = new Map<string, string>(); // token -> userId

export function createSession(userId: string): string {
  const token = randomBytes(32).toString('hex');
  sessions.set(token, userId);
  return token;
}

export function getSessionUser(token: string | undefined) {
  if (!token) return null;
  const userId = sessions.get(token);
  if (!userId) return null;
  return users.find(u => u.id === userId) ?? null;
}

export function deleteSession(token: string) {
  sessions.delete(token);
}

// VULNERABLE: plaintext password comparison (no hashing) — scanner should flag this
export function validateCredentials(email: string, password: string) {
  return users.find(u => u.email === email && u.passwordHash === password) ?? null;
}

export function getTokenFromRequest(request: Request): string | undefined {
  const cookieHeader = request.headers.get('cookie') ?? '';
  const match = cookieHeader.match(/(?:^|;\s*)session=([^;]+)/);
  return match?.[1];
}
