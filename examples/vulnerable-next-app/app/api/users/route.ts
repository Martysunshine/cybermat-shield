// VULNERABLE EXAMPLE — API route with no auth check
// Scanner should flag: missing auth on API route, IDOR via userId param

import { NextRequest, NextResponse } from 'next/server';
import { users } from '../../../lib/db';

// VULNERABLE: No authentication check — any unauthenticated caller can list user data
export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const userId = searchParams.get('userId');

  // VULNERABLE: user_id from request — IDOR risk (no ownership check)
  const user = users.find(u => u.id === userId) ?? null;
  return NextResponse.json({ user: user ? { id: user.id, email: user.email, role: user.role } : null });
}

export async function POST(request: NextRequest) {
  const body = await request.json();
  const { userId, data } = body;

  // VULNERABLE: SQL-like string concatenation pattern
  const query = `SELECT * FROM users WHERE id = '` + userId + `'`;

  return NextResponse.json({ query, data });
}
