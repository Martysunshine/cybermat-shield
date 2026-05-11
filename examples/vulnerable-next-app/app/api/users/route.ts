// VULNERABLE EXAMPLE — API route with no auth check
// Scanner should flag: missing auth on API route, user_id from request body

import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '../../../lib/db';

// VULNERABLE: No authentication check — any unauthenticated caller can access user data
export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const userId = searchParams.get('userId');

  // VULNERABLE: user_id from request — IDOR risk
  const user = await prisma.user.findUnique({ where: { id: userId ?? '' } });

  return NextResponse.json({ user });
}

export async function POST(request: NextRequest) {
  const body = await request.json();

  // VULNERABLE: Accepting user_id from request body (IDOR)
  const { userId, data } = body;

  // VULNERABLE: SQL-like string concatenation pattern
  const query = `SELECT * FROM users WHERE id = '` + userId + `'`;

  return NextResponse.json({ query, data });
}
