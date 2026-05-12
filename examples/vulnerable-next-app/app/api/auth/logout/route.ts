import { NextRequest, NextResponse } from 'next/server';
import { getTokenFromRequest, deleteSession } from '../../../../lib/auth';

export async function POST(request: NextRequest) {
  const token = getTokenFromRequest(request);
  if (token) deleteSession(token);
  const response = NextResponse.json({ ok: true });
  response.cookies.delete('session');
  return response;
}
