import { NextRequest, NextResponse } from 'next/server';
import { validateCredentials, createSession } from '../../../../lib/auth';

export async function POST(request: NextRequest) {
  const { email, password } = await request.json();
  const user = validateCredentials(email, password);

  if (!user) {
    return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
  }

  const token = createSession(user.id);
  const response = NextResponse.json({
    ok: true,
    user: { id: user.id, email: user.email, role: user.role },
  });
  response.cookies.set('session', token, {
    httpOnly: true,
    path: '/',
    maxAge: 60 * 60 * 24,
  });
  return response;
}
