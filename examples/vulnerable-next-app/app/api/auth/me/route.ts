import { NextRequest, NextResponse } from 'next/server';
import { getTokenFromRequest, getSessionUser } from '../../../../lib/auth';

export async function GET(request: NextRequest) {
  const token = getTokenFromRequest(request);
  const user = getSessionUser(token);

  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  return NextResponse.json({ id: user.id, email: user.email, role: user.role });
}
