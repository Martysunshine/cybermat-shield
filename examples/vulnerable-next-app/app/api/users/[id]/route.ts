// VULNERABLE EXAMPLE — Per-user data endpoint with IDOR vulnerability
// Scanner should flag: authenticated but no ownership check

import { NextRequest, NextResponse } from 'next/server';
import { resources } from '../../../../lib/db';
import { getTokenFromRequest, getSessionUser } from '../../../../lib/auth';

export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  const token = getTokenFromRequest(request);
  const currentUser = getSessionUser(token);

  if (!currentUser) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // VULNERABLE: Fetches another user's resource by ownerId without checking currentUser.id === params.id
  const resource = resources.find(r => r.ownerId === params.id) ?? null;
  return NextResponse.json({ resource });
}
