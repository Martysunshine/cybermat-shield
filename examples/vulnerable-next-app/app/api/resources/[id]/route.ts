// VULNERABLE EXAMPLE — Owned resource endpoint with IDOR vulnerability
// Scanner should flag: authenticated but no ownership check (resource-1 accessible by userB)

import { NextRequest, NextResponse } from 'next/server';
import { resources } from '../../../../lib/db';
import { getTokenFromRequest, getSessionUser } from '../../../../lib/auth';

export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  const token = getTokenFromRequest(request);
  const currentUser = getSessionUser(token);

  if (!currentUser) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // VULNERABLE: Looks up resource by ID without checking resource.ownerId === currentUser.id
  const resource = resources.find(r => r.id === params.id) ?? null;
  return NextResponse.json({ resource });
}
