// VULNERABLE EXAMPLE — Admin route with no auth or role check
// Scanner should flag: missing auth, missing role check on admin route

import { NextRequest, NextResponse } from 'next/server';

// VULNERABLE: Admin route with no authentication check at all
export async function GET(request: NextRequest) {
  // No auth() call, no getServerSession(), no currentUser()
  // No role check

  const allUsers = [
    { id: '1', email: 'admin@example.com', role: 'admin', passwordHash: 'fake-hash' },
    { id: '2', email: 'user@example.com', role: 'user' },
  ];

  return NextResponse.json({ users: allUsers });
}

export async function DELETE(request: NextRequest) {
  const { userId } = await request.json();

  // VULNERABLE: No auth, no role check, destructive operation
  return NextResponse.json({ deleted: userId });
}
