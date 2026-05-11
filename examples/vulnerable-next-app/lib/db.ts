// VULNERABLE EXAMPLE — Demonstrates unsafe database patterns

import { PrismaClient } from '@prisma/client';

export const prisma = new PrismaClient();

// VULNERABLE: Raw SQL with potential injection
export async function getUserByIdUnsafe(id: string) {
  // VULNERABLE: $queryRawUnsafe — should trigger injection finding
  return prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = '${id}'`);
}

// VULNERABLE: Hardcoded fake connection string (demo only)
const DB_URL = 'postgresql://admin:fakepassword@localhost/testdb';

// VULNERABLE: child_process usage without input validation
import { exec } from 'child_process';

export function runDbMigration(migrationName: string) {
  // VULNERABLE: exec with potentially user-controlled input
  exec(`prisma migrate run ${migrationName}`, (err, stdout) => {
    if (err) console.error(err);
    console.log(stdout);
  });
}
