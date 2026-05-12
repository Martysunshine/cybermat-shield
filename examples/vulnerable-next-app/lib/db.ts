// VULNERABLE EXAMPLE — In-memory data store for scanner testing (no real database)

export const users = [
  { id: 'user-1', email: 'usera@test.com', name: 'User A', role: 'user', passwordHash: 'password123', ownedResourceId: 'resource-1' },
  { id: 'user-2', email: 'userb@test.com', name: 'User B', role: 'user', passwordHash: 'password123', ownedResourceId: 'resource-2' },
  { id: 'admin-1', email: 'admin@test.com', name: 'Admin', role: 'admin', passwordHash: 'admin123', ownedResourceId: 'resource-admin' },
];

export const resources = [
  { id: 'resource-1', ownerId: 'user-1', data: 'Private data for User A', secret: 'userA-secret-data' },
  { id: 'resource-2', ownerId: 'user-2', data: 'Private data for User B', secret: 'userB-secret-data' },
  { id: 'resource-admin', ownerId: 'admin-1', data: 'Admin private data', secret: 'admin-secret-data' },
];

// VULNERABLE: Hardcoded fake connection string — triggers scanner finding
const DB_URL = 'postgresql://admin:fakepassword@localhost/testdb';

// VULNERABLE: child_process exec with potentially user-controlled input
import { exec } from 'child_process';

export function runDbMigration(migrationName: string) {
  exec(`prisma migrate run ${migrationName}`, (err, stdout) => {
    if (err) console.error(err);
    console.log(stdout);
  });
}
