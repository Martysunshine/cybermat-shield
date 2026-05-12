export default function DashboardPage() {
  return (
    <main style={{ fontFamily: 'sans-serif', padding: '2rem' }}>
      <h1>Dashboard</h1>
      <p>You are logged in.</p>
      <ul>
        <li><a href="/api/auth/me">My profile (GET /api/auth/me)</a></li>
        <li><a href="/api/resources/resource-1">My resource (GET /api/resources/resource-1)</a></li>
        <li><a href="/api/resources/resource-2">Other user resource (IDOR: resource-2)</a></li>
        <li><a href="/api/admin">Admin panel (no auth check)</a></li>
      </ul>
      <form action="/api/auth/logout" method="post" style={{ marginTop: '1rem' }}>
        <button type="submit">Logout</button>
      </form>
    </main>
  );
}
