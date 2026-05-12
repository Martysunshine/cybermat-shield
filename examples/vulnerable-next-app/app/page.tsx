// VULNERABLE EXAMPLE — For scanner testing only
import UserContent from '../components/UserContent';

export default function HomePage() {
  return (
    <main style={{ fontFamily: 'sans-serif', padding: '2rem' }}>
      <h1>Vulnerable Next.js App (Test Target)</h1>
      <ul>
        <li><a href="/login">Login</a></li>
        <li><a href="/dashboard">Dashboard</a></li>
        <li><a href="/api/auth/me">My Profile API</a></li>
        <li><a href="/api/users?userId=user-1">Users API (IDOR)</a></li>
        <li><a href="/api/admin">Admin API (no auth)</a></li>
        <li><a href="/api/resources/resource-1">Resource 1 (IDOR)</a></li>
        <li><a href="/api/resources/resource-2">Resource 2 (IDOR)</a></li>
      </ul>
      <UserContent />
    </main>
  );
}
