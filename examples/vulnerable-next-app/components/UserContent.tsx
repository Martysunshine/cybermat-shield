'use client';
// VULNERABLE EXAMPLE — Scanner should flag dangerouslySetInnerHTML and localStorage

import { useState, useEffect } from 'react';

export default function UserContent() {
  const [userHtml, setUserHtml] = useState('');
  const [token, setToken] = useState('');

  useEffect(() => {
    // VULNERABLE: Token stored in localStorage — should trigger crypto finding
    const savedToken = localStorage.getItem('token');
    if (savedToken) setToken(savedToken);
  }, []);

  const handleLogin = (jwt: string) => {
    // VULNERABLE: Storing JWT in localStorage
    localStorage.setItem('token', jwt);
    localStorage.setItem('session', jwt);
    setToken(jwt);
  };

  return (
    <div>
      {/* VULNERABLE: dangerouslySetInnerHTML without sanitization — should trigger injection finding */}
      <div
        dangerouslySetInnerHTML={{ __html: userHtml }}
      />

      {/* VULNERABLE: innerHTML assignment */}
      <div id="output" />
      <button onClick={() => {
        const el = document.getElementById('output');
        if (el) el.innerHTML = userHtml; // VULNERABLE
      }}>
        Render
      </button>
    </div>
  );
}
