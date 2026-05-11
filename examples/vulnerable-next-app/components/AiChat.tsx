'use client';
// VULNERABLE EXAMPLE — LLM output rendered as raw HTML
// Scanner should flag: ai.llm-output-html-sink (high)
// and user input concatenated into system prompt (ai.user-input-in-system-prompt)
// FAKE — no real AI calls here

import { useState } from 'react';

export default function AiChat() {
  const [userMessage, setUserMessage] = useState('');
  const [aiResponse, setAiResponse] = useState('');

  const sendMessage = async () => {
    const response = await fetch('/api/ai/chat', {
      method: 'POST',
      body: JSON.stringify({ message: userMessage }),
    });
    const data = await response.json();
    const aiResponse = data.content;

    // VULNERABLE: LLM output rendered directly as innerHTML — XSS via prompt injection
    const outputEl = document.getElementById('ai-output');
    if (outputEl) outputEl.innerHTML = aiResponse;
  };

  return (
    <div>
      <textarea value={userMessage} onChange={e => setUserMessage(e.target.value)} />
      <button onClick={sendMessage}>Send</button>

      {/* VULNERABLE: dangerouslySetInnerHTML with AI response */}
      <div
        id="ai-output"
        dangerouslySetInnerHTML={{ __html: aiResponse }}
      />
    </div>
  );
}
