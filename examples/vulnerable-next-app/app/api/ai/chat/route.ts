// VULNERABLE EXAMPLE — AI chat API with prompt injection risk
// Scanner should flag:
//   - user input concatenated into system prompt (ai.user-input-in-system-prompt)
//   - LLM output passed to exec without sanitization
// FAKE — no real OpenAI calls

import { NextRequest, NextResponse } from 'next/server';

// VULNERABLE: User content concatenated directly into the system/developer prompt
export async function POST(request: NextRequest) {
  const body = await request.json();
  const userMessage = body.message;

  // VULNERABLE: System prompt includes user input — prompt injection vector
  const systemPrompt = 'You are a helpful assistant. User context: ' + userMessage;

  // In a real app this would call the OpenAI API
  const messages = [
    { role: 'system', content: systemPrompt },
    { role: 'user', content: userMessage },
  ];

  const completion = await callFakeAI(messages);

  // VULNERABLE: LLM output passed to exec without validation
  // (simulating an AI agent that executes commands)
  const { exec } = await import('child_process');
  if (completion.startsWith('RUN:')) {
    // VULNERABLE: No approval check before executing AI-generated command
    exec(completion.replace('RUN:', '').trim());
  }

  return NextResponse.json({ content: completion });
}

async function callFakeAI(_messages: unknown[]): Promise<string> {
  return 'Hello! I am a fake AI response.';
}
