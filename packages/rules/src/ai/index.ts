import type { Rule, Finding, RuleContext } from '@cybermat/shared';
import { makeFindingId, truncate } from '../utils';

const AI_VARIABLE_NAMES = /\b(?:aiResponse|llmOutput|modelOutput|completion|generatedHtml|assistantMessage|aiContent|llmResponse|chatResponse|gptResponse|aiText|modelResponse|llmResult)\b/;
const HTML_SINKS = /dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML|document\.write/;
const DANGEROUS_TOOL_OPS = /(?:exec|execSync|spawn|child_process)\s*\(|fs\.(unlink|rm|rmdir|writeFile)\s*\(|\.delete\s*\(|\.destroy\s*\(|sendEmail\s*\(|\.transfer\s*\(/;
const APPROVAL_KEYWORDS = /confirm|approve|permission|authorize|userApprove|requiresApproval|humanInLoop|humanReview/i;

// Patterns for LLM output to dangerous sinks beyond HTML
const CRITICAL_SINKS = /(?:exec|execSync|spawn|child_process)\s*\(|db\.execute|sql\s*`|queryRaw|\$queryRawUnsafe|sendEmail|fetch\s*\(|axios\.(?:get|post)|\.delete\s*\(/;

// Prompt injection: user input going into the system/developer message
const SYSTEM_PROMPT_CONCAT = /(?:system|developer|instruction|prompt).*\+.*(?:user|input|message|content|body|query)/i;
const RAG_SYSTEM_INJECTION = /messages\s*:\s*\[.*systemPrompt.*userDocument|documents\.map.*join.*prompt/is;

export const aiSecurityRule: Rule = {
  id: 'ai-security',
  name: 'AI-Specific Security',
  description: 'Detects insecure patterns in AI-assisted and AI-agent code',
  category: 'AI Security',
  owasp: ['A05 Injection', 'A06 Insecure Design'],
  severity: 'high',
  run: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];

    for (const file of context.files) {
      if (!['.ts', '.tsx', '.js', '.jsx', '.mjs'].includes(file.extension)) continue;
      const lines = file.content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!line.trim() || line.trim().startsWith('//')) continue;

        // LLM output → HTML sink (same line or nearby assignment)
        if (AI_VARIABLE_NAMES.test(line) && HTML_SINKS.test(line)) {
          findings.push({
            id: makeFindingId('ai.llm-output-html-sink', file.relativePath, i + 1),
            ruleId: 'ai.llm-output-html-sink',
            title: 'LLM Output Rendered as Raw HTML',
            severity: 'high',
            confidence: 'high',
            owasp: ['A05 Injection', 'A06 Insecure Design'],
            cwe: ['CWE-79', 'CWE-116'],
            category: 'AI Security',
            file: file.relativePath,
            line: i + 1,
            evidence: {
              snippet: truncate(line),
              reason: 'AI/LLM output variable flowing directly into an HTML sink',
            },
            impact: 'LLM-generated HTML rendered without sanitization enables prompt injection and XSS attacks.',
            recommendation: 'Always sanitize AI-generated HTML with DOMPurify before rendering. Use a content allowlist.',
            tags: ['llm', 'xss', 'prompt-injection', 'ai'],
          });
        }

        // LLM output → critical dangerous sinks (exec, SQL, fetch, delete)
        if (AI_VARIABLE_NAMES.test(line) && CRITICAL_SINKS.test(line)) {
          findings.push({
            id: makeFindingId('ai.llm-output-critical-sink', file.relativePath, i + 1),
            ruleId: 'ai.llm-output-critical-sink',
            title: 'LLM Output Flowing to Dangerous Operation',
            severity: 'critical',
            confidence: 'medium',
            owasp: ['A05 Injection', 'A06 Insecure Design'],
            cwe: ['CWE-78', 'CWE-89', 'CWE-918'],
            category: 'AI Security',
            file: file.relativePath,
            line: i + 1,
            evidence: {
              snippet: truncate(line),
              reason: 'LLM output variable flows into exec/SQL/fetch/delete without sanitization',
            },
            impact: 'Prompt injection can cause the AI to generate malicious payloads that execute shell commands, run SQL queries, or delete data.',
            recommendation: 'Never pass LLM output directly to command execution, SQL, or HTTP requests. Validate and sanitize with a strict allowlist.',
            tags: ['llm', 'prompt-injection', 'rce', 'ai', 'critical'],
          });
        }

        // AI tool call executing dangerous operations without approval
        if (AI_VARIABLE_NAMES.test(line) || /tool.*call|toolCall|function_call|tool_use/.test(line)) {
          if (DANGEROUS_TOOL_OPS.test(line)) {
            const surrounding = lines.slice(Math.max(0, i - 5), i + 5).join('\n');
            if (!APPROVAL_KEYWORDS.test(surrounding)) {
              findings.push({
                id: makeFindingId('ai.tool-call-no-approval', file.relativePath, i + 1),
                ruleId: 'ai.tool-call-no-approval',
                title: 'AI Tool Call Executing Dangerous Operation Without Approval',
                severity: 'critical',
                confidence: 'medium',
                owasp: ['A06 Insecure Design', 'A08 Software or Data Integrity Failures'],
                cwe: ['CWE-284', 'CWE-862'],
                category: 'AI Security',
                file: file.relativePath,
                line: i + 1,
                evidence: {
                  snippet: truncate(line),
                  reason: 'AI tool call executes a destructive operation with no human approval check in surrounding code',
                },
                impact: 'Prompt injection can trigger AI agents to execute shell commands, delete data, or send emails without user consent.',
                recommendation: 'Require human approval for destructive tool calls. Implement an allow-list of permitted operations.',
                tags: ['ai-agent', 'tool-use', 'prompt-injection', 'human-in-loop'],
              });
            }
          }
        }

        // Prompt injection: user input concatenated into system/developer message
        if (SYSTEM_PROMPT_CONCAT.test(line)) {
          findings.push({
            id: makeFindingId('ai.user-input-in-system-prompt', file.relativePath, i + 1),
            ruleId: 'ai.user-input-in-system-prompt',
            title: 'User Input Concatenated into AI System Prompt',
            severity: 'high',
            confidence: 'medium',
            owasp: ['A05 Injection', 'A06 Insecure Design'],
            cwe: ['CWE-77'],
            category: 'AI Security',
            file: file.relativePath,
            line: i + 1,
            evidence: {
              snippet: truncate(line),
              reason: 'User-controlled content appears to be concatenated into a system/developer prompt',
            },
            impact: 'Prompt injection allows attackers to override AI instructions, extract sensitive data, or manipulate AI behavior.',
            recommendation: 'Keep system prompts static. Use structured message roles — never concatenate user input into system instructions.',
            tags: ['prompt-injection', 'llm', 'ai'],
          });
        }

        // RAG documents in system prompt
        if (RAG_SYSTEM_INJECTION.test(line)) {
          findings.push({
            id: makeFindingId('ai.rag-injection-risk', file.relativePath, i + 1),
            ruleId: 'ai.rag-injection-risk',
            title: 'RAG Documents Mixed into AI System Instructions',
            severity: 'medium',
            confidence: 'low',
            owasp: ['A05 Injection'],
            cwe: ['CWE-77'],
            category: 'AI Security',
            file: file.relativePath,
            line: i + 1,
            evidence: {
              snippet: truncate(line),
              reason: 'Retrieved documents appear to be concatenated into system-level AI instructions',
            },
            impact: 'Malicious content in retrieved documents can override AI instructions via indirect prompt injection.',
            recommendation: 'Separate system instructions from retrieved context. Use a distinct message role for retrieved documents.',
            tags: ['rag', 'prompt-injection', 'llm', 'ai'],
          });
        }
      }
    }

    return findings;
  },
};
