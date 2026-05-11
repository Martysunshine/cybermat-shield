import type { Rule, Finding, RuleContext } from '@cybermat/shared';
import { makeFindingId, truncate } from '../utils';

// Variable names that suggest AI-generated content
const AI_VARIABLE_NAMES = /\b(?:aiResponse|llmOutput|modelOutput|completion|generatedHtml|assistantMessage|aiContent|llmResponse|chatResponse|gptResponse)\b/;

// HTML sinks where AI output could cause XSS
const HTML_SINKS = /dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML|document\.write/;

// Dangerous tool operations AI agents shouldn't do without approval
const DANGEROUS_TOOL_OPS = /(?:exec|execSync|spawn|child_process)\s*\(|fs\.(unlink|rm|rmdir|writeFile)\s*\(|\.delete\s*\(|\.destroy\s*\(|sendEmail\s*\(|\.transfer\s*\(/;

const APPROVAL_KEYWORDS = /confirm|approve|permission|authorize|userApprove|requiresApproval|humanInLoop|humanReview/i;

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

        // AI output flowing to HTML sink on the same line
        if (AI_VARIABLE_NAMES.test(line) && HTML_SINKS.test(line)) {
          findings.push({
            id: makeFindingId('ai.llm-output-html-sink', file.relativePath, i + 1),
            title: 'LLM Output Rendered as Raw HTML',
            severity: 'high',
            confidence: 'high',
            owasp: ['A05 Injection', 'A06 Insecure Design'],
            category: 'AI Security',
            file: file.relativePath,
            line: i + 1,
            evidence: truncate(line),
            impact: 'LLM-generated HTML rendered without sanitization enables prompt injection and XSS attacks.',
            recommendation: 'Always sanitize AI-generated HTML with DOMPurify before rendering. Use a content allowlist.',
          });
        }

        // AI tool call executing dangerous operations without approval check
        if (AI_VARIABLE_NAMES.test(line) || /tool.*call|toolCall|function_call|tool_use/.test(line)) {
          if (DANGEROUS_TOOL_OPS.test(line)) {
            const surrounding = lines.slice(Math.max(0, i - 5), i + 5).join('\n');
            if (!APPROVAL_KEYWORDS.test(surrounding)) {
              findings.push({
                id: makeFindingId('ai.tool-call-no-approval', file.relativePath, i + 1),
                title: 'AI Tool Call Executing Dangerous Operation Without Approval',
                severity: 'critical',
                confidence: 'medium',
                owasp: ['A06 Insecure Design', 'A08 Software or Data Integrity Failures'],
                category: 'AI Security',
                file: file.relativePath,
                line: i + 1,
                evidence: truncate(line),
                impact: 'Prompt injection can trigger AI agents to execute shell commands, delete data, or send emails without user consent.',
                recommendation: 'Require human approval for destructive tool calls. Implement an allow-list of permitted operations.',
              });
            }
          }
        }
      }
    }

    return findings;
  },
};
