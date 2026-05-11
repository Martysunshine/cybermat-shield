import type { DangerousCall, UserInputSource } from '@cybermat/shared';

export type CorrelationConfidence = 'high' | 'medium' | 'low';

export interface SourceSinkCorrelation {
  source: UserInputSource;
  sink: DangerousCall;
  confidence: CorrelationConfidence;
  hasSanitizer: boolean;
}

const SANITIZER_PATTERNS = [
  /DOMPurify\.sanitize/,
  /sanitizeHtml\s*\(/,
  /validator\.escape/,
  /\.safeParse\s*\(/,
  /\.parse\s*\(/,            // Zod, Joi, Yup
  /Joi\.validate/,
  /yup\.validate/,
  /escapeHtml\s*\(/,
  /parameterized|prepared/i, // parameterized queries
  /isAllowedUrl|validateRedirectUrl|allowedOrigins|allowedHosts/,
];

function hasSanitizerInWindow(lines: string[], startLine: number, endLine: number): boolean {
  const chunk = lines.slice(Math.max(0, startLine - 1), Math.min(lines.length, endLine)).join('\n');
  return SANITIZER_PATTERNS.some(p => p.test(chunk));
}

/** Extracts variable names assigned from a source expression in the surrounding lines */
function extractSourceVariables(lines: string[], sourceLine: number): string[] {
  const vars: string[] = [];
  const window = lines.slice(Math.max(0, sourceLine - 3), sourceLine + 3).join('\n');

  // const foo = req.body / const { foo } = req.body / const { foo } = await request.json()
  const assignRe = /(?:const|let|var)\s+(?:\{([^}]+)\}|(\w+))\s*=\s*(?:await\s+)?(?:req\.|request\.(?:json|formData|text)|searchParams|params\.|body\.|query\.)/g;
  let m: RegExpExecArray | null;
  while ((m = assignRe.exec(window)) !== null) {
    if (m[1]) {
      // destructured: { foo, bar }
      m[1].split(',').forEach(v => vars.push(v.trim().split(':')[0].trim()));
    } else if (m[2]) {
      vars.push(m[2].trim());
    }
  }

  return vars;
}

export function correlateSources(
  sources: UserInputSource[],
  sinks: DangerousCall[],
  fileContents: Map<string, string[]>,
): SourceSinkCorrelation[] {
  const correlations: SourceSinkCorrelation[] = [];

  // Group by file
  const sourcesByFile = new Map<string, UserInputSource[]>();
  for (const src of sources) {
    const arr = sourcesByFile.get(src.file) ?? [];
    arr.push(src);
    sourcesByFile.set(src.file, arr);
  }

  for (const sink of sinks) {
    const fileSources = sourcesByFile.get(sink.file);
    if (!fileSources) continue;

    const lines = fileContents.get(sink.file);
    if (!lines) continue;

    for (const src of fileSources) {
      // Only correlate when source and sink are in the same file
      const windowStart = Math.min(src.line, sink.line);
      const windowEnd = Math.max(src.line, sink.line);

      // Too far apart to be the same function (heuristic: within 50 lines)
      if (windowEnd - windowStart > 50) continue;

      const hasSanitizer = hasSanitizerInWindow(lines, windowStart, windowEnd);
      const sourceVars = extractSourceVariables(lines, src.line - 1);

      // Check if a source variable name appears in the sink line
      const sinkLine = lines[sink.line - 1] ?? '';
      const varInSink = sourceVars.some(v => v.length > 1 && sinkLine.includes(v));

      let confidence: CorrelationConfidence;
      if (varInSink && !hasSanitizer) {
        confidence = 'high';
      } else if (varInSink && hasSanitizer) {
        confidence = 'low';
      } else if (!hasSanitizer) {
        confidence = 'medium';
      } else {
        confidence = 'low';
      }

      correlations.push({ source: src, sink, confidence, hasSanitizer });
    }
  }

  return correlations;
}
