import type { ScannedFile } from '@cybermat/shared';

export interface AstSink {
  file: string;
  line: number;
  column: number;
  sinkType: 'xss' | 'sql' | 'command' | 'ssrf' | 'redirect' | 'filesystem' | 'ai-output';
  expression: string;
}

export interface AstSource {
  file: string;
  line: number;
  column: number;
  sourceType: 'user-input' | 'request-param' | 'query-string' | 'form-body' | 'webhook' | 'env';
  expression: string;
}

export interface AstAnalysisResult {
  sinks: AstSink[];
  sources: AstSource[];
}

/**
 * Finds dangerous sinks and user-controlled sources using ts-morph AST traversal.
 * Phase 4 implementation.
 */
export function analyzeAst(_files: ScannedFile[]): AstAnalysisResult {
  // Phase 4: use ts-morph to visit call expressions and assignments,
  // detect eval/innerHTML/exec sinks, and req.params/req.body/searchParams sources.
  return { sinks: [], sources: [] };
}
