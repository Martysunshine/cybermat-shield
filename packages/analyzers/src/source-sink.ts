import type { AstSource, AstSink } from './ast-analyzer';

export type CorrelationConfidence = 'high' | 'medium' | 'low';

export interface SourceSinkCorrelation {
  source: AstSource;
  sink: AstSink;
  confidence: CorrelationConfidence;
  path: string[];
  hasSanitizer: boolean;
  hasAuthGuard: boolean;
}

/**
 * Correlates user-controlled sources to dangerous sinks at the function level.
 * Phase 4 implementation: known sanitizers and auth guards reduce confidence.
 */
export function correlateSources(
  _sources: AstSource[],
  _sinks: AstSink[],
): SourceSinkCorrelation[] {
  // Phase 4: implement function-level taint tracking.
  // Reduce confidence when a known sanitizer (DOMPurify, parameterized query, etc.) is found between source and sink.
  // Reduce confidence further when an auth guard is present on the handler.
  return [];
}
