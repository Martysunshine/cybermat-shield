import type { ScannedFile } from '@cybermat/shared';

export interface ImportEdge {
  from: string;
  to: string;
  isDynamic: boolean;
}

export interface ImportGraph {
  edges: ImportEdge[];
  /** Files that import server-only modules but are classified as client files */
  serverClientLeaks: string[];
  /** Files that import client-only modules from server context */
  clientServerLeaks: string[];
}

/**
 * Builds a static import graph using ts-morph AST analysis.
 * Phase 4 implementation: resolves both static and dynamic imports, detects client/server boundary violations.
 */
export function buildImportGraph(_files: ScannedFile[]): ImportGraph {
  // Phase 4: use ts-morph to resolve imports, detect circular deps,
  // and flag server→client and client→server boundary violations.
  return { edges: [], serverClientLeaks: [], clientServerLeaks: [] };
}
