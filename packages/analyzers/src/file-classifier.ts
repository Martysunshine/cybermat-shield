import type { ScannedFile } from '@cybermat/shared';

export type FileRole = 'client' | 'server' | 'shared' | 'config' | 'public' | 'test';

export interface ClassifiedFile {
  file: ScannedFile;
  role: FileRole;
  confidence: 'high' | 'medium' | 'low';
  reasons: string[];
}

/**
 * Classifies each file as client/server/shared/config/public/test.
 * Phase 4 implementation: uses heuristics based on path, imports, and framework conventions.
 */
export function classifyFiles(_files: ScannedFile[]): ClassifiedFile[] {
  // Phase 4: implement full classification using path heuristics, 'use client' / 'use server' directives,
  // NEXT_PUBLIC_ variable usage, and import patterns.
  return [];
}
