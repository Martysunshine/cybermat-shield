/**
 * Calculates the Shannon entropy of a string value.
 * Higher entropy = more random = more likely to be a real secret.
 * A typical high-entropy secret scores 4.0+ bits/char.
 * Placeholder strings like "YOUR_API_KEY_HERE" score around 2.0–2.5.
 */
export function calculateShannonEntropy(value: string): number {
  if (value.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const ch of value) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}
