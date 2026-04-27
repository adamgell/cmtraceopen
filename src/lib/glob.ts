/**
 * Simple glob-style pattern matching for filenames.
 *
 * Supports:
 *  - `*` (match everything)
 *  - `*.ext` (suffix matching)
 *  - `prefix*` (prefix matching)
 *  - `prefix*.ext` / `*middle*` (segment-based matching)
 *  - exact names (no wildcard)
 *
 * All comparisons are case-insensitive.
 *
 * @param name     The filename to test.
 * @param patterns Array of glob patterns. An empty array is treated as
 *                 "no restriction" and always returns `true`.
 */
export function matchesAnyPattern(name: string, patterns: string[]): boolean {
  if (patterns.length === 0) return true;
  const lower = name.toLowerCase();
  return patterns.some((p) => {
    if (p === "*") return true;
    const lowerP = p.toLowerCase();
    // Fast path: no wildcard means exact match
    if (!lowerP.includes("*")) return lower === lowerP;
    // Split on `*` and verify each segment appears in order
    const segments = lowerP.split("*");
    let pos = 0;
    for (let i = 0; i < segments.length; i++) {
      const seg = segments[i];
      if (seg === "") {
        // Empty segments arise from leading `*`, trailing `*`, or `**`.
        continue;
      }
      if (i === 0) {
        // First segment (no leading `*`) must anchor at the start
        if (!lower.startsWith(seg)) return false;
        pos = seg.length;
      } else if (i === segments.length - 1) {
        // Last segment (no trailing `*`) must anchor at the end
        if (!lower.endsWith(seg)) return false;
        // Ensure the end segment doesn't overlap with already-matched content
        if (lower.length - seg.length < pos) return false;
      } else {
        // Middle segments — find next occurrence at or after `pos`
        const idx = lower.indexOf(seg, pos);
        if (idx === -1) return false;
        pos = idx + seg.length;
      }
    }
    return true;
  });
}
