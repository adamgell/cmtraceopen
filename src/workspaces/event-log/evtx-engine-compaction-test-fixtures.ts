/**
 * A second, independent statement of the engine's text compaction, for tests only: bytes and
 * BigInt, not the production scan in `bounded-utf8.ts`. It is checked against the engine's own
 * output (`__fixtures__/engine-compaction-vectors.json`, recomputed by Rust tests) in
 * `evtx-engine-compaction.test.ts` before anything relies on it.
 *
 * Test code only: nothing outside a test file imports it.
 */

export const TIMELINE_LIMIT = 256;
export const DISPLAY_LIMIT = 4096;

/** The digest of `compact_text_digest` (two lanes) or `display_text_digest` (the first), over bytes. */
export function referenceDigest(bytes: Uint8Array, twoLanes: boolean): string {
  const mask = 0xffff_ffffn;
  let first = 2_166_136_261n;
  let second = first ^ 0x9e37_79b9n;
  for (const byte of bytes) {
    first = ((first ^ BigInt(byte)) * 16_777_619n) & mask;
    second = ((second ^ BigInt(byte ^ 0xa5)) * 16_777_619n) & mask;
  }
  const hex = (lane: bigint) => lane.toString(16).padStart(8, "0");
  return twoLanes ? hex(first) + hex(second) : hex(first);
}

/** The Rust format, written again from bytes: `compact_timeline_text` and `compact_display_text`. */
export function engineCompactReference(value: string, limit: number, twoLanes: boolean): string {
  const bytes = new TextEncoder().encode(value);
  if (bytes.length <= limit) return value;
  const suffix = `...[${bytes.length} bytes; digest=${referenceDigest(bytes, twoLanes)}]`;
  let end = Math.min(Math.max(limit - suffix.length, 0), bytes.length);
  while (end > 0 && ((bytes[end] ?? 0) & 0xc0) === 0x80) end -= 1;
  return `${new TextDecoder().decode(bytes.slice(0, end))}${suffix}`;
}

/** What the engine does to an identity text over 256 bytes (timeline-origin fields). */
export const timelineReference = (value: string) => engineCompactReference(value, TIMELINE_LIMIT, true);
/** What the engine does to a diagnosis evidence text over 4096 bytes. */
export const displayReference = (value: string) => engineCompactReference(value, DISPLAY_LIMIT, false);
