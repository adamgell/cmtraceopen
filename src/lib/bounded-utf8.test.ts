import { describe, expect, it, vi } from "vitest";

import { boundUtf8WithDigest } from "./bounded-utf8";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

function bufferedReference(value: string, byteLimit: number): string {
  const bytes = encoder.encode(value);
  if (bytes.byteLength <= byteLimit) return value;

  let first = 2_166_136_261;
  let second = (first ^ 0x9e37_79b9) >>> 0;
  for (const byte of bytes) {
    first = Math.imul(first ^ byte, 16_777_619) >>> 0;
    second = Math.imul(second ^ (byte ^ 0xa5), 16_777_619) >>> 0;
  }
  const digest = `${first.toString(16).padStart(8, "0")}${second
    .toString(16)
    .padStart(8, "0")}`;
  const suffix = `…[truncated:${digest}]`;
  let prefixEnd = byteLimit - encoder.encode(suffix).byteLength;
  while (prefixEnd > 0) {
    try {
      return `${decoder.decode(bytes.subarray(0, prefixEnd))}${suffix}`;
    } catch {
      prefixEnd -= 1;
    }
  }
  return suffix;
}

describe("boundUtf8WithDigest", () => {
  it.each([
    ["astral code points", `start-${"🙂𐐷".repeat(80)}-end`],
    ["lone high surrogates", `start-${"x\ud800y".repeat(80)}-end`],
    ["lone low surrogates", `start-${"x\udc00y".repeat(80)}-end`],
  ])("matches the buffered digest and UTF-8 prefix for %s", (_name, value) => {
    expect(boundUtf8WithDigest(value, 96)).toBe(bufferedReference(value, 96));
  });

  it("does not pass a large source string to TextEncoder", () => {
    const value = "🙂".repeat(512 * 1024);
    const encode = vi.spyOn(TextEncoder.prototype, "encode");
    try {
      const bounded = boundUtf8WithDigest(value, 8 * 1024);
      expect(encoder.encode(bounded).byteLength).toBeLessThanOrEqual(8 * 1024);
      expect(encode.mock.calls.some(([input]) => input === value)).toBe(false);
    } finally {
      encode.mockRestore();
    }
  });
});
