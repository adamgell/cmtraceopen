import { afterEach, assert, describe, expect, it, vi } from "vitest";
import {
  formatDisplayDateTime,
  formatDisplayTime,
  parseDisplayDateTime,
  parseDisplayDateTimeValue,
} from "./date-time-format";

describe("parseDisplayDateTime", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns null for absent or unusable input", () => {
    expect(parseDisplayDateTime(null)).toBeNull();
    expect(parseDisplayDateTime(undefined)).toBeNull();
    expect(parseDisplayDateTime("")).toBeNull();
    expect(parseDisplayDateTime("   ")).toBeNull();
    expect(parseDisplayDateTime(new Date("nope"))).toBeNull();
    expect(parseDisplayDateTime(Number.NaN)).toBeNull();
  });

  it("passes a valid Date through and reads a numeric epoch", () => {
    const d = new Date("2026-03-09T14:22:31Z");
    expect(parseDisplayDateTime(d)?.getTime()).toBe(d.getTime());
    expect(parseDisplayDateTime(d.getTime())?.getTime()).toBe(d.getTime());
  });

  it.each([
    ["2026-09-30T12:00:00Z", "2026-03-09"],
    ["2026-03-09T12:00:00Z", "2026-09-30"],
  ])("preserves UTC and local time with now=%s and timestamp=%s", (now, day) => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date(now));

    const marked = parseDisplayDateTime(`${day} 14:22:31 UTC`);
    const bare = parseDisplayDateTime(`${day} 14:22:31`);

    assert.isNotNull(marked);
    assert.isNotNull(bare);
    expect(marked.toISOString()).toBe(`${day}T14:22:31.000Z`);
    expect(bare.getHours()).toBe(14);
    expect(bare.getMinutes()).toBe(22);
    expect(bare.getSeconds()).toBe(31);

    // Use the timestamp's offset, not today's: they can straddle a DST change.
    // Keep the assertion in UTC too, where the two forms must coincide.
    const offsetMinutes = bare.getTimezoneOffset();
    expect(bare.getTime() - marked.getTime()).toBe(offsetMinutes * 60_000);
  });

  it("reads a month-first Windows timestamp", () => {
    const parsed = parseDisplayDateTime("03-09-2026 14:22:31");
    assert.isNotNull(parsed);
    // Month 03, day 09 — the opposite reading would give 3 September.
    expect(parsed.getMonth()).toBe(2);
    expect(parsed.getDate()).toBe(9);
  });

  it("exposes the same result as an epoch value", () => {
    const s = "2026-03-09T14:22:31Z";
    expect(parseDisplayDateTimeValue(s)).toBe(parseDisplayDateTime(s)?.getTime());
    expect(parseDisplayDateTimeValue(null)).toBeNull();
  });
});

describe("display formatting", () => {
  it("formats a parseable value and returns null for an unparseable one", () => {
    expect(formatDisplayDateTime("2026-03-09T14:22:31Z")).toBeTruthy();
    expect(formatDisplayDateTime("not a timestamp")).toBeNull();
    expect(formatDisplayTime("2026-03-09T14:22:31Z")).toBeTruthy();
    expect(formatDisplayTime(null)).toBeNull();
  });
});
