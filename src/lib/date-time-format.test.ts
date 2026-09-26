import { describe, expect, it } from "vitest";
import {
  formatDisplayDateTime,
  formatDisplayTime,
  parseDisplayDateTime,
  parseDisplayDateTimeValue,
} from "./date-time-format";

describe("parseDisplayDateTime", () => {
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

  it("does not shift a timestamp that says UTC", () => {
    // The invariant: a value carrying an explicit UTC marker is offset-invariant,
    // while the same clock reading without one is read in the host zone. On a UTC
    // host those coincide, so this compares the two forms against each other
    // rather than against a hardcoded hour, which makes it meaningful anywhere.
    const marked = parseDisplayDateTime("2026-03-09 14:22:31 UTC");
    const bare = parseDisplayDateTime("2026-03-09 14:22:31");

    expect(marked).not.toBeNull();
    expect(bare).not.toBeNull();
    expect(marked!.getUTCHours()).toBe(14);
    expect(marked!.getUTCMinutes()).toBe(22);

    const offsetMinutes = new Date().getTimezoneOffset();
    if (offsetMinutes !== 0) {
      // Off UTC the bare form must sit exactly the host offset away; the marked
      // form must not move. This is the case the UTC normalisation protects.
      expect(bare!.getTime() - marked!.getTime()).toBe(offsetMinutes * 60_000);
    }
  });

  it("reads a month-first Windows timestamp", () => {
    const parsed = parseDisplayDateTime("03-09-2026 14:22:31");
    expect(parsed).not.toBeNull();
    // Month 03, day 09 — the opposite reading would give 3 September.
    expect(parsed!.getMonth()).toBe(2);
    expect(parsed!.getDate()).toBe(9);
  });

  it("exposes the same result as an epoch value", () => {
    const s = "2026-03-09T14:22:31Z";
    expect(parseDisplayDateTimeValue(s)).toBe(parseDisplayDateTime(s)!.getTime());
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
