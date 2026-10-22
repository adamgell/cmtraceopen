/** The text sizes of the correlation surfaces follow the log list font size (spec 7.1). */
import { describe, expect, it } from "vitest";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { correlationSizes } from "./evtx-correlation-sizes";
import sizesSource from "./evtx-correlation-sizes.ts?raw";

describe("correlationSizes", () => {
  it("sizes the text by spec 7.1 from the log list font size: literal numbers at the default 13 px, and at both ends", () => {
    // f - 2 for secondary text, max(10, f - 3) for captions and badge text, max(9, f - 4) for ticks.
    expect(correlationSizes(13)).toEqual({ f: 13, lane: 11, label: 10, tick: 9 });
    expect(correlationSizes(11)).toEqual({ f: 11, lane: 9, label: 10, tick: 9 });
    expect(correlationSizes(20)).toEqual({ f: 20, lane: 18, label: 17, tick: 16 });
  });

  it("takes f from the log list's own metrics, which bound a setting outside the range the app allows", () => {
    for (const setting of [-5, 0, 1, 9, 13, 40, 200, Number.NaN]) {
      expect(correlationSizes(setting).f, String(setting)).toBe(getLogListMetrics(setting).fontSize);
    }
    expect(getLogListMetrics(200).fontSize).not.toBe(200);
  });

  it("applies the spec's floors and only those", () => {
    for (const setting of [8, 9, 10, 11, 12]) {
      const sizes = correlationSizes(setting);
      expect(sizes.label, String(setting)).toBeGreaterThanOrEqual(10);
      expect(sizes.tick, String(setting)).toBeGreaterThanOrEqual(9);
      expect(sizes.lane, String(setting)).toBe(sizes.f - 2);
    }
  });

  it("is a module of its own: it imports nothing from the lane plot, so a surface can take the sizes alone", () => {
    const imports = [...sizesSource.matchAll(/^import (?!type\b)[^;]*?from\s+"([^"]+)";/gms)].map((match) => match[1]);
    expect(imports).toEqual(["../../lib/log-accessibility"]);
  });
});
