import { tokens } from "@fluentui/react-components";
import { describe, expect, it } from "vitest";
import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes } from "../../lib/themes";
import { buildHistogram, type EvtxHistogram } from "./evtx-histogram";
import {
  BRUSH_FILL_OPACITIES,
  BRUSH_MIN_CONTRAST,
  brushContrasts,
  brushPaletteFor,
  bucketIndexFromFraction,
  clampBrushState,
  compositeOver,
  draftSpan,
  initialBrushCursor,
  rangeAfterActivate,
  rangeOfSpan,
  reduceBrushKey,
  solveBrushOpacity,
  spanOfIndices,
  spanOfRange,
  spanToApply,
  type BrushKeyState,
  type BrushPalette,
} from "./evtx-histogram-brush";
import { resolveToken } from "./evtx-visual-tokens";
import type { EvtxRecord } from "./types";

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const base = Date.UTC(2026, 9, 6, 0, 0, 0);

const rec = (timestampEpoch: number): EvtxRecord =>
  ({
    id: 1,
    eventRecordId: 1,
    timestamp: "",
    timestampEpoch,
    provider: "P",
    channel: "System",
    eventId: 1,
    level: "Information",
    computer: "C",
    message: "m",
    eventData: [],
    rawXml: "",
    sourceLabel: "System",
  }) as EvtxRecord;

/** 20 buckets of 30 minutes with edges on the half hour. */
const histogram: EvtxHistogram = buildHistogram(
  [rec(base), rec(base + 10 * HOUR - 1)],
  "utc",
);

describe("pointer positions", () => {
  it("maps a point across the plot to its bucket, clamped to the first and last", () => {
    const count = histogram.buckets.length;
    expect(bucketIndexFromFraction(0, count)).toBe(0);
    expect(bucketIndexFromFraction(1 / count - 1e-9, count)).toBe(0);
    expect(bucketIndexFromFraction(1 / count, count)).toBe(1);
    expect(bucketIndexFromFraction(0.5, count)).toBe(Math.floor(count / 2));
    expect(bucketIndexFromFraction(1, count)).toBe(count - 1);
    expect(bucketIndexFromFraction(-3, count)).toBe(0);
    expect(bucketIndexFromFraction(9, count)).toBe(count - 1);
    expect(bucketIndexFromFraction(Number.NaN, count)).toBe(0);
  });

  it("orders the ends of a drag", () => {
    expect(spanOfIndices(7, 3)).toEqual({ first: 3, last: 7 });
    expect(spanOfIndices(2, 2)).toEqual({ first: 2, last: 2 });
  });
});

describe("ranges and spans", () => {
  it("makes a half-open range of whole buckets: the first edge to the edge after the last", () => {
    expect(rangeOfSpan(histogram, { first: 3, last: 7 })).toEqual({
      startMs: histogram.edges[3],
      endMs: histogram.edges[8],
    });
    expect(rangeOfSpan(histogram, { first: 0, last: 0 })).toEqual({
      startMs: histogram.edges[0],
      endMs: histogram.edges[1],
    });
  });

  it("reads the buckets back from a range it made, aligned", () => {
    const range = rangeOfSpan(histogram, { first: 3, last: 7 });
    expect(spanOfRange(histogram, range)).toEqual({ first: 3, last: 7, aligned: true });
  });

  it("clips a range that runs past the plot, and calls it not aligned", () => {
    const count = histogram.buckets.length;
    expect(
      spanOfRange(histogram, { startMs: histogram.edges[0] - HOUR, endMs: histogram.edges[2] }),
    ).toEqual({ first: 0, last: 1, aligned: false });
    expect(
      spanOfRange(histogram, { startMs: histogram.edges[count - 2], endMs: histogram.edges[count] + HOUR }),
    ).toEqual({ first: count - 2, last: count - 1, aligned: false });
  });

  it("calls a range off the bucket edges not aligned, and one off the plot nothing", () => {
    expect(
      spanOfRange(histogram, { startMs: histogram.edges[2] + MINUTE, endMs: histogram.edges[5] }),
    ).toEqual({ first: 2, last: 4, aligned: false });
    const count = histogram.buckets.length;
    expect(spanOfRange(histogram, { startMs: histogram.edges[count], endMs: histogram.edges[count] + HOUR })).toBeNull();
    expect(spanOfRange(histogram, { startMs: histogram.edges[0] - HOUR, endMs: histogram.edges[0] })).toBeNull();
    expect(spanOfRange(buildHistogram([], "utc"), { startMs: 1, endMs: 2 })).toBeNull();
  });
});

describe("click and Enter", () => {
  const span = { first: 4, last: 4 };

  it("selects the bucket when there is no range", () => {
    expect(rangeAfterActivate(histogram, null, span)).toEqual(rangeOfSpan(histogram, span));
  });

  it("clears the range when the bucket is already the whole range", () => {
    expect(rangeAfterActivate(histogram, rangeOfSpan(histogram, span), span)).toBeNull();
  });

  it("replaces a different range, and keeps a many-bucket range that is activated again", () => {
    expect(rangeAfterActivate(histogram, rangeOfSpan(histogram, { first: 1, last: 2 }), span)).toEqual(
      rangeOfSpan(histogram, span),
    );
    const wide = { first: 4, last: 6 };
    expect(rangeAfterActivate(histogram, rangeOfSpan(histogram, wide), wide)).toEqual(
      rangeOfSpan(histogram, wide),
    );
    // A bucket inside a wider range is not "the sole bucket": it narrows the range to it.
    expect(rangeAfterActivate(histogram, rangeOfSpan(histogram, wide), span)).toEqual(
      rangeOfSpan(histogram, span),
    );
  });
});

describe("keyboard", () => {
  const count = 20;
  const at = (cursor: number, anchor: number | null = null): BrushKeyState => ({ cursor, anchor });

  it("starts at the newest bucket, or at the end of the applied range", () => {
    expect(initialBrushCursor(count, null)).toBe(19);
    expect(initialBrushCursor(count, { first: 4, last: 9 })).toBe(9);
    expect(initialBrushCursor(count, { first: 4, last: 40 })).toBe(19);
  });

  it("moves the cursor one bucket and stops at the ends", () => {
    expect(reduceBrushKey(at(5), "ArrowRight", false, count, null)).toEqual(at(6));
    expect(reduceBrushKey(at(5), "ArrowLeft", false, count, null)).toEqual(at(4));
    expect(reduceBrushKey(at(0), "ArrowLeft", false, count, null)).toEqual(at(0));
    expect(reduceBrushKey(at(19), "ArrowRight", false, count, null)).toEqual(at(19));
  });

  it("jumps to the first and last bucket with Home and End", () => {
    expect(reduceBrushKey(at(7), "Home", false, count, null)).toEqual(at(0));
    expect(reduceBrushKey(at(7), "End", false, count, null)).toEqual(at(19));
  });

  it("drops a draft when the cursor moves without Shift", () => {
    expect(reduceBrushKey(at(8, 5), "ArrowRight", false, count, null)).toEqual(at(9));
  });

  it("extends a draft from where Shift was first pressed", () => {
    let state = reduceBrushKey(at(10), "ArrowLeft", true, count, null);
    expect(state).toEqual(at(9, 10));
    state = reduceBrushKey(state, "ArrowLeft", true, count, null);
    expect(state).toEqual(at(8, 10));
    expect(draftSpan(state)).toEqual({ first: 8, last: 10 });
    state = reduceBrushKey(state, "ArrowRight", true, count, null);
    state = reduceBrushKey(state, "ArrowRight", true, count, null);
    state = reduceBrushKey(state, "ArrowRight", true, count, null);
    expect(draftSpan(state)).toEqual({ first: 10, last: 11 });
  });

  it("extends to the ends with Shift and Home or End", () => {
    expect(draftSpan(reduceBrushKey(at(10), "Home", true, count, null))).toEqual({ first: 0, last: 10 });
    expect(draftSpan(reduceBrushKey(at(10), "End", true, count, null))).toEqual({ first: 10, last: 19 });
  });

  it("applies the draft, or the one bucket under the cursor when there is none", () => {
    expect(spanToApply(at(8, 10))).toEqual({ first: 8, last: 10 });
    expect(spanToApply(at(8))).toEqual({ first: 8, last: 8 });
    expect(draftSpan(at(8))).toBeNull();
  });

  it("adjusts an applied range: Shift on its right end moves that edge, on its left end the left edge", () => {
    const applied = { first: 5, last: 9 };
    const grown = reduceBrushKey(at(9), "ArrowRight", true, count, applied);
    expect(draftSpan(grown)).toEqual({ first: 5, last: 10 });
    const shrunk = reduceBrushKey(at(9), "ArrowLeft", true, count, applied);
    expect(draftSpan(shrunk)).toEqual({ first: 5, last: 8 });
    const left = reduceBrushKey(at(5), "ArrowLeft", true, count, applied);
    expect(draftSpan(left)).toEqual({ first: 4, last: 9 });
    const leftIn = reduceBrushKey(at(5), "ArrowRight", true, count, applied);
    expect(draftSpan(leftIn)).toEqual({ first: 6, last: 9 });
  });

  it("starts a new draft when the cursor is not on an end of the applied range, or the range is one bucket", () => {
    expect(draftSpan(reduceBrushKey(at(7), "ArrowRight", true, count, { first: 5, last: 9 }))).toEqual({
      first: 7,
      last: 8,
    });
    expect(draftSpan(reduceBrushKey(at(5), "ArrowRight", true, count, { first: 5, last: 5 }))).toEqual({
      first: 5,
      last: 6,
    });
  });

  it("keeps a held cursor and anchor on the plot when the buckets shrink", () => {
    expect(clampBrushState(at(30, 25), 20)).toEqual(at(19, 19));
    expect(clampBrushState(at(3), 20)).toEqual(at(3));
    expect(clampBrushState(at(3, 2), 0)).toEqual(at(0, 0));
  });

  it("does nothing without buckets", () => {
    expect(reduceBrushKey(at(0), "ArrowRight", false, 0, null)).toEqual(at(0));
  });
});

describe("compositeOver", () => {
  it("blends channel by channel and rounds", () => {
    expect(compositeOver("#000000", "#1aebff", 0.6)).toBe("#108d99");
    expect(compositeOver("#ffffff", "#ebebeb", 0.6)).toBe("#f3f3f3");
    expect(compositeOver("#123456", "#abcdef", 0)).toBe("#123456");
    expect(compositeOver("#123456", "#abcdef", 1)).toBe("#abcdef");
  });
});

const themes = getAllThemes();

describe("the wash opacity", () => {
  const solved = Object.fromEntries(themes.map((theme) => [theme.id, solveBrushOpacity(brushPaletteFor(theme))]));

  it("is the spec's 60% in six themes and 25% in high contrast, today", () => {
    // Pinned so a token change that moves it is noticed: the solver re-solves, and this reports it.
    expect(solved).toEqual({
      light: 0.6,
      dark: 0.6,
      "high-contrast": 0.25,
      "classic-cmtrace": 0.6,
      "solarized-dark": 0.6,
      nord: 0.6,
      dracula: 0.6,
    });
  });

  it.each(themes.map((theme) => [theme.id, theme] as const))(
    "keeps every bar, the border, the cursor and the focus ring at 3:1 on the wash in %s",
    (_id, theme) => {
      const palette = brushPaletteFor(theme);
      for (const ratio of brushContrasts(palette, solved[theme.id])) {
        expect(ratio).toBeGreaterThanOrEqual(BRUSH_MIN_CONTRAST);
      }
    },
  );

  it("would fail in high contrast at the spec's 60%: Error 1.01:1 and Critical 1.25:1", () => {
    const palette = brushPaletteFor(themes.find((theme) => theme.id === "high-contrast")!);
    const wash = compositeOver(palette.surface, palette.fill, 0.6);
    expect(wash).toBe("#108d99");
    const [verbose, , , error, critical] = palette.bars.map((bar) => contrastRatio(bar, wash));
    expect(error).toBeLessThan(1.02);
    expect(critical).toBeLessThan(1.3);
    expect(verbose).toBeLessThan(1.02);
  });

  it("would fail in every theme if the wash were drawn over the bars: Error about 1.8:1", () => {
    for (const theme of themes) {
      const palette = brushPaletteFor(theme);
      const opacity = solved[theme.id];
      const wash = compositeOver(palette.surface, palette.fill, opacity);
      const error = palette.bars[3];
      const washedError = compositeOver(error, palette.fill, opacity);
      // The bar under the wash is the wrong order: it is the washed colour that sits on the wash.
      if (theme.id !== "high-contrast") {
        expect(contrastRatio(washedError, wash)).toBeLessThan(BRUSH_MIN_CONTRAST);
      }
    }
  });

  it("takes the largest opacity that works, and none when none does", () => {
    const palette: BrushPalette = {
      surface: "#ffffff",
      fill: "#000000",
      bars: ["#808080"],
      border: "#000000",
      cursor: "#000000",
      focus: "#000000",
    };
    // Mid grey on a white-to-black wash: it fails 3:1 once the wash is dark enough.
    const opacity = solveBrushOpacity(palette);
    expect(BRUSH_FILL_OPACITIES).toContain(opacity);
    expect(opacity).toBeLessThan(0.6);
    expect(brushContrasts(palette, opacity).every((ratio) => ratio >= 3)).toBe(true);
    const next = BRUSH_FILL_OPACITIES[BRUSH_FILL_OPACITIES.indexOf(opacity) - 1];
    expect(brushContrasts(palette, next).some((ratio) => ratio < 3)).toBe(true);

    expect(solveBrushOpacity({ ...palette, bars: ["#ffffff"], fill: "#ffffff" })).toBe(0);
  });

  it.each([
    ["a bar", { bars: ["#ffffff"], border: "#000000", cursor: "#000000", focus: "#000000" }],
    ["the border", { bars: ["#000000"], border: "#ffffff", cursor: "#000000", focus: "#000000" }],
    ["the cursor outline", { bars: ["#000000"], border: "#000000", cursor: "#ffffff", focus: "#000000" }],
    ["the focus ring", { bars: ["#000000"], border: "#000000", cursor: "#000000", focus: "#ffffff" }],
  ])("lowers the opacity when only %s would miss 3:1", (_name, marks) => {
    // Black on a wash of white over black: 0.6 gives #999999, where white is 2.8:1 and black 7.4:1.
    const palette: BrushPalette = { surface: "#000000", fill: "#ffffff", ...marks };
    expect(solveBrushOpacity(palette)).toBe(0.5);
  });
});

describe("the deviations from spec 8.5 and 6.1", () => {
  const resolved = (theme: (typeof themes)[number], value: string) => resolveToken(value, theme);

  it("keeps the brush border, colorNeutralStrokeAccessible, at 3:1 on the surface and the wash in every theme", () => {
    for (const theme of themes) {
      const palette = brushPaletteFor(theme);
      expect(palette.border).toBe(resolved(theme, tokens.colorNeutralStrokeAccessible));
      const wash = compositeOver(palette.surface, palette.fill, solveBrushOpacity(palette));
      expect(contrastRatio(palette.border, palette.surface)).toBeGreaterThanOrEqual(3);
      expect(contrastRatio(palette.border, wash)).toBeGreaterThanOrEqual(3);
    }
  });

  it("is needed: the spec's colorNeutralForeground3 border misses 3:1 on the 60% wash in dracula", () => {
    const dracula = themes.find((theme) => theme.id === "dracula")!;
    const palette = brushPaletteFor(dracula);
    const wash = compositeOver(palette.surface, palette.fill, 0.6);
    const foreground3 = resolved(dracula, tokens.colorNeutralForeground3);
    expect(contrastRatio(foreground3, wash)).toBeLessThan(3);
  });

  it("keeps the axis and legend text, colorNeutralForeground2, at 4.5:1 on the surface in every theme", () => {
    for (const theme of themes) {
      const surface = resolved(theme, tokens.colorNeutralBackground1);
      expect(contrastRatio(resolved(theme, tokens.colorNeutralForeground2), surface)).toBeGreaterThanOrEqual(4.5);
    }
  });

  it("is needed: the spec's colorNeutralForeground3 text misses 4.5:1 in solarized-dark and dracula", () => {
    for (const id of ["solarized-dark", "dracula"]) {
      const theme = themes.find((candidate) => candidate.id === id)!;
      const surface = resolved(theme, tokens.colorNeutralBackground1);
      expect(contrastRatio(resolved(theme, tokens.colorNeutralForeground3), surface)).toBeLessThan(4.5);
    }
  });
});
