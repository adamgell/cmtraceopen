/**
 * The histogram brush's rules, with no React and no DOM: which buckets a gesture selects, what a
 * click or Enter does, how the keyboard moves a cursor and extends a draft, and how opaque the
 * wash over the brushed buckets may be (spec sections 8.5, 9 and 10).
 *
 * A brush always covers whole buckets, at least one, and is set from the buckets of the histogram on
 * screen, so the time range it sets is `{ edges[first], edges[last + 1] }`: half open, like
 * `EvtxTimeRange`, and exactly the events those bars count.
 */
import { tokens } from "@fluentui/react-components";
import { contrastRatio, parseHex } from "../../lib/color-contrast";
import type { CMTraceTheme } from "../../lib/themes/types";
import type { EvtxTimeRange } from "./evtx-filter";
import { HISTOGRAM_STACK_ORDER, bucketIndexAt, type EvtxHistogram } from "./evtx-histogram";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";

/** Buckets `first` to `last`, both included, `first <= last`. */
export interface BucketSpan {
  first: number;
  last: number;
}

export function spanOfIndices(a: number, b: number): BucketSpan {
  return { first: Math.min(a, b), last: Math.max(a, b) };
}

/** The bucket under a point `fraction` (0 to 1) across the plot, clamped to the first and last. */
export function bucketIndexFromFraction(fraction: number, count: number): number {
  if (count < 1 || Number.isNaN(fraction)) return 0;
  return Math.min(count - 1, Math.max(0, Math.floor(fraction * count)));
}

/** The time range of whole buckets. */
export function rangeOfSpan(histogram: EvtxHistogram, span: BucketSpan): EvtxTimeRange {
  return { startMs: histogram.edges[span.first], endMs: histogram.edges[span.last + 1] };
}

/**
 * The buckets a time range covers, and whether it starts and ends exactly on bucket edges. A range
 * set from these buckets is aligned. One set before the buckets changed (the span grew with a live
 * tail, the zone changed) may not be; it is clipped to the plot here. Null when it misses the plot.
 */
export function spanOfRange(
  histogram: EvtxHistogram,
  range: EvtxTimeRange,
): (BucketSpan & { aligned: boolean }) | null {
  const { domain, edges } = histogram;
  if (domain === null || range.endMs <= domain.startMs || range.startMs >= domain.endMs) return null;
  const first = range.startMs <= domain.startMs ? 0 : bucketIndexAt(histogram, range.startMs);
  const last = range.endMs >= domain.endMs ? edges.length - 2 : bucketIndexAt(histogram, range.endMs - 1);
  return {
    first,
    last,
    aligned: edges[first] === range.startMs && edges[last + 1] === range.endMs,
  };
}

/**
 * The range after a click or Enter on `span`: those buckets, except that activating the one bucket
 * that is already the whole range clears it. The second click on the sole active ID does the same
 * in the Top event IDs list. Null means no range.
 */
export function rangeAfterActivate(
  histogram: EvtxHistogram,
  applied: EvtxTimeRange | null,
  span: BucketSpan,
): EvtxTimeRange | null {
  const next = rangeOfSpan(histogram, span);
  if (
    applied !== null &&
    span.first === span.last &&
    applied.startMs === next.startMs &&
    applied.endMs === next.endMs
  ) {
    return null;
  }
  return next;
}

/** The keyboard cursor, and the end a Shift selection started from while one is being made. */
export interface BrushKeyState {
  cursor: number;
  anchor: number | null;
}

export type BrushKey = "ArrowLeft" | "ArrowRight" | "Home" | "End";

/** Where the cursor starts when the plot takes focus: the end of the applied range, else the newest bucket. */
export function initialBrushCursor(count: number, applied: BucketSpan | null): number {
  return applied === null ? Math.max(0, count - 1) : Math.min(count - 1, applied.last);
}

/** Keeps a held cursor and anchor on the plot after the buckets changed. */
export function clampBrushState(state: BrushKeyState, count: number): BrushKeyState {
  const clamp = (index: number) => Math.min(Math.max(0, count - 1), Math.max(0, index));
  return { cursor: clamp(state.cursor), anchor: state.anchor === null ? null : clamp(state.anchor) };
}

/**
 * One key of the keyboard model. Arrows and Home/End move the cursor and drop any draft. With Shift
 * they extend a draft from an anchor instead. The anchor is the cursor where the draft starts, except
 * that when a range is applied and the cursor is on one of its end buckets, Shift moves that edge and
 * the range's other end is the anchor: that is how a range is adjusted.
 */
export function reduceBrushKey(
  state: BrushKeyState,
  key: BrushKey,
  shift: boolean,
  count: number,
  applied: BucketSpan | null,
): BrushKeyState {
  if (count < 1) return state;
  const last = count - 1;
  const target =
    key === "ArrowLeft"
      ? state.cursor - 1
      : key === "ArrowRight"
        ? state.cursor + 1
        : key === "Home"
          ? 0
          : last;
  const cursor = Math.min(last, Math.max(0, target));
  if (!shift) return { cursor, anchor: null };
  let anchor = state.anchor;
  if (anchor === null) {
    anchor = state.cursor;
    if (applied !== null && applied.first !== applied.last) {
      if (state.cursor === applied.last) anchor = applied.first;
      else if (state.cursor === applied.first) anchor = applied.last;
    }
  }
  return { cursor, anchor };
}

/** The draft span being made, or null when there is none. */
export function draftSpan(state: BrushKeyState): BucketSpan | null {
  return state.anchor === null ? null : spanOfIndices(state.anchor, state.cursor);
}

/** What Enter applies: the draft, else the one bucket under the cursor. */
export function spanToApply(state: BrushKeyState): BucketSpan {
  return draftSpan(state) ?? { first: state.cursor, last: state.cursor };
}

/** Opacities the brush wash may take, most opaque first. Spec 8.5 says 60%. */
export const BRUSH_FILL_OPACITIES: readonly number[] = [0.6, 0.5, 0.4, 0.3, 0.25, 0.2, 0.15, 0.1];

/** The non-text contrast every mark on the wash must keep (WCAG 1.4.11). */
export const BRUSH_MIN_CONTRAST = 3;

/** `foreground` at `opacity` over `background`, as `#rrggbb`. */
export function compositeOver(background: string, foreground: string, opacity: number): string {
  const under = parseHex(background);
  const over = parseHex(foreground);
  const channels = under.map((channel, index) =>
    Math.round(over[index] * opacity + channel * (1 - opacity)),
  );
  return `#${channels.map((channel) => channel.toString(16).padStart(2, "0")).join("")}`;
}

/** The resolved colors of everything the wash sits under or beside. */
export interface BrushPalette {
  /** `colorNeutralBackground1`, the plot's surface. */
  surface: string;
  /** `colorNeutralBackground1Selected`, the wash. */
  fill: string;
  /** Every level's bar. */
  bars: readonly string[];
  /** The 2 px edge borders. */
  border: string;
  /** The keyboard cursor's outline. */
  cursor: string;
  /** The plot's focus ring. */
  focus: string;
}

/**
 * The brush colors of a theme, resolved to hex.
 *
 * Deviates from spec 8.5 / D6 (brush borders `colorNeutralForeground3`): that token measures 2.34:1
 * against the wash in dracula and 3.08:1 in solarized-dark, under the 3:1 a boundary needs. The
 * borders use `colorNeutralStrokeAccessible`, the stroke the token map already substitutes where
 * Foreground3 is short (the notCausal badge): at least 3.97:1 against the wash in every theme.
 */
export function brushPaletteFor(theme: CMTraceTheme): BrushPalette {
  const visual = buildEvtxVisualTokens(theme);
  const resolve = (value: string) => resolveToken(value, theme);
  return {
    surface: resolve(tokens.colorNeutralBackground1),
    fill: resolve(tokens.colorNeutralBackground1Selected),
    bars: HISTOGRAM_STACK_ORDER.map((level) => resolve(visual.levels[level].barColor)),
    border: resolve(tokens.colorNeutralStrokeAccessible),
    cursor: resolve(tokens.colorNeutralForeground1),
    focus: resolve(tokens.colorStrokeFocus2),
  };
}

/** The pairs that decide the wash's opacity, each against the wash composited over the surface. */
export function brushContrasts(palette: BrushPalette, opacity: number): number[] {
  const wash = compositeOver(palette.surface, palette.fill, opacity);
  return [...palette.bars, palette.border, palette.cursor, palette.focus].map((color) =>
    contrastRatio(color, wash),
  );
}

/**
 * How opaque the wash over the brushed buckets is: the largest of `BRUSH_FILL_OPACITIES` at which
 * every bar, the border, the cursor outline and the focus ring keep 3:1 on the wash. The wash is
 * drawn BEHIND the bars (surface, wash, bars, borders and cursor): over them, the Error bar measures
 * about 1.8:1 in every theme. Spec 8.5 says 60%, which is what six themes get. High contrast cannot
 * keep it, because its selection fill is cyan (Error 1.01:1, Critical 1.25:1), so it takes 25%. If no
 * opacity works the wash is dropped and the borders carry the range. Solved from the token map, so a
 * token change re-solves rather than silently failing.
 */
export function solveBrushOpacity(palette: BrushPalette): number {
  for (const opacity of BRUSH_FILL_OPACITIES) {
    if (brushContrasts(palette, opacity).every((ratio) => ratio >= BRUSH_MIN_CONTRAST)) return opacity;
  }
  return 0;
}
