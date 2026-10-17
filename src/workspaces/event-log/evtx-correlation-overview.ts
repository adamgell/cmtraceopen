/**
 * The Correlation overview strip's rules, with no React and no DOM (spec 8.11, "Overview strip"):
 * what its time scale is, which bar each chain gets, where the zoom band may go and how a gesture
 * or a key moves it, and how opaque the wash behind the bars may be.
 *
 * The band sets the lane plot's window and nothing else. It is view-local: it is not the time-range
 * criterion (6a) and never reads or writes it, so it does not filter the table, the histogram or
 * the diagnosis. The window it holds is absolute time, so a rebuild of the same chain keeps it.
 *
 * Rules, all enforced here:
 * - The scale (the "domain") is the union of every drawn chain's DEFAULT lane window, so the
 *   default band always fits inside it, whatever the band does. It is the extent of the chains
 *   shown, not of the session: the engine reports no session extent, and the strip says so.
 * - A chain with no resolved position has no span and no bar. It is counted, never drawn at 0.
 * - The band is clamped to the domain and is at least `CORRELATION_MIN_WINDOW_MS` (10 s) wide, the
 *   lane plot's own minimum.
 * - Only chains are read. An unplaced item has no place on any timeline, so nothing here takes one.
 */
import { tokens } from "@fluentui/react-components";
import type { CMTraceTheme } from "../../lib/themes/types";
import { solveBrushOpacity, type BrushPalette } from "./evtx-histogram-brush";
import type { CorrelationChain } from "./evtx-correlation-chains";
import {
  CORRELATION_MIN_WINDOW_MS,
  defaultLaneWindow,
  formatDelta,
  tickLabels,
  type TimeWindow,
} from "./evtx-correlation-view-model";
import type { EvtxTimeZoneMode } from "./evtx-time";
import { buildEvtxVisualTokens, resolveToken, type EvtxChainStrength } from "./evtx-visual-tokens";

/** Spec 8.11: the bordered box (bars and band) is 48 px tall. The caption sits above it, the ticks below. */
export const OVERVIEW_BOX_HEIGHT_PX = 48;
/** One bar's height. Four strength rows of it, with gaps, fit the box. */
export const OVERVIEW_BAR_HEIGHT_PX = 6;
/** Spec 8.11: the chains other than the selected one are drawn at 40%, in their FILL only (R1). */
export const OVERVIEW_UNSELECTED_FILL_OPACITY = 0.4;
/** The caption (spec 8.11) and its hint. */
export const OVERVIEW_CAPTION = "Overview";
export const OVERVIEW_HINT = "drag the band to zoom";
/** Said beside the caption: the strip's scale is the chains shown, not the session (R5). */
export const OVERVIEW_EXTENT_NOTE = "Spans the chains shown, not the whole session.";

/** Bars sit in one row per strength, strongest first: the row says which, so colour does not have to. */
export const OVERVIEW_STRENGTH_ROWS: readonly EvtxChainStrength[] = [
  "exact",
  "candidate",
  "ambiguous",
  "coverageBlocked",
];

type Span = Pick<CorrelationChain, "startMs" | "endMs">;

/**
 * The strip's time scale: the union of every chain's default lane window (the span padded by 25%,
 * at least 10 s), or null when no chain has a position. It depends on the chains alone, so it does
 * not move while the band does.
 */
export function overviewDomain(chains: readonly Span[]): TimeWindow | null {
  let start = Number.POSITIVE_INFINITY;
  let end = Number.NEGATIVE_INFINITY;
  for (const chain of chains) {
    const window = defaultLaneWindow(chain.startMs, chain.endMs);
    if (window === null) continue;
    start = Math.min(start, window.startMs);
    end = Math.max(end, window.endMs);
  }
  return start === Number.POSITIVE_INFINITY ? null : { startMs: start, endMs: end };
}

export interface OverviewBar {
  chainId: string;
  strength: EvtxChainStrength;
  /** Index into `OVERVIEW_STRENGTH_ROWS`. */
  row: number;
  /** 0 to 1 across the domain. */
  left: number;
  /** Width as a fraction of the domain. 0 for a chain that is a single instant: the view gives it a minimum. */
  width: number;
  selected: boolean;
}

export interface OverviewBars {
  /** In draw order: the selected chain last, so it is on top where bars overlap. */
  bars: OverviewBar[];
  /** Chains with no resolved member: they have no span and no bar. */
  undrawn: number;
}

/** One bar per chain with a span, in its strength's row, positioned across `domain`. */
export function overviewBars(
  chains: readonly (Span & Pick<CorrelationChain, "id" | "strength">)[],
  selectedId: string | null,
  domain: TimeWindow | null,
): OverviewBars {
  const bars: OverviewBar[] = [];
  let undrawn = 0;
  const width = domain === null ? 0 : domain.endMs - domain.startMs;
  for (const chain of chains) {
    if (chain.startMs === null || chain.endMs === null || domain === null || width <= 0) {
      undrawn += 1;
      continue;
    }
    bars.push({
      chainId: chain.id,
      strength: chain.strength,
      row: OVERVIEW_STRENGTH_ROWS.indexOf(chain.strength),
      left: (chain.startMs - domain.startMs) / width,
      width: (chain.endMs - chain.startMs) / width,
      selected: chain.id === selectedId,
    });
  }
  // Stable: the selected chain moves to the end and every other bar keeps its place.
  bars.sort((a, b) => Number(a.selected) - Number(b.selected));
  return { bars, undrawn };
}

/** The sentence for chains that cannot be drawn. It claims nothing about why they have no position. */
export function undrawnNote(undrawn: number): string | null {
  if (undrawn <= 0) return null;
  return `${undrawn.toLocaleString()} ${undrawn === 1 ? "chain has" : "chains have"} no loaded timeline position and ${undrawn === 1 ? "is" : "are"} not drawn here.`;
}

// ---- the band -----------------------------------------------------------------------------------

/** The band's two edges as fractions of the domain, clamped to the strip. */
export function bandFractions(window: TimeWindow, domain: TimeWindow): { left: number; right: number } {
  const width = domain.endMs - domain.startMs;
  const at = (ms: number) => Math.min(1, Math.max(0, (ms - domain.startMs) / width));
  return { left: at(window.startMs), right: at(window.endMs) };
}

/** The time at a fraction (0 to 1) across the domain. */
export function fractionToMs(fraction: number, domain: TimeWindow): number {
  return domain.startMs + Math.min(1, Math.max(0, fraction)) * (domain.endMs - domain.startMs);
}

/**
 * `window` made legal for `domain`: no wider than the domain, no narrower than the lane plot's
 * minimum (or than the domain, when that is narrower), and inside it. A window outside the domain
 * is moved in with its width kept, never dropped.
 */
export function clampWindow(window: TimeWindow, domain: TimeWindow): TimeWindow {
  const available = domain.endMs - domain.startMs;
  const width = Math.min(available, Math.max(CORRELATION_MIN_WINDOW_MS, window.endMs - window.startMs));
  const start = Math.min(domain.endMs - width, Math.max(domain.startMs, window.startMs));
  return { startMs: start, endMs: start + width };
}

/** The band moved by `deltaMs`, its width kept, inside the domain. */
export function panWindow(window: TimeWindow, domain: TimeWindow, deltaMs: number): TimeWindow {
  return clampWindow(
    { startMs: window.startMs + deltaMs, endMs: window.endMs + deltaMs },
    domain,
  );
}

/** One edge moved to `toMs`: inside the domain, and never closer to the other edge than the minimum. */
export function resizeEdge(
  window: TimeWindow,
  domain: TimeWindow,
  edge: "start" | "end",
  toMs: number,
): TimeWindow {
  const minimum = Math.min(CORRELATION_MIN_WINDOW_MS, domain.endMs - domain.startMs);
  if (edge === "start") {
    const start = Math.min(window.endMs - minimum, Math.max(domain.startMs, toMs));
    return { startMs: Math.max(domain.startMs, start), endMs: window.endMs };
  }
  const end = Math.max(window.startMs + minimum, Math.min(domain.endMs, toMs));
  return { startMs: window.startMs, endMs: Math.min(domain.endMs, end) };
}

/** What a pointer press on the band took hold of, and where the band was then. */
export interface BandDrag {
  part: "body" | "start" | "end";
  origin: TimeWindow;
  /** The time under the pointer when it went down. */
  grabMs: number;
}

/**
 * The band while the pointer is at `pointerMs`: the body pans, an edge resizes. Everything is
 * measured from the press (the origin and the grab), not from the last move, so the band does not
 * drift and an edge does not jump to the pointer by the width of its handle.
 */
export function dragBand(drag: BandDrag, pointerMs: number, domain: TimeWindow): TimeWindow {
  const delta = pointerMs - drag.grabMs;
  switch (drag.part) {
    case "body":
      return panWindow(drag.origin, domain, delta);
    case "start":
      return resizeEdge(drag.origin, domain, "start", drag.origin.startMs + delta);
    case "end":
      return resizeEdge(drag.origin, domain, "end", drag.origin.endMs + delta);
  }
}

/** A step is a tenth of the band's width, and at least a second (R7). */
export function bandStepMs(window: TimeWindow): number {
  return Math.max(1_000, Math.round((window.endMs - window.startMs) / 10));
}

export type BandKeyResult =
  | { kind: "ignore" }
  /** Home: the band goes back to the chain's default window. */
  | { kind: "reset" }
  | { kind: "set"; window: TimeWindow };

/**
 * One key of the band's keyboard model (R7). Left and Right move it by a step. With Shift they
 * resize it, symmetrically about its centre: Right widens (a step on each side), Left narrows, to
 * no less than the minimum. Home resets. Anything else is not the band's.
 */
export function reduceBandKey(
  window: TimeWindow,
  domain: TimeWindow,
  key: string,
  shift: boolean,
): BandKeyResult {
  const step = bandStepMs(window);
  switch (key) {
    case "Home":
      return { kind: "reset" };
    case "ArrowLeft":
    case "ArrowRight": {
      const direction = key === "ArrowRight" ? 1 : -1;
      if (!shift) return { kind: "set", window: panWindow(window, domain, direction * step) };
      if (direction > 0) {
        return {
          kind: "set",
          window: clampWindow(
            {
              startMs: Math.max(domain.startMs, window.startMs - step),
              endMs: Math.min(domain.endMs, window.endMs + step),
            },
            domain,
          ),
        };
      }
      const centre = (window.startMs + window.endMs) / 2;
      const half = Math.max(CORRELATION_MIN_WINDOW_MS / 2, (window.endMs - window.startMs) / 2 - step);
      return {
        kind: "set",
        window: clampWindow({ startMs: centre - half, endMs: centre + half }, domain),
      };
    }
    default:
      return { kind: "ignore" };
  }
}

/**
 * The window the operator set, for the chain it was set on. Another chain, or none, has none, so
 * choosing a chain always starts from its own default window.
 */
export interface ZoomState {
  chainId: string;
  window: TimeWindow;
}

export function zoomWindowFor(state: ZoomState | null, chainId: string | null): TimeWindow | null {
  return state !== null && chainId !== null && state.chainId === chainId ? state.window : null;
}

/**
 * The slider's value text: the window's two ends and its width, in the zone the view shows times in.
 * The ends carry their day when the window crosses midnight or is not in this year.
 */
export function bandValueText(window: TimeWindow, mode: EvtxTimeZoneMode, nowMs?: number): string {
  const [from, to] = tickLabels([window.startMs, window.endMs], mode, { withSeconds: true, nowMs });
  return `${from} to ${to}, ${formatDelta(window.endMs - window.startMs)} wide`;
}

// ---- paint --------------------------------------------------------------------------------------

/**
 * The resolved colors the wash must keep 3:1 against, in 6b's palette shape: the four strength
 * bars, the handles (`colorNeutralStrokeAccessible`, because `colorNeutralForeground3` measures
 * 2.34:1 on the dracula wash) and the focus ring. The band has no keyboard cursor, so the slot 6b
 * keeps for one is the focus ring again.
 */
export function overviewPaletteFor(theme: CMTraceTheme): BrushPalette {
  const visual = buildEvtxVisualTokens(theme);
  const resolve = (value: string) => resolveToken(value, theme);
  const focus = resolve(tokens.colorStrokeFocus2);
  return {
    surface: resolve(tokens.colorNeutralBackground1),
    fill: resolve(tokens.colorNeutralBackground1Selected),
    bars: OVERVIEW_STRENGTH_ROWS.map((strength) => resolve(visual.strengthBars[strength])),
    border: resolve(tokens.colorNeutralStrokeAccessible),
    cursor: focus,
    focus,
  };
}

/**
 * How opaque the band's wash is: the largest opacity of 6b's ladder at which every bar, the handles
 * and the focus ring keep 3:1 on it (Adam's criterion on #840). The wash is drawn BEHIND the bars;
 * over them the bars measure 1.80 to 3.38:1 in every theme. The spec's 60% holds in six themes; high
 * contrast takes 50% (its Exact bar is 2.72:1 at 60% and 3.67:1 at 50%). Solved from the token map,
 * so a token change re-solves instead of silently failing.
 */
export function overviewBandOpacity(theme: CMTraceTheme): number {
  return solveBrushOpacity(overviewPaletteFor(theme));
}
