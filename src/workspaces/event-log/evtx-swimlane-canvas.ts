/**
 * The swimlane canvas's marks, paint and hit test (spec section 8.9), with no React and no DOM.
 *
 * The painter draws onto a narrow `Paint2D`, so a test hands it a recording object instead of
 * depending on a canvas jsdom does not have, and what a test reads is the very sequence of calls
 * the browser would receive.
 *
 * What it promises:
 *
 * - A level is never told apart by colour alone. Each of the five has its own size and shape
 *   (`DOT_MARKS`): the spec's size ladder (10, 9, 7, 5 px, "larger = more severe"), a diamond for
 *   Critical because 10 and 9 px are one pixel apart, and a hollow ring for Verbose, the shape of
 *   its icon. The legend is drawn from the same table, so it cannot drift from the canvas.
 * - Severity is on top: levels are painted from Verbose to Critical (`HISTOGRAM_STACK_ORDER`).
 *   Every level except Information gets a 1 px ring that is a KNOCKOUT (it clears what is under
 *   the dot) rather than a stroke in the surface colour: outside a brush that reads exactly the
 *   surface, over the wash it reads the wash, and under forced colors it reads Canvas.
 * - Painting costs by what can be seen, not by the number of events: a level's dots in one lane
 *   that land on the same device-pixel column draw once. A lane's dots are in x order, so the
 *   dedupe is one comparison against the last column kept.
 * - The hit test is a 1-D search in the lane under the pointer, because a lane's dots are in
 *   time order and time order is x order. See `hitTest` for the metric and the tie-break.
 */
import { tokens } from "@fluentui/react-components";
import type { CMTraceTheme } from "../../lib/themes/types";
import { HISTOGRAM_STACK_ORDER } from "./evtx-histogram";
import { HIT_SLOP_PX, LEVEL_SLOT, type SwimlaneScene } from "./evtx-swimlanes";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";
import type { EvtxLevel, EvtxRecord } from "./types";

export type DotShape = "circle" | "diamond" | "ring";

export interface DotMark {
  shape: DotShape;
  /** Diameter, or the width of the diamond, in CSS pixels. */
  size: number;
  /** Information is drawn at 55% (spec 8.9); every other level is solid. */
  opacity: number;
  /** A 1 px knockout ring around the mark (spec 8.9: non-Info dots). */
  knockout: boolean;
  /** Stroke width of a `ring`. */
  strokePx: number;
}

/**
 * The marks (spec 8.9: dots of 10, 9, 7 and 5 px for Critical through Information). Verbose is
 * not in the spec's list: a 5 px hollow ring at full opacity, because Verbose at 55% would measure
 * 1.75:1 on the light wash (Information is the one level exempt from the 3:1 floor).
 */
export const DOT_MARKS: Readonly<Record<EvtxLevel, DotMark>> = {
  Critical: { shape: "diamond", size: 10, opacity: 1, knockout: true, strokePx: 0 },
  Error: { shape: "circle", size: 9, opacity: 1, knockout: true, strokePx: 0 },
  Warning: { shape: "circle", size: 7, opacity: 1, knockout: true, strokePx: 0 },
  Information: { shape: "circle", size: 5, opacity: 0.55, knockout: false, strokePx: 0 },
  Verbose: { shape: "ring", size: 5, opacity: 1, knockout: true, strokePx: 1.5 },
};

/** The largest mark's radius: the reach of the hit test beyond the slop. */
export const MAX_MARK_RADIUS_PX = 5;

/** Width of the knockout ring (spec 8.9: 1 px). */
export const KNOCKOUT_PX = 1;

/**
 * The plot is inset from the canvas by this much on both sides, so a dot on the first or last
 * instant of the axis is whole: the largest mark's radius plus the ring.
 */
export const PLOT_INSET_PX = MAX_MARK_RADIUS_PX + KNOCKOUT_PX;

const TAU = Math.PI * 2;

/** The colours the canvas itself draws; everything else is a DOM layer that takes tokens. */
export interface SwimlaneColors {
  /** Lane baselines, `colorNeutralStroke2` (decorative, spec 6.1). */
  baseline: string;
  /** Lane bottom edges, `colorNeutralStroke3` (decorative). */
  separator: string;
  /** `levels.<L>.dotColor`, resolved. */
  dots: Readonly<Record<EvtxLevel, string>>;
}

/**
 * The canvas colours of a theme, resolved to hex through the theme object. A canvas cannot read
 * `var(--x)`; spec 6 resolves them with `getComputedStyle`, which returns what the provider was
 * given, and the provider is given this very object (`main.tsx`: `getThemeById(themeId)`, then
 * `<FluentProvider theme={activeTheme.fluentTheme}>`). Resolving here needs no DOM, follows a
 * theme switch the moment `themeId` changes, and is what the contrast test measures.
 */
export function swimlaneColors(theme: CMTraceTheme): SwimlaneColors {
  const visual = buildEvtxVisualTokens(theme);
  return {
    baseline: resolveToken(tokens.colorNeutralStroke2, theme),
    separator: resolveToken(tokens.colorNeutralStroke3, theme),
    dots: Object.fromEntries(
      HISTOGRAM_STACK_ORDER.map((level) => [level, resolveToken(visual.levels[level].dotColor, theme)]),
    ) as Record<EvtxLevel, string>,
  };
}

/** The subset of `CanvasRenderingContext2D` the painter uses. */
export interface Paint2D {
  globalAlpha: number;
  globalCompositeOperation: GlobalCompositeOperation;
  fillStyle: string | CanvasGradient | CanvasPattern;
  strokeStyle: string | CanvasGradient | CanvasPattern;
  lineWidth: number;
  setTransform(a: number, b: number, c: number, d: number, e: number, f: number): void;
  clearRect(x: number, y: number, width: number, height: number): void;
  beginPath(): void;
  moveTo(x: number, y: number): void;
  lineTo(x: number, y: number): void;
  arc(x: number, y: number, radius: number, startAngle: number, endAngle: number): void;
  closePath(): void;
  fill(): void;
  stroke(): void;
}

/** What a paint needs besides the scene. All sizes are CSS pixels. */
export interface LaneGeometry {
  /** Width of the plot: the axis from its first instant to its last. */
  plotWidth: number;
  laneHeight: number;
  /** Device pixels per CSS pixel. */
  dpr: number;
}

/** The canvas is the plot plus its inset on both sides. */
export function canvasWidthFor(plotWidth: number): number {
  return plotWidth + 2 * PLOT_INSET_PX;
}

/** Where a fraction of the axis lands on the canvas. */
export function xOfFraction(fraction: number, plotWidth: number): number {
  return PLOT_INSET_PX + fraction * plotWidth;
}

/** Centre of a lane. */
export function yOfLane(lane: number, laneHeight: number): number {
  return lane * laneHeight + laneHeight / 2;
}

export interface LevelDraws {
  level: EvtxLevel;
  xs: Float32Array;
  ys: Float32Array;
}

export interface PaintPlan {
  /** Canvas size in CSS pixels. */
  width: number;
  height: number;
  dpr: number;
  plotWidth: number;
  laneHeight: number;
  laneCount: number;
  /** Per level in paint order (Verbose first), levels with nothing to draw left out. */
  draws: readonly LevelDraws[];
  /** Marks to draw, after the dedupe. */
  drawCount: number;
}

/**
 * What to paint for a scene at a size: for each level, the centres of its dots, with dots that
 * land on the same device-pixel column of the same lane drawn once. The result depends on the
 * number of columns, lanes and levels and not on the number of events.
 */
export function planPaint(scene: SwimlaneScene, geometry: LaneGeometry): PaintPlan {
  const { plotWidth, laneHeight, dpr } = geometry;
  const xs: number[][] = HISTOGRAM_STACK_ORDER.map(() => []);
  const ys: number[][] = HISTOGRAM_STACK_ORDER.map(() => []);
  const lastColumn = new Array<number>(HISTOGRAM_STACK_ORDER.length);
  scene.lanes.forEach((lane, laneIndex) => {
    lastColumn.fill(Number.NEGATIVE_INFINITY);
    const y = yOfLane(laneIndex, laneHeight);
    for (let dot = 0; dot < lane.count; dot += 1) {
      const slot = lane.levels[dot];
      const x = xOfFraction(lane.fractions[dot], plotWidth);
      const column = Math.floor(x * dpr);
      if (column === lastColumn[slot]) continue;
      lastColumn[slot] = column;
      xs[slot].push(x);
      ys[slot].push(y);
    }
  });
  let drawCount = 0;
  const draws: LevelDraws[] = [];
  HISTOGRAM_STACK_ORDER.forEach((level, slot) => {
    if (xs[slot].length === 0) return;
    drawCount += xs[slot].length;
    draws.push({ level, xs: Float32Array.from(xs[slot]), ys: Float32Array.from(ys[slot]) });
  });
  return {
    width: canvasWidthFor(plotWidth),
    height: scene.lanes.length * laneHeight,
    dpr,
    plotWidth,
    laneHeight,
    laneCount: scene.lanes.length,
    draws,
    drawCount,
  };
}

function addMark(ctx: Paint2D, shape: DotShape, cx: number, cy: number, extent: number): void {
  const radius = extent / 2;
  if (shape === "diamond") {
    // Same winding as an arc, so a batch of marks in one path fills as their union.
    ctx.moveTo(cx - radius, cy);
    ctx.lineTo(cx, cy - radius);
    ctx.lineTo(cx + radius, cy);
    ctx.lineTo(cx, cy + radius);
    ctx.closePath();
    return;
  }
  ctx.moveTo(cx + radius, cy);
  ctx.arc(cx, cy, radius, 0, TAU);
}

/**
 * Paints a plan. The canvas element must already be sized to `plan.width * dpr` by
 * `plan.height * dpr`. Order: baselines and lane edges, then each level from Verbose to Critical,
 * each as one knockout, one fill (or stroke, for the ring) and, under forced colors, one outline.
 *
 * `forcedRing` is the resolved CanvasText colour under `forced-colors: active`, else null. A
 * canvas is not recoloured by forced colors, so there the marks keep their level colours and each
 * gets a 1 px ring in the system text colour, as the histogram's segments do.
 */
export function paintSwimlanes(
  ctx: Paint2D,
  plan: PaintPlan,
  colors: SwimlaneColors,
  forcedRing: string | null,
): void {
  ctx.setTransform(plan.dpr, 0, 0, plan.dpr, 0, 0);
  ctx.globalAlpha = 1;
  ctx.globalCompositeOperation = "source-over";
  ctx.clearRect(0, 0, plan.width, plan.height);
  if (plan.laneCount === 0) return;

  ctx.lineWidth = 1;
  ctx.strokeStyle = colors.baseline;
  ctx.beginPath();
  for (let lane = 0; lane < plan.laneCount; lane += 1) {
    const y = Math.floor(yOfLane(lane, plan.laneHeight)) + 0.5;
    ctx.moveTo(PLOT_INSET_PX, y);
    ctx.lineTo(PLOT_INSET_PX + plan.plotWidth, y);
  }
  ctx.stroke();
  ctx.strokeStyle = colors.separator;
  ctx.beginPath();
  for (let lane = 0; lane < plan.laneCount; lane += 1) {
    const y = (lane + 1) * plan.laneHeight - 0.5;
    ctx.moveTo(0, y);
    ctx.lineTo(plan.width, y);
  }
  ctx.stroke();

  for (const { level, xs, ys } of plan.draws) {
    const mark = DOT_MARKS[level];
    if (mark.knockout) {
      ctx.globalCompositeOperation = "destination-out";
      ctx.globalAlpha = 1;
      ctx.fillStyle = "#000000";
      ctx.beginPath();
      for (let index = 0; index < xs.length; index += 1) {
        addMark(ctx, mark.shape === "ring" ? "circle" : mark.shape, xs[index], ys[index], mark.size + 2 * KNOCKOUT_PX);
      }
      ctx.fill();
      ctx.globalCompositeOperation = "source-over";
    }
    ctx.globalAlpha = mark.opacity;
    ctx.beginPath();
    if (mark.shape === "ring") {
      ctx.strokeStyle = colors.dots[level];
      ctx.lineWidth = mark.strokePx;
      for (let index = 0; index < xs.length; index += 1) {
        addMark(ctx, "circle", xs[index], ys[index], mark.size - mark.strokePx);
      }
      ctx.stroke();
    } else {
      ctx.fillStyle = colors.dots[level];
      for (let index = 0; index < xs.length; index += 1) addMark(ctx, mark.shape, xs[index], ys[index], mark.size);
      ctx.fill();
    }
    ctx.globalAlpha = 1;
    if (forcedRing !== null) {
      ctx.strokeStyle = forcedRing;
      ctx.lineWidth = 1;
      ctx.beginPath();
      for (let index = 0; index < xs.length; index += 1) {
        addMark(ctx, mark.shape === "ring" ? "circle" : mark.shape, xs[index], ys[index], mark.size + 1);
      }
      ctx.stroke();
    }
  }
  ctx.globalAlpha = 1;
  ctx.globalCompositeOperation = "source-over";
}

export interface DotHit {
  lane: number;
  /** Index into the lane's parallel arrays. */
  dot: number;
  record: EvtxRecord;
  level: EvtxLevel;
  /** Pointer to the dot's edge: zero anywhere on the disc. */
  distance: number;
  /** Pointer to the dot's centre. */
  centerDistance: number;
  /** Where the dot is drawn, on the canvas. */
  x: number;
  y: number;
  /** Other dots within the slop of the pointer: events this one hides or sits among. */
  more: number;
}

/** First index in `fractions` (ascending) at or above `value`. */
function lowerBoundFraction(fractions: Float64Array, value: number): number {
  let low = 0;
  let high = fractions.length;
  while (low < high) {
    const middle = (low + high) >> 1;
    if (fractions[middle] < value) low = middle + 1;
    else high = middle;
  }
  return low;
}

/** Radius a mark has for the hit test: half its size, which a diamond's corners reach. */
export function hitRadiusOf(level: EvtxLevel): number {
  return DOT_MARKS[level].size / 2;
}

/**
 * The dot a click at (`x`, `y`) on the canvas selects, or null.
 *
 * Only the lane under the pointer is searched: half a lane is at least 18 px, and the largest
 * mark's rim and the slop together reach `MAX_MARK_RADIUS_PX + HIT_SLOP_PX` = 9 px, so a dot of
 * another lane cannot be near enough. Inside the lane the dots are in x order, so the candidates
 * are a slice found by binary search.
 *
 * The metric is distance from the pointer to the dot's EDGE (centre distance less the radius,
 * never below zero), at most `HIT_SLOP_PX` CSS px: the visible disc always hits, which a test from
 * the centre would fail for a 10 px dot clicked on its rim. Of the candidates, the winner is:
 *
 * 1. the smallest distance;
 * 2. then the more severe level, which is the dot drawn on top where discs overlap;
 * 3. then the smaller centre distance;
 * 4. then the earlier time;
 * 5. then the lower position in the lane.
 */
export function hitTest(
  scene: SwimlaneScene,
  geometry: Pick<LaneGeometry, "plotWidth" | "laneHeight">,
  x: number,
  y: number,
  slop: number = HIT_SLOP_PX,
): DotHit | null {
  const { plotWidth, laneHeight } = geometry;
  if (plotWidth <= 0 || laneHeight <= 0 || y < 0) return null;
  const laneIndex = Math.floor(y / laneHeight);
  const lane = scene.lanes[laneIndex];
  if (lane === undefined) return null;
  const cy = yOfLane(laneIndex, laneHeight);
  const reach = MAX_MARK_RADIUS_PX + slop;
  const from = lowerBoundFraction(lane.fractions, (x - reach - PLOT_INSET_PX) / plotWidth);
  const until = (x + reach - PLOT_INSET_PX) / plotWidth;

  let best: DotHit | null = null;
  let within = 0;
  for (let dot = from; dot < lane.count && lane.fractions[dot] <= until; dot += 1) {
    const level = HISTOGRAM_STACK_ORDER[lane.levels[dot]];
    const cx = xOfFraction(lane.fractions[dot], plotWidth);
    const centerDistance = Math.hypot(x - cx, y - cy);
    const distance = Math.max(0, centerDistance - hitRadiusOf(level));
    if (distance > slop) continue;
    within += 1;
    if (best !== null && !beats(lane, dot, distance, centerDistance, best)) continue;
    best = {
      lane: laneIndex,
      dot,
      record: lane.records[dot],
      level,
      distance,
      centerDistance,
      x: cx,
      y: cy,
      more: 0,
    };
  }
  return best === null ? null : { ...best, more: within - 1 };
}

/** Whether `dot` beats the current best under the tie-break order of `hitTest`. */
function beats(
  lane: SwimlaneScene["lanes"][number],
  dot: number,
  distance: number,
  centerDistance: number,
  best: DotHit,
): boolean {
  if (distance !== best.distance) return distance < best.distance;
  const slot = lane.levels[dot];
  if (slot !== LEVEL_SLOT[best.level]) return slot > LEVEL_SLOT[best.level];
  if (centerDistance !== best.centerDistance) return centerDistance < best.centerDistance;
  const epoch = lane.epochs[dot];
  const bestEpoch = lane.epochs[best.dot];
  if (epoch !== bestEpoch) return epoch < bestEpoch;
  return dot < best.dot;
}
