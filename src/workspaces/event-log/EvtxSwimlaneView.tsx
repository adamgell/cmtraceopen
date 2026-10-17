/**
 * The Event Logs Timeline view (spec section 8.9): one lane per provider, channel or event ID, a dot
 * for each event, drawn on a canvas.
 *
 * It charts the records it is given, which the workspace builds with the time range left out (the
 * histogram's input), so brushing never empties its own chart. The x axis is the histogram's
 * (`evtx-swimlanes.ts` builds the scene on `buildHistogram`), a count it cannot place is said so,
 * and while a load runs it draws nothing: unknown is never zero.
 *
 * Layers, in document order, which is paint order: the surface, the wash over the brushed range,
 * the canvas (lane baselines and the dots), then the range's edge borders. The wash is a DOM layer
 * behind a transparent canvas so that it is drawn BEHIND the dots (over them the Error dot measures
 * about 1.8:1 in every theme) and so that forced colors can drop it, as the histogram's does.
 *
 * Colors: the canvas takes resolved colors (`swimlaneColors`); everything else here is a token.
 * Lane-count and axis text use `colorNeutralForeground2`, not the spec's Foreground3 (spec 6.1),
 * which measures 3.37:1 on the solarized-dark surface and 3.03:1 on dracula; text needs 4.5:1.
 */
import {
  memo,
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent as ReactKeyboardEvent,
  type PointerEvent as ReactPointerEvent,
} from "react";
import { Dropdown, Option, makeStyles, mergeClasses, tokens } from "@fluentui/react-components";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { getThemeById } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
import { countCoverageGapMessages } from "./evtx-coverage";
import {
  HISTOGRAM_LEVEL_LABELS,
  HISTOGRAM_STACK_ORDER,
  RANGE_OUTSIDE_NOTE,
  buildAxisTicks,
  describeCoverage,
  describeUntimed,
  rangeOnPlot,
} from "./evtx-histogram";
import {
  brushPaletteFor,
  bucketIndexFromFraction,
  clampBrushState,
  draftSpan,
  initialBrushCursor,
  rangeAfterActivate,
  rangeOfSpan,
  reduceBrushKey,
  solveBrushOpacity,
  spanOfIndices,
  spanOfRange,
  spanToApply,
  type BrushKey,
  type BrushKeyState,
} from "./evtx-histogram-brush";
import {
  DOT_MARKS,
  PLOT_INSET_PX,
  canvasWidthFor,
  hitTest,
  paintSwimlanes,
  planPaint,
  swimlaneColors,
  type DotHit,
} from "./evtx-swimlane-canvas";
import {
  SWIMLANE_FIELDS,
  SWIMLANE_FIELD_LABELS,
  SWIMLANE_FIELD_NOUNS,
  buildSwimlanes,
  describeDot,
  describeFoldedLanes,
  describeLaneCell,
  describeLaneCount,
  describeSwimlaneFigure,
  findRecordInScene,
  isCurrentRecord,
  laneHeightFor,
  laneLabelFonts,
  laneLabelLineHeights,
  topEventInCell,
  type SwimlaneField,
  type SwimlaneScene,
} from "./evtx-swimlanes";
import { selectRecordAndShowDetails } from "./evtx-select-record";
import { useEvtxStore } from "./evtx-store";
import { DERIVATION_THROTTLE_MS, useThrottledValue } from "./evtx-throttle";
import { formatTimeRange, timeZoneLabel } from "./evtx-time";
import { useEvtxVisualTokens } from "./evtx-visual-tokens";
import type { EvtxLevel, EvtxRecord } from "./types";

/** The legend lists the levels from the most severe down. */
const LEGEND_ORDER: readonly EvtxLevel[] = [...HISTOGRAM_STACK_ORDER].reverse();

const FORCED_COLORS = "@media (forced-colors: active)";
const FORCED_COLORS_QUERY = "(forced-colors: active)";
const COLOR_SCHEME_QUERY = "(prefers-color-scheme: dark)";

/** The help text of spec 8.9, with "drag to zoom" corrected: the lanes do not rescale, the drag selects a range. */
export const SWIMLANE_HELP_TEXT =
  "each dot is one event · larger = more severe · drag to select a time range";

/** The label block of a lane: 172 px of text and 8 px of padding (spec 8.9). */
const LABEL_TEXT_WIDTH_PX = 172;
const LABEL_PAD_PX = 8;
export const LABEL_WIDTH_PX = LABEL_TEXT_WIDTH_PX + LABEL_PAD_PX;

/**
 * A press that moves this far across the plot (CSS pixels) is a brush; one that moves less is a
 * click. A click selects the dot under it and never sets or clears the time range: the histogram's
 * click toggles a bucket, but here a click is aimed at a dot, and a hand's jitter must not be able
 * to turn it into a range.
 */
export const DRAG_THRESHOLD_PX = 3;

const BRUSH_KEYS: readonly string[] = ["ArrowLeft", "ArrowRight", "Home", "End"];

/** The space a lane view without lanes (loading, empty) keeps, so the message has somewhere to be. */
const MESSAGE_MIN_HEIGHT_PX = 56;

const TEXT_COLOR = tokens.colorNeutralForeground2;

const useStyles = makeStyles({
  root: {
    margin: 0,
    flex: "1 1 auto",
    minHeight: 0,
    display: "flex",
    flexDirection: "column",
    boxSizing: "border-box",
    padding: "6px 12px 6px",
    overflow: "hidden",
    position: "relative",
    backgroundColor: tokens.colorNeutralBackground1,
  },
  header: {
    flexShrink: 0,
    display: "flex",
    flexWrap: "wrap",
    alignItems: "center",
    columnGap: "14px",
    rowGap: "4px",
    paddingBottom: "6px",
  },
  legend: {
    display: "flex",
    flexWrap: "wrap",
    alignItems: "center",
    columnGap: "10px",
    margin: 0,
    padding: 0,
    listStyleType: "none",
  },
  legendItem: { display: "flex", alignItems: "center", columnGap: "5px", whiteSpace: "nowrap" },
  // A mark's glyph in the legend: sized and shaped from the same table the canvas draws from. Under
  // forced colors it keeps its level colour, in a CanvasText ring, as the histogram's swatches do.
  swatch: {
    flexShrink: 0,
    display: "inline-block",
    boxSizing: "border-box",
    [FORCED_COLORS]: {
      forcedColorAdjust: "none",
      outlineStyle: "solid",
      outlineWidth: "1px",
      outlineColor: "CanvasText",
    },
  },
  lanesControl: { display: "flex", alignItems: "center", columnGap: "6px", marginLeft: "auto" },
  scroller: { flex: "1 1 auto", minHeight: 0, overflowX: "hidden", overflowY: "auto" },
  stack: { display: "flex", alignItems: "flex-start" },
  labels: { flexShrink: 0, margin: 0, padding: 0, listStyleType: "none", width: `${LABEL_WIDTH_PX}px` },
  label: {
    boxSizing: "border-box",
    display: "flex",
    flexDirection: "column",
    justifyContent: "center",
    paddingRight: `${LABEL_PAD_PX}px`,
    borderBottom: `1px solid ${tokens.colorNeutralStroke3}`,
    overflow: "hidden",
  },
  text: { whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" },
  plotArea: {
    flex: "1 1 auto",
    minWidth: 0,
    boxSizing: "border-box",
    padding: `0 ${PLOT_INSET_PX}px`,
  },
  plotBox: { position: "relative" },
  plot: {
    position: "relative",
    outlineStyle: "none",
    touchAction: "none",
    userSelect: "none",
    ":focus-visible": {
      outlineStyle: "solid",
      outlineWidth: "2px",
      outlineColor: tokens.colorStrokeFocus2,
      outlineOffset: "1px",
    },
  },
  interactive: { cursor: "crosshair" },
  overDot: { cursor: "pointer" },
  // One tooltip for the plot, for the pointer, drawn here rather than with Fluent's Tooltip: that
  // component handles Escape on the document and marks it handled, which would stop the workspace's
  // Escape from clearing the time range whenever a tooltip was showing.
  tooltip: {
    position: "absolute",
    zIndex: 10,
    pointerEvents: "none",
    whiteSpace: "nowrap",
    padding: "4px 8px",
    borderRadius: tokens.borderRadiusMedium,
    color: tokens.colorNeutralForeground1,
    backgroundColor: tokens.colorNeutralBackground1,
    border: `1px solid ${tokens.colorNeutralStroke1}`,
    boxShadow: tokens.shadow8,
    fontFamily: tokens.fontFamilyNumeric,
    fontVariantNumeric: "tabular-nums",
  },
  layer: { position: "absolute", top: 0, right: 0, bottom: 0, left: 0 },
  // Under forced colors the surface is forced to Canvas but the marks keep their own colours, so the
  // wash's 3:1 proof (made on the theme's surface) no longer holds. The wash is dropped there and the
  // edge borders, whose colour is forced to a system colour, carry the range.
  wash: {
    pointerEvents: "none",
    [FORCED_COLORS]: { display: "none" },
  },
  canvas: { position: "absolute", top: 0, display: "block", pointerEvents: "none" },
  message: { display: "flex", alignItems: "center", justifyContent: "center" },
  axisRow: { flexShrink: 0, display: "flex", alignItems: "flex-start" },
  zone: {
    flexShrink: 0,
    boxSizing: "border-box",
    width: `${LABEL_WIDTH_PX}px`,
    paddingRight: `${LABEL_PAD_PX}px`,
    textAlign: "right",
    whiteSpace: "nowrap",
    fontFamily: tokens.fontFamilyNumeric,
    fontVariantNumeric: "tabular-nums",
  },
  axis: { position: "relative" },
  tick: {
    position: "absolute",
    top: 0,
    whiteSpace: "nowrap",
    fontFamily: tokens.fontFamilyNumeric,
    fontVariantNumeric: "tabular-nums",
  },
  notes: { margin: "2px 0 0", flexShrink: 0 },
  visuallyHidden: {
    position: "absolute",
    width: "1px",
    height: "1px",
    overflow: "hidden",
    clipPath: "inset(50%)",
    whiteSpace: "nowrap",
  },
});

/** Whether a media query holds, kept current. False where `matchMedia` does not exist. */
function useMediaMatch(query: string): boolean {
  const read = () => (typeof window.matchMedia === "function" ? window.matchMedia(query).matches : false);
  const [matches, setMatches] = useState(read);
  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const list = window.matchMedia(query);
    const onChange = () => setMatches(list.matches);
    onChange();
    list.addEventListener?.("change", onChange);
    return () => list.removeEventListener?.("change", onChange);
  }, [query]);
  return matches;
}

/**
 * Device pixels per CSS pixel, kept current. It changes when the window moves to another screen or
 * the page is zoomed, and neither reflows the plot, so a resize observer cannot see it: the
 * resolution media query for the current ratio fires when it stops matching, and is then re-armed
 * for the new one. A window resize covers browsers that zoom without firing the query.
 */
function useDevicePixelRatio(): number {
  const read = () => window.devicePixelRatio || 1;
  const [dpr, setDpr] = useState(read);
  useEffect(() => {
    let list: MediaQueryList | null = null;
    const arm = () => {
      list?.removeEventListener?.("change", onChange);
      list =
        typeof window.matchMedia === "function"
          ? window.matchMedia(`(resolution: ${read()}dppx)`)
          : null;
      list?.addEventListener?.("change", onChange);
    };
    const onChange = () => {
      setDpr(read());
      arm();
    };
    arm();
    const onResize = () => setDpr(read());
    window.addEventListener("resize", onResize);
    return () => {
      list?.removeEventListener?.("change", onChange);
      window.removeEventListener("resize", onResize);
    };
  }, []);
  return dpr;
}

/**
 * The colour CanvasText resolves to here, read from a probe element's computed colour. A canvas is
 * not recoloured by forced colors, so its marks need the resolved system colour passed in.
 */
function resolveCanvasText(host: HTMLElement): string {
  const probe = document.createElement("span");
  probe.setAttribute("aria-hidden", "true");
  probe.dataset.evtxProbe = "canvas-text";
  probe.style.color = "CanvasText";
  probe.style.display = "none";
  host.appendChild(probe);
  const resolved = window.getComputedStyle(probe).color;
  host.removeChild(probe);
  return resolved || "CanvasText";
}

interface LegendProps {
  swatchClass: string;
  itemClass: string;
  listClass: string;
  colors: Readonly<Record<EvtxLevel, string>>;
  fontSize: number;
}

/** The legend: each level's mark as the canvas draws it (shape, size, opacity), from `DOT_MARKS`. */
const Legend = memo(function Legend({ swatchClass, itemClass, listClass, colors, fontSize }: LegendProps) {
  return (
    <ul aria-label="Levels" className={listClass} style={{ fontSize: `${fontSize}px`, color: TEXT_COLOR }}>
      {LEGEND_ORDER.map((level) => {
        const mark = DOT_MARKS[level];
        const color = colors[level];
        return (
          <li key={level} className={itemClass} data-evtx-legend-level={level}>
            <span
              aria-hidden="true"
              className={swatchClass}
              data-evtx-legend-shape={mark.shape}
              style={{
                width: `${mark.size}px`,
                height: `${mark.size}px`,
                opacity: mark.opacity,
                borderRadius: "50%",
                backgroundColor: mark.shape === "ring" ? "transparent" : color,
                border: mark.shape === "ring" ? `${mark.strokePx}px solid ${color}` : undefined,
              }}
            />
            {HISTOGRAM_LEVEL_LABELS[level]}
          </li>
        );
      })}
    </ul>
  );
});

interface EvtxSwimlaneViewProps {
  /**
   * The events the filters leave on screen, WITHOUT the time range (spec 8.5): the context a brush
   * selects from. Empty while a load runs.
   */
  records: readonly EvtxRecord[];
  /** A load is running: the records are being replaced and nothing can be said about them. */
  loading: boolean;
}

/** A ring around a dot: centred on a point of the plot, in a border that is a token. */
function ringStyle(left: string, top: number, size: number, border: string): CSSProperties {
  return {
    position: "absolute",
    left,
    top: `${top}px`,
    width: `${size}px`,
    height: `${size}px`,
    boxSizing: "border-box",
    transform: "translate(-50%, -50%)",
    borderRadius: "50%",
    border,
    pointerEvents: "none",
  };
}

/**
 * Where the tooltip sits against its dot: centred above it, tucked to the side near either end of
 * the plot so it stays inside, and below the dot in the first lane where there is no room above.
 */
function tooltipTransform(tip: DotHit, plotWidth: number, laneHeight: number): string {
  const fraction = plotWidth > 0 ? (tip.x - PLOT_INSET_PX) / plotWidth : 0.5;
  const horizontal =
    fraction < 0.15 ? "translateX(-10px)" : fraction > 0.85 ? "translateX(calc(-100% + 10px))" : "translateX(-50%)";
  const vertical = tip.y < laneHeight ? "translateY(12px)" : "translateY(calc(-100% - 12px))";
  return `${horizontal} ${vertical}`;
}

const EMPTY_FIELD_SCENE = (field: SwimlaneField): SwimlaneScene => buildSwimlanes([], field, "utc");

export function EvtxSwimlaneView({ records, loading }: EvtxSwimlaneViewProps) {
  const styles = useStyles();
  const visual = useEvtxVisualTokens();
  const listFontSize = useUiStore((s) => s.logListFontSize);
  const themeId = useUiStore((s) => s.themeId);
  const metrics = useMemo(() => getLogListMetrics(listFontSize), [listFontSize]);
  const timeZoneMode = useEvtxStore((s) => s.timeZoneMode);
  const legacyGaps = useEvtxStore((s) => s.coverageGaps);
  const structuredGaps = useEvtxStore((s) => s.coverageDetails);
  const tailGaps = useEvtxStore((s) => s.tailCoverageGaps);
  const timeRange = useEvtxStore((s) => s.timeRange);

  // Component state, so it resets when the view is left (a view that is not kept alive unmounts):
  // spec 9 persists the view, panels, rail tab and sizes, and not this choice.
  const [field, setField] = useState<SwimlaneField>("provider");

  // Published at most once per 75 ms (spec section 11), so a live tail does not rebuild per batch.
  const shown = useThrottledValue(records, DERIVATION_THROTTLE_MS);
  // Until the throttled set catches up with an arrival, an empty `shown` is not "no events".
  const catchingUp = shown !== records && shown.length === 0;
  const scene = useMemo(() => buildSwimlanes(shown, field, timeZoneMode), [shown, field, timeZoneMode]);
  const ready = !loading && !catchingUp && scene.axis.domain !== null;
  // The scene a gesture started on. A live tail can regrid the axis, and the top 12 lanes can
  // reorder, under a pointer or a pending keyboard selection; the gesture keeps the whole scene it
  // began with (axis, lanes and their order) and commits that axis's edges.
  const [frozen, setFrozen] = useState<SwimlaneScene | null>(null);
  const view = frozen ?? scene;

  const theme = useMemo(() => getThemeById(themeId), [themeId]);
  // Resolved again whenever the theme changes, with no reload and no remount: the canvas repaints.
  const colors = useMemo(() => swimlaneColors(theme), [theme]);
  // How opaque the wash over the brushed range is: the histogram's, from its solver, unchanged, so
  // the two figures show one wash and every non-exempt dot keeps 3:1 on it.
  const washOpacity = useMemo(() => solveBrushOpacity(brushPaletteFor(theme)), [theme]);
  const gapCount = useMemo(
    () => countCoverageGapMessages(legacyGaps, tailGaps, structuredGaps),
    [legacyGaps, tailGaps, structuredGaps],
  );

  const fontSize = metrics.fontSize;
  const laneHeight = laneHeightFor(fontSize);
  const { namePx, countPx } = laneLabelFonts(fontSize);
  const { nameLine, countLine } = laneLabelLineHeights(fontSize);
  const axisPx = Math.max(9, fontSize - 4);
  const smallPx = Math.max(10, fontSize - 3);
  const axisHeight = Math.max(16, Math.round(axisPx * 1.5));
  const captionLine = Math.round(smallPx * 1.4);
  const ticks = useMemo(() => buildAxisTicks(view.axis, timeZoneMode), [view, timeZoneMode]);

  const plotRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [plotWidth, setPlotWidth] = useState(0);
  const dpr = useDevicePixelRatio();
  const forced = useMediaMatch(FORCED_COLORS_QUERY);
  // Switching from one contrast theme to another keeps forced colors on and flips the system colours
  // (Canvas, CanvasText) with the colour scheme, and nothing else this view reads changes. The scheme
  // query says so, so the marks are painted again, with the new ring colour. Unused otherwise.
  const prefersDark = useMediaMatch(COLOR_SCHEME_QUERY);
  const schemeWhileForced = forced ? prefersDark : null;

  useLayoutEffect(() => {
    const plot = plotRef.current;
    if (plot === null) return;
    const measure = () => setPlotWidth(Math.round(plot.getBoundingClientRect().width));
    measure();
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(measure);
    observer.observe(plot);
    return () => observer.disconnect();
  }, []);

  const plan = useMemo(
    () => (ready && plotWidth > 0 ? planPaint(view, { plotWidth, laneHeight, dpr }) : null),
    [ready, view, plotWidth, laneHeight, dpr],
  );
  useLayoutEffect(() => {
    const canvas = canvasRef.current;
    if (canvas === null || plan === null) return;
    canvas.width = Math.round(plan.width * plan.dpr);
    canvas.height = Math.round(plan.height * plan.dpr);
    const context = canvas.getContext("2d");
    if (context === null) return;
    // Read from the probe on every paint while forced colors are active (it is one element and one
    // computed style): a canvas is not recoloured with the page, so a ring colour kept from an earlier
    // paint would outlive a change of contrast theme.
    const ring = forced ? resolveCanvasText(canvas.parentElement ?? canvas) : null;
    paintSwimlanes(context, plan, colors, ring);
  }, [plan, colors, forced, schemeWhileForced]);

  const setTimeRange = useEvtxStore((s) => s.setTimeRange);
  const selectedRecordId = useEvtxStore((s) => s.selectedRecordId);
  const storeRecords = useEvtxStore((s) => s.records);
  const descriptionId = useId();
  const [hover, setHover] = useState<DotHit | null>(null);
  const [focused, setFocused] = useState(false);
  // Whether the plot is being used from the keyboard: set by Tab focus or a key, cleared by a press.
  // The cursor line in the caption is for the keyboard; a pointer press focuses the plot too, and
  // must not show it.
  const [keyboardMode, setKeyboardMode] = useState(false);
  const pressRef = useRef(false);
  // A press that is not yet known to be a click or a brush: where it started.
  const gestureRef = useRef<{ startX: number } | null>(null);
  const [keys, setKeys] = useState<BrushKeyState | null>(null);
  const [drag, setDrag] = useState<{ anchor: number; current: number } | null>(null);
  // The lane the keyboard cursor is on, held by its lane id: a live tail re-ranks the top 12, and a
  // cursor held by position would slide onto whichever lane takes its row. `index` is where it was
  // last seen, and is used only when its lane is gone.
  const [cursorLane, setCursorLane] = useState<{ id: string | null; index: number }>({ id: null, index: 0 });

  // When a load begins (or the first events of the next set are still arriving), whatever a gesture
  // held belongs to the set that is going away: the scene it froze, the drag, the anchor, the
  // cursor. They are dropped, and derived again from the new scene once it is ready. A new lane
  // field starts over for the same reason. Done while rendering, so no frame draws the old scene
  // under the new state.
  const busy = loading || catchingUp;
  const [wasBusy, setWasBusy] = useState(busy);
  const [seenField, setSeenField] = useState(field);
  if (busy !== wasBusy || field !== seenField) {
    setWasBusy(busy);
    setSeenField(field);
    if (busy || field !== seenField) {
      setDrag(null);
      setFrozen(null);
      setKeys(null);
      setHover(null);
      if (field !== seenField) setCursorLane({ id: null, index: 0 });
    }
  }

  const count = view.axis.buckets.length;
  const laneCount = view.lanes.length;
  const appliedSpan = ready && timeRange !== null ? spanOfRange(view.axis, timeRange) : null;
  const appliedOnPlot = ready && timeRange !== null ? rangeOnPlot(view.axis, timeRange) : null;
  const key = keys === null ? null : clampBrushState(keys, count);
  const draft = drag !== null ? spanOfIndices(drag.anchor, drag.current) : key === null ? null : draftSpan(key);
  const draftOnPlot = ready && draft !== null ? rangeOnPlot(view.axis, rangeOfSpan(view.axis, draft)) : null;
  // A gesture in progress shows its draft alone: the wash over an applied range as well would be
  // twice as opaque as the opacity that was solved.
  const shownRange = draftOnPlot ?? appliedOnPlot;
  const cursor = key?.cursor ?? initialBrushCursor(count, appliedSpan);
  const laneIndex = (() => {
    const held = cursorLane.id === null ? -1 : view.lanes.findIndex((candidate) => candidate.id === cursorLane.id);
    return held >= 0 ? held : Math.min(Math.max(0, laneCount - 1), cursorLane.index);
  })();
  // Bind the cursor to the lane it is on (and note where that is), so that from here on a re-rank
  // moves the cursor with its lane and not onto another one.
  useEffect(() => {
    const row = view.lanes[laneIndex];
    if (row === undefined) return;
    if (cursorLane.id !== row.id || cursorLane.index !== laneIndex) setCursorLane({ id: row.id, index: laneIndex });
  }, [view, laneIndex, cursorLane]);
  // Only a record of the store's current set is rung: a scene is published up to one throttle window
  // late, and after a reload inside it holds the previous set's objects, whose ids are other events'.
  const selectedAt = useMemo(
    () => (ready ? findRecordInScene(view, selectedRecordId, storeRecords) : null),
    [ready, view, selectedRecordId, storeRecords],
  );
  // The lane stack scrolls, and the keyboard cursor can move to a lane that is out of view: bring it in.
  useEffect(() => {
    if (!ready || !focused || !keyboardMode) return;
    const scroller = plotRef.current?.closest<HTMLElement>("[data-evtx-swimlane-scroller]");
    if (!scroller || scroller.clientHeight <= 0) return;
    const top = laneIndex * laneHeight;
    const bottom = top + laneHeight;
    if (top < scroller.scrollTop) scroller.scrollTop = top;
    else if (bottom > scroller.scrollTop + scroller.clientHeight) scroller.scrollTop = bottom - scroller.clientHeight;
  }, [ready, focused, keyboardMode, laneIndex, laneHeight]);

  const notes: string[] = [];
  if (!loading && !catchingUp) {
    if (scene.untimed > 0) notes.push(describeUntimed(scene.untimed));
    if (gapCount > 0) notes.push(describeCoverage(gapCount));
    if (ready && timeRange !== null && appliedOnPlot === null) notes.push(RANGE_OUTSIDE_NOTE);
  }
  const message =
    loading || catchingUp
      ? "Loading events..."
      : scene.axis.domain === null
        ? shown.length === 0
          ? "No events to chart."
          : "No timestamped events to chart."
        : null;

  const zone = ready && scene.axis.domain !== null ? timeZoneLabel(timeZoneMode, scene.axis.domain.startMs) : "";
  const legendColors = useMemo(
    () =>
      Object.fromEntries(HISTOGRAM_STACK_ORDER.map((level) => [level, visual.levels[level].dotColor])) as Record<
        EvtxLevel,
        string
      >,
    [visual],
  );
  const noun = SWIMLANE_FIELD_NOUNS[field];
  const stackHeight = ready ? view.lanes.length * laneHeight : MESSAGE_MIN_HEIGHT_PX;

  /** The pointer on the plot, in the plot's own pixels, or null if the plot has no size. */
  const plotPoint = (event: { clientX: number; clientY: number }) => {
    const rect = plotRef.current?.getBoundingClientRect();
    if (!rect || rect.width <= 0) return null;
    return { width: rect.width, x: event.clientX - rect.left, y: event.clientY - rect.top };
  };
  const indexAt = (event: { clientX: number; clientY: number }): number => {
    const point = plotPoint(event);
    return point === null ? 0 : bucketIndexFromFraction(point.x / point.width, count);
  };
  /** The dot a click here would select. */
  const hitAt = (event: { clientX: number; clientY: number }): DotHit | null => {
    const point = plotPoint(event);
    if (point === null) return null;
    // The width the canvas was drawn on (`plotWidth` is the rounded measure), not the sub-pixel one:
    // on a fractional layout the two differ by up to half a pixel at the far end of the plot.
    return hitTest(view, { plotWidth: Math.round(point.width), laneHeight }, point.x + PLOT_INSET_PX, point.y);
  };
  const endGesture = () => {
    setDrag(null);
    setFrozen(null);
  };

  const onPointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    // Any press, ready or not: the focus it causes is the pointer's, not the keyboard's, and the
    // browser focuses the plot itself while it is not ready (a disabled slider still has a tab stop).
    // onFocus reads `pressRef`; a press, a cancel, leaving the plot or a blur ends it.
    setKeyboardMode(false);
    pressRef.current = true;
    // Primary button only: a right-click opens the context menu and must not arm a gesture.
    if (!ready || event.button !== 0 || !event.isPrimary) return;
    event.preventDefault();
    event.currentTarget.setPointerCapture?.(event.pointerId);
    // Not a brush yet: it becomes one when the pointer moves `DRAG_THRESHOLD_PX`, else it is a click.
    // Either way it is aimed at the scene on screen now, so that scene is held until the release:
    // a live tail can regrid the axis or reorder the lanes in between.
    gestureRef.current = { startX: event.clientX };
    setFrozen(view);
    event.currentTarget.focus({ preventScroll: true });
  };

  const onPointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!ready) return;
    const press = gestureRef.current;
    if (drag === null && press !== null) {
      // The button was released outside the page or the capture was lost: no gesture.
      if (event.buttons === 0) {
        gestureRef.current = null;
        if (key === null || key.anchor === null) setFrozen(null);
        return;
      }
      if (Math.abs(event.clientX - press.startX) < DRAG_THRESHOLD_PX) return;
      // The press became a brush, from the bucket it started on, in the scene it was aimed at.
      gestureRef.current = null;
      const anchor = indexAt({ clientX: press.startX, clientY: event.clientY });
      const current = indexAt(event);
      setHover(null);
      setDrag({ anchor, current });
      setKeys({ cursor: current, anchor: null });
      return;
    }
    if (drag !== null) {
      if (event.buttons === 0) {
        endGesture();
        return;
      }
      const index = indexAt(event);
      if (index !== drag.current) setDrag({ ...drag, current: index });
      return;
    }
    const hit = hitAt(event);
    setHover((previous) =>
      previous?.lane === hit?.lane && previous?.dot === hit?.dot && previous?.more === hit?.more ? previous : hit,
    );
  };

  const onPointerUp = (event: ReactPointerEvent<HTMLDivElement>) => {
    pressRef.current = false;
    const press = gestureRef.current;
    gestureRef.current = null;
    event.currentTarget.releasePointerCapture?.(event.pointerId);
    if (drag !== null) {
      const index = indexAt(event);
      const span = spanOfIndices(drag.anchor, index);
      const axis = view.axis;
      endGesture();
      setKeys({ cursor: index, anchor: null });
      // Whole buckets of the axis the drag began on: the histogram's own commit.
      setTimeRange(rangeAfterActivate(axis, timeRange, span));
      return;
    }
    // The scene is held for a pending keyboard selection, which froze it first, and let go otherwise.
    if (key === null || key.anchor === null) setFrozen(null);
    if (press === null || !ready) return;
    // A click: it selects the dot under it, if any, and never touches the time range. The id is
    // read now, from the record the lane holds: the store renumbers ids in place on every merge.
    const hit = hitAt(event);
    if (hit === null) return;
    // A stale scene (a reload finished inside the throttle window) selects nothing: its ids are the
    // new set's indexes, so selecting by one would open an event the user did not click.
    if (!isCurrentRecord(hit.record, useEvtxStore.getState().records)) return;
    selectRecordAndShowDetails(hit.record.id);
    setCursorLane({ id: view.lanes[hit.lane].id, index: hit.lane });
  };

  const onKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    if (!ready || event.ctrlKey || event.metaKey || event.altKey) return;
    setKeyboardMode(true);
    if (event.key === "Escape") {
      // A pending selection is cancelled and the key is spent, so the workspace's Escape (which
      // clears the applied range) steps aside. With nothing pending the key passes up to it.
      if (drag !== null || (key !== null && key.anchor !== null)) {
        event.preventDefault();
        endGesture();
        setKeys(key === null ? null : { cursor: key.cursor, anchor: null });
      }
      return;
    }
    if (drag !== null) return;
    if (event.key === "Enter") {
      event.preventDefault();
      const state = key ?? { cursor, anchor: null };
      const span = spanToApply(state);
      const axis = view.axis;
      endGesture();
      setKeys({ cursor: state.cursor, anchor: null });
      setTimeRange(rangeAfterActivate(axis, timeRange, span));
      return;
    }
    if (event.key === "ArrowUp" || event.key === "ArrowDown") {
      event.preventDefault();
      const next = Math.min(Math.max(0, laneCount - 1), Math.max(0, laneIndex + (event.key === "ArrowDown" ? 1 : -1)));
      setCursorLane({ id: view.lanes[next]?.id ?? null, index: next });
      return;
    }
    if (event.key === " ") {
      // The keyboard's click: the most severe event in the cell under the cursor, in Details.
      event.preventDefault();
      const row = view.lanes[laneIndex];
      const bucket = view.axis.buckets[cursor];
      const record = row && bucket ? topEventInCell(row, bucket.startMs, bucket.endMs) : null;
      if (record !== null && isCurrentRecord(record, useEvtxStore.getState().records)) {
        selectRecordAndShowDetails(record.id);
      }
      return;
    }
    if (BRUSH_KEYS.includes(event.key)) {
      event.preventDefault();
      const state = key ?? { cursor, anchor: null };
      const next = reduceBrushKey(state, event.key as BrushKey, event.shiftKey, count, appliedSpan);
      setKeys(next);
      if (next.anchor !== null && state.anchor === null) setFrozen(scene);
      if (next.anchor === null) setFrozen(null);
    }
  };

  // The floating tooltip is for the pointer only: at the keyboard cursor it would sit over the lanes
  // for as long as focus stays on the plot, and nothing dismisses it (Escape clears the range). The
  // cursor cell's text is shown inline in the caption line instead, which is persistent content, and
  // the slider's value text carries it for assistive technology.
  const tip = ready && drag === null ? hover : null;
  const cellLane = view.lanes[laneIndex] ?? null;
  const cellBucket = ready && cursor < count ? view.axis.buckets[cursor] : null;
  // Counted from the lane's dots, so it is kept while only the pointer moves.
  const cellText = useMemo(
    () =>
      cellLane !== null && cellBucket !== null
        ? describeLaneCell(cellLane, cellBucket.startMs, cellBucket.endMs, timeZoneMode, view.axis.showYear)
        : null,
    [cellLane, cellBucket, timeZoneMode, view.axis.showYear],
  );
  const cursorText = focused && keyboardMode ? cellText : null;
  const valueText = (() => {
    if (!ready || cellText === null) return undefined;
    if (draft !== null) {
      const range = rangeOfSpan(view.axis, draft);
      return `${cellText}, selecting ${formatTimeRange(range.startMs, range.endMs, timeZoneMode, view.axis.showYear)}`;
    }
    if (timeRange !== null) {
      return `${cellText}, time range ${formatTimeRange(timeRange.startMs, timeRange.endMs, timeZoneMode, view.axis.showYear)} applied`;
    }
    return cellText;
  })();

  const edge = (fraction: number, dashed: boolean, side: string) => (
    <div
      key={side}
      aria-hidden="true"
      data-evtx-layer="edge"
      data-evtx-edge={side}
      style={{
        position: "absolute",
        top: 0,
        bottom: 0,
        left: `${fraction * 100}%`,
        marginLeft: "-1px",
        pointerEvents: "none",
        borderLeft: `2px ${dashed ? "dashed" : "solid"} ${tokens.colorNeutralStrokeAccessible}`,
      }}
    />
  );

  return (
    <figure
      data-evtx-region="swimlanes"
      className={styles.root}
      aria-label={describeSwimlaneFigure(ready ? scene : EMPTY_FIELD_SCENE(field), timeZoneMode)}
      aria-busy={loading || catchingUp}
    >
      <div className={styles.header}>
        <span
          data-evtx-swimlane-title
          style={{ fontSize: `${fontSize}px`, fontWeight: 600, color: tokens.colorNeutralForeground1 }}
        >
          {`Swimlanes by ${noun}`}
        </span>
        <span
          data-evtx-swimlane-help
          style={{ fontSize: `${Math.max(10, fontSize - 2)}px`, color: TEXT_COLOR }}
        >
          {SWIMLANE_HELP_TEXT}
        </span>
        <Legend
          swatchClass={styles.swatch}
          itemClass={styles.legendItem}
          listClass={styles.legend}
          colors={legendColors}
          fontSize={smallPx}
        />
        <span className={styles.lanesControl}>
          <span style={{ fontSize: `${Math.max(10, fontSize - 2)}px`, color: TEXT_COLOR }}>Lanes:</span>
          <Dropdown
            button={{ style: { fontSize: `${Math.max(11, fontSize - 1)}px` } }}
            size="small"
            aria-label="Lanes"
            value={SWIMLANE_FIELD_LABELS[field]}
            selectedOptions={[field]}
            style={{ minWidth: "112px" }}
            onOptionSelect={(_, data) => {
              const next = SWIMLANE_FIELDS.find((candidate) => candidate === data.optionValue);
              if (next !== undefined) setField(next);
            }}
          >
            {SWIMLANE_FIELDS.map((candidate) => (
              <Option
                key={candidate}
                value={candidate}
                text={SWIMLANE_FIELD_LABELS[candidate]}
                style={{ fontSize: `${Math.max(11, fontSize - 1)}px` }}
              >
                {SWIMLANE_FIELD_LABELS[candidate]}
              </Option>
            ))}
          </Dropdown>
        </span>
      </div>

      <div className={styles.scroller} data-evtx-swimlane-scroller>
        <div className={styles.stack}>
          {ready && (
            <ul aria-label="Lanes" className={styles.labels}>
              {view.lanes.map((lane, index) => (
                <li
                  key={lane.id}
                  className={styles.label}
                  data-evtx-lane={index}
                  style={{ height: `${laneHeight}px` }}
                  title={lane.isOther ? describeFoldedLanes(lane, field) : lane.label}
                >
                  <span
                    className={styles.text}
                    style={{
                      fontSize: `${namePx}px`,
                      lineHeight: `${nameLine}px`,
                      color: tokens.colorNeutralForeground1,
                    }}
                  >
                    {lane.label}
                  </span>
                  <span
                    className={styles.text}
                    data-evtx-lane-count
                    style={{
                      fontSize: `${countPx}px`,
                      lineHeight: `${countLine}px`,
                      color: TEXT_COLOR,
                      fontFamily: tokens.fontFamilyNumeric,
                      fontVariantNumeric: "tabular-nums",
                    }}
                  >
                    {describeLaneCount(lane.count)}
                  </span>
                  {lane.isOther && (
                    <span className={styles.visuallyHidden}>{describeFoldedLanes(lane, field)}</span>
                  )}
                </li>
              ))}
            </ul>
          )}
          <div className={styles.plotArea}>
            <div className={styles.plotBox}>
              <div
                ref={plotRef}
                className={mergeClasses(styles.plot, ready && styles.interactive, tip !== null && styles.overDot)}
                style={{ height: `${stackHeight}px` }}
                {...(ready
                  ? {
                      role: "slider",
                      tabIndex: 0,
                      "aria-label": "Time range, by lane",
                      "aria-orientation": "horizontal" as const,
                      "aria-valuemin": 0,
                      "aria-valuemax": count - 1,
                      "aria-valuenow": cursor,
                      "aria-valuetext": valueText,
                      "aria-describedby": descriptionId,
                      "aria-keyshortcuts":
                        "ArrowLeft ArrowRight ArrowUp ArrowDown Shift+ArrowLeft Shift+ArrowRight Home End Enter Space Escape",
                    }
                  : loading || catchingUp
                    ? // The same element stays focusable while a load runs, so focus is not thrown to the body
                      // and is where it was when the load ends; it just says it cannot be used now.
                      {
                        role: "slider",
                        tabIndex: 0,
                        "aria-label": "Time range, by lane",
                        "aria-orientation": "horizontal" as const,
                        "aria-disabled": true,
                        "aria-valuemin": 0,
                        "aria-valuemax": 0,
                        "aria-valuenow": 0,
                        "aria-valuetext": "Loading events",
                      }
                    : {})}
                onPointerDown={onPointerDown}
                onPointerMove={onPointerMove}
                onPointerUp={onPointerUp}
                onPointerCancel={() => {
                  pressRef.current = false;
                  gestureRef.current = null;
                  endGesture();
                }}
                onLostPointerCapture={() => {
                  if (drag !== null) {
                    endGesture();
                    return;
                  }
                  // A press the capture was taken from before its release: no click, and the scene it
                  // held is let go (unless a pending keyboard selection still needs it).
                  if (gestureRef.current !== null) {
                    gestureRef.current = null;
                    if (key === null || key.anchor === null) setFrozen(null);
                  }
                }}
                onPointerLeave={() => {
                  pressRef.current = false;
                  setHover(null);
                }}
                onKeyDown={onKeyDown}
                // The cursor is not stored on focus: with no keys held it is derived from the scene, so
                // focus that arrives during a load does not pin it to an empty chart's first bucket.
                onFocus={() => {
                  setFocused(true);
                  if (!pressRef.current) setKeyboardMode(true);
                }}
                onBlur={() => {
                  pressRef.current = false;
                  setFocused(false);
                  setKeyboardMode(false);
                  setKeys(null);
                  if (drag === null) setFrozen(null);
                }}
              >
                {ready && shownRange !== null && (
                  <div
                    aria-hidden="true"
                    data-evtx-layer="wash"
                    data-evtx-draft={draftOnPlot !== null}
                    className={mergeClasses(styles.layer, styles.wash)}
                    style={{
                      left: `${shownRange.left * 100}%`,
                      right: `${(1 - shownRange.right) * 100}%`,
                      backgroundColor: tokens.colorNeutralBackground1Selected,
                      opacity: washOpacity,
                    }}
                  />
                )}
                {ready && (
                  <canvas
                    ref={canvasRef}
                    aria-hidden="true"
                    data-evtx-layer="marks"
                    className={styles.canvas}
                    style={{
                      left: `-${PLOT_INSET_PX}px`,
                      width: `${canvasWidthFor(plotWidth)}px`,
                      height: `${stackHeight}px`,
                    }}
                  />
                )}
                {ready &&
                  shownRange !== null &&
                  !shownRange.clippedLeft &&
                  edge(shownRange.left, draftOnPlot !== null, "start")}
                {ready &&
                  shownRange !== null &&
                  !shownRange.clippedRight &&
                  edge(shownRange.right, draftOnPlot !== null, "end")}
                {selectedAt !== null && (
                  <div
                    aria-hidden="true"
                    data-evtx-layer="selected"
                    style={ringStyle(
                      `${view.lanes[selectedAt.lane].fractions[selectedAt.dot] * 100}%`,
                      selectedAt.lane * laneHeight + laneHeight / 2,
                      DOT_MARKS[HISTOGRAM_STACK_ORDER[view.lanes[selectedAt.lane].levels[selectedAt.dot]]].size + 6,
                      `2px solid ${visual.selection.foreground}`,
                    )}
                  />
                )}
                {tip !== null && (
                  <div
                    aria-hidden="true"
                    data-evtx-layer="hover"
                    style={ringStyle(
                      `${tip.x - PLOT_INSET_PX}px`,
                      tip.y,
                      DOT_MARKS[tip.level].size + 4,
                      `1px solid ${tokens.colorNeutralForeground1}`,
                    )}
                  />
                )}
                {ready && focused && cellBucket !== null && laneCount > 0 && (
                  <div
                    aria-hidden="true"
                    data-evtx-layer="cursor"
                    style={{
                      position: "absolute",
                      top: `${laneIndex * laneHeight}px`,
                      height: `${laneHeight}px`,
                      left: `${(cursor / count) * 100}%`,
                      width: `${100 / count}%`,
                      boxSizing: "border-box",
                      pointerEvents: "none",
                      outline: `2px solid ${tokens.colorNeutralForeground1}`,
                      outlineOffset: "-2px",
                    }}
                  />
                )}
                {tip !== null && (
                  <div
                    aria-hidden="true"
                    data-evtx-tooltip
                    className={styles.tooltip}
                    style={{
                      left: `${tip.x - PLOT_INSET_PX}px`,
                      top: `${tip.y}px`,
                      transform: tooltipTransform(tip, plotWidth, laneHeight),
                      fontSize: `${Math.max(10, fontSize - 2)}px`,
                    }}
                  >
                    {describeDot(tip.record, timeZoneMode, tip.more)}
                  </div>
                )}
              </div>
              {ready && (
                <span id={descriptionId} className={styles.visuallyHidden}>
                  Left and right arrow keys move between intervals, and up and down arrow keys move between
                  lanes. Hold Shift to select a range, or to move an end of the applied range from the interval
                  at that end. Home and End jump to the first and last interval. Enter applies the selection,
                  or clears the range when it is the one interval already applied. Space selects the most
                  severe event in the lane at that interval and shows it in Details. Escape cancels a pending
                  selection, then clears the time range. The Table view lists every event.
                </span>
              )}
              {message !== null && (
                <div
                  role="status"
                  className={mergeClasses(styles.layer, styles.message)}
                  style={{ fontSize: `${smallPx}px`, color: TEXT_COLOR, pointerEvents: "none" }}
                >
                  {message}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      <div
        aria-hidden="true"
        className={styles.axisRow}
        style={{ height: `${axisHeight}px`, fontSize: `${axisPx}px`, lineHeight: `${axisHeight}px`, color: TEXT_COLOR }}
      >
        <span className={styles.zone} data-evtx-zone>
          {zone}
        </span>
        <div className={styles.plotArea}>
          <div className={styles.axis}>
            {ready &&
              ticks.map((tick) => (
                <span
                  key={tick.edgeIndex}
                  className={styles.tick}
                  data-evtx-tick={tick.edgeIndex}
                  style={{
                    left: `${tick.fraction * 100}%`,
                    transform:
                      tick.fraction === 0
                        ? undefined
                        : tick.fraction === 1
                          ? "translateX(-100%)"
                          : "translateX(-50%)",
                  }}
                >
                  {tick.label}
                </span>
              ))}
          </div>
        </div>
      </div>

      {/* A slot that is always here, so focus and blur never change the figure's height. The notes
          take a line of their own above it; the cursor line fills it only for the keyboard. */}
      <figcaption className={styles.notes} style={{ fontSize: `${smallPx}px`, color: TEXT_COLOR }}>
        {notes.length > 0 && (
          <div data-evtx-notes style={{ lineHeight: `${captionLine}px` }}>
            {notes.join(" ")}
          </div>
        )}
        <div
          data-evtx-cursor-slot
          style={{
            height: `${captionLine}px`,
            lineHeight: `${captionLine}px`,
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
          }}
        >
          {cursorText !== null && (
            <span
              data-evtx-cursor-text={cursor}
              style={{ fontFamily: tokens.fontFamilyNumeric, fontVariantNumeric: "tabular-nums" }}
            >
              {cursorText}
            </span>
          )}
        </div>
      </figcaption>

      {ready && (
        <table className={styles.visuallyHidden}>
          <caption>{describeSwimlaneFigure(scene, timeZoneMode)}</caption>
          <thead>
            <tr>
              <th scope="col">{SWIMLANE_FIELD_LABELS[field]}</th>
              {LEGEND_ORDER.map((level) => (
                <th key={level} scope="col">
                  {HISTOGRAM_LEVEL_LABELS[level]}
                </th>
              ))}
              <th scope="col">Total</th>
            </tr>
          </thead>
          <tbody>
            {scene.lanes.map((lane) => (
              <tr key={lane.id}>
                <th scope="row">{lane.isOther ? `${lane.label}. ${describeFoldedLanes(lane, field)}` : lane.label}</th>
                {LEGEND_ORDER.map((level) => (
                  <td key={level}>{lane.levelCounts[level]}</td>
                ))}
                <td>{lane.count}</td>
              </tr>
            ))}
            {scene.untimed > 0 && (
              <tr>
                <th scope="row">Not charted: no timestamp</th>
                <td colSpan={LEGEND_ORDER.length} />
                <td>{scene.untimed}</td>
              </tr>
            )}
          </tbody>
        </table>
      )}
    </figure>
  );
}
