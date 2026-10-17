/**
 * The Event Logs histogram (spec section 8.5): events per interval over the loaded events, stacked
 * by level, under the chip row.
 *
 * It charts the records it is given, which the workspace builds with the time range left out, so
 * brushing never empties its own chart. The x axis is the extent of the timed records (see
 * `evtx-histogram.ts`), a count it cannot place is said so, and while a load runs it draws nothing
 * rather than an empty chart: unknown is never zero.
 *
 * Colors: level marks come from the token map; the rest are Fluent neutral tokens. Axis and legend
 * text use `colorNeutralForeground2`, not the spec's Foreground3 (spec 6.1, axis labels), which
 * measures 3.37:1 on the solarized-dark surface and 3.03:1 on dracula; text needs 4.5:1.
 */
import {
  memo,
  useId,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type PointerEvent as ReactPointerEvent,
} from "react";
import { makeStyles, mergeClasses, tokens } from "@fluentui/react-components";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { getThemeById } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
import { INSIGHTS_DEBOUNCE_MS, useThrottledValue } from "./EvtxInsightsRail";
import { formatCoverageGap } from "./evtx-coverage";
import {
  HISTOGRAM_BAR_AREA_PX,
  HISTOGRAM_LEVEL_LABELS,
  HISTOGRAM_STACK_ORDER,
  bucketSegments,
  buildAxisTicks,
  buildHistogram,
  describeBucket,
  describeCoverage,
  describeFigure,
  describeUntimed,
  fitScale,
  rangeOnPlot,
  type EvtxHistogram as HistogramData,
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
  type BucketSpan,
} from "./evtx-histogram-brush";
import { useEvtxStore } from "./evtx-store";
import { formatTimeRange, timeZoneLabel } from "./evtx-time";
import { useEvtxVisualTokens } from "./evtx-visual-tokens";
import type { EvtxLevel, EvtxRecord } from "./types";

/** The legend lists the levels from the top of a bar down. */
const LEGEND_ORDER: readonly EvtxLevel[] = [...HISTOGRAM_STACK_ORDER].reverse();

const FORCED_COLORS = "@media (forced-colors: active)";

/**
 * Deviates from spec 6.1 (axis labels `colorNeutralForeground3`): that is text, and it measures
 * 3.37:1 on the solarized-dark surface and 3.03:1 on dracula, under the 4.5:1 text needs. Axis
 * labels, legend text and notes use `colorNeutralForeground2` (at least 5.61:1 in every theme).
 */
const TEXT_COLOR = tokens.colorNeutralForeground2;

/** The note when the applied range lies wholly off the charted events (a filter shrank them). */
const RANGE_OUTSIDE_NOTE = "The time range is outside the charted events.";

const BRUSH_KEYS: readonly string[] = ["ArrowLeft", "ArrowRight", "Home", "End"];

/** The figure's name before anything is charted. */
const EMPTY_HISTOGRAM = buildHistogram([], "utc");

const useStyles = makeStyles({
  root: {
    margin: 0,
    position: "relative",
    flexShrink: 0,
    boxSizing: "border-box",
    padding: "0 12px 6px",
    backgroundColor: tokens.colorNeutralBackground1,
    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
  },
  row: { display: "flex", alignItems: "flex-start", columnGap: "8px" },
  main: { flex: "1 1 auto", minWidth: 0 },
  plot: {
    position: "relative",
    height: `${HISTOGRAM_BAR_AREA_PX}px`,
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
  // One tooltip for the plot, drawn here rather than with Fluent's Tooltip: that component handles
  // Escape on the document and marks it handled, which would stop the workspace's Escape from
  // clearing the time range whenever a tooltip was showing (on hover or at the keyboard cursor).
  tooltip: {
    position: "absolute",
    bottom: "calc(100% + 4px)",
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
  wash: {
    pointerEvents: "none",
    [FORCED_COLORS]: { forcedColorAdjust: "none" },
  },
  layer: { position: "absolute", top: 0, right: 0, bottom: 0, left: 0 },
  // The level colors carry the meaning, so forced colors must not repaint them.
  bars: {
    display: "flex",
    alignItems: "flex-end",
    [FORCED_COLORS]: { forcedColorAdjust: "none" },
  },
  column: {
    flex: "1 1 0",
    minWidth: 0,
    height: "100%",
    boxSizing: "border-box",
    padding: "0 0.5px",
    display: "flex",
    flexDirection: "column-reverse",
  },
  segment: {
    flexShrink: 0,
    boxSizing: "border-box",
    borderTop: `1px solid ${tokens.colorNeutralBackground1}`,
  },
  message: {
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
  },
  axis: { position: "relative" },
  tick: {
    position: "absolute",
    top: 0,
    whiteSpace: "nowrap",
    fontFamily: tokens.fontFamilyNumeric,
    fontVariantNumeric: "tabular-nums",
  },
  legend: {
    width: "84px",
    flexShrink: 0,
    boxSizing: "border-box",
    display: "flex",
    flexDirection: "column",
    justifyContent: "space-between",
    margin: 0,
    padding: 0,
    listStyleType: "none",
  },
  legendItem: { display: "flex", alignItems: "center", columnGap: "6px", whiteSpace: "nowrap" },
  swatch: {
    width: "8px",
    height: "8px",
    flexShrink: 0,
    borderRadius: "2px",
    [FORCED_COLORS]: { forcedColorAdjust: "none" },
  },
  zone: { fontFamily: tokens.fontFamilyNumeric, whiteSpace: "nowrap" },
  notes: { margin: "2px 0 0" },
  visuallyHidden: {
    position: "absolute",
    width: "1px",
    height: "1px",
    overflow: "hidden",
    clipPath: "inset(50%)",
    whiteSpace: "nowrap",
  },
});

interface BarsProps {
  histogram: HistogramData;
  scale: number;
  colors: Readonly<Record<EvtxLevel, string>>;
  className: string;
  columnClass: string;
  segmentClass: string;
}

/** The bars alone, so a pointer move over the plot does not rebuild them. */
const Bars = memo(function Bars({ histogram, scale, colors, className, columnClass, segmentClass }: BarsProps) {
  return (
    <div aria-hidden="true" data-evtx-layer="bars" className={className}>
      {histogram.buckets.map((bucket, index) => (
        <div key={bucket.startMs} data-evtx-bucket={index} className={columnClass}>
          {bucketSegments(bucket, scale).map((segment) => (
            <div
              key={segment.level}
              data-evtx-level={segment.level}
              className={segmentClass}
              style={{ height: `${segment.heightPx}px`, backgroundColor: colors[segment.level] }}
            />
          ))}
        </div>
      ))}
    </div>
  );
});

interface EvtxHistogramProps {
  /**
   * The events the filters leave on screen, WITHOUT the time range (spec 8.5): the context a brush
   * selects from. Empty while a load runs.
   */
  records: readonly EvtxRecord[];
  /** A load is running: the records are being replaced and nothing can be said about them. */
  loading: boolean;
}

export function EvtxHistogram({ records, loading }: EvtxHistogramProps) {
  const styles = useStyles();
  const visual = useEvtxVisualTokens();
  const listFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(listFontSize), [listFontSize]);
  const timeZoneMode = useEvtxStore((s) => s.timeZoneMode);
  const legacyGaps = useEvtxStore((s) => s.coverageGaps);
  const structuredGaps = useEvtxStore((s) => s.coverageDetails);
  const tailGaps = useEvtxStore((s) => s.tailCoverageGaps);

  // Published at most once per 75 ms (spec section 11), so a live tail does not rebucket per batch.
  const shown = useThrottledValue(records, INSIGHTS_DEBOUNCE_MS);
  // Until the throttled set catches up with an arrival, an empty `shown` is not "no events".
  const catchingUp = shown !== records && shown.length === 0;
  const histogram = useMemo(() => buildHistogram(shown, timeZoneMode), [shown, timeZoneMode]);
  const colors = useMemo(
    () =>
      Object.fromEntries(
        HISTOGRAM_STACK_ORDER.map((level) => [level, visual.levels[level].barColor]),
      ) as Record<EvtxLevel, string>,
    [visual],
  );
  const gapCount = useMemo(
    () => new Set([...legacyGaps, ...tailGaps, ...structuredGaps.map(formatCoverageGap)]).size,
    [legacyGaps, tailGaps, structuredGaps],
  );

  const plotRef = useRef<HTMLDivElement>(null);
  const descriptionId = useId();
  const timeRange = useEvtxStore((s) => s.timeRange);
  const setTimeRange = useEvtxStore((s) => s.setTimeRange);
  const themeId = useUiStore((s) => s.themeId);
  // How opaque the wash over the brushed buckets is: solved from the resolved tokens (see
  // `solveBrushOpacity`), so every bar keeps 3:1 on it in every theme.
  const washOpacity = useMemo(
    () => solveBrushOpacity(brushPaletteFor(getThemeById(themeId))),
    [themeId],
  );
  const [hover, setHover] = useState<number | null>(null);
  const [focused, setFocused] = useState(false);
  const [keys, setKeys] = useState<BrushKeyState | null>(null);
  const [drag, setDrag] = useState<{ anchor: number; current: number } | null>(null);
  // The buckets a gesture started on. A live tail can regrid the chart under a pointer or a pending
  // keyboard selection; the gesture keeps the buckets it began with and commits their edges.
  const [frozen, setFrozen] = useState<HistogramData | null>(null);

  const view = frozen ?? histogram;
  const count = view.buckets.length;
  const scale = useMemo(() => fitScale(view), [view]);
  const ready = !loading && !catchingUp && histogram.domain !== null;
  const axisPx = Math.max(9, metrics.fontSize - 4);
  const smallPx = Math.max(10, metrics.fontSize - 3);
  const axisHeight = Math.max(16, Math.round(axisPx * 1.5));
  const ticks = useMemo(() => buildAxisTicks(view, timeZoneMode), [view, timeZoneMode]);

  const appliedSpan = ready && timeRange !== null ? spanOfRange(view, timeRange) : null;
  const appliedOnPlot = ready && timeRange !== null ? rangeOnPlot(view, timeRange) : null;
  const key = keys === null ? null : clampBrushState(keys, count);
  const draft: BucketSpan | null =
    drag !== null ? spanOfIndices(drag.anchor, drag.current) : key === null ? null : draftSpan(key);
  const draftOnPlot = ready && draft !== null ? rangeOnPlot(view, rangeOfSpan(view, draft)) : null;
  // A gesture in progress shows its draft alone: the wash over an applied range as well would be
  // twice as opaque as the opacity that was solved.
  const shownRange = draftOnPlot ?? appliedOnPlot;
  const cursor = key?.cursor ?? initialBrushCursor(count, appliedSpan);

  const notes: string[] = [];
  if (!loading && !catchingUp) {
    if (histogram.untimed > 0) notes.push(describeUntimed(histogram.untimed));
    if (gapCount > 0) notes.push(describeCoverage(gapCount));
    if (ready && timeRange !== null && appliedOnPlot === null) notes.push(RANGE_OUTSIDE_NOTE);
  }

  const message = loading || catchingUp
    ? "Loading events..."
    : histogram.domain === null
      ? shown.length === 0
        ? "No events to chart."
        : "No timestamped events to chart."
      : null;

  const indexAt = (event: ReactPointerEvent<HTMLElement>): number => {
    const rect = plotRef.current?.getBoundingClientRect();
    if (!rect || rect.width <= 0) return 0;
    return bucketIndexFromFraction((event.clientX - rect.left) / rect.width, count);
  };

  const endGesture = () => {
    setDrag(null);
    setFrozen(null);
  };

  // Sets the range from whole buckets. The store refuses while a load runs; the overlay is drawn
  // from the store's range, so a refused commit leaves nothing drawn.
  const commit = (span: BucketSpan) => {
    setTimeRange(rangeAfterActivate(view, timeRange, span));
  };

  const onPointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    // Primary button only: a right-click opens the context menu and must not arm a drag.
    if (!ready || event.button !== 0 || !event.isPrimary) return;
    event.preventDefault();
    event.currentTarget.setPointerCapture?.(event.pointerId);
    const index = indexAt(event);
    setFrozen(histogram);
    setDrag({ anchor: index, current: index });
    setKeys({ cursor: index, anchor: null });
    event.currentTarget.focus({ preventScroll: true });
  };

  const onPointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!ready) return;
    const index = indexAt(event);
    setHover(index);
    if (drag === null) return;
    // The button was released outside the page or the capture was lost: stop rather than follow a
    // pointer that is no longer dragging.
    if (event.buttons === 0) {
      endGesture();
      return;
    }
    if (index !== drag.current) setDrag({ ...drag, current: index });
  };

  const onPointerUp = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (drag === null) return;
    const index = indexAt(event);
    event.currentTarget.releasePointerCapture?.(event.pointerId);
    const span = spanOfIndices(drag.anchor, index);
    endGesture();
    setKeys({ cursor: index, anchor: null });
    commit(span);
  };

  const onKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    if (!ready || event.ctrlKey || event.metaKey || event.altKey) return;
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
      endGesture();
      setKeys({ cursor: state.cursor, anchor: null });
      commit(span);
      return;
    }
    if (BRUSH_KEYS.includes(event.key)) {
      event.preventDefault();
      const state = key ?? { cursor, anchor: null };
      const next = reduceBrushKey(state, event.key as BrushKey, event.shiftKey, count, appliedSpan);
      setKeys(next);
      if (next.anchor !== null && state.anchor === null) setFrozen(histogram);
      if (next.anchor === null) setFrozen(null);
    }
  };

  const tipIndex = ready ? (hover ?? (focused && key !== null ? key.cursor : null)) : null;
  const hovered = tipIndex !== null && tipIndex < count ? view.buckets[tipIndex] : null;
  const zone = histogram.domain === null ? null : timeZoneLabel(timeZoneMode, histogram.domain.startMs);

  const valueText = (() => {
    if (!ready || cursor >= count) return undefined;
    const bucket = describeBucket(view.buckets[cursor], timeZoneMode);
    if (draft !== null) {
      const range = rangeOfSpan(view, draft);
      return `${bucket}, selecting ${formatTimeRange(range.startMs, range.endMs, timeZoneMode)}`;
    }
    if (timeRange !== null) {
      return `${bucket}, time range ${formatTimeRange(timeRange.startMs, timeRange.endMs, timeZoneMode)} applied`;
    }
    return bucket;
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
      data-evtx-region="histogram"
      className={styles.root}
      aria-label={describeFigure(ready ? histogram : EMPTY_HISTOGRAM, timeZoneMode)}
      aria-busy={loading || catchingUp}
    >
      <div className={styles.row}>
        <div className={styles.main}>
          <div
            ref={plotRef}
            className={mergeClasses(styles.plot, ready && styles.interactive)}
            {...(ready
              ? {
                  role: "slider",
                  tabIndex: 0,
                  "aria-label": "Time range",
                  "aria-orientation": "horizontal" as const,
                  "aria-valuemin": 0,
                  "aria-valuemax": count - 1,
                  "aria-valuenow": cursor,
                  "aria-valuetext": valueText,
                  "aria-describedby": descriptionId,
                  "aria-keyshortcuts": "ArrowLeft ArrowRight Shift+ArrowLeft Shift+ArrowRight Home End Enter Escape",
                }
              : {})}
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            onPointerCancel={endGesture}
            onLostPointerCapture={() => {
              if (drag !== null) endGesture();
            }}
            onPointerLeave={() => setHover(null)}
            onKeyDown={onKeyDown}
            onFocus={() => {
              setFocused(true);
              setKeys((held) => held ?? { cursor: initialBrushCursor(count, appliedSpan), anchor: null });
            }}
            onBlur={() => {
              setFocused(false);
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
              <Bars
                histogram={view}
                scale={scale}
                colors={colors}
                className={mergeClasses(styles.layer, styles.bars)}
                columnClass={styles.column}
                segmentClass={styles.segment}
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
            {ready && focused && key !== null && cursor < count && (
              <div
                aria-hidden="true"
                data-evtx-layer="cursor"
                style={{
                  position: "absolute",
                  top: 0,
                  bottom: 0,
                  left: `${(cursor / count) * 100}%`,
                  width: `${100 / count}%`,
                  boxSizing: "border-box",
                  pointerEvents: "none",
                  outline: `2px solid ${tokens.colorNeutralForeground1}`,
                  outlineOffset: "-2px",
                }}
              />
            )}
            {message !== null && (
              <div
                role="status"
                className={mergeClasses(styles.layer, styles.message)}
                style={{ fontSize: `${smallPx}px`, color: TEXT_COLOR }}
              >
                {message}
              </div>
            )}
            {hovered !== null && tipIndex !== null && (
              <div
                aria-hidden="true"
                data-evtx-tooltip={tipIndex}
                className={styles.tooltip}
                style={{
                  left: `${((tipIndex + 0.5) / count) * 100}%`,
                  transform:
                    tipIndex / count < 0.15
                      ? "translateX(-10px)"
                      : tipIndex / count > 0.85
                        ? "translateX(calc(-100% + 10px))"
                        : "translateX(-50%)",
                  fontSize: `${Math.max(10, metrics.fontSize - 2)}px`,
                }}
              >
                {describeBucket(hovered, timeZoneMode)}
              </div>
            )}
          </div>
          {ready && (
            <span id={descriptionId} className={styles.visuallyHidden}>
              Left and right arrow keys move between intervals. Hold Shift to select a range, or to move
              an end of the applied range from the interval at that end. Home and End jump to the first
              and last interval. Enter applies the selection, or clears the range when it is the one
              interval already applied. Escape cancels a pending selection, then clears the time range.
            </span>
          )}
          <div
            aria-hidden="true"
            className={styles.axis}
            style={{
              height: `${axisHeight}px`,
              fontSize: `${axisPx}px`,
              lineHeight: `${axisHeight}px`,
              color: TEXT_COLOR,
            }}
          >
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
        <ul
          aria-label="Levels"
          className={styles.legend}
          style={{
            fontSize: `${smallPx}px`,
            lineHeight: 1.2,
            color: TEXT_COLOR,
            minHeight: `${HISTOGRAM_BAR_AREA_PX + axisHeight}px`,
          }}
        >
          {LEGEND_ORDER.map((level) => (
            <li key={level} className={styles.legendItem}>
              <span className={styles.swatch} style={{ backgroundColor: visual.levels[level].barColor }} />
              {HISTOGRAM_LEVEL_LABELS[level]}
            </li>
          ))}
          <li className={mergeClasses(styles.legendItem, styles.zone)}>{ready ? zone : ""}</li>
        </ul>
      </div>
      {notes.length > 0 && (
        <figcaption className={styles.notes} style={{ fontSize: `${smallPx}px`, color: TEXT_COLOR }}>
          {notes.join(" ")}
        </figcaption>
      )}
      {ready && (
        <table className={styles.visuallyHidden}>
          <caption>{describeFigure(histogram, timeZoneMode)}</caption>
          <thead>
            <tr>
              <th scope="col">Interval</th>
              {LEGEND_ORDER.map((level) => (
                <th key={level} scope="col">
                  {HISTOGRAM_LEVEL_LABELS[level]}
                </th>
              ))}
              <th scope="col">Total</th>
            </tr>
          </thead>
          <tbody>
            {histogram.buckets.map((bucket) => (
              <tr key={bucket.startMs}>
                <th scope="row">{describeBucket(bucket, timeZoneMode)}</th>
                {LEGEND_ORDER.map((level) => (
                  <td key={level}>{bucket.counts[level]}</td>
                ))}
                <td>{bucket.total}</td>
              </tr>
            ))}
            {histogram.untimed > 0 && (
              <tr>
                <th scope="row">Not charted: no timestamp</th>
                <td colSpan={LEGEND_ORDER.length} />
                <td>{histogram.untimed}</td>
              </tr>
            )}
          </tbody>
        </table>
      )}
    </figure>
  );
}
