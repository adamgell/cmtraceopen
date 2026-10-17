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
import { memo, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";
import { Tooltip, makeStyles, mergeClasses, tokens } from "@fluentui/react-components";
import { getLogListMetrics } from "../../lib/log-accessibility";
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
  type EvtxHistogram as HistogramData,
} from "./evtx-histogram";
import { bucketIndexFromFraction } from "./evtx-histogram-brush";
import { useEvtxStore } from "./evtx-store";
import { timeZoneLabel } from "./evtx-time";
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
  const scale = useMemo(() => fitScale(histogram), [histogram]);
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
  const [hover, setHover] = useState<number | null>(null);

  const count = histogram.buckets.length;
  const ready = !loading && !catchingUp && histogram.domain !== null;
  const axisPx = Math.max(9, metrics.fontSize - 4);
  const smallPx = Math.max(10, metrics.fontSize - 3);
  const axisHeight = Math.max(16, Math.round(axisPx * 1.5));
  const ticks = useMemo(() => buildAxisTicks(histogram, timeZoneMode), [histogram, timeZoneMode]);

  const notes: string[] = [];
  if (!loading && !catchingUp) {
    if (histogram.untimed > 0) notes.push(describeUntimed(histogram.untimed));
    if (gapCount > 0) notes.push(describeCoverage(gapCount));
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

  const hovered = ready && hover !== null && hover < count ? histogram.buckets[hover] : null;
  const zone = histogram.domain === null ? null : timeZoneLabel(timeZoneMode, histogram.domain.startMs);

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
            className={styles.plot}
            onPointerMove={ready ? (event) => setHover(indexAt(event)) : undefined}
            onPointerLeave={() => setHover(null)}
          >
            {ready && (
              <Bars
                histogram={histogram}
                scale={scale}
                colors={colors}
                className={mergeClasses(styles.layer, styles.bars)}
                columnClass={styles.column}
                segmentClass={styles.segment}
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
            {hovered !== null && (
              <Tooltip
                visible
                relationship="description"
                positioning={{ position: "above", align: "center" }}
                content={{
                  children: (
                    <span aria-hidden="true" style={{ fontFamily: tokens.fontFamilyNumeric }}>
                      {describeBucket(hovered, timeZoneMode)}
                    </span>
                  ),
                }}
              >
                <span
                  aria-hidden="true"
                  data-evtx-tooltip-anchor={hover}
                  style={{
                    position: "absolute",
                    top: 0,
                    width: 1,
                    height: 1,
                    left: `${(((hover ?? 0) + 0.5) / count) * 100}%`,
                  }}
                />
              </Tooltip>
            )}
          </div>
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
