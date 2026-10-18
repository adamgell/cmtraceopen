/**
 * The lane plot of the Correlation view (spec 8.11): one lane per source, a marker per entry, and
 * a connector per backed exact or candidate edge. Pure drawing: every decision (which entry is
 * pinned, which connector has evidence, which label a context marker may carry) is made by
 * `buildChainPlot`, and this component draws what it is given.
 *
 * Encoding, so that no meaning rides on color alone:
 * - strength: the line style and weight (solid 2.5 px for exact, dashed 1.5 px for candidate), the
 *   legend, and the "linked by" phrase in each marker's accessible name;
 * - level: the marker's accessible name and the Sequence list's icon and word; the fill is the
 *   level color;
 * - an entry outside the window: pinned at the edge, its fill at 55% opacity, its ring and label at
 *   full opacity (the fill alone is faded: the faded ring and label would miss 3:1 and 4.5:1 in most
 *   themes, spec 8.11 deviation recorded for ruling 15), with the arrow icon and how far outside it is;
 * - an entry that is not linked: a dotted outline, no fill, no connector.
 *
 * Keyboard: the markers are one tab stop (roving tabindex) in Sequence order. Left and Right move
 * between them, Home and End go to the ends, Enter and Space activate the focused one, and Escape
 * is handed to `onEscape` after `preventDefault`, so the workspace's Escape handler does not also
 * clear the time range.
 *
 * Two variants share all of the above. The `view` variant is the Correlation view's plot (spec 8.11).
 * The `dock` variant is the Correlation dock's (spec 8.12): 12 px glyphs in the same 24 px hit box,
 * a 170 px label column at max(10, f - 3), lanes 24 px tall with no label row under them, no height
 * cap (the dock caps the lanes at five instead), no per-marker text (the marker's accessible name
 * and tooltip carry it), and a 1 px rule at 50% of the track, which is the selected event's instant
 * because the dock's window is centered on it.
 *
 * Colors come from the visual tokens and the theme; text sizes from the log list font size.
 */
import { Fragment, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { createFocusOutlineStyle, makeStyles, tokens } from "@fluentui/react-components";
import { ArrowLeft12Regular, ArrowRight12Regular } from "@fluentui/react-icons";
import { CONNECTOR_STYLES, ConnectorSwatch, LegendItem, MarkerSwatch } from "./EvtxCorrelationLegendParts";
import { useRailTextColors } from "./evtx-rail-text";
import type { CorrelationSizes } from "./evtx-correlation-sizes";
import type { EvtxTimeZoneMode } from "./evtx-time";
import { tickLabels, type ChainPlot, type PlotConnector, type PlotLane, type PlotMarker } from "./evtx-correlation-view-model";
import { useEvtxVisualTokens, type EvtxVisualTokens } from "./evtx-visual-tokens";

/** Spec 8.11: markers are 14 px; the lane label column is 184 px. */
export const CORRELATION_MARKER_PX = 14;
export const CORRELATION_LANE_LABEL_PX = 184;
/** The clickable box around a marker: WCAG 2.5.8 asks for 24 px, the drawn marker stays 14. */
export const CORRELATION_MARKER_HIT_PX = 24;
/** Spec 8.11: the lane plot is 240 px tall. */
const CORRELATION_PLOT_HEIGHT_PX = 240;
/** Spec 8.12: the dock draws 12 px markers, a 170 px label column and 24 px lanes. */
const DOCK_MARKER_PX = 12;
const DOCK_LANE_LABEL_PX = 170;
/** Spec 8.11: a pinned entry's fill is drawn at 55% opacity. Only the fill. */
export const PINNED_FILL_OPACITY = 0.55;

const useStyles = makeStyles({
  marker: {
    position: "absolute",
    width: `${CORRELATION_MARKER_HIT_PX}px`,
    height: `${CORRELATION_MARKER_HIT_PX}px`,
    padding: 0,
    border: "none",
    backgroundColor: "transparent",
    cursor: "pointer",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    ...createFocusOutlineStyle({ style: { outlineRadius: "4px" } }),
  },
});

type CorrelationLanesVariant = "view" | "dock";

/** What differs between the two variants, so the drawing below reads one object. */
interface LaneGeometry {
  markerPx: number;
  labelColumnPx: number;
  laneHeight: number;
  /** The lane label's text size. */
  laneLabelSize: number;
  /** The figure's height cap, or null for none. */
  maxHeight: number | null;
  /** A text label under each marker. */
  markerLabels: boolean;
  /** A rule at the middle of the track. */
  centerRule: boolean;
}

function geometryFor(variant: CorrelationLanesVariant, sizes: CorrelationSizes): LaneGeometry {
  return variant === "dock"
    ? {
        markerPx: DOCK_MARKER_PX,
        labelColumnPx: DOCK_LANE_LABEL_PX,
        laneHeight: CORRELATION_MARKER_HIT_PX,
        laneLabelSize: sizes.label,
        maxHeight: null,
        markerLabels: false,
        centerRule: true,
      }
    : {
        markerPx: CORRELATION_MARKER_PX,
        labelColumnPx: CORRELATION_LANE_LABEL_PX,
        laneHeight: CORRELATION_MARKER_HIT_PX + sizes.label + 10,
        laneLabelSize: sizes.lane,
        maxHeight: CORRELATION_PLOT_HEIGHT_PX,
        markerLabels: true,
        centerRule: false,
      };
}

const pct = (x: number) => `${x * 100}%`;

/** The glyph inside a marker's box: the ring, the fill and (for a log line) the rounded square. */
function MarkerGlyph({
  marker,
  visuals,
  markerPx,
}: {
  marker: PlotMarker;
  visuals: EvtxVisualTokens;
  markerPx: number;
}) {
  const dot = visuals.levels[marker.level].dotColor;
  const radius = marker.kind === "event" ? "50%" : "3px";
  const size = `${markerPx}px`;
  if (marker.role === "nearby") {
    return (
      <span
        aria-hidden="true"
        style={{
          width: size,
          height: size,
          borderRadius: radius,
          boxSizing: "border-box",
          border: `1px ${visuals.strengths.notCausal.borderStyle} ${visuals.strengths.notCausal.border}`,
          backgroundColor: "transparent",
        }}
      />
    );
  }
  return (
    <span
      aria-hidden="true"
      style={{
        position: "relative",
        width: size,
        height: size,
        borderRadius: radius,
        backgroundColor: tokens.colorNeutralBackground1,
        // The 2 px ring in the surface color and the 1 px outer ring in the level color, both at
        // full opacity. Only the fill below is ever faded.
        boxShadow: `0 0 0 2px ${tokens.colorNeutralBackground1}, 0 0 0 3px ${dot}`,
      }}
    >
      <span
        data-marker-fill=""
        style={{
          position: "absolute",
          inset: 0,
          borderRadius: radius,
          backgroundColor: dot,
          opacity: marker.placement.pinned !== null ? PINNED_FILL_OPACITY : 1,
        }}
      />
    </span>
  );
}

/** Where a marker's label sits, in fractions of the track: it ends where its neighbour begins. */
function labelBox(
  marker: PlotMarker,
  ordered: readonly PlotMarker[],
): { left: number; width: number; rightAligned: boolean } {
  const index = ordered.findIndex((entry) => entry.id === marker.id);
  if (marker.placement.pinned === "after") {
    const previous = index > 0 ? ordered[index - 1]!.placement.x : 0;
    return { left: previous, width: Math.max(0, marker.placement.x - previous), rightAligned: true };
  }
  const next = index < ordered.length - 1 ? ordered[index + 1]!.placement.x : 1;
  return {
    left: marker.placement.x,
    width: Math.max(0, next - marker.placement.x),
    rightAligned: false,
  };
}

function MarkerLabel({
  marker,
  box,
  sizes,
  color,
}: {
  marker: PlotMarker;
  box: { left: number; width: number; rightAligned: boolean };
  sizes: CorrelationSizes;
  color: string;
}) {
  const pinned = marker.placement.pinned;
  const text = pinned !== null ? (marker.pinLabel ?? marker.entry) : marker.entry;
  return (
    <span
      aria-hidden="true"
      data-marker-label=""
      style={{
        position: "absolute",
        top: `${CORRELATION_MARKER_HIT_PX}px`,
        ...(box.rightAligned
          ? { right: pct(1 - (box.left + box.width)), textAlign: "right" }
          : { left: pct(box.left) }),
        width: pct(box.width),
        overflow: "hidden",
        whiteSpace: "nowrap",
        textOverflow: "ellipsis",
        fontSize: `${sizes.label}px`,
        lineHeight: `${sizes.label + 2}px`,
        color,
        fontFamily: tokens.fontFamilyNumeric,
      }}
    >
      {pinned === "before" && <ArrowLeft12Regular aria-hidden="true" style={{ verticalAlign: "middle" }} />}
      {pinned === "before" ? " " : ""}
      {text}
      {pinned === "after" ? " " : ""}
      {pinned === "after" && <ArrowRight12Regular aria-hidden="true" style={{ verticalAlign: "middle" }} />}
    </span>
  );
}

function ConnectorLine({
  connector,
  plot,
  laneIndexByKey,
  laneHeight,
  visuals,
}: {
  connector: PlotConnector;
  plot: ChainPlot;
  laneIndexByKey: ReadonlyMap<string, number>;
  laneHeight: number;
  visuals: EvtxVisualTokens;
}) {
  const left = plot.members.find((marker) => marker.id === connector.left);
  const right = plot.members.find((marker) => marker.id === connector.right);
  if (left === undefined || right === undefined) return null;
  const centreY = (marker: PlotMarker) =>
    (laneIndexByKey.get(marker.laneKey) ?? 0) * laneHeight + CORRELATION_MARKER_HIT_PX / 2;
  const style = CONNECTOR_STYLES[connector.strength];
  return (
    <line
      data-connector=""
      data-strength={connector.strength}
      x1={pct(left.placement.x)}
      y1={centreY(left)}
      x2={pct(right.placement.x)}
      y2={centreY(right)}
      strokeWidth={style.width}
      strokeDasharray={style.dash}
      strokeLinecap="butt"
      style={{
        stroke: visuals.strengths[connector.strength].border,
        vectorEffect: "non-scaling-stroke",
      }}
    />
  );
}

export interface EvtxCorrelationLanesProps {
  /** `view` (the default) is the Correlation view's plot; `dock` is the dock's. */
  variant?: CorrelationLanesVariant;
  plot: ChainPlot;
  timeZoneMode: EvtxTimeZoneMode;
  sizes: CorrelationSizes;
  /** The figure's accessible name: what the plot shows and where the same entries are listed. */
  label: string;
  /** A marker's accessible name. The view writes it: it knows the chain's keys and strength. */
  markerName: (marker: PlotMarker) => string;
  /** Enter, Space or a click on a marker. */
  onActivate?: (marker: PlotMarker) => void;
  /** Escape on a marker: the view moves focus back to the chain list. */
  onEscape?: () => void;
}

/** The lane plot. A chain with no placed entry draws a sentence instead, never an empty frame. */
export function EvtxCorrelationLanes({
  variant = "view",
  plot,
  timeZoneMode,
  sizes,
  label,
  markerName,
  onActivate,
  onEscape,
}: EvtxCorrelationLanesProps) {
  const styles = useStyles();
  const visuals = useEvtxVisualTokens();
  const { cardSecondary } = useRailTextColors();
  const geometry = geometryFor(variant, sizes);
  const { laneHeight } = geometry;
  const ordered = useMemo(() => [...plot.members, ...plot.nearby], [plot.members, plot.nearby]);
  const [focusedId, setFocusedId] = useState<string | null>(null);
  const buttons = useRef(new Map<string, HTMLButtonElement>());
  const tabStopId =
    focusedId !== null && ordered.some((marker) => marker.id === focusedId)
      ? focusedId
      : (ordered[0]?.id ?? null);
  const laneIndexByKey = useMemo(
    () => new Map(plot.lanes.map((lane, index) => [lane.key, index])),
    [plot.lanes],
  );

  if (plot.window === null) {
    return (
      <figure
        aria-label={label}
        style={{
          margin: 0,
          padding: "12px 10px",
          border: `1px solid ${tokens.colorNeutralStroke2}`,
          borderRadius: "6px",
          backgroundColor: tokens.colorNeutralBackground1,
          fontSize: `${sizes.lane}px`,
          color: tokens.colorNeutralForeground2,
        }}
      >
        No entry of this chain has a loaded timeline position, so there is nothing to plot.
      </figure>
    );
  }

  const moveFocus = (from: number, to: number) => {
    const target = ordered[Math.min(Math.max(to, 0), ordered.length - 1)];
    if (target === undefined || to === from) return;
    setFocusedId(target.id);
    buttons.current.get(target.id)?.focus();
  };
  const onKeyDown = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    switch (event.key) {
      case "ArrowRight":
        event.preventDefault();
        moveFocus(index, index + 1);
        return;
      case "ArrowLeft":
        event.preventDefault();
        moveFocus(index, index - 1);
        return;
      case "Home":
        event.preventDefault();
        moveFocus(index, 0);
        return;
      case "End":
        event.preventDefault();
        moveFocus(index, ordered.length - 1);
        return;
      case "Escape":
        // Handled here: the workspace's own Escape handler would otherwise clear the time range.
        event.preventDefault();
        onEscape?.();
        return;
    }
  };

  const trackHeight = Math.max(1, plot.lanes.length) * laneHeight;
  const tickLast = plot.ticks.length - 1;
  // With seconds always: a lane window can be as narrow as 10 s. The day (and year) join the label
  // when the window crosses midnight or is not in this year, so one clock never names two days.
  const axisLabels = tickLabels(plot.ticks, timeZoneMode, { withSeconds: true });

  return (
    <figure
      aria-label={label}
      data-testid="lane-plot"
      data-variant={variant}
      style={{
        margin: 0,
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        borderRadius: "6px",
        padding: "6px 10px",
        backgroundColor: tokens.colorNeutralBackground1,
        ...(geometry.maxHeight === null
          ? {}
          : { maxHeight: `${geometry.maxHeight}px`, overflowY: "auto" as const }),
        overflowX: "hidden",
        boxSizing: "border-box",
      }}
    >
      <div style={{ display: "flex" }}>
        <div style={{ width: `${geometry.labelColumnPx}px`, flexShrink: 0 }}>
          {plot.lanes.map((lane: PlotLane) => (
            <div
              key={lane.key}
              title={lane.detail}
              data-lane-label=""
              style={{
                height: `${laneHeight}px`,
                boxSizing: "border-box",
                paddingTop: `${CORRELATION_MARKER_HIT_PX / 2 - geometry.laneLabelSize / 2 - 1}px`,
                paddingRight: "8px",
                fontSize: `${geometry.laneLabelSize}px`,
                lineHeight: `${geometry.laneLabelSize + 2}px`,
                color: tokens.colorNeutralForeground2,
                overflow: "hidden",
                whiteSpace: "nowrap",
                textOverflow: "ellipsis",
              }}
            >
              {lane.label}
            </div>
          ))}
        </div>
        <div style={{ flex: 1, minWidth: 0, padding: "0 12px" }}>
          <div style={{ position: "relative", height: `${trackHeight}px` }}>
            {plot.lanes.map((lane, index) => (
              <div
                key={lane.key}
                aria-hidden="true"
                style={{
                  position: "absolute",
                  left: 0,
                  right: 0,
                  top: `${index * laneHeight + CORRELATION_MARKER_HIT_PX / 2}px`,
                  borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
                }}
              />
            ))}
            {geometry.centerRule && (
              <div
                aria-hidden="true"
                data-center-rule=""
                style={{
                  position: "absolute",
                  left: "50%",
                  top: 0,
                  bottom: 0,
                  width: "1px",
                  backgroundColor: tokens.colorNeutralStrokeAccessible,
                }}
              />
            )}
            <svg
              aria-hidden="true"
              width="100%"
              height={trackHeight}
              style={{ position: "absolute", inset: 0, overflow: "visible" }}
            >
              {plot.connectors.map((connector) => (
                <ConnectorLine
                  key={`${connector.left}|${connector.right}|${connector.strength}`}
                  connector={connector}
                  plot={plot}
                  laneIndexByKey={laneIndexByKey}
                  laneHeight={laneHeight}
                  visuals={visuals}
                />
              ))}
            </svg>
            {plot.lanes.map((lane, laneIndex) => {
              const inLane = [...lane.markers].sort(
                (a, b) => a.placement.x - b.placement.x || (a.id < b.id ? -1 : 1),
              );
              return (
                <div
                  key={lane.key}
                  data-lane={lane.key}
                  style={{
                    position: "absolute",
                    left: 0,
                    right: 0,
                    top: `${laneIndex * laneHeight}px`,
                    height: `${laneHeight}px`,
                  }}
                >
                  {inLane.map((marker) => {
                    const orderIndex = ordered.findIndex((entry) => entry.id === marker.id);
                    return (
                      <Fragment key={marker.id}>
                        <button
                          type="button"
                          ref={(node) => {
                            if (node === null) buttons.current.delete(marker.id);
                            else buttons.current.set(marker.id, node);
                          }}
                          className={styles.marker}
                          data-marker={marker.id}
                          data-role={marker.role}
                          data-kind={marker.kind}
                          data-level={marker.level}
                          data-pinned={marker.placement.pinned ?? undefined}
                          tabIndex={marker.id === tabStopId ? 0 : -1}
                          aria-label={markerName(marker)}
                          title={markerName(marker)}
                          style={{
                            left: `calc(${pct(marker.placement.x)} - ${CORRELATION_MARKER_HIT_PX / 2}px)`,
                            top: 0,
                          }}
                          onFocus={() => setFocusedId(marker.id)}
                          onClick={() => onActivate?.(marker)}
                          onKeyDown={(event) => onKeyDown(event, orderIndex)}
                        >
                          <MarkerGlyph marker={marker} visuals={visuals} markerPx={geometry.markerPx} />
                        </button>
                        {geometry.markerLabels && (
                          <MarkerLabel
                            marker={marker}
                            box={labelBox(marker, inLane)}
                            sizes={sizes}
                            color={cardSecondary}
                          />
                        )}
                      </Fragment>
                    );
                  })}
                </div>
              );
            })}
          </div>
          <div
            aria-hidden="true"
            data-axis=""
            style={{ position: "relative", height: `${sizes.tick + 6}px`, marginTop: "2px" }}
          >
            {axisLabels.map((text, index) => (
              <span
                key={index}
                style={{
                  position: "absolute",
                  left: pct(tickLast <= 0 ? 0 : index / tickLast),
                  transform: index === 0 ? "none" : index === tickLast ? "translateX(-100%)" : "translateX(-50%)",
                  fontSize: `${sizes.tick}px`,
                  fontFamily: tokens.fontFamilyNumeric,
                  color: cardSecondary,
                  whiteSpace: "nowrap",
                }}
              >
                {text}
              </span>
            ))}
          </div>
        </div>
      </div>
    </figure>
  );
}

/**
 * The key to the plot (spec 8.11 header): a solid line for exact, a dashed one for candidate, the
 * dotted outline for an entry that is not linked (only when such a marker is drawn), and the two
 * marker shapes. The wording for the dotted entry is the plot's own, so the legend can never say
 * "Not linked" where a marker says "No loaded link".
 */
export function CorrelationLegend({ plot, sizes }: { plot: ChainPlot; sizes: CorrelationSizes }) {
  const { cardSecondary } = useRailTextColors();
  return (
    <div
      role="group"
      aria-label="Legend"
      data-testid="correlation-legend"
      style={{ display: "flex", flexWrap: "wrap", columnGap: "14px", rowGap: "4px" }}
    >
      <LegendItem label="exact" color={cardSecondary} size={sizes.label}>
        <ConnectorSwatch strength="exact" />
      </LegendItem>
      <LegendItem label="candidate" color={cardSecondary} size={sizes.label}>
        <ConnectorSwatch strength="candidate" />
      </LegendItem>
      {plot.showsNotLinkedLegend && (
        <LegendItem label={`${plot.notLinkedLabel.toLowerCase()} (no line)`} color={cardSecondary} size={sizes.label}>
          <MarkerSwatch radius="50%" outlined />
        </LegendItem>
      )}
      <LegendItem label="Event" color={cardSecondary} size={sizes.label}>
        <MarkerSwatch radius="50%" outlined={false} />
      </LegendItem>
      <LegendItem label="Log line" color={cardSecondary} size={sizes.label}>
        <MarkerSwatch radius="3px" outlined={false} />
      </LegendItem>
    </div>
  );
}
