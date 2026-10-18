/**
 * The Correlation view's overview strip (spec 8.11, "Overview strip"): every drawn chain's span as a
 * thin bar across the extent of the chains shown, and a draggable, resizable zoom band that sets the
 * lane plot's window.
 *
 * The band is view-local. It sets the lane window (the view passes it to `buildChainPlot`) and
 * nothing else: it never reads or writes the time-range criterion (6a), so it filters no table, no
 * histogram and no diagnosis. Escape is spent here with `preventDefault`, so the workspace's own
 * Escape handler, which clears that criterion, does not also run.
 *
 * Paint, in document order: the wash, the bars, then the handles (`data-evtx-layer`, like the
 * histogram's brush). The wash is behind the bars because over them a bar measures 1.80 to 3.38:1 in
 * every theme; its opacity is solved from the token map (`overviewBandOpacity`), so every bar keeps
 * 3:1 on it (Adam's criterion on #840). The selected chain's bar is solid; the others are drawn at
 * 40% in their FILL only, with a full-opacity 1 px outline, because a bar faded as a whole misses
 * 3:1 on the strip and under the wash in almost every theme (recorded deviation from spec 8.11).
 *
 * The strip is 48 px (bars and band); the caption sits above it and the five ticks below it. The
 * caption row wraps rather than clips, because it carries the note that the extent is only the chains
 * shown (spec 8.11), so its height, and the strip's total, are minimums that hold on one line. The
 * bars are not read by assistive technology: the chain list is their equivalent, and the band is a
 * slider whose value text names its two ends and its width. The handles are not tab stops: the
 * keyboard resizes with Shift+Left and Shift+Right.
 *
 * Text sizes come from the log list font size (`sizes`), and every color from the visual tokens.
 */
import { useEffect, useMemo, useRef, type KeyboardEvent, type PointerEvent } from "react";
import { makeStyles, tokens } from "@fluentui/react-components";
import { getThemeById } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
import type { CorrelationSizes } from "./evtx-correlation-sizes";
import type { CorrelationChain } from "./evtx-correlation-chains";
import {
  OVERVIEW_BAR_HEIGHT_PX,
  OVERVIEW_BOX_HEIGHT_PX,
  OVERVIEW_CAPTION,
  OVERVIEW_EXTENT_NOTE,
  OVERVIEW_HINT,
  OVERVIEW_UNSELECTED_FILL_OPACITY,
  bandFractions,
  bandValueText,
  clampWindow,
  dragBand,
  fractionToMs,
  overviewBandOpacity,
  overviewBars,
  overviewDomain,
  reduceBandKey,
  undrawnNote,
  type BandDrag,
} from "./evtx-correlation-overview";
import { axisTicks, tickLabels, type TimeWindow } from "./evtx-correlation-view-model";
import { useRailTextColors } from "./evtx-rail-text";
import type { EvtxTimeZoneMode } from "./evtx-time";
import { useEvtxVisualTokens } from "./evtx-visual-tokens";

const FORCED_COLORS = "@media (forced-colors: active)";
/** The drawn band is never narrower than this, so a 10 s band on a day-wide strip can be grabbed. */
const BAND_MIN_DRAWN_PX = 12;
/** The pointer-sensitive zone of a handle, centred on the 2 px line. */
const HANDLE_HIT_PX = 12;
const HANDLE_LINE_PX = 2;
const BAR_ROW_GAP_PX = 3;
const BAR_MIN_DRAWN_PX = 3;
const BOX_PADDING_PX = 7;
const CAPTION_GAP_PX = 4;
const AXIS_GAP_PX = 2;

const useStyles = makeStyles({
  box: {
    position: "relative",
    boxSizing: "border-box",
    overflow: "hidden",
    borderRadius: "6px",
    border: `1px solid ${tokens.colorNeutralStroke2}`,
    backgroundColor: tokens.colorNeutralBackground1,
    touchAction: "none",
    userSelect: "none",
    outlineStyle: "none",
    ":focus-visible": {
      outlineStyle: "solid",
      outlineWidth: "2px",
      outlineColor: tokens.colorStrokeFocus2,
      outlineOffset: "1px",
    },
  },
  // Under forced colors the surface is Canvas but the bars keep their own colors, so the wash's 3:1
  // proof (made on the theme's surface) no longer holds: the wash is dropped there and the handles,
  // whose color is forced to a system color, carry the band.
  wash: {
    position: "absolute",
    top: 0,
    bottom: 0,
    cursor: "grab",
    [FORCED_COLORS]: { display: "none" },
  },
  bars: {
    position: "absolute",
    top: 0,
    right: 0,
    bottom: 0,
    left: 0,
    pointerEvents: "none",
    // The colors carry the strength, so forced colors must not repaint them.
    [FORCED_COLORS]: { forcedColorAdjust: "none" },
  },
  bar: {
    position: "absolute",
    boxSizing: "border-box",
    [FORCED_COLORS]: { outlineStyle: "solid", outlineWidth: "1px", outlineColor: "CanvasText" },
  },
  handles: { position: "absolute", top: 0, bottom: 0, pointerEvents: "none" },
  handle: {
    position: "absolute",
    top: 0,
    bottom: 0,
    width: `${HANDLE_HIT_PX}px`,
    cursor: "ew-resize",
    pointerEvents: "auto",
    display: "flex",
    justifyContent: "center",
  },
});

interface EvtxCorrelationOverviewProps {
  /** The chains the view lists (at most the 100-row cap), in the model's order. */
  chains: readonly CorrelationChain[];
  selectedId: string | null;
  /**
   * The window in effect for the selected chain: the one the operator set, else the chain's default.
   * Null when the selected chain has no loaded position, so there is no band to show.
   */
  window: TimeWindow | null;
  /** The operator moved the band, or null to go back to the chain's default window (Home). */
  onWindowChange: (window: TimeWindow | null) => void;
  timeZoneMode: EvtxTimeZoneMode;
  sizes: CorrelationSizes;
}

function partOf(target: EventTarget | null): BandDrag["part"] | null {
  if (!(target instanceof Element)) return null;
  const part = target.closest("[data-part]")?.getAttribute("data-part");
  return part === "start" || part === "end" || part === "body" ? part : null;
}

export function EvtxCorrelationOverview({
  chains,
  selectedId,
  window: bandWindow,
  onWindowChange,
  timeZoneMode,
  sizes,
}: EvtxCorrelationOverviewProps) {
  const styles = useStyles();
  const visuals = useEvtxVisualTokens();
  const { cardSecondary } = useRailTextColors();
  const themeId = useUiStore((s) => s.themeId);
  const washOpacity = useMemo(() => overviewBandOpacity(getThemeById(themeId)), [themeId]);
  const domain = useMemo(() => overviewDomain(chains), [chains]);
  const { bars, undrawn } = useMemo(
    () => overviewBars(chains, selectedId, domain),
    [chains, selectedId, domain],
  );
  const boxRef = useRef<HTMLDivElement>(null);
  // The gesture in progress, if any. A ref: it changes with every pointer event and nothing is drawn from it.
  const dragRef = useRef<{ drag: BandDrag } | null>(null);
  // What the effect below needs when the domain changes, without re-running when they change.
  const latest = useRef({ bandWindow, onWindowChange });
  latest.current = { bandWindow, onWindowChange };

  // A live rebuild can change the domain under a gesture. A drag measured against the old domain
  // would jump, so it ends; and a window that no longer fits is moved in (kept in absolute time,
  // clamped), never dropped.
  const domainStart = domain?.startMs;
  const domainEnd = domain?.endMs;
  useEffect(() => {
    dragRef.current = null;
    const { bandWindow: current, onWindowChange: change } = latest.current;
    if (domainStart === undefined || domainEnd === undefined || current === null) return;
    const legal = clampWindow(current, { startMs: domainStart, endMs: domainEnd });
    if (legal.startMs !== current.startMs || legal.endMs !== current.endMs) change(legal);
  }, [domainStart, domainEnd]);

  const captionHeight = sizes.label + 4;
  const axisHeight = sizes.tick + 6;
  const caption = (
    <div
      data-testid="overview-caption"
      style={{
        // A minimum, not a height: at a large font size, or with the side panes open, the row wraps
        // to a second line instead of cutting off the extent note.
        minHeight: `${captionHeight}px`,
        marginBottom: `${CAPTION_GAP_PX}px`,
        display: "flex",
        alignItems: "baseline",
        flexWrap: "wrap",
        columnGap: "8px",
        fontSize: `${sizes.label}px`,
        lineHeight: `${captionHeight}px`,
        color: cardSecondary,
      }}
    >
      <span style={{ fontWeight: 600 }}>{OVERVIEW_CAPTION}</span>
      {/* The dot stays with the hint, so it never starts a wrapped line. */}
      <span style={{ whiteSpace: "nowrap" }}>{`${OVERVIEW_HINT} ·`}</span>
      <span>{OVERVIEW_EXTENT_NOTE}</span>
    </div>
  );

  if (domain === null) {
    return (
      <div data-testid="correlation-overview">
        {caption}
        <div
          data-testid="overview-box"
          className={styles.box}
          style={{
            height: `${OVERVIEW_BOX_HEIGHT_PX}px`,
            display: "flex",
            alignItems: "center",
            padding: "0 10px",
            fontSize: `${sizes.lane}px`,
            color: cardSecondary,
          }}
        >
          No chain has a loaded timeline position, so there is nothing to show here.
        </div>
      </div>
    );
  }

  const fractions = bandWindow === null ? null : bandFractions(bandWindow, domain);
  const bandStyle =
    fractions === null
      ? null
      : {
          left: `${fractions.left * 100}%`,
          width: `${(fractions.right - fractions.left) * 100}%`,
          minWidth: `${BAND_MIN_DRAWN_PX}px`,
        };

  const msAt = (clientX: number): number | null => {
    const rect = boxRef.current?.getBoundingClientRect();
    if (!rect || rect.width <= 0) return null;
    return fractionToMs((clientX - rect.left) / rect.width, domain);
  };

  const onPointerDown = (event: PointerEvent<HTMLDivElement>) => {
    // Primary button only: a right-click opens the context menu and must not arm a drag.
    if (event.button !== 0 || !event.isPrimary || bandWindow === null) return;
    const ms = msAt(event.clientX);
    if (ms === null) return;
    // A press that is not on the band or a handle does nothing (no click-to-recenter, spec 8.11).
    const part = partOf(event.target) ?? (ms >= bandWindow.startMs && ms <= bandWindow.endMs ? "body" : null);
    if (part === null) return;
    event.preventDefault();
    event.currentTarget.setPointerCapture?.(event.pointerId);
    dragRef.current = { drag: { part, origin: bandWindow, grabMs: ms } };
    event.currentTarget.focus({ preventScroll: true });
  };

  const onPointerMove = (event: PointerEvent<HTMLDivElement>) => {
    const current = dragRef.current;
    if (current === null) return;
    // The button was released outside the page or the capture was lost: stop rather than follow a
    // pointer that is no longer dragging.
    if (event.buttons === 0) {
      dragRef.current = null;
      return;
    }
    const ms = msAt(event.clientX);
    if (ms !== null) onWindowChange(dragBand(current.drag, ms, domain));
  };

  const endGesture = (event?: PointerEvent<HTMLDivElement>) => {
    if (event !== undefined && dragRef.current !== null) {
      event.currentTarget.releasePointerCapture?.(event.pointerId);
    }
    dragRef.current = null;
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.ctrlKey || event.metaKey || event.altKey) return;
    if (event.key === "Escape") {
      // Always spent here, so the workspace's Escape (which clears the time range) steps aside. A
      // drag in progress is cancelled, and the band goes back to where it was pressed.
      event.preventDefault();
      const current = dragRef.current;
      if (current !== null) {
        dragRef.current = null;
        onWindowChange(current.drag.origin);
      }
      return;
    }
    if (dragRef.current !== null || bandWindow === null) return;
    const result = reduceBandKey(bandWindow, domain, event.key, event.shiftKey);
    if (result.kind === "ignore") return;
    event.preventDefault();
    onWindowChange(result.kind === "reset" ? null : result.window);
  };

  const ticks = axisTicks(domain);
  const labels = tickLabels(ticks, timeZoneMode);
  const tickLast = ticks.length - 1;
  const rowTop = (row: number) => BOX_PADDING_PX + row * (OVERVIEW_BAR_HEIGHT_PX + BAR_ROW_GAP_PX);
  const note = undrawnNote(undrawn);

  const sliderProps =
    bandWindow === null
      ? ({
          role: "img",
          "aria-label": `Spans of ${bars.length.toLocaleString()} ${bars.length === 1 ? "chain" : "chains"}. The selected chain has no loaded timeline position, so there is no zoom window.`,
        } as const)
      : ({
          role: "slider",
          tabIndex: 0,
          "aria-label": "Zoom window of the lane plot",
          "aria-orientation": "horizontal",
          "aria-valuemin": domain.startMs,
          "aria-valuemax": domain.endMs,
          "aria-valuenow": bandWindow.startMs,
          "aria-valuetext": bandValueText(bandWindow, timeZoneMode),
          "aria-keyshortcuts": "ArrowLeft ArrowRight Shift+ArrowLeft Shift+ArrowRight Home",
        } as const);

  return (
    <div data-testid="correlation-overview">
      {caption}
      <div
        ref={boxRef}
        data-testid="overview-box"
        className={styles.box}
        style={{ height: `${OVERVIEW_BOX_HEIGHT_PX}px` }}
        {...sliderProps}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={endGesture}
        onPointerCancel={() => endGesture()}
        onLostPointerCapture={() => endGesture()}
        onKeyDown={onKeyDown}
      >
        {bandStyle !== null && (
          <div
            aria-hidden="true"
            data-evtx-layer="wash"
            data-part="body"
            className={styles.wash}
            style={{
              ...bandStyle,
              backgroundColor: tokens.colorNeutralBackground1Selected,
              opacity: washOpacity,
            }}
          />
        )}
        <div aria-hidden="true" data-evtx-layer="bars" className={styles.bars}>
          {bars.map((bar) => {
            const color = visuals.strengthBars[bar.strength];
            return (
              <div
                key={bar.chainId}
                data-bar={bar.chainId}
                data-strength={bar.strength}
                data-selected={bar.selected}
                className={styles.bar}
                style={{
                  left: `${bar.left * 100}%`,
                  width: `${bar.width * 100}%`,
                  minWidth: `${BAR_MIN_DRAWN_PX}px`,
                  top: `${rowTop(bar.row)}px`,
                  height: `${OVERVIEW_BAR_HEIGHT_PX}px`,
                  border: `1px solid ${color}`,
                }}
              >
                <span
                  data-bar-fill=""
                  style={{
                    position: "absolute",
                    top: 0,
                    right: 0,
                    bottom: 0,
                    left: 0,
                    backgroundColor: color,
                    opacity: bar.selected ? 1 : OVERVIEW_UNSELECTED_FILL_OPACITY,
                  }}
                />
              </div>
            );
          })}
        </div>
        {bandStyle !== null && (
          <div aria-hidden="true" className={styles.handles} style={bandStyle}>
            {(["start", "end"] as const).map((side) => (
              <div
                key={side}
                data-part={side}
                className={styles.handle}
                style={side === "start" ? { left: `-${HANDLE_HIT_PX / 2}px` } : { right: `-${HANDLE_HIT_PX / 2}px` }}
              >
                <span
                  data-evtx-layer="edge"
                  data-evtx-edge={side}
                  style={{
                    height: "100%",
                    pointerEvents: "none",
                    borderLeft: `${HANDLE_LINE_PX}px solid ${tokens.colorNeutralStrokeAccessible}`,
                  }}
                />
              </div>
            ))}
          </div>
        )}
      </div>
      <div
        aria-hidden="true"
        data-testid="overview-axis"
        style={{
          position: "relative",
          height: `${axisHeight}px`,
          marginTop: `${AXIS_GAP_PX}px`,
        }}
      >
        {labels.map((text, index) => (
          <span
            key={index}
            style={{
              position: "absolute",
              left: `${(tickLast <= 0 ? 0 : index / tickLast) * 100}%`,
              transform: index === 0 ? "none" : index === tickLast ? "translateX(-100%)" : "translateX(-50%)",
              fontSize: `${sizes.tick}px`,
              fontFamily: tokens.fontFamilyNumeric,
              fontVariantNumeric: "tabular-nums",
              color: cardSecondary,
              whiteSpace: "nowrap",
            }}
          >
            {text}
          </span>
        ))}
      </div>
      {note !== null && (
        <div data-testid="overview-undrawn" style={{ fontSize: `${sizes.label}px`, color: cardSecondary }}>
          {note}
        </div>
      )}
    </div>
  );
}
