/**
 * The Correlation dock (spec 8.12, #842): what was recorded around the selected event, under every
 * view. A header (title, "around Event {id} ...", the window, Open in Correlation view, collapse,
 * close), the lanes of the sources with entries in the window, the selected event's chain as a
 * summary, and what is nearby by time alone.
 *
 * Thin on purpose. Every decision about what the dock may claim is `buildDockModel`'s: this draws it.
 * The words are the copy module's. The window is read by `useEvtxCorrelationWindow`, only while the
 * dock is expanded, behind a debounce.
 *
 * Rules the component itself keeps:
 * - It has no live region (R7). Recentering is the operator's own action and the Details tab already
 *   announces a selection; a failed read is an alert, and nothing else speaks.
 * - Activating a marker selects its record only when exactly one loaded record matches
 *   (`resolveMarkerClick`); otherwise it does nothing, and the marker's accessible name then says why.
 * - Open in Correlation view opens the row through `openCorrelationView`, which counts as an open
 *   (the view drops a loss it held), and moves focus to the Correlation tab, like Phase 10's
 *   "Filter table to chain" moves it to the Table tab. It is aria-disabled, with its reason visible
 *   beside it, when there is no row to open.
 * - Close returns focus to the "Correlation dock" toggle that opened the dock.
 * - Escape on a marker is handled by the lanes (default prevented, so the workspace does not clear
 *   the time range) and moves focus to the window dropdown.
 * - Text sizes come from the log list font size (spec 7.1): title f - 1, subtitle and summary f - 2,
 *   badge and legend text max(10, f - 3). Colors are tokens; where a designed text color misses 4.5:1
 *   on the dock's surface, the rail's text colors stand in (evtx-rail-text).
 *
 * Nothing here imports from the lazily loaded Correlation view.
 */
import { useCallback, useId, useMemo, useRef, useState, type ReactNode } from "react";
import { Button, Dropdown, Option, tokens } from "@fluentui/react-components";
import { ChevronDown12Regular, ChevronUp12Regular, Dismiss12Regular } from "@fluentui/react-icons";
import { LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { CorrelationLegend, EvtxCorrelationLanes } from "./EvtxCorrelationLanes";
import { correlationSizes, type CorrelationSizes } from "./evtx-correlation-sizes";
import { EvtxStrengthBadge } from "./EvtxStrengthBadge";
import {
  ANALYSIS_BUILDING_TEXT,
  NO_SELECTION_TEXT,
  NO_SESSION_TEXT,
  READING_WINDOW_TEXT,
  UNTIMED_TEXT,
  dockSubtitle,
  keyKindLabel,
  nearbyReason,
  openDisabledText,
  windowFailureText,
  windowWidthLabel,
} from "./evtx-correlation-copy";
import {
  buildDockModel,
  dockCenterMs,
  dockMarkerName,
  resolveMarkerClick,
  type DockCounts,
  type DockModel,
  type DockReady,
  type MarkerSelectability,
} from "./evtx-correlation-dock-model";
import { useEvtxAnalysisSession, type EvtxAnalysisSession } from "./evtx-analysis-session";
import { itemsByOriginId } from "./evtx-correlation-origin-index";
import { openCorrelationView } from "./evtx-correlation-store";
import type { CorrelationWindowDeps, LoadedCorrelationWindow } from "./evtx-correlation-window";
import {
  EVTX_DOCK_WINDOW_OPTIONS_MS,
  evtxPanelToggleId,
  evtxViewTabId,
  useEvtxLayoutStore,
} from "./evtx-layout-store";
import { findRecordById } from "./evtx-insights-data";
import { useRailTextColors } from "./evtx-rail-text";
import { selectRecordAndShowDetails } from "./evtx-select-record";
import { useEvtxStore } from "./evtx-store";
import { formatClock } from "./evtx-time";
import type { PlotMarker } from "./evtx-correlation-view-model";
import { useEvtxVisualTokens } from "./evtx-visual-tokens";
import { useEvtxCorrelationData, type EvtxCorrelationData } from "./useEvtxCorrelation";
import { useEvtxCorrelationWindow } from "./useEvtxCorrelationWindow";
import { useUnreadSources } from "./useUnreadSources";

interface EvtxCorrelationDockProps {
  /** Test seams: the window reader's IO and its two settle times. */
  windowDeps?: Partial<CorrelationWindowDeps>;
  selectionSettleMs?: number;
  sessionSettleMs?: number;
}

/** What a click on each marker found, for the window it was made in; another window forgets it. */
interface ClickResults {
  window: LoadedCorrelationWindow | null;
  byId: ReadonlyMap<string, MarkerSelectability>;
}
const NO_CLICKS: ReadonlyMap<string, MarkerSelectability> = new Map();

export default function EvtxCorrelationDock({
  windowDeps,
  selectionSettleMs,
  sessionSettleMs,
}: EvtxCorrelationDockProps = {}) {
  const uid = useId();
  const bodyId = `${uid}-body`;
  const reasonId = `${uid}-open-reason`;
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const sizes = useMemo(() => correlationSizes(logListFontSize), [logListFontSize]);
  const visuals = useEvtxVisualTokens();
  const railText = useRailTextColors();
  const timeZoneMode = useEvtxStore((s) => s.timeZoneMode);
  // The selected record's object, not the records: the dock does no derived work over the array.
  const record = useEvtxStore((s) => findRecordById(s.records, s.selectedRecordId));
  const halfWidthMs = useEvtxLayoutStore((s) => s.dockWindowMs);
  const collapsed = useEvtxLayoutStore((s) => s.dockCollapsed);
  const setDockWindowMs = useEvtxLayoutStore((s) => s.setDockWindowMs);
  const setDockCollapsed = useEvtxLayoutStore((s) => s.setDockCollapsed);
  const correlation = useEvtxCorrelationData();
  const counts = correlation.counts;
  const stage = correlation.stage;
  // The session comes from the workspace's provider, the unread sources from the store's coverage:
  // the same two readings the Details context list takes, so there is one of each.
  const status = useEvtxAnalysisSession();
  const unreadSources = useUnreadSources();

  const centerMs = dockCenterMs(record);
  const { window, reading, retry } = useEvtxCorrelationWindow({
    status,
    centerMs,
    halfWidthMs,
    active: !collapsed,
    selectionSettleMs,
    sessionSettleMs,
    deps: windowDeps,
  });

  // The counts object is new on every scan-progress tick; what the model reads of it is not, so the
  // model is rebuilt only when one of those parts is.
  const countsModel = counts?.model;
  const countsBuiltFor = counts?.builtFor;
  const countsPartners = counts?.linkPartners;
  const countsGaps = counts?.gaps;
  const countsScope = counts?.scope;
  const countsUnplaced = counts?.unplacedList;
  const countsUpdating = counts?.updating;
  const dockCounts = useMemo<DockCounts | null>(
    () =>
      countsModel === undefined ||
      countsBuiltFor === undefined ||
      countsPartners === undefined ||
      countsGaps === undefined ||
      countsScope === undefined ||
      countsUnplaced === undefined ||
      countsUpdating === undefined
        ? null
        : {
            model: countsModel,
            builtFor: countsBuiltFor,
            linkPartners: countsPartners,
            gaps: countsGaps,
            scope: countsScope,
            unplacedList: countsUnplaced,
            updating: countsUpdating,
          },
    [countsModel, countsBuiltFor, countsPartners, countsGaps, countsScope, countsUnplaced, countsUpdating],
  );
  // Nothing is built while collapsed: no read was made, and the body is not shown.
  const model = useMemo(
    () => (collapsed ? null : buildDockModel({ record, window, counts: dockCounts, unreadSources })),
    [collapsed, record, window, dockCounts, unreadSources],
  );
  const ready = model !== null && model.kind === "ready" ? model : null;

  const [clicks, setClicks] = useState<ClickResults>({ window: null, byId: NO_CLICKS });
  const clickResults = clicks.window === window ? clicks.byId : NO_CLICKS;
  const windowItems = useMemo(
    () => (window === null ? new Map() : itemsByOriginId(window.items)),
    [window],
  );
  const activateMarker = useCallback(
    (marker: PlotMarker) => {
      const item = windowItems.get(marker.id);
      if (item === undefined || ready === null) return;
      if (ready.facts.get(marker.id)?.selectability === "selected") return;
      const click = resolveMarkerClick(item.origin, useEvtxStore.getState().records);
      if (click.kind === "select") {
        selectRecordAndShowDetails(click.recordId);
        return;
      }
      setClicks((previous) => ({
        window,
        byId: new Map(previous.window === window ? previous.byId : NO_CLICKS).set(marker.id, click.selectability),
      }));
    },
    [windowItems, ready, window],
  );
  const markerName = useCallback(
    (marker: PlotMarker) =>
      ready === null ? marker.entry : dockMarkerName(ready, marker, timeZoneMode, clickResults.get(marker.id)),
    [ready, timeZoneMode, clickResults],
  );

  const controlsRef = useRef<HTMLDivElement>(null);
  const focusWindowDropdown = useCallback(() => {
    controlsRef.current?.querySelector<HTMLElement>('[role="combobox"]')?.focus();
  }, []);

  const openRow = () => {
    if (ready === null || !("rowId" in ready.open)) return;
    // The view's own loss record is dropped by an open (evtx-correlation-store's `openChain`).
    openCorrelationView(ready.open.rowId);
    document.getElementById(evtxViewTabId("correlation"))?.focus();
  };
  const close = () => {
    useEvtxLayoutStore.getState().setPanel("dock", false);
    document.getElementById(evtxPanelToggleId("dock"))?.focus();
  };

  const subtitle =
    record === null || centerMs === null
      ? null
      : dockSubtitle({
          eventId: record.eventId,
          timeText: formatClock(centerMs, timeZoneMode, true),
          halfWidthMs: ready?.halfWidthMs ?? halfWidthMs,
          sources: ready?.sources ?? null,
        });

  const openDisabled = ready !== null && "disabled" in ready.open ? ready.open.disabled : null;
  const canOpen = ready !== null && "rowId" in ready.open;
  // Waiting for a session that is on the way is busy too: the body says so, and a reader is told.
  const waitingForSession = model !== null && model.kind === "unread" && status === null && stage === "pending";
  const busy = !collapsed && (reading || waitingForSession || (ready !== null && ready.updating));
  const primary = railText.primary;
  const secondary = railText.secondary;

  return (
    <section
      aria-label="Correlation dock"
      data-testid="correlation-dock"
      aria-busy={busy || undefined}
      style={{
        display: "flex",
        flexDirection: "column",
        minHeight: 0,
        backgroundColor: tokens.colorNeutralBackground2,
        color: primary,
      }}
    >
      <div
        data-testid="correlation-dock-header"
        // Sticky: the workspace's slot scrolls the whole dock, and the controls stay in reach.
        style={{
          display: "flex",
          alignItems: "center",
          gap: "10px",
          padding: "6px 12px",
          minWidth: 0,
          position: "sticky",
          top: 0,
          zIndex: 1,
          backgroundColor: tokens.colorNeutralBackground2,
        }}
      >
        <span style={{ fontSize: `${sizes.f - 1}px`, fontWeight: 600, color: primary, flexShrink: 0 }}>
          Correlation
        </span>
        {subtitle !== null && (
          <span
            data-testid="correlation-dock-subtitle"
            title={subtitle}
            style={{
              fontSize: `${sizes.lane}px`,
              color: tokens.colorNeutralForeground2,
              fontFamily: tokens.fontFamilyNumeric,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              // The one text container in the header that gives way to the controls (an ellipsis,
              // with the whole line in its title). A floor keeps it from vanishing: past it the
              // header overflows and the slot scrolls.
              minWidth: "10ch",
            }}
          >
            {subtitle}
          </span>
        )}
        <span style={{ flex: 1 }} />
        {!collapsed && (
          <>
            <div ref={controlsRef} style={{ display: "inline-flex" }}>
              <Dropdown
                aria-label="Correlation window"
                size="small"
                button={{ style: { fontSize: `${sizes.lane}px` } }}
                style={{ minWidth: "96px" }}
                value={windowWidthLabel(halfWidthMs)}
                selectedOptions={[String(halfWidthMs)]}
                onOptionSelect={(_, data) => {
                  const next = Number(data.optionValue);
                  if (Number.isFinite(next)) setDockWindowMs(next);
                }}
              >
                {EVTX_DOCK_WINDOW_OPTIONS_MS.map((ms) => (
                  <Option key={ms} value={String(ms)} text={windowWidthLabel(ms)} style={{ fontSize: `${sizes.lane}px` }}>
                    {windowWidthLabel(ms)}
                  </Option>
                ))}
              </Dropdown>
            </div>
            {openDisabled !== null && (
              <span
                id={reasonId}
                data-testid="correlation-dock-open-reason"
                style={{ fontSize: `${sizes.lane}px`, color: secondary, whiteSpace: "nowrap" }}
              >
                {openDisabledText(openDisabled)}
              </span>
            )}
            <Button
              size="small"
              appearance="secondary"
              disabledFocusable={!canOpen}
              aria-describedby={openDisabled !== null ? reasonId : undefined}
              title={
                ready !== null && ready.row !== null
                  ? `Open this event's chain, ${ready.row.title}, in the Correlation view`
                  : undefined
              }
              onClick={openRow}
              style={{ fontSize: `${sizes.lane}px` }}
            >
              Open in Correlation view
            </Button>
          </>
        )}
        <Button
          size="small"
          appearance="subtle"
          icon={collapsed ? <ChevronDown12Regular /> : <ChevronUp12Regular />}
          aria-label={collapsed ? "Expand correlation" : "Collapse correlation"}
          aria-expanded={!collapsed}
          aria-controls={bodyId}
          onClick={() => setDockCollapsed(!collapsed)}
        />
        <Button
          size="small"
          appearance="subtle"
          icon={<Dismiss12Regular />}
          aria-label="Close correlation dock"
          onClick={close}
        />
      </div>

      <div id={bodyId} hidden={collapsed}>
        {!collapsed && (
          // `max-content` rows: the lane plot is a scroll container (overflow-x hidden makes the
          // other axis auto), and a scroll container's automatic minimum size is 0, so as an `auto`
          // row of a grid with a height of its own it would be squeezed to a sliver instead of the
          // slot scrolling. Here the grid is as tall as its content, and the rows say so.
          <div style={{ padding: "0 12px 8px", display: "grid", gridAutoRows: "max-content", gap: "6px" }}>
            {ready === null ? (
              <DockMessage text={messageFor(model, status, stage)} color={secondary} size={sizes.lane}>
                {model !== null && model.kind === "failed" && (
                  <div
                    role="alert"
                    style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: `${sizes.lane}px`, color: primary }}
                  >
                    <span>{windowFailureText(model.error)}</span>
                    <Button size="small" appearance="secondary" onClick={retry}>
                      Retry
                    </Button>
                  </div>
                )}
              </DockMessage>
            ) : (
              <ReadyBody
                ready={ready}
                sizes={sizes}
                visuals={visuals}
                primary={primary}
                secondary={secondary}
                timeZoneMode={timeZoneMode}
                markerName={markerName}
                onActivate={activateMarker}
                onEscape={focusWindowDropdown}
              />
            )}
          </div>
        )}
      </div>
    </section>
  );
}

/** The sentence for a dock with nothing to draw yet, or null when the failure's alert says it. */
function messageFor(
  model: DockModel | null,
  status: EvtxAnalysisSession | null,
  stage: EvtxCorrelationData["stage"],
): string | null {
  if (model === null) return "";
  switch (model.kind) {
    case "noSelection":
      return NO_SELECTION_TEXT;
    case "untimed":
      return UNTIMED_TEXT;
    case "failed":
      return null;
    case "unread":
    case "ready":
      // No session is two states: one is on the way (the events are loaded and the analysis is being
      // built or rebuilt), or none is and none is coming. Only the second says there is nothing.
      if (status !== null) return READING_WINDOW_TEXT;
      return stage === "pending" ? ANALYSIS_BUILDING_TEXT : NO_SESSION_TEXT;
  }
}

function DockMessage({
  text,
  color,
  size,
  children,
}: {
  text: string | null;
  color: string;
  size: number;
  children?: ReactNode;
}) {
  return (
    <div data-testid="correlation-dock-message" style={{ fontSize: `${size}px`, color }}>
      {text}
      {children}
    </div>
  );
}

function ReadyBody({
  ready,
  sizes,
  visuals,
  primary,
  secondary,
  timeZoneMode,
  markerName,
  onActivate,
  onEscape,
}: {
  ready: DockReady;
  sizes: CorrelationSizes;
  visuals: ReturnType<typeof useEvtxVisualTokens>;
  primary: string;
  secondary: string;
  timeZoneMode: "local" | "utc";
  markerName: (marker: PlotMarker) => string;
  onActivate: (marker: PlotMarker) => void;
  onEscape: () => void;
}) {
  const { row, plot } = ready;
  return (
    <>
      {ready.updating && (
        <div data-testid="correlation-dock-updating" style={{ fontSize: `${sizes.lane}px`, color: secondary }}>
          Updating correlation...
        </div>
      )}
      <EvtxCorrelationLanes
        variant="dock"
        plot={plot}
        timeZoneMode={timeZoneMode}
        sizes={sizes}
        label={`Lane plot of the entries around Event ${ready.eventId}: ${plot.lanes.length.toLocaleString()} sources shown`}
        markerName={markerName}
        onActivate={onActivate}
        onEscape={onEscape}
      />
      {plot.nearby.length > 0 && <CorrelationLegend plot={plot} sizes={sizes} />}
      {ready.notices.length > 0 && (
        <ul
          data-testid="correlation-dock-notices"
          style={{ margin: 0, paddingLeft: "18px", fontSize: `${sizes.lane}px`, color: tokens.colorNeutralForeground2 }}
        >
          {ready.notices.map((text) => (
            <li key={text}>{text}</li>
          ))}
        </ul>
      )}
      {ready.empty !== null && (
        <div data-testid="correlation-dock-empty" style={{ fontSize: `${sizes.lane}px`, color: primary }}>
          {ready.empty.text}
        </div>
      )}
      {row !== null && (
        <div data-testid="correlation-dock-summary" style={{ display: "grid", gap: "3px", fontSize: `${sizes.lane}px`, color: primary }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
            <EvtxStrengthBadge strength={row.strength} visuals={visuals} textSize={sizes.label} />
            <span style={{ fontWeight: 600 }}>{row.title}</span>
            {row.key !== null && (
              <span style={{ color: secondary }}>
                key {keyKindLabel(row.key.kind)}{" "}
                <span title={row.key.value} style={{ fontFamily: LOG_MONOSPACE_FONT_FAMILY }}>
                  {row.key.shortValue}
                </span>
                {row.key.more > 0 ? ` and ${row.key.more.toLocaleString()} more` : ""}
              </span>
            )}
            {row.otherRows > 0 && (
              <span style={{ color: secondary }}>
                also in {row.otherRows.toLocaleString()} other {row.otherRows === 1 ? "row" : "rows"}
              </span>
            )}
          </div>
          <ol data-testid="correlation-dock-steps" style={{ margin: 0, paddingLeft: "18px", color: secondary }}>
            {ready.steps.map((step) => (
              <li key={step.id}>
                <span style={{ fontFamily: tokens.fontFamilyNumeric }}>
                  {formatClock(step.timestampMs, timeZoneMode, true)}
                </span>
                {" · "}
                {step.entry}
                {step.message === "" ? "" : ` · ${step.message}`}
              </li>
            ))}
          </ol>
          {ready.moreStepsText !== null && <div style={{ color: secondary }}>{ready.moreStepsText}</div>}
        </div>
      )}
      {ready.nearby.length > 0 && (
        <div data-testid="correlation-dock-nearby" style={{ fontSize: `${sizes.lane}px`, color: secondary }}>
          Also nearby:{" "}
          {ready.nearby.map((entry, index) => (
            <span key={entry.id}>
              {index > 0 ? " · " : ""}
              {entry.entry} ({nearbyReason(entry.reason)})
            </span>
          ))}
          {ready.moreNearbyText !== null ? ` · ${ready.moreNearbyText}` : ""}
        </div>
      )}
    </>
  );
}
