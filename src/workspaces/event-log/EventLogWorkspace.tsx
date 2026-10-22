import {
  lazy,
  useCallback,
  useMemo,
  useRef,
  useState,
  useEffect,
  useLayoutEffect,
  Suspense,
  type ReactNode,
} from "react";
import { ProgressBar, Spinner, tokens } from "@fluentui/react-components";
import {
  closeEventLogAnalysisSession,
  queryEventLogAnalysisTimeline,
  type EventLogAnalysisSessionStatus,
  type EventLogAnalysisTimelinePage,
} from "../../lib/commands";
import { sourceKeyOf, useEvtxStore } from "./evtx-store";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import { getLogListMetrics } from "../../lib/log-accessibility";
import type { LogEntry } from "../../types/log";
import { SourcePicker } from "./SourcePicker";
import { ChannelPicker } from "./ChannelPicker";
import { EvtxFilterBar } from "./EvtxFilterBar";
import { EvtxFilterChips } from "./EvtxFilterChips";
import { EvtxHistogram } from "./EvtxHistogram";
import { EvtxCoverageBanner } from "./EvtxCoverageBanner";
import { EvtxTimeline } from "./EvtxTimeline";
import { UnifiedTimelineView } from "./UnifiedTimelineView";
import {
  DOCK_MIN_HEIGHT_PX,
  dockHandleBounds,
  gridRecordRowPx,
  tableGridFloorPx,
  timelineStripHeightPx,
  viewMinHeightPx,
} from "./evtx-main-column-layout";
import { EvtxInsightsRail } from "./EvtxInsightsRail";
import { EvtxViewBar } from "./EvtxViewBar";
import { EvtxResizeHandle } from "./EvtxResizeHandle";
import { effectiveResizeRange, proposeResize, useRowCappedSize } from "./use-row-capped-size";
import {
  EVTX_VIEW_LABELS,
  EVTX_VIEW_PANEL_ID,
  evtxViewTabId,
  MAX_RAIL_WIDTH,
  MIN_DOCK_HEIGHT,
  MIN_RAIL_WIDTH,
  correlationItemsNeeded,
  maxDockHeightFor,
  useEvtxLayoutStore,
  type EvtxViewId,
} from "./evtx-layout-store";
import {
  countHiddenForWantOfTimestamp,
  selectVisibleRecords,
  type VisibleRecordsInput,
} from "./evtx-filter";
import { scopeLogEntries } from "./unified-timeline";
import { mergeDiagnosisCoverageGaps } from "./evtx-coverage";
import type {
  DiagnosisSummary,
  EvtxCoverageGap,
  EvtxRecord,
} from "./types";
import {
  buildEventLogAnalysisSession,
  EventLogAnalysisCancelled,
} from "./event-analysis-session";
import type { ScopeDisclosureInput } from "./evtx-correlation-copy";
import { EvtxCorrelationProvider, useEvtxCorrelation } from "./useEvtxCorrelation";
import { EvtxAnalysisSessionProvider } from "./evtx-analysis-session";
import { sessionKeyOf } from "./evtx-correlation-load";

// The view is lazy (spec 11); the hook and the provider above it are not, because the Insights
// card and later the status bar read the same shared data whether or not this view is open.
const EvtxCorrelationView = lazy(() => import("./EvtxCorrelationView"));
// The dock is lazy too (spec 11): its lanes, model and copy stay out of the entry chunk for a user
// who keeps the dock closed. It is mounted only while the dock is shown, so a hidden dock reads
// nothing (R5).
const EvtxCorrelationDock = lazy(() => import("./EvtxCorrelationDock"));

const DIAGNOSIS_DEBOUNCE_MS = 75;

const NO_EVENTS: EvtxRecord[] = [];

const NOT_IMPLEMENTED = "Not implemented in this phase";

/**
 * One entry per workbench view. A later phase adds its view file and changes one line here; a
 * lazily loaded view (`React.lazy`) works as-is because every render sits in a Suspense boundary.
 * `keepAlive` entries stay mounted while another view is active (hidden, not unmounted), so
 * switching away and back keeps the component and the unified timeline's page cache.
 */
export interface EvtxViewEntry {
  keepAlive: boolean;
  render: () => ReactNode;
}

const EVTX_RAIL_ID = "evtx-insights-rail";
const EVTX_DOCK_ID = "evtx-correlation-dock";

function ViewPlaceholder({ view }: { view: EvtxViewId }) {
  return <RegionPlaceholder title={`${EVTX_VIEW_LABELS[view]} view`} />;
}

function RegionPlaceholder({ title, loading }: { title: string; loading?: boolean }) {
  const f = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(f), [f]);
  return (
    <div
      role="status"
      style={{
        padding: "12px",
        fontSize: `${Math.max(10, metrics.fontSize - 2)}px`,
        color: tokens.colorNeutralForeground3,
      }}
    >
      <strong style={{ color: tokens.colorNeutralForeground2 }}>{title}</strong>
      {loading ? "..." : `: ${NOT_IMPLEMENTED}.`}
    </div>
  );
}

/**
 * The dock as it is rendered: its own box, and the main column's height, both measured. The chosen
 * height is only what the dock asks for; the Table's floor can render it smaller, and the resize
 * handle has to speak for what is there. Null until measured (and where nothing observes layout,
 * as in jsdom), when the chosen height stands in.
 */
function useDockMeasure(
  slot: HTMLElement | null,
  main: HTMLElement | null,
): { renderedHeight: number | null; mainHeight: number | null } {
  const [measure, setMeasure] = useState<{ renderedHeight: number | null; mainHeight: number | null }>({
    renderedHeight: null,
    mainHeight: null,
  });
  useLayoutEffect(() => {
    if (slot === null || main === null) return;
    const read = () => {
      const rendered = slot.getBoundingClientRect().height;
      const mainHeight = main.clientHeight;
      const next = {
        renderedHeight: rendered > 0 ? rendered : null,
        mainHeight: mainHeight > 0 ? mainHeight : null,
      };
      setMeasure((previous) =>
        previous.renderedHeight === next.renderedHeight && previous.mainHeight === next.mainHeight
          ? previous
          : next,
      );
    };
    read();
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(read);
    observer.observe(slot);
    observer.observe(main);
    return () => observer.disconnect();
  }, [slot, main]);
  return measure;
}

/**
 * The tabpanel the Layout tablist controls. Each view renders inside its own Suspense boundary, so
 * a lazily loaded view shows a fallback here while the tablist and the other regions stay mounted.
 *
 * `minHeightPx` is the least height the active view keeps (`viewMinHeightPx`: the Table's strip and
 * grid floor, the Correlation view's list and detail header, or the generic minimum). The panel is
 * a flex item of the main column, and a flex item that is only `flex: 1` shrinks to nothing; with
 * a floor it holds, and the column scrolls instead (evtx-main-column-layout.ts).
 */
export function EvtxViewHost({
  views,
  activeView,
  minHeightPx = 0,
}: {
  views: Record<EvtxViewId, EvtxViewEntry>;
  activeView: EvtxViewId;
  minHeightPx?: number;
}) {
  return (
    <div
      role="tabpanel"
      id={EVTX_VIEW_PANEL_ID}
      aria-labelledby={evtxViewTabId(activeView)}
      style={{
        flex: 1,
        minHeight: `${minHeightPx}px`,
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}
    >
      {(Object.keys(views) as EvtxViewId[]).map((view) => {
        const entry = views[view];
        const active = view === activeView;
        if (!active && !entry.keepAlive) return null;
        return (
          <div
            key={view}
            data-evtx-view={view}
            style={{
              flex: 1,
              minHeight: 0,
              display: active ? "flex" : "none",
              flexDirection: "column",
              overflow: "hidden",
            }}
          >
            <Suspense fallback={<RegionPlaceholder title="Loading view" loading />}>
              {entry.render()}
            </Suspense>
          </div>
        );
      })}
    </div>
  );
}

interface EventLogAnalysisSnapshot {
  revision: number;
  readyAt: number;
  records: EvtxRecord[];
  entries: LogEntry[];
  coverageGaps: EvtxCoverageGap[];
}

interface EventLogAnalysisPump {
  mounted: boolean;
  revision: number;
  running: boolean;
  pending: EventLogAnalysisSnapshot | null;
  timer: number | null;
  publishedSessionId: string | null;
}

/** A control the operator types into or picks from: Escape there belongs to the control. */
function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  if (["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName)) return true;
  return ["textbox", "searchbox", "combobox", "spinbutton"].includes(target.getAttribute("role") ?? "");
}

/** A modal dialog is open, and Escape is its to spend. */
function isModalDialogOpen(): boolean {
  return document.querySelector('[aria-modal="true"], dialog[open]') !== null;
}

/**
 * Escape clears the transient time range (spec section 9). One window listener for the mounted
 * workspace, so it works wherever focus sits in it. It steps aside for anything that has already
 * used the key: a popover or menu that handled it (`defaultPrevented`), a control being typed into,
 * and an open modal dialog. It clears the range only: the record scope is cleared from its chip.
 */
function useClearTimeRangeOnEscape(): void {
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Escape" || event.defaultPrevented) return;
      if (isEditableTarget(event.target) || isModalDialogOpen()) return;
      const { timeRange, setTimeRange } = useEvtxStore.getState();
      if (timeRange === null) return;
      setTimeRange(null);
      event.preventDefault();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);
}

function hasSameRecordMembership(
  left: readonly EvtxRecord[],
  right: readonly EvtxRecord[],
): boolean {
  return (
    left === right ||
    (left.length === right.length &&
      right.every((record, index) => record === left[index]))
  );
}

function useStableRecordMembership(records: EvtxRecord[]): EvtxRecord[] {
  const [stableRecords, setStableRecords] = useState(records);
  const stableMembership = hasSameRecordMembership(stableRecords, records);

  useEffect(() => {
    if (!stableMembership) {
      setStableRecords(records);
    }
  }, [records, stableMembership]);

  return stableMembership ? stableRecords : records;
}

export function EventLogWorkspace() {
  useClearTimeRangeOnEscape();
  const sourceMode = useEvtxStore((s) => s.sourceMode);
  const timeWindow = useEvtxStore((s) => s.timeWindow);
  const isLoading = useEvtxStore((s) => s.isLoading);
  const loadError = useEvtxStore((s) => s.loadError);
  const logEntries = useLogStore((s) => s.entries);
  const activeLogSource = useLogStore((s) => s.activeSource);
  const logSourceOpenMode = useLogStore((s) => s.sourceOpenMode);
  const currentPlatform = useUiStore((s) => s.currentPlatform);
  const scopedLogEntries = useMemo(
    () =>
      scopeLogEntries(
        logEntries,
        activeLogSource,
        logSourceOpenMode,
        currentPlatform,
      ),
    [logEntries, activeLogSource, logSourceOpenMode, currentPlatform],
  );
  const records = useEvtxStore((s) => s.records);
  const selectedChannels = useEvtxStore((s) => s.selectedChannels);
  const filterLevels = useEvtxStore((s) => s.filterLevels);
  const filterEventIds = useEvtxStore((s) => s.filterEventIds);
  const filterSearch = useEvtxStore((s) => s.filterSearch);
  const quickFilter = useEvtxStore((s) => s.quickFilter);
  const timeRange = useEvtxStore((s) => s.timeRange);
  const recordScope = useEvtxStore((s) => s.recordScope);
  const timeZoneMode = useEvtxStore((s) => s.timeZoneMode);
  const columnOrder = useEvtxStore((s) => s.columnConfig.order);
  // The clock a relative time window (1 h to 30 d) is measured from. It is read again when what the
  // operator is looking at changes, and NOT when a transient criterion (a time range or a record
  // scope) is set or cleared: brushing must not move the start of a "last 24 hours" window, or the
  // histogram a brush selects from would shift under the brush.
  const nowEpoch = useMemo(
    () => Date.now(),
    [
      records,
      selectedChannels,
      filterLevels,
      filterEventIds,
      filterSearch,
      quickFilter,
      columnOrder,
      timeZoneMode,
      timeWindow,
      isLoading,
    ],
  );
  // The criteria except the time range: what the histogram charts and the brush selects from
  // (spec 8.5), so brushing never empties its own histogram. Its identity is stable while a range is
  // set and cleared, so neither the histogram nor this pass reacts to the brush.
  const contextInput = useMemo<VisibleRecordsInput>(
    () => ({
      records,
      selectedChannels,
      filterLevels,
      nowEpoch,
      filterEventIds,
      filterSearch,
      quickFilter,
      visibleColumns: columnOrder,
      timeZoneMode,
      timeWindow,
      timeRange: null,
      scopeRecords: recordScope?.records ?? null,
    }),
    [
      records,
      selectedChannels,
      filterLevels,
      filterEventIds,
      filterSearch,
      quickFilter,
      columnOrder,
      timeZoneMode,
      timeWindow,
      recordScope,
      nowEpoch,
    ],
  );
  // One input for every pass over the records, so the chip row's count cannot read another set.
  const visibleInput = useMemo<VisibleRecordsInput>(
    () => ({ ...contextInput, timeRange }),
    [contextInput, timeRange],
  );
  const contextRecords = useMemo(
    () => (isLoading ? NO_EVENTS : selectVisibleRecords(contextInput)),
    [isLoading, contextInput],
  );
  // Without a range the visible set IS the context, so there is one pass and one array; with one it
  // is a pass of its own, by the same selector the grid and the export use.
  const visibleRecords = useMemo(
    () =>
      isLoading ? NO_EVENTS : timeRange === null ? contextRecords : selectVisibleRecords(visibleInput),
    [isLoading, timeRange, contextRecords, visibleInput],
  );
  // Events a time range hides only because they carry no usable timestamp (spec 8.4 chip tooltip).
  const untimedHiddenCount = useMemo(
    () => (isLoading ? 0 : countHiddenForWantOfTimestamp(visibleInput)),
    [isLoading, visibleInput],
  );
  const analysisRecords = useStableRecordMembership(visibleRecords);
  const channels = useEvtxStore((s) => s.channels);
  const coverageGaps = useEvtxStore((s) => s.coverageGaps);
  const coverageDetails = useEvtxStore((s) => s.coverageDetails);
  const sourceManifest = useEvtxStore((s) => s.sourceManifest);
  const tailCoverageGaps = useEvtxStore((s) => s.tailCoverageGaps);
  const diagnosisCoverageGaps = useMemo(
    () =>
      mergeDiagnosisCoverageGaps(
        coverageDetails,
        sourceManifest?.coverage ?? [],
        coverageGaps,
        tailCoverageGaps,
      ),
    [coverageDetails, sourceManifest, coverageGaps, tailCoverageGaps],
  );

  const [diagnosis, setDiagnosis] = useState<DiagnosisSummary | null>(null);
  const [diagnosisError, setDiagnosisError] = useState<string | null>(null);
  const [analysisStatus, setAnalysisStatus] =
    useState<EventLogAnalysisSessionStatus | null>(null);
  const [initialTimelinePage, setInitialTimelinePage] =
    useState<EventLogAnalysisTimelinePage | null>(null);
  // What the published session was built from, set in the same batch as its status and page so
  // the correlation hook stores it with the models it builds from them.
  const [analysisScope, setAnalysisScope] = useState<ScopeDisclosureInput | null>(null);
  const [timelinePending, setTimelinePending] = useState(false);
  const [timelineError, setTimelineError] = useState<string | null>(null);
  const analysisPumpRef = useRef<EventLogAnalysisPump>({
    mounted: false,
    revision: 0,
    running: false,
    pending: null,
    timer: null,
    publishedSessionId: null,
  });

  const activeView = useEvtxLayoutStore((s) => s.activeView);
  const panels = useEvtxLayoutStore((s) => s.panels);
  // The entries are read only for a surface that lists them: the layout store's one rule.
  const correlationEntriesNeeded = useEvtxLayoutStore(correlationItemsNeeded);
  const railWidth = useEvtxLayoutStore((s) => s.railWidth);
  const dockHeight = useEvtxLayoutStore((s) => s.dockHeight);
  const dockCollapsed = useEvtxLayoutStore((s) => s.dockCollapsed);
  const setRailWidth = useEvtxLayoutStore((s) => s.setRailWidth);
  // The rail is capped to a share of the body row (see its style), so the handle reports and
  // steps from the width actually rendered and its maximum never exceeds the cap.
  const { ref: railRef, ...railMeasure } = useRowCappedSize(1, railWidth);
  const railRange = effectiveResizeRange(railWidth, MIN_RAIL_WIDTH, MAX_RAIL_WIDTH, railMeasure);

  const setDockHeight = useEvtxLayoutStore((s) => s.setDockHeight);
  const [viewportHeight, setViewportHeight] = useState(() => window.innerHeight);
  useEffect(() => {
    const onResize = () => setViewportHeight(window.innerHeight);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);
  // The ceiling is half the viewport and the viewport changes, so it is applied in pixels here
  // rather than stored.
  const dockMax = maxDockHeightFor(viewportHeight);
  const effectiveDockHeight = Math.min(Math.max(dockHeight, MIN_DOCK_HEIGHT), dockMax);
  // The floors of the main column (evtx-main-column-layout.ts): the Table grid keeps five rows, the
  // dock gives way down to its header and one lane, and the column scrolls when they do not fit.
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const gridRowPx = gridRecordRowPx(getLogListMetrics(logListFontSize).rowHeight, columnOrder);
  const tableGridFloor = tableGridFloorPx(gridRowPx);
  const dockMin = DOCK_MIN_HEIGHT_PX;
  const viewMin = viewMinHeightPx({
    view: activeView,
    gridRowPx,
    windowHeight: viewportHeight,
    logListFontSize,
  });
  // The dock's resize handle speaks for the dock as rendered: its measured height, and what the
  // column leaves it after the active view's floor, never above the store's maximum.
  const [dockSlot, setDockSlot] = useState<HTMLElement | null>(null);
  const [mainColumn, setMainColumn] = useState<HTMLElement | null>(null);
  const dockMeasure = useDockMeasure(dockSlot, mainColumn);
  const dockHandle = dockHandleBounds({
    renderedHeight: dockMeasure.renderedHeight ?? effectiveDockHeight,
    availableHeight: dockMeasure.mainHeight === null ? Number.POSITIVE_INFINITY : dockMeasure.mainHeight - viewMin,
    storeMax: dockMax,
  });
  // A step is taken from the rendered height. At a bound it changes nothing, and the handle's value
  // already says it is there; the stored height is not rewritten by a step that moves nothing.
  const resizeDock = (next: number) => {
    const target = Math.min(dockHandle.max, Math.max(dockHandle.min, Math.round(next)));
    if (target === Math.round(dockHandle.value)) return;
    setDockHeight(target, window.innerHeight);
  };

  useEffect(() => {
    const pump = analysisPumpRef.current;
    pump.mounted = true;
    return () => {
      pump.mounted = false;
      pump.revision += 1;
      pump.pending = null;
      if (pump.timer !== null) window.clearTimeout(pump.timer);
      pump.timer = null;
      if (pump.publishedSessionId !== null) {
        void closeEventLogAnalysisSession(pump.publishedSessionId).catch(
          () => undefined,
        );
        pump.publishedSessionId = null;
      }
    };
  }, []);

  useEffect(() => {
    const pump = analysisPumpRef.current;
    const revision = pump.revision + 1;
    pump.revision = revision;
    pump.pending = null;
    if (pump.timer !== null) window.clearTimeout(pump.timer);
    pump.timer = null;
    if (pump.publishedSessionId !== null) {
      void closeEventLogAnalysisSession(pump.publishedSessionId).catch(
        () => undefined,
      );
      pump.publishedSessionId = null;
    }

    setDiagnosis(null);
    setDiagnosisError(null);
    setAnalysisStatus(null);
    setInitialTimelinePage(null);
    setAnalysisScope(null);
    setTimelineError(null);

    if (isLoading) {
      setTimelinePending(true);
      return;
    }

    if (
      analysisRecords.length === 0 &&
      scopedLogEntries.length === 0 &&
      diagnosisCoverageGaps.length === 0
    ) {
      setTimelinePending(false);
      return;
    }

    setTimelinePending(true);
    pump.pending = {
      revision,
      readyAt: Date.now() + DIAGNOSIS_DEBOUNCE_MS,
      records: analysisRecords,
      entries: scopedLogEntries,
      coverageGaps: diagnosisCoverageGaps,
    };

    function schedule(): void {
      if (
        !pump.mounted ||
        pump.running ||
        pump.pending === null ||
        pump.timer !== null
      ) {
        return;
      }
      const delay = Math.max(pump.pending.readyAt - Date.now(), 0);
      pump.timer = window.setTimeout(run, delay);
    }

    function run(): void {
      pump.timer = null;
      if (!pump.mounted || pump.running || pump.pending === null) return;
      const snapshot = pump.pending;
      pump.pending = null;
      pump.running = true;
      void buildEventLogAnalysisSession({
        records: snapshot.records,
        entries: snapshot.entries,
        coverageGaps: snapshot.coverageGaps,
        cancelled: () =>
          !pump.mounted || pump.revision !== snapshot.revision,
      })
        .then((result) => {
          if (!pump.mounted || pump.revision !== snapshot.revision) {
            void closeEventLogAnalysisSession(result.status.sessionId).catch(
              () => undefined,
            );
            return;
          }
          pump.publishedSessionId = result.status.sessionId;
          setAnalysisStatus(result.status);
          setInitialTimelinePage(result.initialPage);
          // The one scope of this session, for the Correlation view and the Insights rail alike.
          // visible and the text logs are what the session was BUILT from (the snapshot); loaded is
          // what the store holds NOW, at the publish, in the same batch as the status and the page:
          // an event the filter hides that arrived during the build is loaded, and the session
          // was not built from it, which is exactly what makes the view narrowed.
          setAnalysisScope({
            visibleCount: snapshot.records.length,
            loadedCount: useEvtxStore.getState().records.length,
            textLogCount: snapshot.entries.length,
          });
          setDiagnosis(result.diagnosis);
          setTimelinePending(false);
        })
        .catch((error: unknown) => {
          if (
            !pump.mounted ||
            pump.revision !== snapshot.revision ||
            error instanceof EventLogAnalysisCancelled
          ) {
            return;
          }
          const message =
            error instanceof Error ? error.message : String(error);
          setTimelinePending(false);
          setDiagnosis(null);
          setDiagnosisError(
            `Operational diagnosis could not be built: ${message}`,
          );
          setTimelineError(`Unified timeline could not be built: ${message}`);
        })
        .finally(() => {
          pump.running = false;
          schedule();
        });
    }

    schedule();
  }, [
    analysisRecords,
    diagnosisCoverageGaps,
    scopedLogEntries,
    isLoading,
  ]);

  // One shared correlation model for the Correlation view, the Insights card, the Chains tab and the
  // later charts tile and status bar. `initialPage` is the STATE value: one object for the life of a
  // session, because the hook keys what it has loaded on it (a fresh object per render would
  // restart it every time). Items are scanned only while the Correlation view is the one shown or
  // the Chains tab is the one the visible rail shows; counts-only consumers never cause a scan.
  const correlation = useEvtxCorrelation({
    status: analysisStatus,
    initialPage: initialTimelinePage,
    pending: timelinePending,
    scope: analysisScope,
    needItems: correlationEntriesNeeded,
  });

  const loadTimelinePage = useCallback(
    async (offset: number, limit: number) => {
      if (analysisStatus === null) {
        throw new Error("The event-log analysis session is not ready.");
      }
      const page = await queryEventLogAnalysisTimeline(
        analysisStatus.sessionId,
        offset,
        limit,
      );
      if (page.revision !== analysisStatus.revision) {
        throw new Error("The event-log analysis session changed while paging.");
      }
      return page;
    },
    [analysisStatus],
  );

  // The full-screen spinner is for a source's first load only: until a load has completed for the
  // current source. A later refresh (a live level or Event ID change empties the records and
  // reloads the loaded channels) keeps the view bar, filter row, chip row, channel pane and rail
  // mounted, so the control that was just used keeps its focus, an open popover stays open, and the
  // filter row shows its own busy state. That holds when the first load found nothing, which is
  // when the operator is most likely to widen a filter. The store records which source a completed
  // load belonged to, in the same tick the load ends, so a replayed change that starts reading
  // straight away cannot be rendered before it is known that the first load finished.
  const remoteMachine = useEvtxStore((s) => s.remoteMachine);
  const sourcePaths = useEvtxStore((s) => s.sourcePaths);
  const completedSourceKey = useEvtxStore((s) => s.completedSourceKey);
  const sourceKey = sourceKeyOf({ sourceMode, remoteMachine, sourcePaths });
  const firstLoadDone = sourceKey !== null && completedSourceKey === sourceKey;

  const hasData =
    scopedLogEntries.length > 0 ||
    (sourceMode !== null &&
      (records.length > 0 ||
        channels.length > 0 ||
        coverageGaps.length > 0 ||
        diagnosisCoverageGaps.length > 0));

  // Today's stack: the unified timeline and the record grid. The diagnosis and the record details
  // live in the rail. The Table keeps the unified timeline, so its unplaced and coverage previews
  // stay; Phase 7 restyles the grid.
  const renderTableView = () => (
    <>
      <div
        style={{
          height: `${timelineStripHeightPx(viewportHeight)}px`,
          flexShrink: 0,
          overflowY: "auto",
          overflowX: "hidden",
        }}
      >
        <UnifiedTimelineView
          key={sessionKeyOf(analysisStatus) ?? "pending"}
          status={analysisStatus}
          initialPage={initialTimelinePage}
          loadPage={loadTimelinePage}
          pending={timelinePending}
        />
      </div>
      <div style={{ flex: 1, minHeight: `${tableGridFloor}px`, overflow: "hidden" }}>
        <EvtxTimeline nowEpoch={nowEpoch} />
      </div>
    </>
  );

  const views: Record<EvtxViewId, EvtxViewEntry> = {
    table: { keepAlive: true, render: renderTableView },
    grouped: { keepAlive: false, render: () => <ViewPlaceholder view="grouped" /> },
    timeline: { keepAlive: false, render: () => <ViewPlaceholder view="timeline" /> },
    charts: { keepAlive: false, render: () => <ViewPlaceholder view="charts" /> },
    correlation: {
      keepAlive: false,
      render: () => <EvtxCorrelationView />,
    },
  };

  if (!hasData && !isLoading) {
    return <SourcePicker />;
  }

  if (isLoading && records.length === 0 && !firstLoadDone) {
    return (
      <div
        style={{
          flex: 1,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <Spinner label="Loading event logs..." />
      </div>
    );
  }

  return (
    <EvtxAnalysisSessionProvider value={analysisStatus}>
      <EvtxCorrelationProvider value={correlation}>
        <div
          style={{
            flex: 1,
            display: "flex",
            flexDirection: "column",
            overflow: "hidden",
          }}
        >
          {loadError && (
            <div
              role="alert"
              style={{
                color: tokens.colorPaletteRedForeground1,
                padding: "4px 12px",
              }}
            >
              {loadError}
            </div>
          )}
          {diagnosisError && (
            <div
              role="alert"
              style={{
                color: tokens.colorPaletteRedForeground1,
                padding: "4px 12px",
              }}
            >
              {diagnosisError}
            </div>
          )}
          {isLoading && <ProgressBar style={{ width: "100%", flexShrink: 0 }} />}
          <EvtxViewBar nowEpoch={nowEpoch} />
          <EvtxFilterBar nowEpoch={nowEpoch} />
          <EvtxFilterChips
            visibleCount={visibleRecords.length}
            loadedCount={records.length}
            untimedHiddenCount={untimedHiddenCount}
          />
          {/* Spec 5.1 order: chip row, histogram, body. It charts the context, not the brushed set. */}
          <EvtxHistogram records={contextRecords} loading={isLoading} />
          <EvtxCoverageBanner />

          {timelineError && (
            <div
              role="alert"
              style={{
                color: tokens.colorPaletteRedForeground1,
                padding: "4px 12px",
              }}
            >
              {timelineError}
            </div>
          )}

          <div
            style={{
              flex: 1,
              display: "flex",
              overflow: "hidden",
            }}
          >
            {/* Hidden, not unmounted: the picker keeps its search text, expanded nodes and width. */}
            {channels.length > 0 && (
              <div
                data-evtx-region="channels"
                // The body row's flex child, so this percentage resolves against the row. The pane
                // inside shrinks to fit (a cap on the pane itself would be relative to this
                // shrink-to-fit wrapper, i.e. to itself).
                style={{
                  display: panels.channels ? "flex" : "none",
                  flexShrink: 0,
                  minWidth: 0,
                  maxWidth: "40%",
                }}
              >
                <ChannelPicker />
              </div>
            )}

            <div
              data-evtx-region="main"
              ref={setMainColumn}
              style={{
                flex: 1,
                minWidth: 0,
                display: "flex",
                flexDirection: "column",
                // Scrolls, not clips: when the Table's floor and the dock's minimum do not fit
                // together, the column is taller than its box and the operator scrolls to the rest.
                overflowX: "hidden",
                overflowY: "auto",
                backgroundColor: tokens.colorNeutralBackground1,
              }}
            >
              <EvtxViewHost
                views={views}
                activeView={activeView}
                minHeightPx={viewMin}
              />

              {/*
                The dock's slot is always here, hidden when the dock is off, but the dock is mounted
                only while it is shown: a hidden dock reads nothing (R5) and its chunk loads on first
                use. Collapsed, the slot is as tall as the dock's header and has no resize handle and
                does not shrink. Expanded, the height the user chose is its basis, and it is the one
                item of the column that gives way: it shrinks down to its header plus one lane once
                the view has its floor, and the column scrolls past that (evtx-main-column-layout.ts).
                The scroll container inside it is a child of this box, whose height is a number of
                pixels (or auto), so it cannot be squeezed to a sliver of its own.
              */}
              <div
                id={EVTX_DOCK_ID}
                data-evtx-region="dock"
                ref={setDockSlot}
                style={{
                  display: panels.dock ? "block" : "none",
                  position: "relative",
                  height: dockCollapsed ? "auto" : `${effectiveDockHeight}px`,
                  flexShrink: dockCollapsed ? 0 : 1,
                  minHeight: dockCollapsed ? undefined : `${dockMin}px`,
                  boxSizing: "border-box",
                  borderTop: `1px solid ${tokens.colorNeutralStroke1}`,
                  backgroundColor: tokens.colorNeutralBackground2,
                }}
              >
                {!dockCollapsed && (
                  <EvtxResizeHandle
                    orientation="horizontal"
                    edge="start"
                    label="Resize correlation dock"
                    controls={EVTX_DOCK_ID}
                    value={dockHandle.value}
                    min={dockHandle.min}
                    max={dockHandle.max}
                    direction={-1}
                    onChange={resizeDock}
                  />
                )}
                <div data-evtx-dock-scroll="" style={{ height: dockCollapsed ? "auto" : "100%", overflow: "auto" }}>
                  {panels.dock && (
                    <Suspense fallback={null}>
                      <EvtxCorrelationDock />
                    </Suspense>
                  )}
                </div>
              </div>
            </div>

            {/* Hidden, not unmounted, so the rail's tab and scroll state survive a toggle. */}
            <aside
              id={EVTX_RAIL_ID}
              ref={railRef}
              data-evtx-region="rail"
              aria-label="Insights rail"
              style={{
                display: panels.insights ? "flex" : "none",
                flexDirection: "column",
                position: "relative",
                width: `${railWidth}px`,
                // The aside is a child of the body row, so this resolves against the row.
                minWidth: 0,
                maxWidth: "40%",
                flexShrink: 0,
                boxSizing: "border-box",
                borderLeft: `1px solid ${tokens.colorNeutralStroke2}`,
                backgroundColor: tokens.colorNeutralBackground2,
              }}
            >
              <EvtxResizeHandle
                orientation="vertical"
                edge="start"
                label="Resize insights rail"
                controls={EVTX_RAIL_ID}
                value={railRange.value}
                min={railRange.min}
                max={railRange.max}
                direction={-1}
                onChange={(next) => {
                  // Same rule as the channel pane: never overwrite the requested width with a value
                  // that leaves the rendered rail unchanged.
                  const proposed = proposeResize(next, railRange);
                  if (proposed !== null) setRailWidth(proposed);
                }}
              />
              {/* The rail scrolls its own tab bodies under a fixed tablist, so this wrapper does not. */}
              <div style={{ height: "100%", display: "flex", flexDirection: "column", overflow: "hidden" }}>
                <EvtxInsightsRail
                  summary={diagnosis}
                  records={analysisRecords}
                  pending={timelinePending}
                  error={diagnosisError}
                  scope={analysisScope}
                />
              </div>
            </aside>
          </div>
        </div>
      </EvtxCorrelationProvider>
    </EvtxAnalysisSessionProvider>
  );
}
