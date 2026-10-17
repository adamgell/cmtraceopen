import {
  useCallback,
  useMemo,
  useRef,
  useState,
  useEffect,
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
import { useEvtxStore } from "./evtx-store";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import { getLogListMetrics } from "../../lib/log-accessibility";
import type { LogEntry } from "../../types/log";
import { SourcePicker } from "./SourcePicker";
import { ChannelPicker } from "./ChannelPicker";
import { EvtxFilterBar } from "./EvtxFilterBar";
import { EvtxCoverageBanner } from "./EvtxCoverageBanner";
import { EvtxTimeline } from "./EvtxTimeline";
import { UnifiedTimelineView } from "./UnifiedTimelineView";
import { EvtxInsightsRail } from "./EvtxInsightsRail";
import { EvtxViewBar } from "./EvtxViewBar";
import { EvtxResizeHandle } from "./EvtxResizeHandle";
import {
  EVTX_VIEW_LABELS,
  EVTX_VIEW_PANEL_ID,
  evtxViewTabId,
  MAX_RAIL_WIDTH,
  MIN_DOCK_HEIGHT,
  MIN_RAIL_WIDTH,
  maxDockHeightFor,
  useEvtxLayoutStore,
  type EvtxViewId,
} from "./evtx-layout-store";
import { selectVisibleRecords } from "./evtx-filter";
import { scopeLogEntries } from "./unified-timeline";
import { coverageDisclosureKeys, mergeDiagnosisCoverageGaps } from "./evtx-coverage";
import { CoverageClaimsProvider } from "./evtx-coverage-claims";
import type {
  DiagnosisSummary,
  EvtxCoverageGap,
  EvtxRecord,
} from "./types";
import {
  buildEventLogAnalysisSession,
  EventLogAnalysisCancelled,
} from "./event-analysis-session";

const DIAGNOSIS_DEBOUNCE_MS = 75;

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

/** Dock contents. Off in this phase; Phase 11 replaces the entry with the correlation dock. */
const DOCK_SLOTS: Record<"correlation", () => ReactNode> = {
  correlation: () => <RegionPlaceholder title="Correlation dock" />,
};

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
 * The tabpanel the Layout tablist controls. Each view renders inside its own Suspense boundary, so
 * a lazily loaded view shows a fallback here while the tablist and the other regions stay mounted.
 */
export function EvtxViewHost({
  views,
  activeView,
}: {
  views: Record<EvtxViewId, EvtxViewEntry>;
  activeView: EvtxViewId;
}) {
  return (
    <div
      role="tabpanel"
      id={EVTX_VIEW_PANEL_ID}
      aria-labelledby={evtxViewTabId(activeView)}
      style={{
        flex: 1,
        minHeight: 0,
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
  const timeZoneMode = useEvtxStore((s) => s.timeZoneMode);
  const columnOrder = useEvtxStore((s) => s.columnConfig.order);
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
  const visibleRecords = useMemo(
    () =>
      isLoading
        ? []
        : selectVisibleRecords({
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
          }),
    [
      isLoading,
      records,
      selectedChannels,
      filterLevels,
      filterEventIds,
      filterSearch,
      quickFilter,
      columnOrder,
      timeZoneMode,
      timeWindow,
      nowEpoch,
    ],
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
  // The shared keys of the gaps `diagnosis` was built from (its snapshot's input), set and cleared
  // with it, so the rail claims what that summary covers and never a gap that arrived since.
  const [diagnosisCoverageKeys, setDiagnosisCoverageKeys] =
    useState<ReadonlySet<string> | null>(null);
  const [diagnosisError, setDiagnosisError] = useState<string | null>(null);
  const [analysisStatus, setAnalysisStatus] =
    useState<EventLogAnalysisSessionStatus | null>(null);
  const [initialTimelinePage, setInitialTimelinePage] =
    useState<EventLogAnalysisTimelinePage | null>(null);
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
  const railWidth = useEvtxLayoutStore((s) => s.railWidth);
  const dockHeight = useEvtxLayoutStore((s) => s.dockHeight);
  const setRailWidth = useEvtxLayoutStore((s) => s.setRailWidth);
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
    setDiagnosisCoverageKeys(null);
    setDiagnosisError(null);
    setAnalysisStatus(null);
    setInitialTimelinePage(null);
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
          setDiagnosis(result.diagnosis);
          setDiagnosisCoverageKeys(coverageDisclosureKeys(snapshot.coverageGaps));
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
          setDiagnosisCoverageKeys(null);
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

  const hasData =
    scopedLogEntries.length > 0 ||
    (sourceMode !== null &&
      (records.length > 0 ||
        channels.length > 0 ||
        coverageGaps.length > 0 ||
        diagnosisCoverageGaps.length > 0));

  // Today's stack: the unified timeline and the record grid. The diagnosis and the record details
  // live in the rail; Phases 10 and 11 move the unified timeline; Phase 7 restyles the grid.
  const renderTableView = () => (
    <>
      <div
        style={{
          height: "320px",
          minHeight: "240px",
          maxHeight: "50vh",
          flexShrink: 0,
          overflowY: "auto",
          overflowX: "hidden",
        }}
      >
        <UnifiedTimelineView
          key={
            analysisStatus === null
              ? "pending"
              : `${analysisStatus.sessionId}:${analysisStatus.revision}`
          }
          status={analysisStatus}
          initialPage={initialTimelinePage}
          loadPage={loadTimelinePage}
          pending={timelinePending}
        />
      </div>
      <div style={{ flex: 1, overflow: "hidden" }}>
        <EvtxTimeline nowEpoch={nowEpoch} />
      </div>
    </>
  );

  const views: Record<EvtxViewId, EvtxViewEntry> = {
    table: { keepAlive: true, render: renderTableView },
    grouped: { keepAlive: false, render: () => <ViewPlaceholder view="grouped" /> },
    timeline: { keepAlive: false, render: () => <ViewPlaceholder view="timeline" /> },
    charts: { keepAlive: false, render: () => <ViewPlaceholder view="charts" /> },
    correlation: { keepAlive: false, render: () => <ViewPlaceholder view="correlation" /> },
  };

  // The one polite live region for newly reported gaps, whichever surface shows them. It is the
  // first child of every branch below, so it stays mounted through the picker and the spinner and
  // is already in place when a load's first gaps arrive.
  const announcer = <EvtxCoverageBanner variant="announcer" />;

  if (!hasData && !isLoading) {
    return (
      <>
        {announcer}
        <SourcePicker />
      </>
    );
  }

  if (isLoading && records.length === 0) {
    return (
      <>
        {announcer}
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
      </>
    );
  }

  const workspace = (
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
      {/* The gaps no other surface shows (evtx-coverage-claims.tsx): the rail claims what its
          coverage note and its coverage disclosure render, while they are on screen. */}
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
          style={{
            flex: 1,
            minWidth: 0,
            display: "flex",
            flexDirection: "column",
            overflow: "hidden",
            backgroundColor: tokens.colorNeutralBackground1,
          }}
        >
          <EvtxViewHost views={views} activeView={activeView} />

          {/* Hidden, not unmounted, so the dock's future state survives a toggle. */}
          <div
            id={EVTX_DOCK_ID}
            data-evtx-region="dock"
            style={{
              display: panels.dock ? "block" : "none",
              position: "relative",
              height: `${effectiveDockHeight}px`,
              flexShrink: 0,
              boxSizing: "border-box",
              borderTop: `1px solid ${tokens.colorNeutralStroke1}`,
              backgroundColor: tokens.colorNeutralBackground2,
            }}
          >
            <EvtxResizeHandle
              orientation="horizontal"
              edge="start"
              label="Resize correlation dock"
              controls={EVTX_DOCK_ID}
              value={effectiveDockHeight}
              min={MIN_DOCK_HEIGHT}
              max={dockMax}
              direction={-1}
              onChange={(next) => setDockHeight(next, window.innerHeight)}
            />
            <div style={{ height: "100%", overflow: "auto" }}>{DOCK_SLOTS.correlation()}</div>
          </div>
        </div>

        {/* Hidden, not unmounted, so the rail's tab and scroll state survive a toggle. */}
        <aside
          id={EVTX_RAIL_ID}
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
            value={railWidth}
            min={MIN_RAIL_WIDTH}
            max={MAX_RAIL_WIDTH}
            direction={-1}
            onChange={setRailWidth}
          />
          {/* The rail scrolls its own tab bodies under a fixed tablist, so this wrapper does not. */}
          <div style={{ height: "100%", display: "flex", flexDirection: "column", overflow: "hidden" }}>
            <EvtxInsightsRail
              summary={diagnosis}
              records={analysisRecords}
              pending={timelinePending}
              error={diagnosisError}
              summaryCoverageKeys={diagnosisCoverageKeys}
            />
          </div>
        </aside>
      </div>
    </div>
  );

  return (
    <>
      {announcer}
      <CoverageClaimsProvider>{workspace}</CoverageClaimsProvider>
    </>
  );
}
