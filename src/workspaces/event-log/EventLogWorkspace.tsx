import {
  useCallback,
  useMemo,
  useRef,
  useState,
  useEffect,
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
import { EventDiagnosisPanel } from "./EventDiagnosisPanel";
import { EvtxTimeline } from "./EvtxTimeline";
import { UnifiedTimelineView } from "./UnifiedTimelineView";
import { EvtxDetailPane } from "./EvtxDetailPane";
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
  type EvtxRailTabId,
  type EvtxViewId,
} from "./evtx-layout-store";
import { selectVisibleRecords } from "./evtx-filter";
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

const DEFAULT_DETAIL_HEIGHT = 300;
const MIN_DETAIL_HEIGHT = 100;
const MAX_DETAIL_RATIO = 0.7;
const DIAGNOSIS_DEBOUNCE_MS = 75;

const NOT_IMPLEMENTED = "Not implemented in this phase";

/**
 * One entry per workbench view. A later phase adds its view file and changes one line here.
 * `keepAlive` entries stay mounted while another view is active (hidden, not unmounted), so
 * switching away and back keeps scroll position and the unified timeline's page cache.
 */
interface EvtxViewEntry {
  keepAlive: boolean;
  render: () => ReactNode;
}

/** Rail contents by tab (Phase 4 replaces these with the Insights, Chains and Details tabs). */
const RAIL_SLOT_LABELS: Record<EvtxRailTabId, string> = {
  insights: "Insights",
  chains: "Chains",
  details: "Details",
};

/** Dock contents (Phase 11 replaces this with the correlation dock). */
const DOCK_SLOT_LABELS: Record<"correlation", string> = {
  correlation: "Correlation dock",
};

function ViewPlaceholder({ view }: { view: EvtxViewId }) {
  return <RegionPlaceholder title={`${EVTX_VIEW_LABELS[view]} view`} />;
}

function RegionPlaceholder({ title }: { title: string }) {
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
      {`: ${NOT_IMPLEMENTED}.`}
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
  const selectedRecordId = useEvtxStore((s) => s.selectedRecordId);
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
  const railTab = useEvtxLayoutStore((s) => s.railTab);
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

  const [detailHeight, setDetailHeight] = useState(DEFAULT_DETAIL_HEIGHT);
  const resizeRef = useRef<{ startY: number; startHeight: number } | null>(
    null,
  );

  useEffect(() => {
    const onMouseMove = (e: MouseEvent) => {
      if (!resizeRef.current) return;
      const delta = resizeRef.current.startY - e.clientY;
      const newHeight = Math.max(
        MIN_DETAIL_HEIGHT,
        Math.min(
          resizeRef.current.startHeight + delta,
          window.innerHeight * MAX_DETAIL_RATIO,
        ),
      );
      setDetailHeight(newHeight);
    };
    const onMouseUp = () => {
      if (resizeRef.current) {
        resizeRef.current = null;
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
      }
    };
    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
    return () => {
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
      if (resizeRef.current) {
        resizeRef.current = null;
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
      }
    };
  }, []);
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

  // Today's stack: the unified timeline, the record grid and the detail pane. Phase 4 moves the
  // detail pane and the diagnosis card into the rail; Phase 7 restyles the grid.
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

      {/* Resize handle + detail pane */}
      {selectedRecordId != null && (
        <>
          <div
            style={{
              height: "4px",
              cursor: "row-resize",
              backgroundColor: tokens.colorNeutralStroke2,
              flexShrink: 0,
            }}
            onMouseDown={(e) => {
              e.preventDefault();
              resizeRef.current = {
                startY: e.clientY,
                startHeight: detailHeight,
              };
              document.body.style.cursor = "row-resize";
              document.body.style.userSelect = "none";
            }}
          />
          <div
            style={{
              height: `${detailHeight}px`,
              flexShrink: 0,
              overflow: "hidden",
            }}
          >
            <EvtxDetailPane />
          </div>
        </>
      )}
    </>
  );

  const views: Record<EvtxViewId, EvtxViewEntry> = {
    table: { keepAlive: true, render: renderTableView },
    grouped: { keepAlive: false, render: () => <ViewPlaceholder view="grouped" /> },
    timeline: { keepAlive: false, render: () => <ViewPlaceholder view="timeline" /> },
    charts: { keepAlive: false, render: () => <ViewPlaceholder view="charts" /> },
    correlation: { keepAlive: false, render: () => <ViewPlaceholder view="correlation" /> },
  };

  if (!hasData && !isLoading) {
    return <SourcePicker />;
  }

  if (isLoading && records.length === 0) {
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
      <EvtxCoverageBanner />
      <EventDiagnosisPanel summary={diagnosis} />

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
            style={{ display: panels.channels ? "flex" : "none", flexShrink: 0 }}
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
                  {entry.render()}
                </div>
              );
            })}
          </div>

          {panels.dock && (
            <div
              data-evtx-region="dock"
              style={{
                position: "relative",
                height: `${effectiveDockHeight}px`,
                flexShrink: 0,
                borderTop: `1px solid ${tokens.colorNeutralStroke1}`,
                backgroundColor: tokens.colorNeutralBackground2,
                overflow: "auto",
              }}
            >
              <EvtxResizeHandle
                orientation="horizontal"
                label="Resize correlation dock"
                value={effectiveDockHeight}
                min={MIN_DOCK_HEIGHT}
                max={dockMax}
                direction={-1}
                onChange={(next) => setDockHeight(next, window.innerHeight)}
              />
              <RegionPlaceholder title={DOCK_SLOT_LABELS.correlation} />
            </div>
          )}
        </div>

        {/* Hidden, not unmounted, so the rail's future tab state survives a toggle. */}
        <aside
          data-evtx-region="rail"
          aria-label="Insights rail"
          style={{
            display: panels.insights ? "block" : "none",
            position: "relative",
            width: `${railWidth}px`,
            flexShrink: 0,
            boxSizing: "border-box",
            borderLeft: `1px solid ${tokens.colorNeutralStroke2}`,
            backgroundColor: tokens.colorNeutralBackground2,
            overflowY: "auto",
          }}
        >
          <EvtxResizeHandle
            orientation="vertical"
            label="Resize insights rail"
            value={railWidth}
            min={MIN_RAIL_WIDTH}
            max={MAX_RAIL_WIDTH}
            direction={-1}
            onChange={setRailWidth}
          />
          <RegionPlaceholder title={RAIL_SLOT_LABELS[railTab]} />
        </aside>
      </div>
    </div>
  );
}
