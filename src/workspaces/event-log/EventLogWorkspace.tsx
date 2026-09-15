import { useCallback, useMemo, useRef, useState, useEffect } from "react";
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
import type { LogEntry } from "../../types/log";
import { SourcePicker } from "./SourcePicker";
import { ChannelPicker } from "./ChannelPicker";
import { EvtxFilterBar } from "./EvtxFilterBar";
import { EvtxCoverageBanner } from "./EvtxCoverageBanner";
import { EventDiagnosisPanel } from "./EventDiagnosisPanel";
import { EvtxTimeline } from "./EvtxTimeline";
import { UnifiedTimelineView } from "./UnifiedTimelineView";
import { EvtxDetailPane } from "./EvtxDetailPane";
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

function useStableRecordMembership(records: EvtxRecord[]): EvtxRecord[] {
  const stableRecordsRef = useRef(records);
  const stableRecords = stableRecordsRef.current;
  if (stableRecords === records) return stableRecords;
  if (
    stableRecords.length !== records.length ||
    records.some((record, index) => record !== stableRecords[index])
  ) {
    stableRecordsRef.current = records;
  }
  return stableRecordsRef.current;
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
        {channels.length > 0 && <ChannelPicker />}

        <div
          style={{
            flex: 1,
            display: "flex",
            flexDirection: "column",
            overflow: "hidden",
          }}
        >
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
        </div>
      </div>
    </div>
  );
}
