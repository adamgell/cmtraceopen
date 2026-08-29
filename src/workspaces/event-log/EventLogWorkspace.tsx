import { useMemo, useRef, useState, useEffect } from "react";
import { ProgressBar, Spinner, tokens } from "@fluentui/react-components";
import { diagnoseEventRecords } from "../../lib/commands";
import { useEvtxStore, buildUnifiedTimeline } from "./evtx-store";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import { SourcePicker } from "./SourcePicker";
import { ChannelPicker } from "./ChannelPicker";
import { EvtxFilterBar } from "./EvtxFilterBar";
import { EvtxCoverageBanner } from "./EvtxCoverageBanner";
import { EventDiagnosisPanel } from "./EventDiagnosisPanel";
import { EvtxTimeline } from "./EvtxTimeline";
import { UnifiedTimelineView } from "./UnifiedTimelineView";
import { EvtxDetailPane } from "./EvtxDetailPane";
import { selectVisibleRecords } from "./evtx-filter";
import {
  filterTimelineToRecords,
  scopeLogEntries,
  type UnifiedTimeline,
} from "./unified-timeline";
import { mergeDiagnosisCoverageGaps } from "./evtx-coverage";
import type { DiagnosisSummary } from "./types";

const DEFAULT_DETAIL_HEIGHT = 300;
const MIN_DETAIL_HEIGHT = 100;
const MAX_DETAIL_RATIO = 0.7;
const DIAGNOSIS_DEBOUNCE_MS = 75;
const EMPTY_TIMELINE: UnifiedTimeline = { items: [], unplaced: [] };

type DiagnosisSnapshot = {
  records: Parameters<typeof diagnoseEventRecords>[0];
  coverageGaps: Exclude<Parameters<typeof diagnoseEventRecords>[1], undefined>;
  timeline: UnifiedTimeline;
  textEntries: Exclude<Parameters<typeof diagnoseEventRecords>[3], undefined>;
};

type DiagnosisPump = {
  pending: DiagnosisSnapshot | null;
  running: boolean;
  timer: number | null;
  revision: number;
  mounted: boolean;
};

type TimelineSnapshot = {
  records: Parameters<typeof buildUnifiedTimeline>[0];
  entries: Parameters<typeof buildUnifiedTimeline>[1];
};

type TimelinePump = {
  pending: TimelineSnapshot | null;
  running: boolean;
  timer: number | null;
  revision: number;
  mounted: boolean;
};

export function EventLogWorkspace() {
  const sourceMode = useEvtxStore((s) => s.sourceMode);
  const timeWindow = useEvtxStore((s) => s.timeWindow);
  const isLoading = useEvtxStore((s) => s.isLoading);
  const loadError = useEvtxStore((s) => s.loadError);
  const [nowEpoch, setNowEpoch] = useState(() => Date.now());
  useEffect(() => {
    if (timeWindow === "all") return;
    setNowEpoch(Date.now());
    const timer = window.setInterval(() => setNowEpoch(Date.now()), 30_000);
    return () => window.clearInterval(timer);
  }, [timeWindow]);
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
  const visibleRecords = useMemo(
    () =>
      selectVisibleRecords({
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
  const diagnosisPumpRef = useRef<DiagnosisPump>({
    pending: null,
    running: false,
    timer: null,
    revision: 0,
    mounted: false,
  });

  const [timeline, setTimeline] = useState<UnifiedTimeline>({
    items: [],
    unplaced: [],
  });
  const [timelinePending, setTimelinePending] = useState(false);
  const [timelineError, setTimelineError] = useState<string | null>(null);
  const timelineInputsRef = useRef<TimelineSnapshot | null>(null);
  const timelinePumpRef = useRef<TimelinePump>({
    pending: null,
    running: false,
    timer: null,
    revision: 0,
    mounted: false,
  });
  const timelineIsCurrent =
    timelineInputsRef.current?.records === records &&
    timelineInputsRef.current?.entries === scopedLogEntries;
  const visibleTimeline = useMemo(
    () =>
      timelineIsCurrent
        ? filterTimelineToRecords(timeline, visibleRecords, records)
        : null,
    [timeline, timelineIsCurrent, visibleRecords, records],
  );

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
    const pump = diagnosisPumpRef.current;
    pump.mounted = true;
    return () => {
      pump.mounted = false;
      pump.revision += 1;
      if (pump.timer !== null) window.clearTimeout(pump.timer);
      pump.timer = null;
      pump.pending = null;
    };
  }, []);
  useEffect(() => {
    const pump = timelinePumpRef.current;
    pump.mounted = true;
    return () => {
      pump.mounted = false;
      pump.revision += 1;
      if (pump.timer !== null) window.clearTimeout(pump.timer);
      pump.timer = null;
      pump.pending = null;
    };
  }, []);

  useEffect(() => {
    const pump = diagnosisPumpRef.current;
    const revision = pump.revision + 1;
    pump.revision = revision;
    if (pump.timer !== null) window.clearTimeout(pump.timer);
    pump.timer = null;
    pump.pending = null;

    if (
      records.length === 0 &&
      diagnosisCoverageGaps.length === 0 &&
      scopedLogEntries.length === 0
    ) {
      setDiagnosis(null);
      setDiagnosisError(null);
      return () => {
        if (pump.timer !== null) window.clearTimeout(pump.timer);
        pump.timer = null;
        if (pump.revision !== revision) return;
        pump.pending = null;
      };
    }

    if (visibleTimeline === null) {
      setDiagnosis(null);
      setDiagnosisError(null);
      return () => {
        if (pump.timer !== null) window.clearTimeout(pump.timer);
        pump.timer = null;
        if (pump.revision !== revision) return;
        pump.pending = null;
      };
    }

    pump.pending = {
      records: visibleRecords,
      coverageGaps: diagnosisCoverageGaps,
      timeline: visibleTimeline,
      textEntries: scopedLogEntries,
    };
    setDiagnosis(null);
    setDiagnosisError(null);

    const run = () => {
      pump.timer = null;
      if (!pump.mounted || pump.running || pump.pending === null) return;
      const snapshot = pump.pending;
      pump.pending = null;
      pump.running = true;
      const startRevision = pump.revision;
      void diagnoseEventRecords(
        snapshot.records,
        snapshot.coverageGaps,
        snapshot.timeline,
        snapshot.textEntries,
      )
        .then((summary) => {
          if (pump.mounted && pump.revision === startRevision)
            setDiagnosis(summary);
        })
        .catch((error: unknown) => {
          if (!pump.mounted || pump.revision !== startRevision) return;
          const message =
            error instanceof Error ? error.message : String(error);
          setDiagnosis(null);
          setDiagnosisError(
            `Operational diagnosis could not be built: ${message}`,
          );
        })
        .finally(() => {
          pump.running = false;
          if (!pump.mounted || pump.pending === null || pump.timer !== null)
            return;
          pump.timer = window.setTimeout(run, DIAGNOSIS_DEBOUNCE_MS);
        });
    };

    pump.timer = window.setTimeout(run, DIAGNOSIS_DEBOUNCE_MS);
    return () => {
      if (pump.timer !== null) window.clearTimeout(pump.timer);
      pump.timer = null;
      if (pump.revision !== revision) return;
      pump.pending = null;
    };
  }, [
    visibleRecords,
    visibleTimeline,
    diagnosisCoverageGaps,
    scopedLogEntries,
  ]);

  useEffect(() => {
    const pump = timelinePumpRef.current;
    const revision = pump.revision + 1;
    pump.revision = revision;
    if (pump.timer !== null) window.clearTimeout(pump.timer);
    pump.timer = null;
    pump.pending = null;

    if (records.length === 0 && scopedLogEntries.length === 0) {
      timelineInputsRef.current = { records, entries: scopedLogEntries };
      setTimelinePending(false);
      setTimeline(EMPTY_TIMELINE);
      setTimelineError(null);
      return () => {
        if (pump.timer !== null) window.clearTimeout(pump.timer);
        pump.timer = null;
        if (pump.revision !== revision) return;
        pump.pending = null;
      };
    }

    pump.pending = { records, entries: scopedLogEntries };
    setTimelinePending(true);
    timelineInputsRef.current = null;
    setTimelineError(null);

    const run = () => {
      pump.timer = null;
      if (!pump.mounted || pump.running || pump.pending === null) return;
      const snapshot = pump.pending;
      pump.pending = null;
      pump.running = true;
      const startRevision = pump.revision;
      void buildUnifiedTimeline(snapshot.records, snapshot.entries)
        .then((nextTimeline) => {
          if (!pump.mounted || pump.revision !== startRevision) return;
          setTimelinePending(false);
          timelineInputsRef.current = snapshot;
          setTimeline(nextTimeline);
          setTimelineError(null);
        })
        .catch((error: unknown) => {
          if (!pump.mounted || pump.revision !== startRevision) return;
          setTimelinePending(false);
          const message =
            error instanceof Error ? error.message : String(error);
          timelineInputsRef.current = null;
          setTimeline(EMPTY_TIMELINE);
          setTimelineError(`Unified timeline could not be built: ${message}`);
        })
        .finally(() => {
          pump.running = false;
          if (!pump.mounted || pump.pending === null || pump.timer !== null)
            return;
          pump.timer = window.setTimeout(run, DIAGNOSIS_DEBOUNCE_MS);
        });
    };

    pump.timer = window.setTimeout(run, DIAGNOSIS_DEBOUNCE_MS);

    return () => {
      if (pump.timer !== null) window.clearTimeout(pump.timer);
      pump.timer = null;
      if (pump.revision !== revision) return;
      pump.pending = null;
    };
  }, [scopedLogEntries, records]);

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
              timeline={visibleTimeline ?? EMPTY_TIMELINE}
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
