import { useMemo, useRef, useState, useEffect } from "react";
import { ProgressBar, Spinner, tokens } from "@fluentui/react-components";
import { useEvtxStore, buildUnifiedTimeline } from "./evtx-store";
import { useLogStore } from "../../stores/log-store";
import { SourcePicker } from "./SourcePicker";
import { ChannelPicker } from "./ChannelPicker";
import { EvtxFilterBar } from "./EvtxFilterBar";
import { EvtxCoverageBanner } from "./EvtxCoverageBanner";
import { EvtxTimeline } from "./EvtxTimeline";
import { UnifiedTimelineView } from "./UnifiedTimelineView";
import { EvtxDetailPane } from "./EvtxDetailPane";
import { selectVisibleRecords } from "./evtx-filter";
import {
  filterTimelineToRecords,
  type UnifiedTimeline,
} from "./unified-timeline";
const DEFAULT_DETAIL_HEIGHT = 300;
const MIN_DETAIL_HEIGHT = 100;
const MAX_DETAIL_RATIO = 0.7;

export function EventLogWorkspace() {
  const sourceMode = useEvtxStore((s) => s.sourceMode);
  const isLoading = useEvtxStore((s) => s.isLoading);
  const logEntries = useLogStore((s) => s.entries);
  const records = useEvtxStore((s) => s.records);
  const selectedChannels = useEvtxStore((s) => s.selectedChannels);
  const filterLevels = useEvtxStore((s) => s.filterLevels);
  const filterEventIds = useEvtxStore((s) => s.filterEventIds);
  const filterSearch = useEvtxStore((s) => s.filterSearch);
  const visibleRecords = useMemo(
    () =>
      selectVisibleRecords({
        records,
        selectedChannels,
        filterLevels,
        filterEventIds,
        filterSearch,
      }),
    [records, selectedChannels, filterLevels, filterEventIds, filterSearch]
  );
  const channels = useEvtxStore((s) => s.channels);
  const selectedRecordId = useEvtxStore((s) => s.selectedRecordId);

  const [timeline, setTimeline] = useState<UnifiedTimeline>({ items: [], unplaced: [] });
  const [timelineError, setTimelineError] = useState<string | null>(null);
  const visibleTimeline = useMemo(
    () => filterTimelineToRecords(timeline, visibleRecords),
    [timeline, visibleRecords]
  );

  const [detailHeight, setDetailHeight] = useState(DEFAULT_DETAIL_HEIGHT);
  const resizeRef = useRef<{ startY: number; startHeight: number } | null>(null);

  useEffect(() => {
    const onMouseMove = (e: MouseEvent) => {
      if (!resizeRef.current) return;
      const delta = resizeRef.current.startY - e.clientY;
      const newHeight = Math.max(
        MIN_DETAIL_HEIGHT,
        Math.min(resizeRef.current.startHeight + delta, window.innerHeight * MAX_DETAIL_RATIO)
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
    let cancelled = false;
    if (records.length === 0 && logEntries.length === 0) {
      setTimeline({ items: [], unplaced: [] });
      setTimelineError(null);
      return () => {
        cancelled = true;
      };
    }

    void buildUnifiedTimeline(records, logEntries)
      .then((nextTimeline) => {
        if (cancelled) return;
        setTimeline(nextTimeline);
        setTimelineError(null);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        const message = error instanceof Error ? error.message : String(error);
        setTimeline({ items: [], unplaced: [] });
        setTimelineError(`Unified timeline could not be built: ${message}`);
      });

    return () => {
      cancelled = true;
    };
  }, [logEntries, records]);

  const hasData =
    logEntries.length > 0 || (sourceMode !== null && (records.length > 0 || channels.length > 0));

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
      {isLoading && (
        <ProgressBar style={{ width: "100%", flexShrink: 0 }} />
      )}
      <EvtxFilterBar />
      <EvtxCoverageBanner />

      {timelineError && (
        <div role="alert" style={{ color: tokens.colorPaletteRedForeground1, padding: "4px 12px" }}>
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
          <div style={{ height: "240px", flexShrink: 0, overflow: "hidden" }}>
            <UnifiedTimelineView timeline={visibleTimeline} />
          </div>
          <div style={{ flex: 1, overflow: "hidden" }}>
            <EvtxTimeline />
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
                  resizeRef.current = { startY: e.clientY, startHeight: detailHeight };
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
