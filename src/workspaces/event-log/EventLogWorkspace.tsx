import { useRef, useState, useEffect } from "react";
import { ProgressBar, Spinner, tokens } from "@fluentui/react-components";
import { useEvtxStore } from "./evtx-store";
import { SourcePicker } from "./SourcePicker";
import { ChannelPicker } from "./ChannelPicker";
import { EvtxFilterBar } from "./EvtxFilterBar";
import { EvtxTimeline } from "./EvtxTimeline";
import { EvtxDetailPane } from "./EvtxDetailPane";

const DEFAULT_DETAIL_HEIGHT = 300;
const MIN_DETAIL_HEIGHT = 100;
const MAX_DETAIL_RATIO = 0.7;

export function EventLogWorkspace() {
  const sourceMode = useEvtxStore((s) => s.sourceMode);
  const isLoading = useEvtxStore((s) => s.isLoading);
  const records = useEvtxStore((s) => s.records);
  const channels = useEvtxStore((s) => s.channels);
  const selectedRecordId = useEvtxStore((s) => s.selectedRecordId);

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

  const hasData = sourceMode !== null && (records.length > 0 || channels.length > 0);

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
          {/* Timeline */}
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
