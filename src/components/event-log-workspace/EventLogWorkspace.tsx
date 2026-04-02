import { Spinner, tokens } from "@fluentui/react-components";
import { useEvtxStore } from "../../stores/evtx-store";
import { SourcePicker } from "./SourcePicker";
import { ChannelPicker } from "./ChannelPicker";
import { EvtxFilterBar } from "./EvtxFilterBar";
import { EvtxTimeline } from "./EvtxTimeline";
import { EvtxDetailPane } from "./EvtxDetailPane";

export function EventLogWorkspace() {
  const sourceMode = useEvtxStore((s) => s.sourceMode);
  const isLoading = useEvtxStore((s) => s.isLoading);
  const records = useEvtxStore((s) => s.records);
  const channels = useEvtxStore((s) => s.channels);
  const selectedRecordId = useEvtxStore((s) => s.selectedRecordId);

  const hasData = sourceMode !== null && (records.length > 0 || channels.length > 0);

  // No data loaded yet — show source picker
  if (!hasData && !isLoading) {
    return <SourcePicker />;
  }

  // Loading state
  if (isLoading) {
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

          {/* Detail pane — shown when a record is selected */}
          {selectedRecordId != null && (
            <div
              style={{
                height: "260px",
                flexShrink: 0,
                borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
                overflow: "hidden",
              }}
            >
              <EvtxDetailPane />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
