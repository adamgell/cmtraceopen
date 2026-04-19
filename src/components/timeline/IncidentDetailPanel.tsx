import { useIncidentDetail } from "./hooks/useIncidentDetail";
import { useTimelineStore } from "../../stores/timeline-store";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";

export function IncidentDetailPanel() {
  const selectedIncidentId = useTimelineStore((s) => s.selectedIncidentId);
  const selectIncident = useTimelineStore((s) => s.selectIncident);
  const detail = useIncidentDetail(selectedIncidentId);

  if (!detail) return null;
  const i = detail.incident;

  return (
    <aside
      style={{
        width: 340,
        borderLeft: "1px solid #e5e7eb",
        overflowY: "auto",
        padding: 12,
        fontSize: 12,
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: 8,
        }}
      >
        <strong>Incident #{i.id}</strong>
        <button onClick={() => selectIncident(null)}>Close</button>
      </div>

      <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 4 }}>
        {i.summary}
      </div>
      <div style={{ color: "#6b7280", marginBottom: 10 }}>
        {new Date(i.tsStartMs).toLocaleTimeString()}–
        {new Date(i.tsEndMs).toLocaleTimeString()} · confidence{" "}
        {Math.round(i.confidence * 100)}%
      </div>

      <div style={{ marginBottom: 10 }}>
        <div
          style={{
            fontSize: 10,
            color: "#6b7280",
            textTransform: "uppercase",
          }}
        >
          Sources
        </div>
        {Object.entries(detail.perSourceSignalCounts).map(([name, count]) => (
          <div
            key={name}
            style={{ display: "flex", justifyContent: "space-between" }}
          >
            <span>{name}</span>
            <span>{count}</span>
          </div>
        ))}
      </div>

      {i.anchorGuid && (
        <div style={{ marginBottom: 10 }}>
          <div
            style={{
              fontSize: 10,
              color: "#6b7280",
              textTransform: "uppercase",
            }}
          >
            Anchor GUID
          </div>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <code
              style={{
                background: "#f3f4f6",
                padding: "1px 4px",
                borderRadius: 2,
              }}
            >
              {i.anchorGuid}
            </code>
            <button
              onClick={() => {
                void writeText(i.anchorGuid!);
              }}
            >
              Copy
            </button>
          </div>
        </div>
      )}

      <div>
        <div
          style={{
            fontSize: 10,
            color: "#6b7280",
            textTransform: "uppercase",
          }}
        >
          Signals ({detail.signals.length})
        </div>
        {detail.signals.map((s, idx) => (
          <div
            key={idx}
            style={{ padding: "4px 0", borderBottom: "1px solid #f3f4f6" }}
          >
            <div style={{ fontSize: 10, color: "#9ca3af" }}>
              {new Date(s.tsMs).toLocaleTimeString()} · {s.sourceName} ·{" "}
              {s.kind}
              {s.correlationId && " · (correlated)"}
            </div>
            <div style={{ fontFamily: "ui-monospace, monospace", fontSize: 11 }}>
              {s.preview}
            </div>
          </div>
        ))}
      </div>
    </aside>
  );
}
