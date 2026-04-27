import { tokens } from "@fluentui/react-components";
import { useTimelineStore } from "../../stores/timeline-store";

export function IncidentChipBar() {
  const bundle = useTimelineStore((s) => s.bundle);
  const selectedIncidentId = useTimelineStore((s) => s.selectedIncidentId);
  const selectIncident = useTimelineStore((s) => s.selectIncident);

  if (!bundle) return null;
  if (bundle.incidents.length === 0) {
    return (
      <div style={{ padding: "6px 10px", fontSize: 11, color: tokens.colorNeutralForeground3 }}>
        No incidents detected — adjust signal settings in the gear menu.
      </div>
    );
  }

  return (
    <div
      style={{
        display: "flex",
        gap: 6,
        padding: "6px 10px",
        overflowX: "auto",
      }}
    >
      {bundle.incidents.map((inc) => {
        const isSel = inc.id === selectedIncidentId;
        const color =
          inc.confidence >= 0.8
            ? tokens.colorPaletteRedForeground1
            : inc.confidence >= 0.6
              ? tokens.colorPaletteYellowForeground2
              : tokens.colorNeutralForeground3;
        return (
          <button
            key={inc.id}
            onClick={() => selectIncident(isSel ? null : inc.id)}
            style={{
              display: "inline-flex",
              gap: 6,
              alignItems: "center",
              padding: "3px 10px",
              borderRadius: 999,
              border: `1px solid ${isSel ? color : tokens.colorNeutralStroke2}`,
              background: isSel
                ? `color-mix(in srgb, ${color} 10%, transparent)`
                : tokens.colorNeutralBackground1,
              fontSize: 11,
              whiteSpace: "nowrap",
              cursor: "pointer",
            }}
          >
            <span
              style={{
                width: 8,
                height: 8,
                borderRadius: 999,
                background: color,
              }}
            />
            #{inc.id} · {inc.summary}
          </button>
        );
      })}
    </div>
  );
}
