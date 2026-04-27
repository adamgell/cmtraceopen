import { tokens } from "@fluentui/react-components";
import { useTimelineStore } from "../../stores/timeline-store";

export function LaneLegend() {
  const bundle = useTimelineStore((s) => s.bundle);
  const laneVisibility = useTimelineStore((s) => s.laneVisibility);
  const soloSourceIdx = useTimelineStore((s) => s.soloSourceIdx);
  const setSolo = useTimelineStore((s) => s.setSolo);
  const toggleMute = useTimelineStore((s) => s.toggleMute);
  if (!bundle) return null;

  return (
    <div
      style={{
        display: "flex",
        gap: 8,
        padding: "6px 10px",
        flexWrap: "wrap",
      }}
    >
      {bundle.sources.map((src) => {
        const muted = laneVisibility[src.idx] === false;
        const isSolo = soloSourceIdx === src.idx;
        return (
          <button
            key={src.idx}
            onClick={(e) => {
              if (e.shiftKey) {
                toggleMute(src.idx);
              } else {
                setSolo(isSolo ? null : src.idx);
              }
            }}
            title="Click: solo this lane. Shift-click: mute this lane."
            style={{
              display: "inline-flex",
              gap: 6,
              alignItems: "center",
              padding: "2px 8px",
              borderRadius: tokens.borderRadiusCircular,
              border: `1px solid ${isSolo ? src.color : tokens.colorNeutralStroke1}`,
              background: muted ? tokens.colorNeutralBackground3 : tokens.colorNeutralBackground1,
              color: muted ? tokens.colorNeutralForeground4 : tokens.colorNeutralForeground1,
              opacity: muted ? 0.6 : 1,
              fontSize: 12,
              cursor: "pointer",
            }}
          >
            <span
              style={{
                width: 10,
                height: 10,
                borderRadius: 2,
                background: src.color,
              }}
            />
            {src.displayName}
            <span style={{ color: tokens.colorNeutralForeground4 }}>{src.entryCount}</span>
          </button>
        );
      })}
    </div>
  );
}
