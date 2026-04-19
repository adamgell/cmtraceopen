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
              borderRadius: 999,
              border: `1px solid ${isSolo ? src.color : "#d1d5db"}`,
              background: muted ? "#f3f4f6" : "white",
              color: muted ? "#9ca3af" : "#111",
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
            <span style={{ color: "#9ca3af" }}>{src.entryCount}</span>
          </button>
        );
      })}
    </div>
  );
}
