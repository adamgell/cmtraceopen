import { tokens } from "@fluentui/react-components";
import { useLogStore } from "../../stores/log-store";
import { fileBaseName } from "../../lib/merge-entries";
import { LOG_UI_FONT_FAMILY } from "../../lib/log-accessibility";

const CORRELATION_WINDOWS = [
  { label: "100ms", value: 100 },
  { label: "500ms", value: 500 },
  { label: "1s", value: 1000 },
  { label: "5s", value: 5000 },
  { label: "10s", value: 10000 },
];

export function MergeLegendBar() {
  const mergedTabState = useLogStore((s) => s.mergedTabState);
  const correlationWindowMs = useLogStore((s) => s.correlationWindowMs);
  const autoCorrelate = useLogStore((s) => s.autoCorrelate);
  const setFileVisibility = useLogStore((s) => s.setFileVisibility);
  const setAllFileVisibility = useLogStore((s) => s.setAllFileVisibility);
  const setCorrelationWindowMs = useLogStore((s) => s.setCorrelationWindowMs);
  const setAutoCorrelate = useLogStore((s) => s.setAutoCorrelate);
  const visibleEntryCount = useLogStore((s) => s.entries.length);

  if (!mergedTabState) return null;

  const fileCounts: Record<string, number> = {};
  for (const entry of mergedTabState.mergedEntries) {
    fileCounts[entry.filePath] = (fileCounts[entry.filePath] ?? 0) + 1;
  }

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "6px",
        padding: "4px 12px",
        backgroundColor: tokens.colorNeutralBackground3,
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        fontFamily: LOG_UI_FONT_FAMILY,
        fontSize: "11px",
        overflowX: "auto",
        scrollbarWidth: "none",
        flexShrink: 0,
      }}
    >
      {mergedTabState.sourceFilePaths.map((fp) => {
        const color = mergedTabState.colorAssignments[fp] ?? "#888";
        const visible = mergedTabState.fileVisibility[fp] !== false;
        const count = fileCounts[fp] ?? 0;

        return (
          <button
            key={fp}
            type="button"
            onClick={() => setFileVisibility(fp, !visible)}
            title={fp}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "4px",
              padding: "2px 8px",
              borderRadius: "12px",
              border: `1px solid ${visible ? color : tokens.colorNeutralStroke2}`,
              backgroundColor: visible ? `${color}20` : "transparent",
              color: visible ? tokens.colorNeutralForeground1 : tokens.colorNeutralForeground4,
              cursor: "pointer",
              opacity: visible ? 1 : 0.5,
              whiteSpace: "nowrap",
              fontSize: "11px",
              fontFamily: LOG_UI_FONT_FAMILY,
            }}
          >
            <span
              style={{
                width: "8px",
                height: "8px",
                borderRadius: "50%",
                backgroundColor: visible ? color : tokens.colorNeutralForeground4,
                flexShrink: 0,
              }}
            />
            <span>{fileBaseName(fp)}</span>
            <span style={{ color: tokens.colorNeutralForeground3, fontWeight: 600 }}>
              {count}
            </span>
          </button>
        );
      })}

      <div style={{ width: "1px", height: "16px", backgroundColor: tokens.colorNeutralStroke2, margin: "0 2px", flexShrink: 0 }} />

      <button
        type="button"
        onClick={() => setAllFileVisibility(true)}
        style={{
          fontSize: "10px",
          padding: "2px 6px",
          border: `1px solid ${tokens.colorNeutralStroke2}`,
          borderRadius: "3px",
          backgroundColor: tokens.colorNeutralBackground1,
          color: tokens.colorNeutralForeground1,
          cursor: "pointer",
        }}
      >
        All
      </button>
      <button
        type="button"
        onClick={() => setAllFileVisibility(false)}
        style={{
          fontSize: "10px",
          padding: "2px 6px",
          border: `1px solid ${tokens.colorNeutralStroke2}`,
          borderRadius: "3px",
          backgroundColor: tokens.colorNeutralBackground1,
          color: tokens.colorNeutralForeground1,
          cursor: "pointer",
        }}
      >
        None
      </button>

      <div style={{ width: "1px", height: "16px", backgroundColor: tokens.colorNeutralStroke2, margin: "0 2px", flexShrink: 0 }} />

      <span style={{ color: tokens.colorNeutralForeground3, fontWeight: 600, fontSize: "10px", textTransform: "uppercase" }}>
        Correlate:
      </span>
      <select
        value={correlationWindowMs}
        onChange={(e) => setCorrelationWindowMs(Number(e.target.value))}
        style={{
          fontSize: "11px",
          padding: "1px 4px",
          border: `1px solid ${tokens.colorNeutralStroke2}`,
          borderRadius: "3px",
          backgroundColor: tokens.colorNeutralBackground1,
          color: tokens.colorNeutralForeground1,
        }}
      >
        {CORRELATION_WINDOWS.map((w) => (
          <option key={w.value} value={w.value}>{w.label}</option>
        ))}
      </select>
      <button
        type="button"
        onClick={() => setAutoCorrelate(!autoCorrelate)}
        style={{
          fontSize: "10px",
          padding: "2px 6px",
          border: `1px solid ${autoCorrelate ? tokens.colorBrandStroke1 : tokens.colorNeutralStroke2}`,
          borderRadius: "3px",
          backgroundColor: autoCorrelate ? tokens.colorBrandBackground2 : tokens.colorNeutralBackground1,
          color: autoCorrelate ? tokens.colorBrandForeground1 : tokens.colorNeutralForeground3,
          cursor: "pointer",
        }}
      >
        Auto
      </button>

      <div style={{ marginLeft: "auto", color: tokens.colorNeutralForeground3, flexShrink: 0 }}>
        {visibleEntryCount} merged
      </div>
    </div>
  );
}
