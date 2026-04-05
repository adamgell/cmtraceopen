import { tokens } from "@fluentui/react-components";
import type { FactGroup } from "./dsregcmd-formatters";

export function FactsTable({
  group,
  showNotReported,
}: {
  group: FactGroup;
  showNotReported: boolean;
}) {
  const visibleRows = showNotReported
    ? group.rows
    : group.rows.filter((row) => row.isNotReported !== true);
  const hiddenCount = group.rows.length - visibleRows.length;

  return (
    <div
      style={{
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        backgroundColor: tokens.colorNeutralCardBackground,
        borderRadius: "10px",
        overflow: "hidden",
      }}
    >
      <div style={{ padding: "10px 12px", backgroundColor: tokens.colorNeutralBackground3 }}>
        <div style={{ fontSize: "13px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}>
          {group.title}
        </div>
        <div style={{ marginTop: "4px", fontSize: "11px", color: tokens.colorNeutralForeground3 }}>
          {group.caption}
        </div>
      </div>
      <div style={{ borderTop: `1px solid ${tokens.colorNeutralStroke2}` }} />
      <div>
        {visibleRows.length === 0 ? (
          <div
            style={{ padding: "10px 12px", fontSize: "12px", color: tokens.colorNeutralForeground3 }}
          >
            All fields in this group were not reported by dsregcmd for this
            capture.
          </div>
        ) : (
          visibleRows.map((row) => {
            const tones = {
              neutral: { value: tokens.colorNeutralForeground1, background: tokens.colorNeutralCardBackground },
              good: { value: tokens.colorPaletteGreenForeground1, background: tokens.colorPaletteGreenBackground1 },
              warn: { value: tokens.colorPaletteMarigoldForeground2, background: tokens.colorPaletteYellowBackground1 },
              bad: { value: tokens.colorPaletteRedForeground1, background: tokens.colorPaletteRedBackground1 },
            } as const;
            const palette = tones[row.tone ?? "neutral"];

            return (
              <div
                key={`${group.id}-${row.label}`}
                style={{
                  display: "grid",
                  gridTemplateColumns: "170px minmax(0, 1fr)",
                  gap: "8px",
                  padding: "9px 12px",
                  borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
                  alignItems: "start",
                }}
              >
                <div
                  style={{
                    fontSize: "12px",
                    fontWeight: 600,
                    color: tokens.colorNeutralForeground3,
                  }}
                >
                  {row.label}
                </div>
                <div
                  style={{
                    fontSize: "12px",
                    color: palette.value,
                    backgroundColor: palette.background,
                    padding: "2px 6px",
                    borderRadius: "2px",
                    wordBreak: "break-word",
                    whiteSpace: "pre-wrap",
                  }}
                >
                  {row.value}
                </div>
              </div>
            );
          })
        )}
        {!showNotReported && hiddenCount > 0 && (
          <div
            style={{
              padding: "10px 12px",
              borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
              fontSize: "11px",
              color: tokens.colorNeutralForeground3,
            }}
          >
            {hiddenCount} not reported {hiddenCount === 1 ? "field" : "fields"}{" "}
            hidden.
          </div>
        )}
      </div>
    </div>
  );
}
