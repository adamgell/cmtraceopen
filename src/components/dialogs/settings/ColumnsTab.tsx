import { tokens } from "@fluentui/react-components";
import { ALL_COLUMNS } from "../../../lib/column-config";
import { useUiStore } from "../../../stores/ui-store";

export function ColumnsTab() {
  const hiddenColumns = useUiStore((state) => state.hiddenColumns);
  const toggleColumnVisibility = useUiStore((state) => state.toggleColumnVisibility);

  return (
    <div>
      <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3, marginBottom: "14px", lineHeight: 1.5 }}>
        Choose which columns are visible in the log list. The severity and message columns are always shown.
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "4px 16px",
        }}
      >
        {ALL_COLUMNS.map((col) => {
          // Severity and message are always visible
          const isRequired = col.id === "severity" || col.id === "message";
          const isHidden = hiddenColumns.includes(col.id);
          const label = col.label || (col.id === "severity" ? "Severity" : col.id);

          return (
            <label
              key={col.id}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                padding: "4px 6px",
                fontSize: "12px",
                color: isRequired
                  ? tokens.colorNeutralForeground3
                  : tokens.colorNeutralForeground1,
                borderRadius: "4px",
                cursor: isRequired ? "default" : "pointer",
              }}
            >
              <input
                type="checkbox"
                checked={!isHidden}
                disabled={isRequired}
                onChange={() => {
                  if (!isRequired) {
                    toggleColumnVisibility(col.id);
                  }
                }}
                style={{ cursor: isRequired ? "default" : "pointer" }}
              />
              {label}
            </label>
          );
        })}
      </div>
    </div>
  );
}
