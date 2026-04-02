import { tokens } from "@fluentui/react-components";
import { useUiStore } from "../../../stores/ui-store";

export function ColumnsTab() {
  const resetColumns = useUiStore((state) => state.resetColumns);
  const columnOrder = useUiStore((state) => state.columnOrder);
  const columnWidths = useUiStore((state) => state.columnWidths);

  const hasCustomOrder = columnOrder !== null && columnOrder.length > 0;
  const hasCustomWidths = Object.keys(columnWidths).length > 0;
  const hasCustomizations = hasCustomOrder || hasCustomWidths;

  return (
    <div>
      <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3, marginBottom: "14px", lineHeight: 1.5 }}>
        Columns are automatically determined by the log file format. You can reorder columns by dragging column headers in the log view, and resize them by dragging column borders.
      </div>

      {hasCustomizations ? (
        <div style={{ display: "grid", gap: "8px" }}>
          {hasCustomOrder && (
            <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground2 }}>
              Custom column order is active.
            </div>
          )}
          {hasCustomWidths && (
            <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground2 }}>
              Custom column widths are active ({Object.keys(columnWidths).length} columns).
            </div>
          )}
          <div style={{ marginTop: "8px" }}>
            <button
              type="button"
              onClick={resetColumns}
              style={{
                padding: "6px 12px",
                fontSize: "12px",
                border: `1px solid ${tokens.colorNeutralStroke1}`,
                borderRadius: "4px",
                background: tokens.colorNeutralBackground3,
                color: tokens.colorNeutralForeground1,
                cursor: "pointer",
              }}
            >
              Reset to Defaults
            </button>
          </div>
        </div>
      ) : (
        <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3 }}>
          Using default column order and widths.
        </div>
      )}
    </div>
  );
}
