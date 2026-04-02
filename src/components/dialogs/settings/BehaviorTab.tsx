import { tokens } from "@fluentui/react-components";
import { useUiStore } from "../../../stores/ui-store";

export function BehaviorTab() {
  const defaultShowInfoPane = useUiStore((state) => state.defaultShowInfoPane);
  const confirmTabClose = useUiStore((state) => state.confirmTabClose);
  const setDefaultShowInfoPane = useUiStore((state) => state.setDefaultShowInfoPane);
  const setConfirmTabClose = useUiStore((state) => state.setConfirmTabClose);

  return (
    <div>
      <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3, marginBottom: "14px", lineHeight: 1.5 }}>
        Configure default behaviors for the application.
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
        <label
          style={{
            display: "flex",
            alignItems: "flex-start",
            gap: "8px",
            fontSize: "12px",
            color: tokens.colorNeutralForeground1,
            cursor: "pointer",
          }}
        >
          <input
            type="checkbox"
            checked={defaultShowInfoPane}
            onChange={(e) => setDefaultShowInfoPane(e.target.checked)}
            style={{ marginTop: "2px", cursor: "pointer" }}
          />
          <div>
            <div style={{ fontWeight: 600 }}>Show info pane by default</div>
            <div style={{ fontSize: "11px", color: tokens.colorNeutralForeground3, marginTop: "2px" }}>
              When enabled, the info pane is visible when opening new files.
            </div>
          </div>
        </label>

        <label
          style={{
            display: "flex",
            alignItems: "flex-start",
            gap: "8px",
            fontSize: "12px",
            color: tokens.colorNeutralForeground1,
            cursor: "pointer",
          }}
        >
          <input
            type="checkbox"
            checked={confirmTabClose}
            onChange={(e) => setConfirmTabClose(e.target.checked)}
            style={{ marginTop: "2px", cursor: "pointer" }}
          />
          <div>
            <div style={{ fontWeight: 600 }}>Confirm before closing tabs</div>
            <div style={{ fontSize: "11px", color: tokens.colorNeutralForeground3, marginTop: "2px" }}>
              Show a confirmation prompt before closing a log tab.
            </div>
          </div>
        </label>
      </div>
    </div>
  );
}
