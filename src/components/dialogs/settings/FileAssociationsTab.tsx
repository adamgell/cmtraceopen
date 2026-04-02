import { useState } from "react";
import { tokens } from "@fluentui/react-components";
import { invoke } from "@tauri-apps/api/core";
import { useUiStore } from "../../../stores/ui-store";

export function FileAssociationsTab() {
  const currentPlatform = useUiStore((state) => state.currentPlatform);
  const [status, setStatus] = useState<"idle" | "success" | "error">("idle");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  if (currentPlatform !== "windows") {
    return (
      <div>
        <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3, lineHeight: 1.5 }}>
          File associations are only available on Windows. On macOS and Linux, use your system settings to associate .log files with CMTrace Open.
        </div>
      </div>
    );
  }

  const handleAssociate = async () => {
    try {
      setStatus("idle");
      setErrorMessage(null);
      await invoke("associate_log_files_with_app");
      setStatus("success");
    } catch (err) {
      setStatus("error");
      setErrorMessage(String(err));
    }
  };

  return (
    <div>
      <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3, marginBottom: "14px", lineHeight: 1.5 }}>
        Register CMTrace Open as the default handler for .log files on Windows.
      </div>

      <button
        type="button"
        onClick={handleAssociate}
        style={{
          padding: "6px 16px",
          fontSize: "12px",
          border: `1px solid ${tokens.colorNeutralStroke1}`,
          borderRadius: "4px",
          background: tokens.colorBrandBackground,
          color: tokens.colorNeutralForegroundOnBrand,
          cursor: "pointer",
          fontWeight: 600,
        }}
      >
        Associate .log files with CMTrace Open
      </button>

      {status === "success" && (
        <div style={{ fontSize: "12px", color: tokens.colorPaletteGreenForeground1, marginTop: "8px" }}>
          File associations registered successfully.
        </div>
      )}

      {status === "error" && (
        <div style={{ fontSize: "12px", color: tokens.colorPaletteRedForeground1, marginTop: "8px" }}>
          Failed to register file associations: {errorMessage}
        </div>
      )}
    </div>
  );
}
