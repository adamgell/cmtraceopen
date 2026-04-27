import { useCallback, useEffect, useState } from "react";
import { tokens } from "@fluentui/react-components";
import { invoke } from "@tauri-apps/api/core";
import { useUiStore } from "../../../stores/ui-store";

interface FileAssociationPromptStatus {
  supported: boolean;
  shouldPrompt: boolean;
  isAssociated: boolean;
}

export function FileAssociationsTab() {
  const currentPlatform = useUiStore((state) => state.currentPlatform);
  const [status, setStatus] = useState<"idle" | "success" | "error">("idle");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isAssociated, setIsAssociated] = useState<boolean | null>(null);

  const refreshAssociationStatus = useCallback(async () => {
    if (currentPlatform !== "windows") {
      return;
    }
    try {
      const result = await invoke("get_file_association_prompt_status");
      // Defensive shape check — the dev ipc_bridge stub used to return a
      // plain string ("dismissed"), and other transports could change too.
      if (
        typeof result === "object" &&
        result !== null &&
        "isAssociated" in result &&
        typeof (result as FileAssociationPromptStatus).isAssociated === "boolean"
      ) {
        setIsAssociated((result as FileAssociationPromptStatus).isAssociated);
      } else {
        console.warn(
          "[file-associations] unexpected association status shape",
          result
        );
        setIsAssociated(null);
      }
    } catch (err) {
      console.warn("[file-associations] failed to read association status", err);
      setIsAssociated(null);
    }
  }, [currentPlatform]);

  useEffect(() => {
    void refreshAssociationStatus();
  }, [refreshAssociationStatus]);

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
      await refreshAssociationStatus();
    } catch (err) {
      setStatus("error");
      setErrorMessage(String(err));
    }
  };

  return (
    <div>
      <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3, marginBottom: "16px", lineHeight: 1.5 }}>
        Register CMTrace Open as the default handler for .log files on Windows.
      </div>

      {isAssociated === true ? (
        <>
          <div
            style={{
              fontSize: "12px",
              color: tokens.colorPaletteGreenForeground1,
              marginBottom: "10px",
              fontWeight: 600,
            }}
          >
            CMTrace Open is currently registered as the handler for .log files.
          </div>
          <button
            type="button"
            onClick={handleAssociate}
            style={{
              padding: "6px 16px",
              fontSize: "12px",
              border: `1px solid ${tokens.colorNeutralStroke1}`,
              borderRadius: "4px",
              background: tokens.colorNeutralBackground1,
              color: tokens.colorNeutralForeground1,
              cursor: "pointer",
            }}
          >
            Re-register associations
          </button>
        </>
      ) : (
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
      )}

      {status === "success" && isAssociated !== true && (
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
