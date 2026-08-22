import { useCallback, useEffect, useState } from "react";
import { tokens } from "@fluentui/react-components";
import {
  getSafeErrorMessage,
  getFileAssociationPromptStatus,
  openWindowsDefaultApps,
  registerLogFileHandler,
} from "../../../lib/commands";
import { useUiStore } from "../../../stores/ui-store";

export function FileAssociationsTab() {
  const currentPlatform = useUiStore((state) => state.currentPlatform);
  const [status, setStatus] = useState<"idle" | "success" | "error">("idle");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isRegistered, setIsRegistered] = useState<boolean | null>(null);

  const refreshRegistrationStatus = useCallback(async () => {
    if (currentPlatform !== "windows") {
      return;
    }
    try {
      const result = await getFileAssociationPromptStatus();
      setIsRegistered(result.isRegistered);
    } catch (err) {
      console.warn("[file-associations] failed to read handler registration", err);
      setIsRegistered(null);
    }
  }, [currentPlatform]);

  useEffect(() => {
    void refreshRegistrationStatus();
  }, [refreshRegistrationStatus]);

  if (currentPlatform !== "windows") {
    return (
      <div>
        <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3, lineHeight: 1.5 }}>
          File associations are only available on Windows. On macOS and Linux, use your system settings to associate .log, .log_, .lo_, and .cmtlog files with CMTrace Open.
        </div>
      </div>
    );
  }

  const handleRegister = async () => {
    try {
      setStatus("idle");
      setErrorMessage(null);
      await registerLogFileHandler();
      setStatus("success");
      await refreshRegistrationStatus();
    } catch (err) {
      setStatus("error");
      setErrorMessage(
        `Failed to register CMTrace Open: ${getSafeErrorMessage(err, "Unknown error")}`,
      );
    }
  };

  const handleOpenDefaultApps = async () => {
    try {
      setErrorMessage(null);
      await openWindowsDefaultApps();
    } catch (err) {
      setStatus("error");
      setErrorMessage(
        `Failed to open Windows Default Apps: ${getSafeErrorMessage(err, "Unknown error")}`,
      );
    }
  };

  return (
    <div>
      <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3, marginBottom: "16px", lineHeight: 1.5 }}>
        Register CMTrace Open as an available handler for .log, .log_, .lo_, and
        .cmtlog files. Windows keeps your current defaults until you choose
        CMTrace Open in Default Apps.
      </div>

      {isRegistered === true && (
        <div
          style={{
            fontSize: "12px",
            color: tokens.colorPaletteGreenForeground1,
            marginBottom: "10px",
            fontWeight: 600,
          }}
        >
          CMTrace Open is registered as an available handler for the supported
          log file types.
        </div>
      )}

      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
        <button
          type="button"
          onClick={() => void handleRegister()}
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
          {isRegistered === true
            ? "Re-register CMTrace Open handler"
            : "Register CMTrace Open as an available handler"}
        </button>

        <button
          type="button"
          onClick={() => void handleOpenDefaultApps()}
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
          Open Windows Default Apps
        </button>
      </div>

      {status === "success" && (
        <div style={{ fontSize: "12px", color: tokens.colorPaletteGreenForeground1, marginTop: "8px" }}>
          CMTrace Open is now available to choose in Windows Default Apps.
        </div>
      )}

      {status === "error" && errorMessage && (
        <div style={{ fontSize: "12px", color: tokens.colorPaletteRedForeground1, marginTop: "8px" }}>
          {errorMessage}
        </div>
      )}
    </div>
  );
}
