import { useCallback, useEffect, useRef, useState } from "react";
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
  const [isRegistering, setIsRegistering] = useState(false);
  const [isOpeningDefaultApps, setIsOpeningDefaultApps] = useState(false);
  const actionInFlightRef = useRef(false);
  const [isReadingInitialStatus, setIsReadingInitialStatus] = useState(
    currentPlatform === "windows",
  );

  const readRegistrationStatus = useCallback(async (): Promise<boolean | null> => {
    if (currentPlatform !== "windows") {
      return null;
    }
    const result = await getFileAssociationPromptStatus();
    return result.isRegistered;
  }, [currentPlatform]);

  useEffect(() => {
    if (currentPlatform !== "windows") {
      setIsReadingInitialStatus(false);
      return;
    }

    let cancelled = false;
    setIsReadingInitialStatus(true);
    void readRegistrationStatus()
      .then((registered) => {
        if (!cancelled && registered !== null) {
          setIsRegistered(registered);
        }
      })
      .catch((err) => {
        if (cancelled) return;
        console.warn("[file-associations] failed to read handler registration", err);
        setIsRegistered(null);
        setStatus("error");
        setErrorMessage(
          `Failed to read CMTrace Open handler registration: ${getSafeErrorMessage(err, "Unknown error")}`,
        );
      })
      .finally(() => {
        if (!cancelled) {
          setIsReadingInitialStatus(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [currentPlatform, readRegistrationStatus]);

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
    if (actionInFlightRef.current || isReadingInitialStatus) return;

    actionInFlightRef.current = true;
    setIsRegistering(true);
    setStatus("idle");
    setErrorMessage(null);

    try {
      try {
        await registerLogFileHandler();
      } catch (err) {
        setStatus("error");
        setErrorMessage(
          `Failed to register CMTrace Open: ${getSafeErrorMessage(err, "Unknown error")}`,
        );
        return;
      }

      let registered: boolean | null;
      try {
        registered = await readRegistrationStatus();
        setIsRegistered(registered);
      } catch (err) {
        console.warn("[file-associations] failed to confirm handler registration", err);
        setIsRegistered(null);
        setStatus("error");
        setErrorMessage(
          `CMTrace Open was registered, but Windows registration could not be confirmed: ${getSafeErrorMessage(err, "Unknown error")}`,
        );
        return;
      }

      if (registered !== true) {
        setStatus("error");
        setErrorMessage(
          "CMTrace Open registration could not be confirmed by Windows. Try again or check Windows Default Apps.",
        );
        return;
      }

      setStatus("success");
    } finally {
      actionInFlightRef.current = false;
      setIsRegistering(false);
    }
  };

  const handleOpenDefaultApps = async () => {
    if (actionInFlightRef.current || isReadingInitialStatus) return;

    actionInFlightRef.current = true;
    setIsOpeningDefaultApps(true);
    setStatus("idle");
    setErrorMessage(null);
    try {
      await openWindowsDefaultApps();
    } catch (err) {
      setStatus("error");
      setErrorMessage(
        `Failed to open Windows Default Apps: ${getSafeErrorMessage(err, "Unknown error")}`,
      );
    } finally {
      actionInFlightRef.current = false;
      setIsOpeningDefaultApps(false);
    }
  };

  const controlsDisabled =
    isRegistering || isOpeningDefaultApps || isReadingInitialStatus;

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
          disabled={controlsDisabled}
          onClick={() => void handleRegister()}
          style={{
            padding: "6px 16px",
            fontSize: "12px",
            border: `1px solid ${tokens.colorNeutralStroke1}`,
            borderRadius: "4px",
            background: tokens.colorBrandBackground,
            color: tokens.colorNeutralForegroundOnBrand,
            cursor:
              controlsDisabled ? "default" : "pointer",
            fontWeight: 600,
          }}
        >
          {isRegistering
            ? "Registering…"
            : isRegistered === true
            ? "Re-register CMTrace Open handler"
            : "Register CMTrace Open as an available handler"}
        </button>

        <button
          type="button"
          disabled={controlsDisabled}
          onClick={() => void handleOpenDefaultApps()}
          style={{
            padding: "6px 16px",
            fontSize: "12px",
            border: `1px solid ${tokens.colorNeutralStroke1}`,
            borderRadius: "4px",
            background: tokens.colorNeutralBackground1,
            color: tokens.colorNeutralForeground1,
            cursor:
              controlsDisabled ? "default" : "pointer",
          }}
        >
          Open Windows Default Apps
        </button>
      </div>

      {status === "success" && (
        <div role="status" style={{ fontSize: "12px", color: tokens.colorPaletteGreenForeground1, marginTop: "8px" }}>
          CMTrace Open is now available to choose in Windows Default Apps.
        </div>
      )}

      {status === "error" && errorMessage && (
        <div role="alert" style={{ fontSize: "12px", color: tokens.colorPaletteRedForeground1, marginTop: "8px" }}>
          {errorMessage}
        </div>
      )}
    </div>
  );
}
