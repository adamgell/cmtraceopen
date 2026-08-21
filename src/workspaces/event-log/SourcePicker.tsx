import { useEffect, useRef, useState } from "react";
import { Button, Input, Spinner, tokens } from "@fluentui/react-components";
import { open } from "@tauri-apps/plugin-dialog";
import { openEventLogSource, openEventLogSources } from "./open-event-log-source";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { useEvtxStore } from "./evtx-store";
import { useUiStore } from "../../stores/ui-store";

const EVTX_FILE_DIALOG_FILTERS = [
  { name: "Event Log Files", extensions: ["evtx"] },
  { name: "All Files", extensions: ["*"] },
];

export function SourcePicker() {
  const enumerateLocalChannels = useEvtxStore((s) => s.enumerateLocalChannels);
  const enumerateRemoteChannels = useEvtxStore((s) => s.enumerateRemoteChannels);
  const isLoading = useEvtxStore((s) => s.isLoading);
  const loadError = useEvtxStore((s) => s.loadError);
  const coverageGaps = useEvtxStore((s) => s.coverageGaps);
  const remoteMachine = useEvtxStore((s) => s.remoteMachine);
  const currentPlatform = useUiStore((s) => s.currentPlatform);
  const [remoteTarget, setRemoteTarget] = useState(remoteMachine ?? "");
  const [remoteTargetDirty, setRemoteTargetDirty] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const [isOpening, setIsOpening] = useState(false);
  const openingRef = useRef(false);

  const beginOpening = () => {
    if (openingRef.current) return false;
    openingRef.current = true;
    setIsOpening(true);
    return true;
  };

  const finishOpening = () => {
    openingRef.current = false;
    setIsOpening(false);
  };

  useEffect(() => {
    if (!remoteTargetDirty && remoteMachine && remoteMachine !== remoteTarget) {
      setRemoteTarget(remoteMachine);
    }
  }, [remoteMachine, remoteTarget, remoteTargetDirty]);
  const isWindows = currentPlatform === "windows";
  const metrics = getLogListMetrics(useUiStore((s) => s.logListFontSize));
  const headingFontSize = metrics.fontSize + 5;
  const secondaryFontSize = metrics.fontSize;
  const errorFontSize = Math.max(10, metrics.fontSize - 1);

  const handleOpenFiles = async () => {
    if (!beginOpening()) return;
    setLocalError(null);
    try {
      const selected = await open({
        multiple: true,
        filters: EVTX_FILE_DIALOG_FILTERS,
      });
      if (!selected) return;
      const paths = Array.isArray(selected) ? selected : [selected];
      if (paths.length === 0) return;
      await openEventLogSources(paths.map((path) => ({ kind: "file" as const, path })));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setLocalError(message);
    } finally {
      finishOpening();
    }
  };
  const handleOpenFolder = async () => {
    if (!beginOpening()) return;
    setLocalError(null);
    try {
      const selected = await open({ directory: true, multiple: false });
      if (typeof selected !== "string") return;
      await openEventLogSource({ kind: "folder", path: selected });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setLocalError(message);
    } finally {
      finishOpening();
    }
  };
  const handleEnumerate = async () => {
    if (!beginOpening()) return;
    setLocalError(null);
    try {
      await enumerateLocalChannels();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setLocalError(message);
    } finally {
      finishOpening();
    }
  };

  const handleRemoteEnumerate = async () => {
    if (!beginOpening()) return;
    setLocalError(null);
    try {
      await enumerateRemoteChannels(remoteTarget);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setLocalError(message);
    } finally {
      finishOpening();
    }

  };
  const displayError = loadError ?? localError;
  const displayCoverage = coverageGaps.join(" • ");

  return (
    <div
      style={{
        flex: 1,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: "24px",
        padding: "40px",
      }}
    >
      <div
        style={{
          fontSize: `${headingFontSize}px`,
          fontWeight: 600,
          color: tokens.colorNeutralForeground1,
        }}
      >
        Event Log Viewer
      </div>
      <div
        style={{
          fontSize: `${secondaryFontSize}px`,
          color: tokens.colorNeutralForeground3,
          textAlign: "center",
          maxWidth: "400px",
        }}
      >
        Open .evtx files to parse Windows Event Log data, or browse live event
        log channels on this computer.
      </div>

      {isLoading ? (
        <Spinner label="Loading..." />
      ) : (
        <div style={{ display: "flex", gap: "16px" }}>
          <Button
            appearance="primary"
            disabled={isOpening}
            onClick={() => void handleOpenFiles()}
            style={{ fontSize: `${secondaryFontSize}px` }}
          >
            Open .evtx files...
          </Button>
          <Button
            appearance="secondary"
            disabled={isOpening}
            onClick={() => void handleOpenFolder()}
            style={{ fontSize: `${secondaryFontSize}px` }}
          >
            Open folder recursively...
          </Button>
          {isWindows && (
            <Button
              appearance="secondary"
              disabled={isOpening}
              onClick={() => void handleEnumerate()}
              style={{ fontSize: `${secondaryFontSize}px` }}
            >
              This computer
            </Button>
          )}
        </div>
      )}

      {isWindows && !isLoading && (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: "8px",
            width: "min(420px, 100%)",
          }}
        >
          <div style={{ display: "flex", gap: "8px", width: "100%" }}>
            <Input
              value={remoteTarget}
              onChange={(_, data) => {
                setRemoteTargetDirty(true);
                setRemoteTarget(data.value);
              }}
              aria-label="Remote computer name"
              input={{ style: { fontSize: `${secondaryFontSize}px` } }}
              style={{ flex: 1 }}
            />
            <Button
              appearance="secondary"
              disabled={isOpening || !remoteTarget.trim()}
              onClick={() => void handleRemoteEnumerate()}
              style={{ fontSize: `${secondaryFontSize}px` }}
            >
              Remote computer
            </Button>
          </div>
          <div
            style={{
              fontSize: `${secondaryFontSize}px`,
              color: tokens.colorNeutralForeground3,
              textAlign: "center",
            }}
          >
            Uses your current Windows sign-in. Usernames, passwords, and tokens are not stored.
          </div>
        </div>
      )}

      {displayError && (
        <div
          style={{
            fontSize: `${errorFontSize}px`,
            color: tokens.colorPaletteRedForeground1,
            maxWidth: "500px",
            textAlign: "center",
            wordBreak: "break-word",
          }}
        >
          {displayError}
        </div>
      )}

      {displayCoverage && (
        <div
          style={{
            fontSize: `${secondaryFontSize}px`,
            color: tokens.colorPaletteYellowForeground1,
            maxWidth: "500px",
            textAlign: "center",
            wordBreak: "break-word",
          }}
        >
          {displayCoverage}
        </div>
      )}
    </div>
  );
}
