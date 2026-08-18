import { useState } from "react";
import { Button, Input, Spinner, tokens } from "@fluentui/react-components";
import { open } from "@tauri-apps/plugin-dialog";
import { useEvtxStore } from "./evtx-store";
import { useUiStore } from "../../stores/ui-store";

const EVTX_FILE_DIALOG_FILTERS = [
  { name: "Event Log Files", extensions: ["evtx"] },
  { name: "All Files", extensions: ["*"] },
];

export function SourcePicker() {
  const parseFiles = useEvtxStore((s) => s.parseFiles);
  const enumerateLocalChannels = useEvtxStore((s) => s.enumerateLocalChannels);
  const enumerateRemoteChannels = useEvtxStore((s) => s.enumerateRemoteChannels);
  const isLoading = useEvtxStore((s) => s.isLoading);
  const loadError = useEvtxStore((s) => s.loadError);
  const coverageGaps = useEvtxStore((s) => s.coverageGaps);
  const currentPlatform = useUiStore((s) => s.currentPlatform);
  const [remoteTarget, setRemoteTarget] = useState("");
  const [localError, setLocalError] = useState<string | null>(null);

  const isWindows = currentPlatform === "windows";

  const handleOpenFiles = async () => {
    setLocalError(null);
    try {
      const selected = await open({
        multiple: true,
        filters: EVTX_FILE_DIALOG_FILTERS,
      });
      if (!selected) return;
      const paths = Array.isArray(selected) ? selected : [selected];
      if (paths.length === 0) return;
      await parseFiles(paths);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setLocalError(message);
    }
  };
  const handleEnumerate = async () => {
    setLocalError(null);
    try {
      await enumerateLocalChannels();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setLocalError(message);
    }
  };

  const handleRemoteEnumerate = async () => {
    setLocalError(null);
    try {
      await enumerateRemoteChannels(remoteTarget);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setLocalError(message);
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
          fontSize: "18px",
          fontWeight: 600,
          color: tokens.colorNeutralForeground1,
        }}
      >
        Event Log Viewer
      </div>
      <div
        style={{
          fontSize: "13px",
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
          <Button appearance="primary" onClick={() => void handleOpenFiles()}>
            Open .evtx files...
          </Button>
          {isWindows && (
            <Button appearance="secondary" onClick={() => void handleEnumerate()}>
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
              onChange={(_, data) => setRemoteTarget(data.value)}
              placeholder="Remote computer name"
              aria-label="Remote computer name"
              style={{ flex: 1 }}
            />
            <Button
              appearance="secondary"
              disabled={!remoteTarget.trim()}
              onClick={() => void handleRemoteEnumerate()}
            >
              Remote computer
            </Button>
          </div>
          <div
            style={{
              fontSize: "11px",
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
            fontSize: "12px",
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
            fontSize: "12px",
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
