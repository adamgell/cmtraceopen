import { useState } from "react";
import { Button, Spinner, tokens } from "@fluentui/react-components";
import { open } from "@tauri-apps/plugin-dialog";
import { useEvtxStore } from "./evtx-store";
import { useUiStore } from "../../stores/ui-store";

const EVTX_FILE_DIALOG_FILTERS = [
  { name: "Event Log Files", extensions: ["evtx"] },
  { name: "All Files", extensions: ["*"] },
];

export function SourcePicker() {
  const parseFiles = useEvtxStore((s) => s.parseFiles);
  const enumerateChannels = useEvtxStore((s) => s.enumerateChannels);
  const isLoading = useEvtxStore((s) => s.isLoading);
  const loadError = useEvtxStore((s) => s.loadError);
  const currentPlatform = useUiStore((s) => s.currentPlatform);
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
      await enumerateChannels();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setLocalError(message);
    }
  };

  const displayError = loadError ?? localError;

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
            Open .evtx Files
          </Button>
          {isWindows && (
            <Button appearance="secondary" onClick={() => void handleEnumerate()}>
              This Computer
            </Button>
          )}
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
    </div>
  );
}
