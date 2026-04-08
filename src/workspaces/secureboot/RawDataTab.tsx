import { useState } from "react";
import { Button, tokens } from "@fluentui/react-components";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";

export interface RawDataTabProps {
  rawDump: string | null;
}

export function RawDataTab({ rawDump }: RawDataTabProps) {
  const [copyStatus, setCopyStatus] = useState<"idle" | "copied" | "error">("idle");

  if (!rawDump) {
    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: "48px 24px",
          color: tokens.colorNeutralForeground3,
          fontSize: "13px",
          textAlign: "center",
        }}
      >
        No raw data is available for this analysis.
      </div>
    );
  }

  const handleCopy = () => {
    writeText(rawDump).then(
      () => {
        setCopyStatus("copied");
        window.setTimeout(() => setCopyStatus("idle"), 2500);
      },
      () => {
        setCopyStatus("error");
        window.setTimeout(() => setCopyStatus("idle"), 3000);
      },
    );
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "8px",
          flexWrap: "wrap",
        }}
      >
        <span
          style={{ fontSize: "12px", color: tokens.colorNeutralForeground3 }}
        >
          Raw registry and scan dump for debugging.
        </span>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          {copyStatus === "copied" && (
            <span
              style={{ fontSize: "12px", color: tokens.colorPaletteGreenForeground1 }}
            >
              Copied to clipboard.
            </span>
          )}
          {copyStatus === "error" && (
            <span
              style={{ fontSize: "12px", color: tokens.colorPaletteRedForeground1 }}
            >
              Copy failed.
            </span>
          )}
          <Button appearance="secondary" onClick={handleCopy}>
            Copy
          </Button>
        </div>
      </div>

      <pre
        style={{
          margin: 0,
          padding: "12px",
          border: `1px solid ${tokens.colorNeutralStroke2}`,
          borderRadius: "8px",
          backgroundColor: tokens.colorNeutralBackground2,
          fontFamily: "monospace",
          fontSize: "12px",
          lineHeight: 1.6,
          color: tokens.colorNeutralForeground1,
          overflowX: "auto",
          whiteSpace: "pre-wrap",
          wordBreak: "break-word",
        }}
      >
        {rawDump}
      </pre>
    </div>
  );
}
