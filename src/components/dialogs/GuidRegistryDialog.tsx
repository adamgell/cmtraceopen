import { useMemo, useState } from "react";
import {
  Button,
  Dialog,
  DialogActions,
  DialogBody,
  DialogContent,
  DialogSurface,
  DialogTitle,
  Input,
  tokens,
} from "@fluentui/react-components";
import { SearchRegular } from "@fluentui/react-icons";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";
import { useIntuneStore } from "../../stores/intune-store";
import type { GuidRegistryEntry } from "../../types/intune";

const SOURCE_LABELS: Record<string, { label: string; color: string }> = {
  ApplicationName: { label: "AppName", color: tokens.colorPaletteGreenForeground1 },
  NameField: { label: "Name", color: tokens.colorBrandForeground1 },
  SetUpFilePath: { label: "FilePath", color: tokens.colorNeutralForeground3 },
};

interface GuidRegistryDialogProps {
  isOpen: boolean;
  onClose: () => void;
}

export function GuidRegistryDialog({ isOpen, onClose }: GuidRegistryDialogProps) {
  const guidRegistry = useIntuneStore((s) => s.guidRegistry);
  const [filter, setFilter] = useState("");

  const entries = useMemo(() => {
    const all = Object.entries(guidRegistry).map(([guid, entry]) => ({
      guid,
      ...entry,
    }));
    all.sort((a, b) => a.name.localeCompare(b.name));

    if (!filter.trim()) return all;
    const needle = filter.toLowerCase();
    return all.filter(
      (e) =>
        e.name.toLowerCase().includes(needle) ||
        e.guid.toLowerCase().includes(needle)
    );
  }, [guidRegistry, filter]);

  const totalCount = Object.keys(guidRegistry).length;

  return (
    <Dialog open={isOpen} onOpenChange={(_, data) => { if (!data.open) onClose(); }}>
      <DialogSurface style={{ maxWidth: "750px", width: "90vw" }}>
        <DialogBody>
          <DialogTitle>GUID Registry</DialogTitle>
          <DialogContent>
            <div style={{ marginBottom: "12px", display: "flex", alignItems: "center", gap: "8px" }}>
              <Input
                contentBefore={<SearchRegular />}
                placeholder="Filter by name or GUID..."
                value={filter}
                onChange={(_, data) => setFilter(data.value)}
                style={{ flex: 1 }}
              />
              <span style={{ fontSize: "12px", color: tokens.colorNeutralForeground3 }}>
                {entries.length === totalCount
                  ? `${totalCount} entries`
                  : `${entries.length} / ${totalCount}`}
              </span>
            </div>

            {totalCount === 0 ? (
              <div style={{ padding: "20px", textAlign: "center", color: tokens.colorNeutralForeground3 }}>
                No GUID registry data available. Run an Intune analysis first.
              </div>
            ) : (
              <div
                style={{
                  maxHeight: "400px",
                  overflowY: "auto",
                  border: `1px solid ${tokens.colorNeutralStroke2}`,
                  borderRadius: "4px",
                }}
              >
                <table
                  style={{
                    width: "100%",
                    borderCollapse: "collapse",
                    fontSize: "12px",
                    fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                  }}
                >
                  <thead>
                    <tr
                      style={{
                        position: "sticky",
                        top: 0,
                        backgroundColor: tokens.colorNeutralBackground3,
                        zIndex: 1,
                      }}
                    >
                      <th style={thStyle}>App Name</th>
                      <th style={thStyle}>GUID</th>
                      <th style={{ ...thStyle, width: "80px" }}>Source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {entries.map((entry) => (
                      <GuidRow key={entry.guid} guid={entry.guid} entry={entry} />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </DialogContent>
          <DialogActions>
            <Button appearance="secondary" onClick={onClose}>
              Close
            </Button>
          </DialogActions>
        </DialogBody>
      </DialogSurface>
    </Dialog>
  );
}

const thStyle: React.CSSProperties = {
  textAlign: "left",
  padding: "6px 8px",
  fontWeight: 600,
  fontSize: "11px",
  textTransform: "uppercase",
  letterSpacing: "0.5px",
  borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
};

const tdStyle: React.CSSProperties = {
  padding: "4px 8px",
  borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
  verticalAlign: "middle",
};

function GuidRow({ guid, entry }: { guid: string; entry: GuidRegistryEntry }) {
  const sourceInfo = SOURCE_LABELS[entry.source] ?? { label: entry.source, color: tokens.colorNeutralForeground3 };

  const handleCopyGuid = async () => {
    try {
      await writeText(guid);
    } catch { /* ignore */ }
  };

  return (
    <tr
      style={{ cursor: "pointer" }}
      onClick={handleCopyGuid}
      title="Click to copy GUID"
    >
      <td style={{ ...tdStyle, fontWeight: 500, color: tokens.colorNeutralForeground1 }}>
        {entry.name}
      </td>
      <td style={{ ...tdStyle, color: tokens.colorNeutralForeground3, fontSize: "11px" }}>
        {guid}
      </td>
      <td style={tdStyle}>
        <span
          style={{
            fontSize: "10px",
            fontWeight: 600,
            color: sourceInfo.color,
          }}
        >
          {sourceInfo.label}
        </span>
      </td>
    </tr>
  );
}
