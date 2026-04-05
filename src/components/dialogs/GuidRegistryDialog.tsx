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
import type { GuidCategory, GuidRegistryEntry } from "../../types/intune";

const SOURCE_LABELS: Record<string, { label: string; color: string }> = {
  ApplicationName: { label: "AppName", color: tokens.colorPaletteGreenForeground1 },
  NameField: { label: "Name", color: tokens.colorBrandForeground1 },
  SetUpFilePath: { label: "FilePath", color: tokens.colorNeutralForeground3 },
  GraphApi: { label: "Graph API", color: tokens.colorPalettePurpleForeground2 },
};

type TabId = "all" | "apps" | "scripts" | "remediations";

interface TabDef {
  id: TabId;
  label: string;
  filter: (category: GuidCategory | undefined) => boolean;
}

const TABS: TabDef[] = [
  { id: "all", label: "All", filter: () => true },
  { id: "apps", label: "Apps", filter: (c) => !c || c === "app" || c === "unknown" },
  { id: "scripts", label: "Scripts", filter: (c) => c === "script" },
  { id: "remediations", label: "Remediations", filter: (c) => c === "remediation" },
];

interface GuidRegistryDialogProps {
  isOpen: boolean;
  onClose: () => void;
}

interface RowEntry extends GuidRegistryEntry {
  guid: string;
}

export function GuidRegistryDialog({ isOpen, onClose }: GuidRegistryDialogProps) {
  const guidRegistry = useIntuneStore((s) => s.guidRegistry);
  const [filter, setFilter] = useState("");
  const [activeTab, setActiveTab] = useState<TabId>("all");

  const allEntries = useMemo(() => {
    const all: RowEntry[] = Object.entries(guidRegistry).map(([guid, entry]) => ({
      guid,
      ...entry,
    }));
    all.sort((a, b) => a.name.localeCompare(b.name));
    return all;
  }, [guidRegistry]);

  const tabCounts = useMemo(() => {
    const counts: Record<TabId, number> = { all: allEntries.length, apps: 0, scripts: 0, remediations: 0 };
    for (const entry of allEntries) {
      const tab = TABS.find((t) => t.id !== "all" && t.filter(entry.category));
      if (tab) counts[tab.id]++;
    }
    return counts;
  }, [allEntries]);

  const filteredEntries = useMemo(() => {
    const tabDef = TABS.find((t) => t.id === activeTab) ?? TABS[0];
    let entries = allEntries.filter((e) => tabDef.filter(e.category));

    if (filter.trim()) {
      const needle = filter.toLowerCase();
      entries = entries.filter(
        (e) =>
          e.name.toLowerCase().includes(needle) ||
          e.guid.toLowerCase().includes(needle) ||
          (e.publisher?.toLowerCase().includes(needle) ?? false)
      );
    }

    return entries;
  }, [allEntries, activeTab, filter]);

  return (
    <Dialog open={isOpen} onOpenChange={(_, data) => { if (!data.open) onClose(); }}>
      <DialogSurface style={{ maxWidth: "900px", width: "90vw" }}>
        <DialogBody>
          <DialogTitle>GUID Registry</DialogTitle>
          <DialogContent>
            {/* Tab bar */}
            <div
              style={{
                display: "flex",
                gap: "0",
                borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                marginBottom: "12px",
              }}
            >
              {TABS.map((tab) => {
                const count = tabCounts[tab.id];
                if (tab.id !== "all" && count === 0) return null;
                return (
                  <button
                    type="button"
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    style={{
                      padding: "6px 14px",
                      fontSize: "12px",
                      border: "none",
                      borderBottom:
                        activeTab === tab.id
                          ? `2px solid ${tokens.colorBrandForeground1}`
                          : "2px solid transparent",
                      background: "transparent",
                      color:
                        activeTab === tab.id
                          ? tokens.colorBrandForeground1
                          : tokens.colorNeutralForeground2,
                      fontWeight: activeTab === tab.id ? 600 : 400,
                      cursor: "pointer",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {tab.label} ({count})
                  </button>
                );
              })}
            </div>

            {/* Search */}
            <div style={{ marginBottom: "12px", display: "flex", alignItems: "center", gap: "8px" }}>
              <Input
                contentBefore={<SearchRegular />}
                placeholder="Filter by name, GUID, or publisher..."
                value={filter}
                onChange={(_, data) => setFilter(data.value)}
                style={{ flex: 1 }}
              />
              <span style={{ fontSize: "12px", color: tokens.colorNeutralForeground3, whiteSpace: "nowrap" }}>
                {filteredEntries.length === tabCounts[activeTab]
                  ? `${filteredEntries.length} entries`
                  : `${filteredEntries.length} / ${tabCounts[activeTab]}`}
              </span>
            </div>

            {allEntries.length === 0 ? (
              <div style={{ padding: "20px", textAlign: "center", color: tokens.colorNeutralForeground3 }}>
                No GUID registry data available. Run an Intune analysis or enable Graph API in Settings.
              </div>
            ) : filteredEntries.length === 0 ? (
              <div style={{ padding: "20px", textAlign: "center", color: tokens.colorNeutralForeground3 }}>
                No matches for &ldquo;{filter}&rdquo;
              </div>
            ) : (
              <div
                style={{
                  maxHeight: "500px",
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
                      <th style={thStyle}>Name</th>
                      <th style={thStyle}>GUID</th>
                      {activeTab === "all" && <th style={{ ...thStyle, width: "90px" }}>Type</th>}
                      <th style={{ ...thStyle, width: "120px" }}>Publisher</th>
                      <th style={{ ...thStyle, width: "80px" }}>Source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredEntries.map((entry) => (
                      <GuidRow key={entry.guid} entry={entry} showType={activeTab === "all"} />
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

const CATEGORY_LABELS: Record<string, { label: string; color: string }> = {
  app: { label: "App", color: tokens.colorBrandForeground1 },
  script: { label: "Script", color: tokens.colorPaletteMarigoldForeground1 },
  remediation: { label: "Remediation", color: tokens.colorPaletteTealForeground2 },
  unknown: { label: "-", color: tokens.colorNeutralForeground3 },
};

function GuidRow({ entry, showType }: { entry: RowEntry; showType: boolean }) {
  const sourceInfo = SOURCE_LABELS[entry.source] ?? { label: entry.source, color: tokens.colorNeutralForeground3 };
  const categoryInfo = CATEGORY_LABELS[entry.category ?? "unknown"] ?? CATEGORY_LABELS.unknown;

  const handleCopyGuid = async () => {
    try {
      await writeText(entry.guid);
    } catch { /* ignore */ }
  };

  return (
    <tr
      style={{ cursor: "pointer" }}
      onClick={handleCopyGuid}
      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); handleCopyGuid(); } }}
      tabIndex={0}
      role="button"
      title="Click to copy GUID"
      aria-label={`Copy GUID ${entry.guid}`}
    >
      <td style={{ ...tdStyle, fontWeight: 500, color: tokens.colorNeutralForeground1 }}>
        {entry.name}
      </td>
      <td style={{ ...tdStyle, color: tokens.colorNeutralForeground3, fontSize: "11px" }}>
        {entry.guid}
      </td>
      {showType && (
        <td style={tdStyle}>
          <span style={{ fontSize: "10px", fontWeight: 600, color: categoryInfo.color }}>
            {categoryInfo.label}
          </span>
        </td>
      )}
      <td style={{ ...tdStyle, color: tokens.colorNeutralForeground3, fontSize: "11px" }}>
        {entry.publisher ?? ""}
      </td>
      <td style={tdStyle}>
        <span style={{ fontSize: "10px", fontWeight: 600, color: sourceInfo.color }}>
          {sourceInfo.label}
        </span>
      </td>
    </tr>
  );
}
