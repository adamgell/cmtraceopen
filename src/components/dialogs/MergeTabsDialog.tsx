import { useMemo, useState } from "react";
import {
  Button,
  Checkbox,
  Dialog,
  DialogActions,
  DialogBody,
  DialogContent,
  DialogSurface,
  DialogTitle,
  tokens,
} from "@fluentui/react-components";
import { WarningRegular } from "@fluentui/react-icons";
import { LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";
import { getCachedTabSnapshot } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import { formatLogEntryTimestamp } from "../../lib/date-time-format";

interface MergeTabsDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onMerge: (filePaths: string[]) => void;
}

interface TabInfo {
  filePath: string;
  fileName: string;
  entryCount: number;
  hasTimestamps: boolean;
  timeRange: string | null;
}

function getTabInfo(filePath: string): TabInfo {
  const snapshot = getCachedTabSnapshot(filePath);
  const fileName = filePath.split(/[\\/]/).pop() ?? filePath;
  if (!snapshot) {
    return { filePath, fileName, entryCount: 0, hasTimestamps: false, timeRange: null };
  }

  const timestamped = snapshot.entries.filter((e) => e.timestamp != null);
  const hasTimestamps = timestamped.length > 0;

  let timeRange: string | null = null;
  if (hasTimestamps) {
    const first = formatLogEntryTimestamp(timestamped[0]);
    const last = formatLogEntryTimestamp(timestamped[timestamped.length - 1]);
    if (first && last) {
      timeRange = `${first} — ${last}`;
    }
  }

  return {
    filePath,
    fileName,
    entryCount: snapshot.entries.length,
    hasTimestamps,
    timeRange,
  };
}

export function MergeTabsDialog({ isOpen, onClose, onMerge }: MergeTabsDialogProps) {
  const openTabs = useUiStore((s) => s.openTabs);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const tabInfos = useMemo(() => {
    return openTabs.map((tab) => getTabInfo(tab.filePath));
  }, [openTabs]);

  const toggleFile = (filePath: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(filePath)) next.delete(filePath);
      else next.add(filePath);
      return next;
    });
  };

  const selectAll = () => {
    const eligible = tabInfos.filter((t) => t.hasTimestamps).map((t) => t.filePath);
    setSelected(new Set(eligible));
  };

  const selectNone = () => setSelected(new Set());

  const canMerge = selected.size >= 2;

  const handleMerge = () => {
    if (!canMerge) return;
    onMerge(Array.from(selected));
    setSelected(new Set());
    onClose();
  };

  const handleClose = () => {
    setSelected(new Set());
    onClose();
  };

  return (
    <Dialog open={isOpen} onOpenChange={(_, data) => { if (!data.open) handleClose(); }}>
      <DialogSurface style={{ maxWidth: "600px", width: "90vw" }}>
        <DialogBody>
          <DialogTitle>Merge Tabs into Timeline</DialogTitle>
          <DialogContent>
            <div style={{ marginBottom: "8px", fontSize: "12px", color: tokens.colorNeutralForeground3 }}>
              Select 2 or more tabs to merge into a unified time-sorted view.
              Files without timestamps cannot be merged.
            </div>

            <div style={{ display: "flex", gap: "8px", marginBottom: "12px" }}>
              <Button size="small" appearance="subtle" onClick={selectAll}>Select All</Button>
              <Button size="small" appearance="subtle" onClick={selectNone}>Select None</Button>
            </div>

            <div
              style={{
                maxHeight: "300px",
                overflowY: "auto",
                border: `1px solid ${tokens.colorNeutralStroke2}`,
                borderRadius: "4px",
              }}
            >
              {tabInfos.map((tab) => (
                <div
                  key={tab.filePath}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                    padding: "8px 12px",
                    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                    opacity: tab.hasTimestamps ? 1 : 0.5,
                  }}
                >
                  <Checkbox
                    checked={selected.has(tab.filePath)}
                    onChange={() => toggleFile(tab.filePath)}
                    disabled={!tab.hasTimestamps}
                  />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{
                      fontWeight: 500,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}>
                      {tab.fileName}
                      {!tab.hasTimestamps && (
                        <WarningRegular
                          style={{ marginLeft: "6px", color: tokens.colorPaletteMarigoldForeground1 }}
                          fontSize={14}
                        />
                      )}
                    </div>
                    <div style={{
                      fontSize: "11px",
                      color: tokens.colorNeutralForeground3,
                      fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                    }}>
                      {tab.entryCount} entries
                      {tab.timeRange && ` | ${tab.timeRange}`}
                      {!tab.hasTimestamps && " | No timestamps — cannot merge"}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </DialogContent>
          <DialogActions>
            <Button appearance="secondary" onClick={handleClose}>Cancel</Button>
            <Button appearance="primary" disabled={!canMerge} onClick={handleMerge}>
              Merge {canMerge ? `(${selected.size} files)` : ""}
            </Button>
          </DialogActions>
        </DialogBody>
      </DialogSurface>
    </Dialog>
  );
}
