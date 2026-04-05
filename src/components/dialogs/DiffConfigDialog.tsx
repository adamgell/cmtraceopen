import { useMemo, useState } from "react";
import {
  Button,
  Dialog,
  DialogActions,
  DialogBody,
  DialogContent,
  DialogSurface,
  DialogTitle,
  tokens,
} from "@fluentui/react-components";
import { LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";
import { getCachedTabSnapshot } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import type { DiffSource } from "../../lib/diff-entries";

interface DiffConfigDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onCompare: (sourceA: DiffSource, sourceB: DiffSource) => void;
}

export function DiffConfigDialog({ isOpen, onClose, onCompare }: DiffConfigDialogProps) {
  const openTabs = useUiStore((s) => s.openTabs);
  const [fileA, setFileA] = useState<string>("");
  const [fileB, setFileB] = useState<string>("");

  const tabOptions = useMemo(() => {
    return openTabs
      .filter((tab) => tab.fileKind === "log")
      .map((tab) => {
        const snapshot = getCachedTabSnapshot(tab.filePath);
        const count = snapshot?.entries.length ?? 0;
        return { filePath: tab.filePath, fileName: tab.fileName, entryCount: count };
      });
  }, [openTabs]);

  const hasFileA = tabOptions.some((option) => option.filePath === fileA);
  const hasFileB = tabOptions.some((option) => option.filePath === fileB);
  const canCompare = fileA !== "" && fileB !== "" && fileA !== fileB && hasFileA && hasFileB;

  const handleCompare = () => {
    if (!canCompare) return;
    const nameA = fileA.split(/[\\/]/).pop() ?? fileA;
    const nameB = fileB.split(/[\\/]/).pop() ?? fileB;
    onCompare(
      { filePath: fileA, label: nameA },
      { filePath: fileB, label: nameB }
    );
    onClose();
  };

  const handleClose = () => {
    setFileA("");
    setFileB("");
    onClose();
  };

  const selectStyle: React.CSSProperties = {
    flex: 1,
    padding: "6px 8px",
    fontSize: "12px",
    border: `1px solid ${tokens.colorNeutralStroke2}`,
    borderRadius: "4px",
    backgroundColor: tokens.colorNeutralBackground1,
    color: tokens.colorNeutralForeground1,
    fontFamily: LOG_MONOSPACE_FONT_FAMILY,
  };

  return (
    <Dialog open={isOpen} onOpenChange={(_, data) => { if (!data.open) handleClose(); }}>
      <DialogSurface style={{ maxWidth: "500px", width: "90vw" }}>
        <DialogBody>
          <DialogTitle>Compare Log Files</DialogTitle>
          <DialogContent>
            <div style={{ marginBottom: "12px", fontSize: "12px", color: tokens.colorNeutralForeground3 }}>
              Select two open tabs to compare. Lines unique to each file will be highlighted.
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <div>
                <div style={{ fontSize: "11px", fontWeight: 600, color: tokens.colorNeutralForeground2, marginBottom: "4px" }}>
                  Source A
                </div>
                <select value={fileA} onChange={(e) => setFileA(e.target.value)} style={selectStyle}>
                  <option value="">Select a file...</option>
                  {tabOptions.map((t) => (
                    <option key={t.filePath} value={t.filePath} disabled={t.filePath === fileB}>
                      {t.fileName} ({t.entryCount} entries)
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <div style={{ fontSize: "11px", fontWeight: 600, color: tokens.colorNeutralForeground2, marginBottom: "4px" }}>
                  Source B
                </div>
                <select value={fileB} onChange={(e) => setFileB(e.target.value)} style={selectStyle}>
                  <option value="">Select a file...</option>
                  {tabOptions.map((t) => (
                    <option key={t.filePath} value={t.filePath} disabled={t.filePath === fileA}>
                      {t.fileName} ({t.entryCount} entries)
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </DialogContent>
          <DialogActions>
            <Button appearance="secondary" onClick={handleClose}>Cancel</Button>
            <Button appearance="primary" disabled={!canCompare} onClick={handleCompare}>
              Compare
            </Button>
          </DialogActions>
        </DialogBody>
      </DialogSurface>
    </Dialog>
  );
}
