import { useEffect, useState } from "react";
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
import { useUiStore } from "../../stores/ui-store";

interface MergeTabsDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onMerge: (filePaths: string[]) => void;
}

export function MergeTabsDialog({ isOpen, onClose, onMerge }: MergeTabsDialogProps) {
  const openTabs = useUiStore((s) => s.openTabs);
  const [selectedPaths, setSelectedPaths] = useState<Set<string>>(new Set());

  // Reset selection when dialog opens
  useEffect(() => {
    if (isOpen) {
      setSelectedPaths(new Set());
    }
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [isOpen, onClose]);

  const togglePath = (path: string) => {
    setSelectedPaths((prev) => {
      const next = new Set(prev);
      if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      return next;
    });
  };

  const handleMerge = () => {
    if (selectedPaths.size < 2) return;
    onMerge(Array.from(selectedPaths));
    onClose();
  };

  // Only show log-type tabs that have file paths
  const mergeable = openTabs.filter((t) => t.filePath && t.fileKind !== "registry");

  if (!isOpen) return null;

  return (
    <Dialog open={isOpen} onOpenChange={(_, data) => { if (!data.open) onClose(); }}>
      <DialogSurface>
        <DialogBody>
          <DialogTitle>Merge Tabs into Unified Timeline</DialogTitle>
          <DialogContent>
            <p style={{ margin: "0 0 12px", color: tokens.colorNeutralForeground2, fontSize: 13 }}>
              Select two or more log files to merge into a single chronological timeline.
            </p>
            {mergeable.length < 2 ? (
              <p style={{ color: tokens.colorNeutralForeground3, fontSize: 13 }}>
                Open at least two log files to use this feature.
              </p>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {mergeable.map((tab) => {
                  const label = tab.filePath.split(/[\\/]/).pop() || tab.filePath;
                  return (
                    <Checkbox
                      key={tab.filePath}
                      checked={selectedPaths.has(tab.filePath)}
                      onChange={() => togglePath(tab.filePath)}
                      label={label}
                    />
                  );
                })}
              </div>
            )}
          </DialogContent>
          <DialogActions>
            <Button appearance="secondary" onClick={onClose}>Cancel</Button>
            <Button
              appearance="primary"
              onClick={handleMerge}
              disabled={selectedPaths.size < 2}
            >
              Merge ({selectedPaths.size} files)
            </Button>
          </DialogActions>
        </DialogBody>
      </DialogSurface>
    </Dialog>
  );
}
