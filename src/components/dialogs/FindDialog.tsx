import { useEffect, useRef } from "react";
import {
  Button,
  Caption1,
  Checkbox,
  Dialog,
  DialogActions,
  DialogBody,
  DialogContent,
  DialogSurface,
  DialogTitle,
  Field,
  Input,
} from "@fluentui/react-components";
import { useLogStore } from "../../stores/log-store";

interface FindDialogProps {
  isOpen: boolean;
  onClose: () => void;
}

export function FindDialog({ isOpen, onClose }: FindDialogProps) {
  const inputRef = useRef<HTMLInputElement>(null);

  const searchText = useLogStore((s) => s.findQuery);
  const caseSensitive = useLogStore((s) => s.findCaseSensitive);
  const statusText = useLogStore((s) => s.findStatusText);
  const setFindQuery = useLogStore((s) => s.setFindQuery);
  const setFindCaseSensitive = useLogStore((s) => s.setFindCaseSensitive);
  const findNext = useLogStore((s) => s.findNext);
  const findPrevious = useLogStore((s) => s.findPrevious);

  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus();
      inputRef.current.select();
    }
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) {
      return;
    }

    const handleKey = (event: KeyboardEvent) => {
      if (event.key === "Enter" || event.key === "F3") {
        event.preventDefault();

        if (event.shiftKey) {
          findPrevious("find-dialog.keyboard");
          return;
        }

        findNext("find-dialog.keyboard");
      }
    };

    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [findNext, findPrevious, isOpen, onClose]);

  if (!isOpen) {
    return null;
  }

  return (
    <Dialog
      open={isOpen}
      modalType="modal"
      onOpenChange={(_, data) => {
        if (!data.open) {
          onClose();
        }
      }}
    >
      <DialogSurface
        style={{
          width: "min(460px, calc(100vw - 32px))",
          paddingTop: "8px",
        }}
      >
        <DialogBody>
          <DialogTitle>Find</DialogTitle>
          <DialogContent style={{ display: "grid", gap: "12px" }}>
            <Field label="Find what:">
              <Input
                ref={inputRef}
                value={searchText}
                onChange={(_, data) => setFindQuery(data.value)}
                placeholder="Search the current log view"
              />
            </Field>

            <div style={{ display: "grid", gap: "8px" }}>
              <Checkbox
                label="Match case"
                checked={caseSensitive}
                onChange={(_, data) => setFindCaseSensitive(Boolean(data.checked))}
              />
              {statusText && <Caption1>{statusText}</Caption1>}
            </div>
          </DialogContent>
          <DialogActions>
            <Button appearance="secondary" onClick={() => findPrevious("find-dialog.button.previous")}>
              Find Previous
            </Button>
            <Button appearance="primary" onClick={() => findNext("find-dialog.button.next")}>
              Find Next
            </Button>
            <Button appearance="secondary" onClick={onClose}>
              Close
            </Button>
          </DialogActions>
        </DialogBody>
      </DialogSurface>
    </Dialog>
  );
}
