/**
 * The dialogs of the view strip (spec 8.15; design system "Adding a new dialog": 8 px radius,
 * shadow16, 24 px padding, a right-aligned action row with the primary button last, Escape cancels).
 *
 * The strip owns the library; these hold only what is typed and say why a request was refused.
 */
import { useEffect, useRef, useState } from "react";
import {
  Button,
  Checkbox,
  Dialog,
  DialogActions,
  DialogBody,
  DialogContent,
  DialogSurface,
  DialogTitle,
  Field,
  Input,
  tokens,
} from "@fluentui/react-components";
import { MAX_CUSTOM_VIEWS, MAX_VIEW_NAME_LENGTH } from "./evtx-views";
import type { EvtxViewFailure } from "./evtx-views-store";
import { useEvtxVisualTokens } from "./evtx-visual-tokens";

/** What the dialog says when a request is refused, in the operator's terms. */
export function viewFailureMessage(reason: EvtxViewFailure, name: string): string {
  switch (reason) {
    case "invalid-name":
      return name.trim()
        ? `Use a name of up to ${MAX_VIEW_NAME_LENGTH} characters, without control characters.`
        : "Enter a name.";
    case "name-taken":
      return "A view with that name already exists.";
    case "library-full":
      return `The library holds ${MAX_CUSTOM_VIEWS} views. Delete one to make room.`;
    case "unreadable":
      return "These filters would not read back as written, so they cannot be saved. Check the Event IDs list.";
    case "not-found":
      return "That view is no longer in the library.";
  }
}

const DIALOG_STYLE = {
  borderRadius: "8px",
  boxShadow: tokens.shadow16,
  padding: "24px",
} as const;

interface EvtxNewViewDialogProps {
  open: boolean;
  /** The text size of the dialog's labels and fields. */
  fontSize: string;
  onClose: () => void;
  /** Makes the view. Returns why it was refused, or null once it is made. */
  onSave: (name: string, includeLayout: boolean) => EvtxViewFailure | null;
}

/** "+ New view": a name, and whether the current layout is saved with the filters. */
export function EvtxNewViewDialog({ open, fontSize, onClose, onSave }: EvtxNewViewDialogProps) {
  const { levels } = useEvtxVisualTokens();
  const [name, setName] = useState("");
  const [includeLayout, setIncludeLayout] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const nameRef = useRef<HTMLInputElement>(null);

  // Each opening starts from a blank form, with the cursor in the name. Focus is set after the
  // dialog has taken it for itself, which it does when it mounts.
  useEffect(() => {
    if (!open) return;
    setName("");
    setIncludeLayout(true);
    setError(null);
    const timer = setTimeout(() => nameRef.current?.focus(), 0);
    return () => clearTimeout(timer);
  }, [open]);

  const save = () => {
    const failure = onSave(name, includeLayout);
    if (failure === null) onClose();
    else setError(viewFailureMessage(failure, name));
  };

  return (
    <Dialog open={open} onOpenChange={(_, data) => !data.open && onClose()}>
      <DialogSurface style={DIALOG_STYLE} aria-label="New view">
        <DialogBody>
          <DialogTitle>New view</DialogTitle>
          <DialogContent style={{ display: "flex", flexDirection: "column", gap: "12px", fontSize }}>
            <span style={{ color: tokens.colorNeutralForeground2 }}>
              Saves the filters that are applied now, so one click brings them back.
            </span>
            <Field label={{ children: "Name", style: { fontSize } }} required>
              <Input
                ref={nameRef}
                size="small"
                value={name}
                maxLength={MAX_VIEW_NAME_LENGTH}
                input={{ style: { fontSize } }}
                aria-invalid={error !== null}
                aria-describedby={error ? "evtx-new-view-error" : undefined}
                onChange={(_, data) => {
                  setName(data.value);
                  setError(null);
                }}
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    event.preventDefault();
                    save();
                  }
                }}
              />
            </Field>
            {error && (
              <span id="evtx-new-view-error" role="alert" style={{ color: levels.Error.textColor }}>
                {error}
              </span>
            )}
            <Checkbox
              checked={includeLayout}
              label={<span style={{ fontSize }}>Include current layout</span>}
              onChange={(_, data) => setIncludeLayout(data.checked === true)}
            />
          </DialogContent>
          <DialogActions>
            <Button appearance="secondary" size="small" onClick={onClose}>
              Cancel
            </Button>
            <Button appearance="primary" size="small" onClick={save}>
              Save
            </Button>
          </DialogActions>
        </DialogBody>
      </DialogSurface>
    </Dialog>
  );
}
