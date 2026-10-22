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
import {
  MAX_CUSTOM_VIEWS,
  MAX_VIEW_FILE_LENGTH,
  MAX_VIEW_NAME_LENGTH,
  SAVED_VIEW_SCHEMA,
  type EvtxViewImportFailure,
  type EvtxViewMerge,
} from "./evtx-views";
import type { EvtxViewFailure } from "./evtx-views-store";
import { useEvtxVisualTokens } from "./evtx-visual-tokens";

/** What the dialog says when a request is refused, in the operator's terms. */
export function viewFailureMessage(reason: EvtxViewFailure): string {
  switch (reason) {
    case "invalid-name":
      return `Use a name of 1 to ${MAX_VIEW_NAME_LENGTH} characters.`;
    case "name-taken":
      return "A view with that name already exists.";
    case "library-full":
      return `The library holds ${MAX_CUSTOM_VIEWS} views. Delete one to make room.`;
    case "unreadable":
      return "These filters would not read back as written, so they cannot be saved. Check that the Event IDs list is valid and that not too many channels are selected.";
    case "not-found":
      return "That view is no longer in the library.";
  }
}

/** Why a file was not imported, for the dialog to say. */
export function viewImportFailureMessage(reason: EvtxViewImportFailure): string {
  switch (reason) {
    case "too-large":
      return `That file is larger than ${MAX_VIEW_FILE_LENGTH / 1_048_576} MB, so it was not read.`;
    case "not-json":
      return "That file is not JSON, so it was not read.";
    case "unsupported-schema":
      return `That is not a view file this version can read. It reads schema ${SAVED_VIEW_SCHEMA}.`;
    case "not-a-view-file":
      return "That file has no list of views.";
  }
}

/** How picking and reading an import file ended. A cancelled picker is not a failure and not a success. */
export type EvtxViewImportOutcome =
  | { kind: "imported" }
  | { kind: "cancelled" }
  | { kind: "failed"; message: string };

/** What an import did, in counts: "Imported 2 views, 1 replaced, 1 skipped." */
export function viewImportSummary(result: Pick<EvtxViewMerge, "added" | "replaced" | "skipped">): string {
  const parts = [`Imported ${result.added} ${result.added === 1 ? "view" : "views"}`];
  if (result.replaced > 0) parts.push(`${result.replaced} replaced`);
  if (result.skipped > 0) parts.push(`${result.skipped} skipped`);
  return `${parts.join(", ")}.`;
}

const DIALOG_STYLE = {
  borderRadius: "8px",
  boxShadow: tokens.shadow16,
  padding: "24px",
} as const;

interface EvtxViewNameDialogProps {
  open: boolean;
  title: string;
  saveLabel: string;
  /** What the field holds each time the dialog opens. */
  initialName: string;
  /** Whether the "Include current layout" choice is offered (a new view), or not (a rename). */
  offerLayout: boolean;
  /** The text size of the dialog's labels and fields. */
  fontSize: string;
  onClose: () => void;
  /** Applies the name. Returns why it was refused, or null once it is done. */
  onSave: (name: string, includeLayout: boolean) => EvtxViewFailure | null;
  /**
   * Offers "Import views..." in the footer: picks a file and imports it. The dialog closes once it
   * imported, stays open and says why when it failed, and stays open when the picker was cancelled.
   * Left out where importing makes no sense.
   */
  onImport?: () => Promise<EvtxViewImportOutcome>;
}

/**
 * A name, and for a new view whether the current layout is saved with the filters ("+ New view",
 * spec 8.15). Also the rename dialog, which has the name alone.
 */
export function EvtxViewNameDialog({
  open,
  title,
  saveLabel,
  initialName,
  offerLayout,
  fontSize,
  onClose,
  onSave,
  onImport,
}: EvtxViewNameDialogProps) {
  const { levels } = useEvtxVisualTokens();
  const [name, setName] = useState(initialName);
  const [includeLayout, setIncludeLayout] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);
  const nameRef = useRef<HTMLInputElement>(null);

  // Each opening starts from the form's start, with the cursor in the name. Focus is set after the
  // dialog has taken it for itself, which it does when it mounts.
  useEffect(() => {
    if (!open) return;
    setName(initialName);
    setIncludeLayout(true);
    setError(null);
    const timer = setTimeout(() => {
      nameRef.current?.focus();
      nameRef.current?.select();
    }, 0);
    return () => clearTimeout(timer);
  }, [open, initialName]);

  const save = () => {
    const failure = onSave(name, includeLayout);
    if (failure === null) onClose();
    else setError(viewFailureMessage(failure));
  };
  const importViews = async () => {
    if (!onImport) return;
    setImporting(true);
    try {
      const outcome = await onImport();
      if (outcome.kind === "imported") onClose();
      else if (outcome.kind === "failed") setError(outcome.message);
    } finally {
      setImporting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(_, data) => !data.open && onClose()}>
      <DialogSurface style={DIALOG_STYLE} aria-label={title}>
        <DialogBody>
          <DialogTitle>{title}</DialogTitle>
          <DialogContent style={{ display: "flex", flexDirection: "column", gap: "12px", fontSize }}>
            <Field label={{ children: "Name", style: { fontSize } }} required>
              <Input
                ref={nameRef}
                size="small"
                value={name}
                maxLength={MAX_VIEW_NAME_LENGTH}
                input={{ style: { fontSize } }}
                aria-invalid={error !== null}
                aria-describedby={error ? "evtx-view-name-error" : undefined}
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
              <span id="evtx-view-name-error" role="alert" style={{ color: levels.Error.textColor }}>
                {error}
              </span>
            )}
            {offerLayout && (
              <Checkbox
                checked={includeLayout}
                label={<span style={{ fontSize }}>Include current layout</span>}
                onChange={(_, data) => setIncludeLayout(data.checked === true)}
              />
            )}
          </DialogContent>
          {onImport && (
            <DialogActions position="start">
              <Button appearance="secondary" size="small" disabled={importing} onClick={() => void importViews()}>
                Import views...
              </Button>
            </DialogActions>
          )}
          <DialogActions position="end">
            <Button appearance="secondary" size="small" onClick={onClose}>
              Cancel
            </Button>
            <Button appearance="primary" size="small" onClick={save}>
              {saveLabel}
            </Button>
          </DialogActions>
        </DialogBody>
      </DialogSurface>
    </Dialog>
  );
}

interface EvtxDeleteViewDialogProps {
  open: boolean;
  name: string;
  fontSize: string;
  onClose: () => void;
  onConfirm: () => void;
}

/** Asks before a view is deleted. Cancel has the focus: the safe action, not the destructive one. */
export function EvtxDeleteViewDialog({ open, name, fontSize, onClose, onConfirm }: EvtxDeleteViewDialogProps) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!open) return;
    const timer = setTimeout(() => cancelRef.current?.focus(), 0);
    return () => clearTimeout(timer);
  }, [open]);

  return (
    <Dialog open={open} onOpenChange={(_, data) => !data.open && onClose()}>
      <DialogSurface style={DIALOG_STYLE} aria-label="Delete view">
        <DialogBody>
          <DialogTitle>Delete view</DialogTitle>
          <DialogContent style={{ fontSize }}>
            Delete the view &quot;{name}&quot;? It cannot be brought back.
          </DialogContent>
          <DialogActions>
            <Button ref={cancelRef} appearance="secondary" size="small" onClick={onClose}>
              Cancel
            </Button>
            <Button appearance="primary" size="small" onClick={onConfirm}>
              Delete
            </Button>
          </DialogActions>
        </DialogBody>
      </DialogSurface>
    </Dialog>
  );
}
