/**
 * The channel pane's clear controls and their confirmation dialog. Both only render the workflow
 * that `useChannelClear` holds: the picker places the controls in its control stack, shown in live
 * mode while a channel is loaded, and the dialog right after that stack.
 */
import {
  Button,
  Dialog,
  DialogActions,
  DialogBody,
  DialogContent,
  DialogSurface,
  DialogTitle,
  Select,
  tokens,
} from "@fluentui/react-components";
import type { ChannelClearWorkflow } from "./use-channel-clear";

/** The channel select, the Clear button, and the clear's status or error line. */
export function ChannelClearControls({
  workflow,
  loadedChannels,
  isLoading,
  fontSize,
  smallFontSize,
}: {
  workflow: ChannelClearWorkflow;
  loadedChannels: ReadonlySet<string>;
  /** A channel load is running: no clear may start until it settles. */
  isLoading: boolean;
  fontSize: number;
  smallFontSize: number;
}) {
  const { target, clearingChannel, error } = workflow;
  return (
    <>
      <div style={{ display: "flex", gap: "4px", alignItems: "center" }}>
        <Select
          ref={workflow.selectRef}
          aria-label="Channel to clear"
          value={target ?? ""}
          disabled={clearingChannel !== null}
          onChange={(_, data) => workflow.chooseTarget(data.value || null)}
          style={{ flex: 1, minWidth: 0, fontSize: `${fontSize}px` }}
        >
          <option value="">Select channel to clear…</option>
          {[...loadedChannels].sort().map((channel) => (
            <option key={channel} value={channel}>
              {channel}
            </option>
          ))}
        </Select>
        <Button
          disabled={!target || isLoading || clearingChannel !== null}
          onClick={workflow.requestConfirmation}
          style={{ fontSize: `${fontSize}px` }}
        >
          Clear
        </Button>
      </div>
      {clearingChannel !== null && (
        <div
          ref={workflow.statusRef}
          role="status"
          tabIndex={-1}
          onFocus={workflow.onStatusFocus}
          onBlur={workflow.onStatusBlur}
          style={{ fontSize: `${smallFontSize}px` }}
        >
          Clearing {clearingChannel}…
        </div>
      )}
      {error && (
        <div
          ref={workflow.alertRef}
          role="alert"
          tabIndex={-1}
          style={{
            color: tokens.colorPaletteRedForeground1,
            fontSize: `${smallFontSize}px`,
          }}
        >
          {error}
        </div>
      )}
    </>
  );
}

/** Asks before a clear, which cannot be undone; it shows only while the modal queue grants it. */
export function ChannelClearDialog({ workflow }: { workflow: ChannelClearWorkflow }) {
  return (
    <Dialog
      open={workflow.confirmationOpen}
      onOpenChange={(_, data) => workflow.onConfirmationOpenChange(data.open)}
    >
      <DialogSurface>
        <DialogBody>
          <DialogTitle>Clear event channel?</DialogTitle>
          <DialogContent>
            This permanently removes every event currently stored in{" "}
            <strong>{workflow.clearingChannel ?? workflow.target}</strong>. The action requires an
            already elevated application and cannot be undone.
          </DialogContent>
          <DialogActions>
            <Button appearance="secondary" onClick={workflow.cancelConfirmation}>
              Cancel
            </Button>
            <Button appearance="primary" onClick={workflow.confirm}>
              Clear channel
            </Button>
          </DialogActions>
        </DialogBody>
      </DialogSurface>
    </Dialog>
  );
}
