/**
 * The channel-clear workflow of the channel pane: which loaded channel is chosen, the confirmation
 * request, the single clear that may run at a time, how its result is announced, and where focus
 * goes while it runs and after it settles.
 *
 * It lives in a hook called by `ChannelPicker`, not in the clear controls, because the controls
 * unmount when the last loaded channel is cleared, and the focus recovery below must outlive them.
 * The store's `clearChannel` and `loadedChannels` come in as arguments, so a test can drive the
 * workflow with a fake. `ChannelClearControls` and `ChannelClearDialog` render what it returns.
 */
import { useEffect, useRef, useState, type RefObject } from "react";
import type { EvtxClearStatusResult } from "../../lib/commands";
import { useModalOwnership } from "../../hooks/use-modal-ownership";
import { useUiStore } from "../../stores/ui-store";

export interface ChannelClearOptions {
  /** The store's action: clears `channel` on the machine, stopping its live tail first. */
  clearChannel: (channel: string, confirmed: boolean) => Promise<EvtxClearStatusResult>;
  /** Only a loaded channel can be chosen; a chosen channel that stops being loaded is dropped. */
  loadedChannels: ReadonlySet<string>;
  /** The pane's channel filter: where focus goes when the clear controls cannot take it. */
  channelFilterRef: RefObject<HTMLElement | null>;
}

export interface ChannelClearWorkflow {
  /** The channel chosen in the select, or null. */
  target: string | null;
  /** The channel a confirmed clear is running for, or null. */
  clearingChannel: string | null;
  /** Why the last clear did not clear the channel, or null. */
  error: string | null;
  /** The confirmation is requested and the app's modal queue lets it show. */
  confirmationOpen: boolean;
  selectRef: RefObject<HTMLSelectElement | null>;
  statusRef: RefObject<HTMLDivElement | null>;
  alertRef: RefObject<HTMLDivElement | null>;
  /** The select's change: `null` is its empty option. */
  chooseTarget: (channel: string | null) => void;
  /** The Clear button: asks for confirmation of the chosen channel. */
  requestConfirmation: () => void;
  /** The dialog's own open change, such as Escape. */
  onConfirmationOpenChange: (open: boolean) => void;
  /** The dialog's Cancel button. */
  cancelConfirmation: () => void;
  /** The dialog's Clear channel button: starts the clear unless one is already running. */
  confirm: () => void;
  /** Focus entering and leaving the "Clearing" status, which decides whether focus is restored. */
  onStatusFocus: () => void;
  onStatusBlur: () => void;
}

export function useChannelClear({
  clearChannel,
  loadedChannels,
  channelFilterRef,
}: ChannelClearOptions): ChannelClearWorkflow {
  const [clearTarget, setClearTarget] = useState<string | null>(null);
  const clearTargetRef = useRef<string | null>(null);
  const clearInFlightRef = useRef<string | null>(null);
  const clearSelectRef = useRef<HTMLSelectElement | null>(null);
  const clearStatusRef = useRef<HTMLDivElement | null>(null);
  const clearAlertRef = useRef<HTMLDivElement | null>(null);
  const restoreClearFocusRef = useRef(false);
  const clearWorkflowOwnsFocusRef = useRef(false);
  const clearExternalFocusTargetRef = useRef<HTMLElement | null>(null);
  const clearDialogWasOpenRef = useRef(false);
  const clearDialogSubmittedRef = useRef(false);
  const [clearingChannel, setClearingChannel] = useState<string | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);
  const ownsClearConfirmation = useModalOwnership(
    "eventLogChannelClear",
    confirmClear,
  );
  const [clearError, setClearError] = useState<string | null>(null);

  useEffect(() => {
    if (clearingChannel !== null) {
      clearStatusRef.current?.focus();
      return;
    }
    if (!restoreClearFocusRef.current) return;
    restoreClearFocusRef.current = false;
    clearExternalFocusTargetRef.current = null;
    if (clearError !== null) {
      clearAlertRef.current?.focus();
    } else {
      (clearSelectRef.current ?? channelFilterRef.current)?.focus();
    }
  }, [clearingChannel, clearError]);

  useEffect(() => {
    if (clearingChannel === null) {
      const previousTarget = clearExternalFocusTargetRef.current;
      clearExternalFocusTargetRef.current = null;
      if (
        previousTarget !== null &&
        !previousTarget.isConnected &&
        document.activeElement === document.body &&
        useUiStore.getState().modalOwner === null
      ) {
        channelFilterRef.current?.focus();
      }
      return;
    }

    const rememberExternalFocus = (event: FocusEvent) => {
      if (
        event.target instanceof HTMLElement &&
        event.target !== clearStatusRef.current
      ) {
        clearExternalFocusTargetRef.current = event.target;
      }
    };
    document.addEventListener("focusin", rememberExternalFocus);
    return () => document.removeEventListener("focusin", rememberExternalFocus);
  }, [clearingChannel]);

  useEffect(() => {
    if (confirmClear) {
      clearDialogWasOpenRef.current = true;
      return;
    }
    if (!clearDialogWasOpenRef.current) return;
    clearDialogWasOpenRef.current = false;
    if (!clearDialogSubmittedRef.current) {
      (clearSelectRef.current ?? channelFilterRef.current)?.focus();
    }
    clearDialogSubmittedRef.current = false;
  }, [confirmClear]);

  useEffect(() => {
    if (clearingChannel !== null) return;
    const target = clearTargetRef.current;
    if (target === null || loadedChannels.has(target)) return;
    clearTargetRef.current = null;
    setClearTarget(null);
    setClearError(null);
  }, [clearingChannel, loadedChannels]);

  // Plain functions, rebuilt every render like the inline handlers they were, so each one reads
  // this render's `clearTarget`.
  return {
    target: clearTarget,
    clearingChannel,
    error: clearError,
    confirmationOpen: ownsClearConfirmation,
    selectRef: clearSelectRef,
    statusRef: clearStatusRef,
    alertRef: clearAlertRef,
    chooseTarget: (channel) => {
      clearTargetRef.current = channel;
      setClearTarget(channel);
      setClearError(null);
    },
    requestConfirmation: () => {
      if (!clearTarget) return;
      clearDialogSubmittedRef.current = false;
      setClearError(null);
      setConfirmClear(true);
    },
    onConfirmationOpenChange: (open) => {
      setConfirmClear(open);
      if (open) setClearError(null);
    },
    cancelConfirmation: () => setConfirmClear(false),
    confirm: () => {
      if (!clearTarget || clearInFlightRef.current !== null) return;
      const channel = clearTarget;
      clearDialogSubmittedRef.current = true;
      clearWorkflowOwnsFocusRef.current = true;
      clearExternalFocusTargetRef.current = null;
      clearInFlightRef.current = channel;
      setClearingChannel(channel);
      setClearError(null);
      setConfirmClear(false);
      const releasePendingClear = () => {
        if (clearInFlightRef.current !== channel) return false;
        restoreClearFocusRef.current = clearWorkflowOwnsFocusRef.current;
        clearWorkflowOwnsFocusRef.current = false;
        clearInFlightRef.current = null;
        setClearingChannel(null);
        return clearTargetRef.current === channel;
      };
      void clearChannel(channel, true)
        .then((result) => {
          if (!releasePendingClear()) return;
          if (result.status === "cleared") {
            clearTargetRef.current = null;
            setClearTarget(null);
            setClearError(null);
          } else if ("detail" in result) {
            setClearError(result.detail);
          } else {
            setClearError(
              result.status === "cancelled"
                ? "Clear was cancelled."
                : `${channel} is already empty.`
            );
          }
        })
        .catch((error: unknown) => {
          if (!releasePendingClear()) return;
          setClearError(error instanceof Error ? error.message : String(error));
        });
    },
    onStatusFocus: () => {
      clearWorkflowOwnsFocusRef.current = true;
    },
    onStatusBlur: () => {
      clearWorkflowOwnsFocusRef.current = false;
    },
  };
}
