import { useCallback, useEffect, useRef, useState } from "react";
import { tokens } from "@fluentui/react-components";
import { useUiStore } from "../../stores/ui-store";
import { describeElevationPrompt } from "../../lib/elevation-request";
import {
  describeElevationOutcome,
  requestElevatedRestart,
  type ElevationOutcome,
} from "../../lib/elevation";

/** Everything the browser would let Tab reach inside the modal. */
const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(", ");

/**
 * The single confirmation shown before CMTrace Open requests UAC.
 *
 * File > Restart as Administrator and the Access Denied recovery prompt both
 * render through here, so neither can reach the backend without a second,
 * deliberate click. The reason carried on the request changes only the wording;
 * the backend call is identical.
 *
 * The ESP coverage banner is the one caller that does not route through this
 * dialog. Its button is already an explicit, labelled affordance rather than a
 * failure the user did not ask for, so it calls the coordinator directly.
 *
 * `aria-modal` is a promise to assistive technology, not an implementation:
 * the browser still walks Tab into the content behind the overlay. So this
 * component moves focus in on open, cycles Tab inside the surface, and restores
 * focus to whatever opened it on close. Fluent's `Dialog` would supply all
 * three, but its focus manager (tabster) calls `getComputedStyle` in a way the
 * pinned jsdom build throws on, which takes the whole dialog suite down.
 *
 * On a successful launch the dialog intentionally stays up in a pending state:
 * the current process is exiting, and swapping to a success message the user
 * will never finish reading only invites a second click during teardown.
 */
export function RestartAsAdministratorDialog() {
  const prompt = useUiStore((state) => state.elevationPrompt);
  const modalOwner = useUiStore((state) => state.modalOwner);
  const setElevationPrompt = useUiStore((state) => state.setElevationPrompt);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const surfaceRef = useRef<HTMLDivElement>(null);

  const close = useCallback(() => {
    setElevationPrompt(null);
  }, [setElevationPrompt]);

  // Reset per-prompt UI state so a previous failure never leaks into a new
  // request opened from a different source.
  useEffect(() => {
    if (prompt) {
      setIsSubmitting(false);
      setFailure(null);
    }
  }, [prompt]);

  const activePrompt = modalOwner === "elevationPrompt" ? prompt : null;
  const isOpen = Boolean(activePrompt);

  // Move focus into the modal on open and hand it back on close, so a keyboard
  // user is not left tabbing through the application behind the overlay.
  useEffect(() => {
    if (!isOpen) return;

    const previouslyFocused =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;

    const surface = surfaceRef.current;
    const target =
      surface?.querySelector<HTMLElement>(FOCUSABLE_SELECTOR) ?? surface;
    target?.focus();

    return () => {
      previouslyFocused?.focus();
    };
  }, [isOpen]);

  useEffect(() => {
    if (!activePrompt) return;

    const handleKey = (event: KeyboardEvent) => {
      // Escape is a cancellation, which by contract makes no backend call. It is
      // ignored mid-flight because the request is already with Windows.
      if (event.key === "Escape") {
        if (!isSubmitting) close();
        return;
      }
      if (event.key !== "Tab") return;

      const surface = surfaceRef.current;
      if (!surface) return;

      const focusable = Array.from(
        surface.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
      );
      if (focusable.length === 0) {
        event.preventDefault();
        return;
      }

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active =
        document.activeElement instanceof HTMLElement
          ? document.activeElement
          : null;

      if (!active || !surface.contains(active)) {
        event.preventDefault();
        first.focus();
        return;
      }
      if (event.shiftKey && active === first) {
        event.preventDefault();
        last.focus();
        return;
      }
      if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    };

    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [activePrompt, isSubmitting, close]);

  const confirm = useCallback(async () => {
    if (!activePrompt || isSubmitting) return;

    setIsSubmitting(true);
    setFailure(null);

    let outcome: ElevationOutcome;
    try {
      outcome = await requestElevatedRestart(activePrompt.request);
    } catch (error) {
      // requestElevatedRestart is documented never to throw; treat a broken
      // contract as a failure rather than leaving the button stuck.
      console.error("[elevation] restart request threw", { error });
      setFailure("Administrator restart could not be started.");
      setIsSubmitting(false);
      return;
    }

    if (outcome.status === "launched") {
      // The process is exiting. Hold the pending state rather than closing.
      return;
    }

    if (outcome.status === "alreadyElevated") {
      close();
      return;
    }

    if (outcome.status === "cancelled") {
      // Cancelling UAC is not a failure: leave the app exactly as it was.
      close();
      return;
    }

    setFailure(describeElevationOutcome(outcome));
    setIsSubmitting(false);
  }, [activePrompt, isSubmitting, close]);

  if (!activePrompt) return null;

  return (
    <div
      role="presentation"
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: "rgba(0,0,0,0.3)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000,
      }}
      onClick={(event) => {
        if (event.target === event.currentTarget && !isSubmitting) close();
      }}
    >
      <div
        ref={surfaceRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="elevation-dialog-title"
        tabIndex={-1}
        style={{
          backgroundColor: tokens.colorNeutralBackground1,
          color: tokens.colorNeutralForeground1,
          border: `1px solid ${tokens.colorNeutralStroke1}`,
          borderRadius: "4px",
          padding: "16px",
          minWidth: "420px",
          maxWidth: "520px",
          boxShadow: tokens.shadow16,
        }}
      >
        <div
          id="elevation-dialog-title"
          style={{ fontSize: "16px", fontWeight: "bold", marginBottom: "10px" }}
        >
          Restart as administrator?
        </div>

        <div style={{ fontSize: "12px", marginBottom: "12px", lineHeight: 1.5 }}>
          {describeElevationPrompt(activePrompt.request)}
        </div>

        <div
          style={{
            fontSize: "11px",
            color: tokens.colorNeutralForeground3,
            marginBottom: failure ? "10px" : "16px",
          }}
        >
          Windows will ask you to approve the elevation.
        </div>

        {failure && (
          <div
            role="alert"
            style={{
              backgroundColor: tokens.colorNeutralBackground2,
              border: `1px solid ${tokens.colorPaletteRedBorder1}`,
              borderRadius: "2px",
              padding: "8px",
              marginBottom: "16px",
              fontSize: "11px",
              color: tokens.colorPaletteRedForeground1,
            }}
          >
            {failure}
          </div>
        )}

        <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px" }}>
          <button
            type="button"
            onClick={close}
            disabled={isSubmitting}
            style={{ padding: "4px 14px", fontSize: "12px" }}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => void confirm()}
            disabled={isSubmitting}
            style={{ padding: "4px 14px", fontSize: "12px", fontWeight: 600 }}
          >
            {isSubmitting ? "Requesting…" : "Restart as administrator"}
          </button>
        </div>
      </div>
    </div>
  );
}
