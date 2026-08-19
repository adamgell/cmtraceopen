import { useEffect, type RefObject } from "react";

const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(", ");

export function useModalFocus(
  isOpen: boolean,
  surfaceRef: RefObject<HTMLElement | null>,
  initialFocusRef?: RefObject<HTMLElement | null>,
  focusKey?: string | number | null,
): void {
  useEffect(() => {
    if (!isOpen) return;

    const previouslyFocused =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    const surface = surfaceRef.current;
    const preferred = initialFocusRef?.current;
    const target =
      preferred && !preferred.hasAttribute("disabled")
        ? preferred
        : surface?.querySelector<HTMLElement>(FOCUSABLE_SELECTOR) ?? surface;
    target?.focus();

    return () => {
      if (previouslyFocused?.isConnected) {
        previouslyFocused.focus();
      }
    };
  }, [initialFocusRef, isOpen, surfaceRef]);

  useEffect(() => {
    if (!isOpen || focusKey == null) return;

    const surface = surfaceRef.current;
    if (!surface) return;

    const active =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    if (active && surface.contains(active)) return;

    const preferred = initialFocusRef?.current;
    const target =
      preferred && !preferred.hasAttribute("disabled")
        ? preferred
        : surface.querySelector<HTMLElement>(FOCUSABLE_SELECTOR) ?? surface;
    target.focus();
  }, [focusKey, initialFocusRef, isOpen, surfaceRef]);

  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Tab") return;

      const surface = surfaceRef.current;
      if (!surface) return;

      const focusable = Array.from(
        surface.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
      );
      if (focusable.length === 0) {
        event.preventDefault();
        surface.focus();
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
        (event.shiftKey ? last : first).focus();
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

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, surfaceRef]);
}
