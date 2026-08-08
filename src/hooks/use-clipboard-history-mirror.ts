import { useEffect } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { useUiStore } from "../stores/ui-store";

function copiedTextFrom(event: ClipboardEvent): string {
  const target = event.target;

  if (
    target instanceof HTMLInputElement ||
    target instanceof HTMLTextAreaElement
  ) {
    const { selectionStart, selectionEnd, value } = target;

    if (
      selectionStart !== null &&
      selectionEnd !== null &&
      selectionEnd > selectionStart
    ) {
      return value.slice(selectionStart, selectionEnd);
    }

    return "";
  }

  return window.getSelection()?.toString() ?? "";
}

/**
 * Mirrors native WebView copies through the Tauri clipboard plugin so they
 * register in Windows clipboard history (Win+V).
 *
 * Copies the WebView performs itself — the built-in context menu over the
 * Info pane, Ctrl+C on a text selection — reach the OS clipboard but are not
 * captured by clipboard history, while copies written through the plugin are
 * (#520). Re-writing the same text through the plugin after the native copy
 * makes every copy land in history; the content is identical, so the extra
 * write is otherwise invisible.
 *
 * Windows-only: no other platform has a history consumer, and skipping the
 * mirror elsewhere avoids replacing rich clipboard content with plain text.
 */
export function useClipboardHistoryMirror() {
  const isWindows = useUiStore(
    (state) => state.currentPlatform === "windows"
  );

  useEffect(() => {
    if (!isWindows) {
      return;
    }

    const handleCopy = (event: ClipboardEvent) => {
      // An app handler that prevented default owns this copy and has already
      // written the clipboard through the plugin itself.
      if (event.defaultPrevented) {
        return;
      }

      const text = copiedTextFrom(event);

      if (text.length === 0) {
        return;
      }

      writeText(text).catch((error) => {
        console.error(
          "[clipboard] failed to mirror copy into clipboard history",
          { error }
        );
      });
    };

    document.addEventListener("copy", handleCopy);
    return () => document.removeEventListener("copy", handleCopy);
  }, [isWindows]);
}
