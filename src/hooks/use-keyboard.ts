import { useEffect } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { useLogStore } from "../stores/log-store";
import { useUiStore } from "../stores/ui-store";
import { useFilterStore } from "../stores/filter-store";
import { useAppActions } from "../components/layout/Toolbar";

function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) {
    return false;
  }

  return (
    target.tagName === "INPUT" ||
    target.tagName === "TEXTAREA" ||
    target.tagName === "SELECT" ||
    target.isContentEditable
  );
}

function isLogListFocused(): boolean {
  const active = document.activeElement;

  if (!(active instanceof HTMLElement)) {
    return false;
  }

  return active.closest("[data-log-list='true']") !== null;
}

function getDisplayEntryIds(): number[] {
  const logState = useLogStore.getState();
  const filteredIds = useFilterStore.getState().filteredIds;

  if (!filteredIds) {
    return logState.entries.map((entry) => entry.id);
  }

  return logState.entries
    .filter((entry) => filteredIds.has(entry.id))
    .map((entry) => entry.id);
}

function navigateSelection(key: string): boolean {
  const entryIds = getDisplayEntryIds();

  if (entryIds.length === 0) {
    return false;
  }

  const logState = useLogStore.getState();
  const currentIndex =
    logState.selectedId === null ? -1 : entryIds.indexOf(logState.selectedId);
  const lastIndex = entryIds.length - 1;

  let nextIndex = currentIndex;

  switch (key) {
    case "ArrowDown":
      nextIndex = currentIndex < 0 ? 0 : Math.min(currentIndex + 1, lastIndex);
      break;
    case "ArrowUp":
      nextIndex = currentIndex < 0 ? lastIndex : Math.max(currentIndex - 1, 0);
      break;
    case "PageDown":
      nextIndex = currentIndex < 0 ? 0 : Math.min(currentIndex + 20, lastIndex);
      break;
    case "PageUp":
      nextIndex = currentIndex < 0 ? lastIndex : Math.max(currentIndex - 20, 0);
      break;
    case "Home":
      nextIndex = 0;
      break;
    case "End":
      nextIndex = lastIndex;
      break;
    default:
      return false;
  }

  const nextId = entryIds[nextIndex];

  if (nextId === undefined || nextId === logState.selectedId) {
    return true;
  }

  logState.selectEntry(nextId);
  return true;
}

/**
 * Keyboard shortcut handler matching CMTrace's accelerator table.
 * From REVERSE_ENGINEERING.md:
 *   Ctrl+O  → Open
 *   Ctrl+F  → Find
 *   F3      → Find Next
 *   Shift+F3→ Find Previous
 *   Ctrl+U  → Pause/Resume
 *   Ctrl+H  → Toggle Details
 *   Ctrl+L  → Filter
 *   Ctrl+C  → Copy (tab-separated selected entry)
 *   Ctrl+E  → Error Lookup
 *   F5      → Refresh
 */
export function useKeyboard() {
  const showFindDialogOpen = useUiStore((state) => state.showFindDialog);
  const showFilterDialogOpen = useUiStore((state) => state.showFilterDialog);
  const showErrorLookupDialogOpen = useUiStore(
    (state) => state.showErrorLookupDialog
  );
  const showAboutDialogOpen = useUiStore((state) => state.showAboutDialog);
  const {
    openSourceFileDialog,
    showFindDialog,
    showFilterDialog,
    showErrorLookupDialog,
    togglePauseResume,
    refreshActiveSource,
    toggleDetailsPane,
    dismissTransientDialogs,
  } = useAppActions();

  useEffect(() => {
    const handleKeyDown = async (event: KeyboardEvent) => {
      const ctrl = event.ctrlKey || event.metaKey;
      const isInput = isTypingTarget(event.target);
      const isDialogOpen =
        showFindDialogOpen ||
        showFilterDialogOpen ||
        showErrorLookupDialogOpen ||
        showAboutDialogOpen;

      if (ctrl && event.key.toLowerCase() === "o") {
        event.preventDefault();
        await openSourceFileDialog();
        return;
      }

      if (ctrl && event.key.toLowerCase() === "f") {
        event.preventDefault();
        showFindDialog();
        return;
      }

      if (event.key === "F3" && !isInput) {
        if (showFindDialogOpen) {
          return;
        }

        event.preventDefault();

        const logState = useLogStore.getState();

        if (!logState.hasFindSession()) {
          showFindDialog();
          return;
        }

        if (event.shiftKey) {
          logState.findPrevious("keyboard.shift-f3");
          return;
        }

        logState.findNext("keyboard.f3");
        return;
      }

      if (ctrl && event.key.toLowerCase() === "u") {
        event.preventDefault();
        togglePauseResume();
        return;
      }

      if (ctrl && event.key.toLowerCase() === "h") {
        event.preventDefault();
        toggleDetailsPane();
        return;
      }

      if (ctrl && event.key.toLowerCase() === "l") {
        event.preventDefault();
        showFilterDialog();
        return;
      }

      if (ctrl && event.key.toLowerCase() === "e") {
        event.preventDefault();
        showErrorLookupDialog();
        return;
      }

      if (event.key === "F5" && !isInput) {
        event.preventDefault();

        try {
          await refreshActiveSource();
        } catch (error) {
          console.error("[keyboard] refresh failed", { error });
        }

        return;
      }

      if (ctrl && event.key.toLowerCase() === "c" && !isInput) {
        event.preventDefault();
        const state = useLogStore.getState();

        if (state.selectedId === null) {
          return;
        }

        const entry = state.entries.find(
          (entryItem) => entryItem.id === state.selectedId
        );

        if (!entry) {
          return;
        }

        const text = [
          entry.message,
          entry.component ?? "",
          entry.timestampDisplay ?? "",
          entry.threadDisplay ?? "",
        ].join("\t");

        try {
          await writeText(text);
        } catch (error) {
          console.error("[keyboard] failed to copy selected entry", { error });
        }
        return;
      }

      if (
        !ctrl &&
        !isInput &&
        !isDialogOpen &&
        isLogListFocused() &&
        navigateSelection(event.key)
      ) {
        event.preventDefault();
        return;
      }

      if (event.key === "Escape" && !isInput) {
        dismissTransientDialogs("keyboard.escape");
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [
    dismissTransientDialogs,
    openSourceFileDialog,
    refreshActiveSource,
    showAboutDialogOpen,
    showErrorLookupDialog,
    showErrorLookupDialogOpen,
    showFilterDialog,
    showFilterDialogOpen,
    showFindDialog,
    showFindDialogOpen,
    toggleDetailsPane,
    togglePauseResume,
  ]);
}