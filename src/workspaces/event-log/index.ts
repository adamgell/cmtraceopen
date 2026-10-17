// src/workspaces/event-log/index.ts
import { lazy } from "react";
import { MULTI_FILE_OPEN_TRIGGER, TAB_SWITCH_TRIGGER } from "../../lib/log-load-triggers";
import { useUiStore } from "../../stores/ui-store";
import type { WorkspaceDefinition } from "../types";

export const eventLogWorkspace: WorkspaceDefinition = {
  id: "event-log",
  label: "Event Log Viewer (Preview)",
  statusLabel: "Event Log (Preview)",
  platforms: "all",
  capabilities: {
    sidebar: false,
    // "Add log source..." loads a text log through the Log workspace's loaders, and opening its
    // tab (or a multi-file load) asks for the Log view. The log belongs to this workspace's
    // analysis session, so those two loads must not move the user out of it. Every other trigger
    // (the toolbar's "open all", find, filter, refresh, a file association) still goes to Log.
    keepsViewOnLogLoad: [TAB_SWITCH_TRIGGER, MULTI_FILE_OPEN_TRIGGER],
  },
  component: lazy(() =>
    import("./EventLogWorkspace").then(
      (m) => ({ default: m.EventLogWorkspace })
    )
  ),
  fileFilters: [
    { name: "EVTX Files", extensions: ["evtx"] },
    { name: "All Files", extensions: ["*"] },
  ],
  actionLabels: {
    file: "Open EVTX file...",
    folder: "Open EVTX folder...",
    placeholder: "Open event log source...",
  },
  onOpenSource: async (source, trigger) => {
    useUiStore.getState().ensureWorkspaceVisible("event-log", trigger);
    // Lazy: evtx-store registers Tauri event listeners at module load.
    try {
      const { openEventLogSource } = await import("./open-event-log-source");
      await openEventLogSource(source);
    } catch (error) {
      console.error("[event-log] failed to open source", {
        source,
        trigger,
        error,
      });
      try {
        const { useEvtxStore } = await import("./evtx-store");
        useEvtxStore.getState().setLoadError(
          error instanceof Error ? error.message : String(error),
        );
      } catch (storeError) {
        console.error("[event-log] failed to record load error", storeError);
      }
      if (trigger === "drag-drop.path-open") {
        throw error;
      }
    }
  },
};
