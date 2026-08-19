// src/workspaces/event-log/index.ts
import { lazy } from "react";
import { useUiStore } from "../../stores/ui-store";
import type { WorkspaceDefinition } from "../types";

export const eventLogWorkspace: WorkspaceDefinition = {
  id: "event-log",
  label: "Event Log Viewer",
  platforms: "all",
  capabilities: {
    sidebar: false,
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
