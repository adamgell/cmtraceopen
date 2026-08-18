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
    const { openEventLogSource } = await import("./open-event-log-source");
    await openEventLogSource(source);
  },
};
