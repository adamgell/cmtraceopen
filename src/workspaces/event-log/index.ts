// src/workspaces/event-log/index.ts
import { lazy } from "react";
import type { WorkspaceDefinition } from "../types";

export const eventLogWorkspace: WorkspaceDefinition = {
  id: "event-log",
  label: "Event Log Viewer",
  platforms: "all",
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
    file: "Open EVTX File",
    folder: "Open EVTX Folder",
    placeholder: "Open Event Log Source...",
  },
};
