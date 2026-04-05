// src/workspaces/event-log/index.ts
import { lazy } from "react";
import type { WorkspaceDefinition } from "../types";

export const eventLogWorkspace: WorkspaceDefinition = {
  id: "event-log",
  label: "Event Log Viewer",
  platforms: "all",
  component: lazy(() =>
    import("../../components/event-log-workspace/EventLogWorkspace").then(
      (m) => ({ default: m.EventLogWorkspace })
    )
  ),
  sidebar: lazy(() =>
    import("../dsregcmd/DsregcmdSidebar").then((m) => ({
      default: m.DsregcmdSidebar,
    }))
  ),
  fileFilters: [
    { name: "Log Files", extensions: ["log"] },
    { name: "Old Log Files", extensions: ["lo_"] },
    { name: "Registry Files", extensions: ["reg"] },
    { name: "All Files", extensions: ["*"] },
  ],
  actionLabels: {
    file: "Open File",
    folder: "Open Folder",
    placeholder: "Open...",
  },
};
