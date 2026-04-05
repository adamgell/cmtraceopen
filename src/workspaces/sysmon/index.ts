// src/workspaces/sysmon/index.ts
import { lazy } from "react";
import type { WorkspaceDefinition } from "../types";

export const sysmonWorkspace: WorkspaceDefinition = {
  id: "sysmon",
  label: "Sysmon",
  platforms: ["windows"],
  component: lazy(() =>
    import("./SysmonWorkspace").then((m) => ({ default: m.SysmonWorkspace }))
  ),
  sidebar: lazy(() =>
    import("./SysmonSidebar").then((m) => ({ default: m.SysmonSidebar }))
  ),
  capabilities: {},
  fileFilters: [
    { name: "EVTX Files", extensions: ["evtx"] },
    { name: "All Files", extensions: ["*"] },
  ],
  actionLabels: {
    file: "Open EVTX File",
    folder: "Open EVTX Folder",
    placeholder: "Open Sysmon Source...",
  },
};
