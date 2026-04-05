// src/workspaces/intune/index.ts
import { lazy } from "react";
import type { WorkspaceDefinition } from "../types";

export const intuneWorkspace: WorkspaceDefinition = {
  id: "intune",
  label: "Intune Diagnostics",
  platforms: "all",
  component: lazy(() =>
    import("../../components/intune/IntuneDashboard").then((m) => ({
      default: m.IntuneDashboard,
    }))
  ),
  sidebar: lazy(() =>
    import("../../components/layout/FileSidebar").then((m) => ({
      default: m.IntuneSidebar,
    }))
  ),
  fileFilters: [
    { name: "Intune IME Logs", extensions: ["log"] },
    { name: "All Files", extensions: ["*"] },
  ],
  actionLabels: {
    file: "Open IME Log File",
    folder: "Open IME Or Evidence Folder",
    placeholder: "Open Intune Source...",
  },
};
