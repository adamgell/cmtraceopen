// src/workspaces/new-intune/index.ts
import { lazy } from "react";
import type { WorkspaceDefinition } from "../types";
import { createIntuneOnOpenSource } from "../intune";

export const newIntuneWorkspace: WorkspaceDefinition = {
  id: "new-intune",
  label: "New Intune Workspace",
  statusLabel: "New Intune Workspace",
  platforms: "all",
  component: lazy(() =>
    import("../intune/NewIntuneWorkspace").then((m) => ({
      default: m.NewIntuneWorkspace,
    }))
  ),
  sidebar: lazy(() =>
    import("../intune/IntuneSidebar").then((m) => ({
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
  onOpenSource: createIntuneOnOpenSource("new-intune"),
};
