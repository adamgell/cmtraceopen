// src/workspaces/new-intune/index.ts
import { lazy } from "react";
import type { WorkspaceDefinition } from "../types";
import { createIntuneOnOpenSource } from "../intune";

export const newIntuneWorkspace: WorkspaceDefinition = {
  id: "new-intune",
  label: "Intune Analysis",
  statusLabel: "Intune analysis",
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
    file: "Open IME log file...",
    folder: "Open IME or evidence folder...",
    placeholder: "Open Intune source...",
  },
  capabilities: {
    // The handler loads a file source through the log store before it analyzes it, so a restore
    // through the handler reopens the text log too.
    reopensTextLogs: true,
  },
  onOpenSource: createIntuneOnOpenSource("new-intune"),
};
