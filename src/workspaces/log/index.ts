// src/workspaces/log/index.ts
import { lazy } from "react";
import type { WorkspaceDefinition } from "../types";

export const logWorkspace: WorkspaceDefinition = {
  id: "log",
  label: "Log Explorer",
  statusLabel: "Log view",
  platforms: "all",
  component: lazy(() =>
    import("../../components/log-view/LogListView").then((m) => ({
      default: m.LogListView,
    }))
  ),
  sidebar: lazy(() =>
    import("../../components/layout/FileSidebar").then((m) => ({
      default: m.LogSidebar,
    }))
  ),
  capabilities: {
    tabStrip: true,
    findBar: true,
    detailsPane: true,
    infoPane: true,
    footerBar: true,
    multiFileDrop: true,
    fontSizing: true,
    tailing: true,
    knownSources: true,
  },
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
