// src/workspaces/macos-diag/index.ts
import { lazy } from "react";
import type { WorkspaceDefinition } from "../types";

export const macosDiagWorkspace: WorkspaceDefinition = {
  id: "macos-diag",
  label: "macOS Diagnostics",
  platforms: ["macos"],
  component: lazy(() =>
    import("./MacosDiagWorkspace").then((m) => ({
      default: m.MacosDiagWorkspace,
    }))
  ),
  sidebar: lazy(() =>
    import("../../components/layout/FileSidebar").then((m) => ({
      default: m.LogSidebar,
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
