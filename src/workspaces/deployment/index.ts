// src/workspaces/deployment/index.ts
import { lazy } from "react";
import type { WorkspaceDefinition } from "../types";

export const deploymentWorkspace: WorkspaceDefinition = {
  id: "deployment",
  label: "Software Deployment",
  platforms: ["windows"],
  component: lazy(() =>
    import("../../components/deployment/DeploymentWorkspace").then((m) => ({
      default: m.DeploymentWorkspace,
    }))
  ),
  sidebar: lazy(() =>
    import("../../components/layout/FileSidebar").then((m) => ({
      default: m.LogSidebar,
    }))
  ),
  capabilities: {
    footerBar: true,
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
