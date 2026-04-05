// src/workspaces/dsregcmd/index.ts
import { lazy } from "react";
import type { WorkspaceDefinition } from "../types";

export const dsregcmdWorkspace: WorkspaceDefinition = {
  id: "dsregcmd",
  label: "dsregcmd",
  platforms: ["windows"],
  component: lazy(() =>
    import("./DsregcmdWorkspace").then((m) => ({
      default: m.DsregcmdWorkspace,
    }))
  ),
  sidebar: lazy(() =>
    import("./DsregcmdSidebar").then((m) => ({
      default: m.DsregcmdSidebar,
    }))
  ),
  fileFilters: [
    { name: "Text Files", extensions: ["txt"] },
    { name: "Log Files", extensions: ["log"] },
    { name: "All Files", extensions: ["*"] },
  ],
  actionLabels: {
    file: "Open Text File",
    folder: "Open Evidence Folder",
    placeholder: "Open dsregcmd Source...",
  },
};
