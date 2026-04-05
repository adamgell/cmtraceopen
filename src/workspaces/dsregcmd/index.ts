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
  capabilities: {
    knownSources: false,
  },
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
  onOpenSource: async (source, trigger) => {
    const [{ useUiStore }, { analyzeDsregcmdSource }] = await Promise.all([
      import("../../stores/ui-store"),
      import("../../lib/dsregcmd-source"),
    ]);

    useUiStore.getState().ensureWorkspaceVisible("dsregcmd", trigger);

    if (source.kind === "known") {
      throw new Error("Known log presets are not supported in the dsregcmd workspace.");
    }

    await analyzeDsregcmdSource(source);
  },
};
