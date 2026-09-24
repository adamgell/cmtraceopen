import { lazy } from "react";
import type { WorkspaceDefinition } from "../types";

export const sccmWorkspace: WorkspaceDefinition = {
  id: "sccm",
  label: "SCCM Diagnostics",
  statusLabel: "SCCM diagnostics workspace",
  platforms: ["windows"],
  component: lazy(() =>
    import("./SccmWorkspace").then((module) => ({
      default: module.SccmWorkspace,
    })),
  ),
  capabilities: {
    sidebar: false,
    tabStrip: false,
    findBar: false,
    detailsPane: false,
    infoPane: false,
    footerBar: false,
    fontSizing: false,
    knownSources: false,
  },
};
