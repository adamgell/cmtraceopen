// src/workspaces/timeline/index.ts
import { lazy } from "react";
import type { WorkspaceDefinition } from "../types";

export const timelineWorkspace: WorkspaceDefinition = {
  id: "timeline",
  label: "Timeline",
  statusLabel: "Timeline",
  platforms: "all",
  component: lazy(() =>
    import("../../components/timeline/TimelineWorkspace").then((m) => ({
      default: m.TimelineWorkspace,
    }))
  ),
  capabilities: {
    multiFileDrop: true,
    fontSizing: true,
  },
  fileFilters: [
    { name: "Log Files", extensions: ["log", "cmtlog", "evtx"] },
    { name: "All Files", extensions: ["*"] },
  ],
  actionLabels: {
    placeholder: "Open Timeline Source...",
  },
};
