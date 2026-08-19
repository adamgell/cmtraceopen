// src/workspaces/timeline/index.ts
import { lazy } from "react";
import { useUiStore } from "../../stores/ui-store";
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
    file: "Open timeline file...",
    folder: "Open timeline folder...",
    placeholder: "Open timeline source...",
  },
  onOpenSource: async (source, trigger) => {
    useUiStore.getState().ensureWorkspaceVisible("timeline", trigger);
    try {
      const { openTimelineSource } = await import("./open-timeline-source");
      await openTimelineSource(source);
    } catch (error) {
      console.error("[timeline] failed to open source", {
        source,
        trigger,
        error,
      });
      if (trigger === "drag-drop.path-open") {
        throw error;
      }
    }
  },
};
