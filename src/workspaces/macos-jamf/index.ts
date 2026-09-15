import { lazy } from "react";
import type { WorkspaceDefinition } from "../types";

export const jamfWorkspace: WorkspaceDefinition = {
  id: "macos-jamf",
  label: "macOS JAMF",
  platforms: ["macos"],
  component: lazy(() =>
    import("./MacosJamfWorkspace").then((m) => ({
      default: m.MacosJamfWorkspace,
    }))
  ),
  sidebar: lazy(() =>
    import("../../components/layout/FileSidebar").then((m) => ({
      default: m.LogSidebar,
    }))
  ),
  capabilities: {
    // The workspace's own Logs tab is where its log work happens; loading a log
    // from its log list must not eject the user into the Log workspace.
    keepsViewOnLogLoad: true,
  },
  fileFilters: [
    { name: "Log Files", extensions: ["log"] },
    { name: "All Files", extensions: ["*"] },
  ],
  actionLabels: {
    file: "Open file...",
    folder: "Open folder...",
    placeholder: "Open...",
  },
};
