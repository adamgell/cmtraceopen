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
