import { lazy } from "react";
import type { WorkspaceDefinition } from "../types";

export const securebootWorkspace: WorkspaceDefinition = {
  id: "secureboot",
  label: "Secure Boot Certs",
  platforms: "all",
  component: lazy(() =>
    import("./SecureBootWorkspace").then((m) => ({ default: m.SecureBootWorkspace }))
  ),
  sidebar: lazy(() =>
    import("./SecureBootSidebar").then((m) => ({ default: m.SecureBootSidebar }))
  ),
  capabilities: { knownSources: false },
  fileFilters: [
    { name: "Secure Boot Logs", extensions: ["log"] },
    { name: "All Files", extensions: ["*"] },
  ],
  actionLabels: { file: "Open Log File", placeholder: "Analyze Secure Boot..." },
  onOpenSource: async (source, trigger) => {
    // Dynamic imports to avoid circular deps
    const [{ useUiStore }, { analyzeSecureBoot }, { useSecureBootStore }] =
      await Promise.all([
        import("../../stores/ui-store"),
        import("../../lib/commands"),
        import("./secureboot-store"),
      ]);
    useUiStore.getState().ensureWorkspaceVisible("secureboot", trigger);
    const store = useSecureBootStore.getState();
    if (source.kind === "file") {
      store.beginAnalysis("Analyzing log file...");
      try {
        store.setResult(await analyzeSecureBoot(source.path));
      } catch (e) {
        store.failAnalysis(e);
      }
    } else if (source.kind === "known") {
      throw new Error("Known log presets not supported in Secure Boot workspace.");
    } else {
      store.beginAnalysis("Scanning device...");
      try {
        store.setResult(await analyzeSecureBoot());
      } catch (e) {
        store.failAnalysis(e);
      }
    }
  },
};
