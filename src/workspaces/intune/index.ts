// src/workspaces/intune/index.ts
import { startTransition, lazy } from "react";
import type { WorkspaceDefinition } from "../types";
import type { IntuneWorkspaceId } from "../../stores/ui-store";
import type { LogSource } from "../../types/log";

const LIVE_INTUNE_SOURCE_ID = "windows-intune-ime-logs";

function shouldSyncSourceBeforeIntuneAnalysis(source: LogSource): boolean {
  if (source.kind === "file") {
    return true;
  }
  return source.kind === "known" && source.pathKind === "file";
}

function shouldIncludeLiveEventLogs(source: LogSource): boolean {
  return source.kind === "known" && source.sourceId === LIVE_INTUNE_SOURCE_ID;
}

function createIntuneAnalysisRequestId(): string {
  return `intune-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * Shared onOpenSource handler for intune workspaces.
 * Used by both the "intune" and "new-intune" workspace definitions.
 */
export function createIntuneOnOpenSource(
  workspaceId: IntuneWorkspaceId,
): WorkspaceDefinition["onOpenSource"] {
  return async (source, trigger) => {
    const [
      { useUiStore },
      { getLogSourcePath, loadLogSource },
      { analyzeIntuneLogs },
      { useIntuneStore },
    ] = await Promise.all([
      import("../../stores/ui-store"),
      import("../../lib/log-source"),
      import("../../lib/commands"),
      import("./intune-store"),
    ]);

    useUiStore.getState().ensureWorkspaceVisible(workspaceId, trigger);
    const requestId = createIntuneAnalysisRequestId();
    useIntuneStore.getState().beginAnalysis(
      getLogSourcePath(source),
      source.kind === "known" ? "known" : source.kind,
      requestId,
    );

    try {
      if (shouldSyncSourceBeforeIntuneAnalysis(source)) {
        await loadLogSource(source).catch((error) => {
          console.warn("[intune] failed to sync source before Intune analysis", {
            source,
            trigger,
            error,
          });
        });
      }

      const result = await analyzeIntuneLogs(getLogSourcePath(source), requestId, {
        includeLiveEventLogs: shouldIncludeLiveEventLogs(source),
        graphApiEnabled: useUiStore.getState().graphApiEnabled,
      });

      startTransition(() => {
        useIntuneStore.getState().setResults(
          result.events,
          result.downloads,
          result.summary,
          result.diagnostics,
          result.sourceFile,
          result.sourceFiles,
          {
            diagnosticsConfidence: result.diagnosticsConfidence,
            diagnosticsCoverage: result.diagnosticsCoverage,
            repeatedFailures: result.repeatedFailures,
            evidenceBundle: result.evidenceBundle ?? null,
            eventLogAnalysis: result.eventLogAnalysis ?? null,
            policyMetadata: result.policyMetadata ?? undefined,
            guidRegistry: result.guidRegistry,
          },
        );
      });
    } catch (error) {
      console.error("[intune] failed to analyze Intune source", {
        source,
        trigger,
        error,
      });
      useIntuneStore.getState().failAnalysis(error);
    }
  };
}

export const intuneWorkspace: WorkspaceDefinition = {
  id: "intune",
  label: "Intune Diagnostics",
  statusLabel: "Intune workspace",
  platforms: "all",
  component: lazy(() =>
    import("./IntuneDashboard").then((m) => ({
      default: m.IntuneDashboard,
    }))
  ),
  sidebar: lazy(() =>
    import("./IntuneSidebar").then((m) => ({
      default: m.IntuneSidebar,
    }))
  ),
  fileFilters: [
    { name: "Intune IME Logs", extensions: ["log"] },
    { name: "All Files", extensions: ["*"] },
  ],
  actionLabels: {
    file: "Open IME Log File",
    folder: "Open IME Or Evidence Folder",
    placeholder: "Open Intune Source...",
  },
  onOpenSource: createIntuneOnOpenSource("intune"),
};
