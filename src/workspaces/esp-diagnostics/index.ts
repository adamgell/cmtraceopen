import { lazy } from "react";
import { analyzeEspEvidence, inspectPathKind } from "../../lib/commands";
import { useUiStore } from "../../stores/ui-store";
import type { LogSource, PlatformKind } from "../../types/log";
import type { WorkspaceDefinition } from "../types";
import { useEspDiagnosticsStore } from "./esp-diagnostics-store";

export const ESP_EVIDENCE_SOURCE_ERROR =
  "ESP Diagnostics accepts CMTrace evidence folders, manifest.json, CAB, or ZIP sources.";
export const ESP_LIVE_IMPORT_ERROR =
  "Stop live diagnostics before importing captured evidence.";

function createAnalysisRequestId(): string {
  return `esp-analysis-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function pathFromSource(source: LogSource): string {
  return source.kind === "known" ? source.defaultPath : source.path;
}

function isSupportedEvidenceFile(path: string): boolean {
  const fileName = path.split(/[\\/]/).pop()?.toLowerCase() ?? "";
  return (
    fileName === "manifest.json" ||
    fileName.endsWith(".cab") ||
    fileName.endsWith(".zip")
  );
}

export function supportsEspLiveAcquisition(platform: PlatformKind): boolean {
  return platform === "windows";
}

export function resolveEspEvidenceSource(source: LogSource): string | null {
  if (source.kind === "folder") return source.path;
  if (source.kind === "known" && source.pathKind === "folder") {
    return source.defaultPath;
  }

  const path = pathFromSource(source);
  return isSupportedEvidenceFile(path) ? path : null;
}

export async function analyzeEspEvidenceSource(
  source: LogSource,
  trigger: string,
): Promise<void> {
  const currentState = useEspDiagnosticsStore.getState();
  if (
    currentState.sessionId !== null ||
    ["starting", "live", "stopping"].includes(currentState.phase)
  ) {
    throw new Error(ESP_LIVE_IMPORT_ERROR);
  }

  const path = resolveEspEvidenceSource(source);
  if (!path) {
    throw new Error(ESP_EVIDENCE_SOURCE_ERROR);
  }

  useUiStore.getState().ensureWorkspaceVisible("esp-diagnostics", trigger);
  const requestId = createAnalysisRequestId();
  const store = useEspDiagnosticsStore.getState();
  store.beginAnalysis(requestId);

  try {
    const snapshot = await analyzeEspEvidence(path, requestId);
    store.applyAnalysis(requestId, snapshot);
  } catch (error) {
    store.fail(requestId, getErrorMessage(error));
  }
}

export const espDiagnosticsWorkspace: WorkspaceDefinition = {
  id: "esp-diagnostics",
  label: "ESP Diagnostics",
  statusLabel: "ESP diagnostics workspace",
  platforms: "all",
  component: lazy(() =>
    import("./EspDiagnosticsWorkspace").then((module) => ({
      default: module.EspDiagnosticsWorkspace,
    })),
  ),
  toolbarAction: lazy(() =>
    import("./EspToolbarAction").then((module) => ({
      default: module.EspToolbarAction,
    })),
  ),
  statusBarContent: lazy(() =>
    import("./EspStatusBarContent").then((module) => ({
      default: module.EspStatusBarContent,
    })),
  ),
  dock: lazy(() =>
    import("./LiveEvidenceDock").then((module) => ({
      default: module.EspLiveEvidenceDock,
    })),
  ),
  capabilities: {
    sidebar: false,
    liveAcquisition: true,
    tabStrip: false,
    findBar: false,
    detailsPane: false,
    infoPane: false,
    knownSources: false,
  },
  fileFilters: [{ name: "ESP evidence", extensions: ["json", "cab", "zip"] }],
  actionLabels: {
    file: "Import captured evidence...",
    folder: "Import evidence folder...",
    placeholder: "Import ESP evidence...",
  },
  onOpenSource: analyzeEspEvidenceSource,
  onOpenPath: async (path) => {
    const kind = await inspectPathKind(path);
    const source: LogSource =
      kind === "folder" ? { kind: "folder", path } : { kind: "file", path };

    if (kind === "unknown" && !isSupportedEvidenceFile(path)) {
      throw new Error(`Unable to identify ESP evidence source '${path}'.`);
    }

    await analyzeEspEvidenceSource(source, "app-actions.open-path");
  },
};
