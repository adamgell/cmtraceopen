import { expandEventLogSources } from "../../lib/commands";
import type { LogSource } from "../../types/log";
import { useEvtxStore } from "./evtx-store";
import type {
  EventLogSourceCoverage,
  EventLogSourceManifest,
  EventLogSourceSelection,
} from "./types";

export type EventLogOpenSource =
  | { kind: "file"; path: string }
  | { kind: "folder"; path: string }
  | { kind: "wildcard"; path: string }
  | { kind: "archive"; path: string }
  | { kind: "vss"; path: string }
  | Extract<LogSource, { kind: "known" }>;

const MAX_COVERAGE_DETAILS = 3;
const MAX_DIAGNOSTIC_FIELD_LENGTH = 160;

interface SourceOpenOperation {
  loadGeneration: number;
}

function beginSourceOpen(): SourceOpenOperation {
  return {
    loadGeneration: useEvtxStore.getState().supersedePendingLoad(),
  };
}

function isCurrentSourceOpen(operation: SourceOpenOperation): boolean {
  return useEvtxStore.getState().loadGeneration === operation.loadGeneration;
}

function startSourceLoad(
  operation: SourceOpenOperation,
  load: () => Promise<void>,
): Promise<void> {
  const pending = load();
  // Store loads advance their generation synchronously before the first await. Hand currency to
  // that generation so the current parse is not mistaken for the transition that superseded it.
  operation.loadGeneration = useEvtxStore.getState().loadGeneration;
  return pending;
}

async function expandCurrentSource(
  sources: EventLogSourceSelection[],
  operation: SourceOpenOperation,
): Promise<EventLogSourceManifest | null> {
  const manifest = await expandEventLogSources(sources);
  return isCurrentSourceOpen(operation) ? manifest : null;
}

function boundedDiagnosticField(value: string): string {
  const normalized = value.replace(/\s+/g, " ").trim();
  return normalized.length <= MAX_DIAGNOSTIC_FIELD_LENGTH
    ? normalized
    : `${normalized.slice(0, MAX_DIAGNOSTIC_FIELD_LENGTH - 1)}…`;
}

function formatCoverageDiagnostics(coverage: EventLogSourceCoverage[]): string {
  const details = coverage
    .slice(0, MAX_COVERAGE_DETAILS)
    .map(
      ({ path, reason }) =>
        `${boundedDiagnosticField(path)}: ${boundedDiagnosticField(reason)}`,
    );
  const remaining = coverage.length - details.length;
  return `${details.join("; ")}${remaining > 0 ? `; ${remaining} more` : ""}`;
}

function requireManifestEntries(
  manifest: EventLogSourceManifest,
  emptyMessage: string,
): void {
  if (manifest.entries.length > 0) return;
  const usefulCoverage = manifest.coverage.filter(
    (coverage) => coverage.kind !== "empty",
  );
  const coverageDetails = usefulCoverage.length
    ? ` Source diagnostics: ${formatCoverageDiagnostics(usefulCoverage)}`
    : "";
  throw new Error(emptyMessage + coverageDetails);
}

/** Expand selected sources once and hand the complete manifest to the store. */
export async function openEventLogSources(
  sources: EventLogSourceSelection[],
): Promise<void> {
  const operation = beginSourceOpen();
  try {
    const manifest = await expandCurrentSource(sources, operation);
    if (!manifest) return;
    requireManifestEntries(manifest, "No .evtx files were found.");
    await startSourceLoad(operation, () =>
      useEvtxStore.getState().parseManifest(manifest),
    );
  } catch (error) {
    if (!isCurrentSourceOpen(operation)) return;
    useEvtxStore
      .getState()
      .setLoadError(error instanceof Error ? error.message : String(error));
    throw error;
  }
}

/** Open a single source while preserving known-source folder discovery. */
export async function openEventLogSource(source: EventLogOpenSource): Promise<void> {
  const operation = beginSourceOpen();

  try {
    if (
      source.kind === "wildcard" ||
      source.kind === "archive" ||
      source.kind === "vss"
    ) {
      const manifest = await expandCurrentSource([source], operation);
      if (!manifest) return;
      requireManifestEntries(manifest, "No .evtx files were found.");
      await startSourceLoad(operation, () =>
        useEvtxStore.getState().parseManifest(manifest),
      );
      return;
    }

    if (source.kind === "file") {
      await startSourceLoad(operation, () =>
        useEvtxStore.getState().parseFiles([source.path]),
      );
      return;
    }

    const path = source.kind === "folder" ? source.path : source.defaultPath;
    if (source.kind === "known" && source.pathKind === "file") {
      await startSourceLoad(operation, () =>
        useEvtxStore.getState().parseFiles([path]),
      );
      return;
    }

    const manifest = await expandCurrentSource(
      [{ kind: "folder", path }],
      operation,
    );
    if (!manifest) return;
    requireManifestEntries(
      manifest,
      source.kind === "known"
        ? "No .evtx files were found for that known source."
        : "No .evtx files were found in that folder. Choose a folder that contains Windows Event Log files.",
    );
    await startSourceLoad(operation, () =>
      useEvtxStore.getState().parseManifest(manifest),
    );
  } catch (error) {
    if (!isCurrentSourceOpen(operation)) return;
    useEvtxStore
      .getState()
      .setLoadError(error instanceof Error ? error.message : String(error));
    throw error;
  }
}
