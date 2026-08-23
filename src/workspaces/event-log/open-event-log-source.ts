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
let sourceOpenGeneration = 0;

function beginSourceOpen(): number {
  sourceOpenGeneration += 1;
  useEvtxStore.getState().supersedePendingLoad();
  return sourceOpenGeneration;
}

function isCurrentSourceOpen(generation: number): boolean {
  return sourceOpenGeneration === generation;
}

async function expandCurrentSource(
  sources: EventLogSourceSelection[],
  generation: number,
): Promise<EventLogSourceManifest | null> {
  const manifest = await expandEventLogSources(sources);
  return isCurrentSourceOpen(generation) ? manifest : null;
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

/** Expand selected sources once and hand the complete manifest to the store. */
export async function openEventLogSources(
  sources: EventLogSourceSelection[],
): Promise<void> {
  const generation = beginSourceOpen();
  try {
    const manifest = await expandCurrentSource(sources, generation);
    if (!manifest) return;
    await useEvtxStore.getState().parseManifest(manifest);
  } catch (error) {
    if (!isCurrentSourceOpen(generation)) return;
    useEvtxStore
      .getState()
      .setLoadError(error instanceof Error ? error.message : String(error));
    throw error;
  }
}

/** Open a single source while preserving known-source folder discovery. */
export async function openEventLogSource(source: EventLogOpenSource): Promise<void> {
  const generation = beginSourceOpen();
  const parseFiles = useEvtxStore.getState().parseFiles;

  try {
    if (
      source.kind === "wildcard" ||
      source.kind === "archive" ||
      source.kind === "vss"
    ) {
      const manifest = await expandCurrentSource([source], generation);
      if (!manifest) return;
      await useEvtxStore.getState().parseManifest(manifest);
      return;
    }

    if (source.kind === "file") {
      await parseFiles([source.path]);
      return;
    }

    const path = source.kind === "folder" ? source.path : source.defaultPath;
    if (source.kind === "known" && source.pathKind === "file") {
      await parseFiles([path]);
      return;
    }

    const manifest = await expandCurrentSource(
      [{ kind: "folder", path }],
      generation,
    );
    if (!manifest) return;
    if (manifest.entries.length === 0) {
      const usefulCoverage = manifest.coverage.filter(
        (coverage) => coverage.kind !== "empty",
      );
      const coverageDetails = usefulCoverage.length
        ? ` Source diagnostics: ${formatCoverageDiagnostics(usefulCoverage)}`
        : "";
      throw new Error(
        (source.kind === "known"
          ? "No .evtx files were found for that known source."
          : "No .evtx files were found in that folder. Choose a folder that contains Windows Event Log files.") +
          coverageDetails,
      );
    }
    await useEvtxStore.getState().parseManifest(manifest);
  } catch (error) {
    if (!isCurrentSourceOpen(generation)) return;
    useEvtxStore
      .getState()
      .setLoadError(error instanceof Error ? error.message : String(error));
    throw error;
  }
}
