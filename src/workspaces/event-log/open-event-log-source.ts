import { expandEventLogSources, listLogFolder } from "../../lib/commands";
import type { FolderEntry, LogSource, PathDiagnostic } from "../../types/log";
import { useEvtxStore } from "./evtx-store";
import type { EventLogSourceManifest, EventLogSourceSelection } from "./types";

export type EventLogOpenSource =
  | { kind: "file"; path: string }
  | { kind: "folder"; path: string }
  | { kind: "wildcard"; path: string }
  | { kind: "archive"; path: string }
  | { kind: "vss"; path: string }
  | Extract<LogSource, { kind: "known" }>;

const MAX_CHILD_ERROR_DETAILS = 3;
const MAX_DIAGNOSTIC_FIELD_LENGTH = 160;

function boundedDiagnosticField(value: string): string {
  const normalized = value.replace(/\s+/g, " ").trim();
  return normalized.length <= MAX_DIAGNOSTIC_FIELD_LENGTH
    ? normalized
    : `${normalized.slice(0, MAX_DIAGNOSTIC_FIELD_LENGTH - 1)}…`;
}

function formatChildErrors(childErrors: PathDiagnostic[]): string {
  const details = childErrors
    .slice(0, MAX_CHILD_ERROR_DETAILS)
    .map(
      ({ path, reason }) =>
        `${boundedDiagnosticField(path)}: ${boundedDiagnosticField(reason)}`,
    );
  const remaining = childErrors.length - details.length;
  return `${details.join("; ")}${remaining > 0 ? `; ${remaining} more` : ""}`;
}

function evtxPathsFromFolderEntries(entries: FolderEntry[]): string[] {
  return entries
    .filter((entry) => !entry.isDir && entry.name.toLowerCase().endsWith(".evtx"))
    .map((entry) => entry.path);
}

/** Expand selected sources once and hand the complete manifest to the store. */
export async function openEventLogSources(
  sources: EventLogSourceSelection[],
): Promise<void> {
  let manifest: EventLogSourceManifest;
  try {
    manifest = await expandEventLogSources(sources);
  } catch (error) {
    useEvtxStore.getState().setLoadError(
      error instanceof Error ? error.message : String(error)
    );
    throw error;
  }
  await useEvtxStore.getState().parseManifest(manifest);
}

/** Open a single source while preserving known-source folder discovery. */
export async function openEventLogSource(source: EventLogOpenSource): Promise<void> {
  const parseFiles = useEvtxStore.getState().parseFiles;

  try {
    if (
      source.kind === "wildcard" ||
      source.kind === "archive" ||
      source.kind === "vss"
    ) {
      await openEventLogSources([source]);
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

    const listing = await listLogFolder(path);
    const evtxPaths = evtxPathsFromFolderEntries(listing.entries);
    if (evtxPaths.length === 0) {
      const childErrorDetails = listing.childErrors?.length
        ? ` Access diagnostics: ${formatChildErrors(listing.childErrors)}`
        : "";
      throw new Error(
        (source.kind === "known"
          ? "No .evtx files were found for that known source."
          : "No .evtx files were found in that folder. Choose a folder that contains Windows Event Log files.") +
          childErrorDetails,
      );
    }
    await parseFiles(evtxPaths);
  } catch (error) {
    useEvtxStore.getState().setLoadError(
      error instanceof Error ? error.message : String(error)
    );
    throw error;
  }
}
