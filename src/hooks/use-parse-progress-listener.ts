import { useEffect, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import { useLogStore } from "../stores/log-store";

const PARSE_PROGRESS_EVENT = "parse-progress";

interface ParseProgressPayload {
  /** Source-load generation that owns this batch. */
  requestId: number;
  filePath: string;
  fileName: string;
  /** Files completed within the current batch (1-based). */
  completed: number;
  /** Total files in the current batch. */
  total: number;
  /** Files completed across all sequential batches for this source load. */
  globalCompleted: number;
  entries: number;
  fileSize: number;
  parseMs: number;
}

function isParseProgressPayload(value: unknown): value is ParseProgressPayload {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }

  const payload = value as Record<string, unknown>;
  const isSafeNonNegativeInteger = (candidate: unknown): candidate is number =>
    typeof candidate === "number" &&
    Number.isSafeInteger(candidate) &&
    candidate >= 0;

  return (
    isSafeNonNegativeInteger(payload.requestId) &&
    typeof payload.filePath === "string" &&
    typeof payload.fileName === "string" &&
    isSafeNonNegativeInteger(payload.completed) &&
    payload.completed >= 1 &&
    isSafeNonNegativeInteger(payload.total) &&
    payload.total >= 1 &&
    payload.completed <= payload.total &&
    isSafeNonNegativeInteger(payload.globalCompleted) &&
    payload.globalCompleted >= payload.completed &&
    isSafeNonNegativeInteger(payload.entries) &&
    isSafeNonNegativeInteger(payload.fileSize) &&
    isSafeNonNegativeInteger(payload.parseMs)
  );
}

/**
 * Listens for `parse-progress` events emitted by the Rust backend as
 * individual files finish parsing inside `parse_files_batch`. Updates the log
 * store's folder-load-progress so the UI can show real-time per-file progress
 * instead of only updating between batches.
 *
 * Rust emits both a per-batch counter and a monotonic global counter. The
 * global counter remains correct when Rayon delivers per-file events out of
 * order, while the request ID prevents a superseded source load from writing
 * into the active one.
 */
export function useParseProgressListener() {
  const isFolderLoading = useLogStore(
    (state) => state.folderLoadProgress !== null,
  );
  const folderLoadRequestId = useLogStore(
    (state) => state.folderLoadRequestId,
  );
  const globalCompletedRef = useRef(0);
  const trackedRequestIdRef = useRef<number | null>(null);

  useEffect(() => {
    if (!isFolderLoading || folderLoadRequestId === null) {
      globalCompletedRef.current = 0;
      trackedRequestIdRef.current = null;
      return;
    }

    if (trackedRequestIdRef.current !== folderLoadRequestId) {
      globalCompletedRef.current = 0;
      trackedRequestIdRef.current = folderLoadRequestId;
    }
  }, [folderLoadRequestId, isFolderLoading]);

  useEffect(() => {
    const unlisten = listen<ParseProgressPayload>(
      PARSE_PROGRESS_EVENT,
      (event) => {
        if (!isParseProgressPayload(event.payload)) {
          return;
        }

        const state = useLogStore.getState();
        if (state.folderLoadProgress === null) {
          return;
        }
        if (event.payload.requestId !== state.folderLoadRequestId) {
          return;
        }

        const globalTotal = state.folderLoadTotalFiles;
        if (
          globalTotal === null ||
          event.payload.globalCompleted > globalTotal ||
          event.payload.globalCompleted <= globalCompletedRef.current
        ) {
          return;
        }

        globalCompletedRef.current = event.payload.globalCompleted;
        state.setFolderLoadProgress({
          current: event.payload.globalCompleted,
          total: globalTotal,
          currentFile: event.payload.fileName,
        });
      },
    );

    return () => {
      unlisten.then((dispose) => dispose());
    };
  }, []);
}
