import { useEffect, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import { useLogStore } from "../stores/log-store";

const PARSE_PROGRESS_EVENT = "parse-progress";

interface ParseProgressPayload {
  filePath: string;
  fileName: string;
  /** Files completed within the current batch (1-based). */
  completed: number;
  /** Total files in the current batch. */
  total: number;
  entries: number;
  fileSize: number;
  parseMs: number;
}

/**
 * Listens for `parse-progress` events emitted by the Rust backend as
 * individual files finish parsing inside `parse_files_batch`.  Updates
 * the log store's folder-load-progress so the UI can show real-time
 * per-file progress instead of only updating between batches.
 *
 * The Rust side emits per-batch counters, but the UI needs a global
 * count across all batches.  We maintain a running offset that is
 * reset by an effect each time a new folder load begins
 * (folderLoadProgress transitions from null → non-null), so progress
 * from a previous load can never bleed into the next one.
 */
export function useParseProgressListener() {
  const folderLoadProgress = useLogStore((state) => state.folderLoadProgress);
  const globalCompletedRef = useRef(0);
  const prevBatchCompletedRef = useRef(0);
  const wasLoadingRef = useRef(false);

  useEffect(() => {
    const isLoading = folderLoadProgress !== null;

    if (isLoading && !wasLoadingRef.current) {
      globalCompletedRef.current = 0;
      prevBatchCompletedRef.current = 0;
    }

    wasLoadingRef.current = isLoading;
  }, [folderLoadProgress]);

  useEffect(() => {
    const unlisten = listen<ParseProgressPayload>(
      PARSE_PROGRESS_EVENT,
      (event) => {
        const p = event.payload;
        const state = useLogStore.getState();

        // Only update if a folder load is currently in progress. The reset
        // for the next load is handled by the effect above on the
        // null → non-null transition.
        if (state.folderLoadProgress === null) {
          return;
        }

        // Detect new batch: per-batch completed count resets to a lower value
        if (p.completed < prevBatchCompletedRef.current) {
          // New batch started — promote previous batch count to global offset
          globalCompletedRef.current += prevBatchCompletedRef.current;
        }
        prevBatchCompletedRef.current = p.completed;

        const globalCompleted = globalCompletedRef.current + p.completed;
        const globalTotal = state.folderLoadTotalFiles ?? p.total;

        state.setFolderLoadProgress({
          current: globalCompleted,
          total: globalTotal,
          currentFile: p.fileName,
        });
      }
    );

    return () => {
      unlisten.then((dispose) => dispose());
    };
  }, []);
}
