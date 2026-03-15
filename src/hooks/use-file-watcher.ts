import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { useLogStore } from "../stores/log-store";
import { startTail, stopTail, pauseTail, resumeTail } from "../lib/commands";
import type { TailPayload } from "../types/log";

/**
 * Hook that manages the file-tail lifecycle:
 * - Starts tailing after a file is opened
 * - Appends new entries as they arrive via Tauri events
 * - Handles pause/resume
 * - Cleans up on unmount or file change
 */
export function useFileWatcher() {
  const openFilePath = useLogStore((s) => s.openFilePath);
  const sourceOpenMode = useLogStore((s) => s.sourceOpenMode);
  const aggregateFiles = useLogStore((s) => s.aggregateFiles);
  const formatDetected = useLogStore((s) => s.formatDetected);
  const isPaused = useLogStore((s) => s.isPaused);
  const appendEntries = useLogStore((s) => s.appendEntries);
  const appendAggregateEntries = useLogStore((s) => s.appendAggregateEntries);
  const setParserSelection = useLogStore((s) => s.setParserSelection);

  // Start/stop tailing when file changes
  useEffect(() => {
    if (sourceOpenMode === "aggregate-folder") {
      if (aggregateFiles.length === 0) {
        return;
      }

      const tailFormat = formatDetected ?? "Plain";

      for (const file of aggregateFiles) {
        startTail(file.filePath, tailFormat, file.byteOffset, 0, file.totalLines + 1).catch(
          (err) => console.error("Failed to start aggregate tail:", err)
        );
      }

      return () => {
        for (const file of aggregateFiles) {
          stopTail(file.filePath).catch((err) =>
            console.error("Failed to stop aggregate tail:", err)
          );
        }
      };
    }

    if (!openFilePath || !formatDetected) return;

    const byteOffset = useLogStore.getState().byteOffset;
    const currentEntries = useLogStore.getState().entries;
    const nextId =
      currentEntries.length > 0
        ? currentEntries[currentEntries.length - 1].id + 1
        : 0;
    const nextLine =
      currentEntries.length > 0
        ? currentEntries[currentEntries.length - 1].lineNumber + 1
        : 1;

    startTail(openFilePath, formatDetected, byteOffset, nextId, nextLine).catch(
      (err) => console.error("Failed to start tail:", err)
    );

    return () => {
      stopTail(openFilePath).catch((err) =>
        console.error("Failed to stop tail:", err)
      );
    };
  }, [aggregateFiles, formatDetected, openFilePath, sourceOpenMode]);

  // Handle pause/resume
  useEffect(() => {
    if (sourceOpenMode === "aggregate-folder") {
      if (aggregateFiles.length === 0) {
        return;
      }

      for (const file of aggregateFiles) {
        const action = isPaused ? pauseTail : resumeTail;
        action(file.filePath).catch((err) =>
          console.error(`Failed to ${isPaused ? "pause" : "resume"} aggregate tail:`, err)
        );
      }
      return;
    }

    if (!openFilePath) return;

    if (isPaused) {
      pauseTail(openFilePath).catch((err) =>
        console.error("Failed to pause tail:", err)
      );
    } else {
      resumeTail(openFilePath).catch((err) =>
        console.error("Failed to resume tail:", err)
      );
    }
  }, [aggregateFiles, isPaused, openFilePath, sourceOpenMode]);

  // Listen for new tail entries from the Rust backend
  useEffect(() => {
    const unlisten = listen<TailPayload>("tail-new-entries", (event) => {
      const { entries: newEntries, filePath, parserSelection } = event.payload;
      const state = useLogStore.getState();

      if (state.sourceOpenMode === "aggregate-folder") {
        const isTrackedFile = state.aggregateFiles.some((file) => file.filePath === filePath);

        if (!isTrackedFile || newEntries.length === 0) {
          return;
        }

        appendAggregateEntries(filePath, newEntries);
        return;
      }

      const currentPath = state.openFilePath;

      if (!currentPath || currentPath !== filePath || newEntries.length === 0) {
        return;
      }

      if (parserSelection) {
        setParserSelection(parserSelection);
      }

      appendEntries(newEntries);
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, [appendAggregateEntries, appendEntries, setParserSelection]);
}