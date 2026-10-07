import type { FirewallControlToken, LogFormat } from "../types/log";
import { sameFirewallControl } from "../stores/firewall-state";
import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { useLogStore } from "../stores/log-store";
import { startTail, stopTail, pauseTail, resumeTail } from "../lib/commands";
import { parseTailPayload } from "../lib/tail-payload-validation";

function currentFirewallControl(path: string): FirewallControlToken | undefined {
  const source = useLogStore.getState().firewallSources[path];
  return source?.active ? { sourceSessionId: source.sessionId, watchEpoch: source.watchEpoch } : undefined;
}

function startSourceWatch(path: string, format: LogFormat, offset: number, nextId: number, nextLine: number): () => void {
  const token = useLogStore.getState().beginFirewallWatch(path);
  if (!token && useLogStore.getState().firewallSources[path]) return () => {};
  const started = token ? startTail(path, format, offset, nextId, nextLine, token) : startTail(path, format, offset, nextId, nextLine);
  started.then(async () => {
    if (!token) return;
    const state = useLogStore.getState();
    const source = state.firewallSources[path];
    if (!source?.active || !sameFirewallControl(source, token)) return;
    // The first pause may have reached native before start was admitted. Apply
    // the latest pause state after start resolves; cancelled epochs stay stopped.
    await (state.isPaused ? pauseTail : resumeTail)(path, token);
  }).catch(err => console.error("Failed to start tail:", err));
  return () => {
    if (token) useLogStore.getState().endFirewallWatch(path, token);
    const stopped = token ? stopTail(path, token) : stopTail(path);
    stopped.catch(err => console.error("Failed to stop tail:", err));
  };
}

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
  const aggregateTailGeneration = useLogStore(
    (s) => s.aggregateTailGeneration,
  );
  const formatDetected = useLogStore((s) => s.formatDetected);
  const isPaused = useLogStore((s) => s.isPaused);
  const appendEntries = useLogStore((s) => s.appendEntries);
  const amendEntry = useLogStore((s) => s.amendEntry);
  const appendAggregateEntries = useLogStore((s) => s.appendAggregateEntries);
  const amendAggregateEntry = useLogStore((s) => s.amendAggregateEntry);
  const observeAggregateTailLine = useLogStore((s) => s.observeAggregateTailLine);
  const recordAggregateTailParseErrors = useLogStore(
    (s) => s.recordAggregateTailParseErrors,
  );
  const resetEntries = useLogStore((s) => s.resetEntries);
  const resetAggregateEntries = useLogStore((s) => s.resetAggregateEntries);
  const setParserSelection = useLogStore((s) => s.setParserSelection);
  const setTotalLines = useLogStore((s) => s.setTotalLines);
  const firewallSessionKey = useLogStore(s => s.sourceOpenMode === "aggregate-folder"
    ? JSON.stringify(s.aggregateFiles.map(file => [file.filePath, s.firewallSources[file.filePath]?.sessionId]))
    : s.firewallSources[s.openFilePath ?? ""]?.sessionId ?? "");
  const aggregateTailKey = JSON.stringify(
    [
      aggregateTailGeneration,
      aggregateFiles.map(({ filePath, byteOffset }) => [filePath, byteOffset]),
    ],
  );

  // Start/stop tailing when file changes
  useEffect(() => {
    if (sourceOpenMode === "aggregate-folder") {
      if (aggregateFiles.length === 0) {
        return;
      }

      const tailFormat = formatDetected ?? "Plain";

      const cleanups = aggregateFiles.map(file => startSourceWatch(file.filePath, tailFormat, file.byteOffset, 0, file.totalLines + 1));
      return () => cleanups.forEach(cleanup => cleanup());
    }

    if (!openFilePath || !formatDetected) return;

    const byteOffset = useLogStore.getState().byteOffset;
    const totalLines = useLogStore.getState().totalLines;
    const currentEntries = useLogStore.getState().entries;
    const nextId =
      currentEntries.length > 0
        ? currentEntries[currentEntries.length - 1].id + 1
        : 0;
    const nextLine = totalLines + 1;

    return startSourceWatch(openFilePath, formatDetected, byteOffset, nextId, nextLine);
  }, [aggregateTailKey, firewallSessionKey, formatDetected, openFilePath, sourceOpenMode]);

  // Handle pause/resume
  useEffect(() => {
    if (sourceOpenMode === "aggregate-folder") {
      if (aggregateFiles.length === 0) {
        return;
      }

      for (const file of aggregateFiles) {
        const action = isPaused ? pauseTail : resumeTail;
        const token = currentFirewallControl(file.filePath);
        if (!token && useLogStore.getState().firewallSources[file.filePath]) continue;
        (token ? action(file.filePath, token) : action(file.filePath)).catch((err) =>
          console.error(`Failed to ${isPaused ? "pause" : "resume"} aggregate tail:`, err)
        );
      }
      return;
    }

    if (!openFilePath) return;

    const token = currentFirewallControl(openFilePath);
    if (!token && useLogStore.getState().firewallSources[openFilePath]) return;
    if (isPaused) {
      (token ? pauseTail(openFilePath, token) : pauseTail(openFilePath)).catch((err) =>
        console.error("Failed to pause tail:", err)
      );
    } else {
      (token ? resumeTail(openFilePath, token) : resumeTail(openFilePath)).catch((err) =>
        console.error("Failed to resume tail:", err)
      );
    }
  }, [aggregateFiles, firewallSessionKey, isPaused, openFilePath, sourceOpenMode]);

  // Listen for new tail entries from the Rust backend
  useEffect(() => {
    const unlisten = listen<unknown>("tail-new-entries", (event) => {
      const payload = parseTailPayload(event.payload);
      if (!payload) {
        console.error("Ignored invalid tail payload from the backend");
        return;
      }
      const {
        amendments,
        entries: newEntries,
        filePath,
        observedThroughLine,
        parseErrors,
        parserSelection,
        reset,
      } = payload;
      const state = useLogStore.getState();
      if (payload.firewallControl || state.firewallSources[filePath]) {
        state.applyFirewallTail(payload);
        return;
      }

      if (state.sourceOpenMode === "aggregate-folder") {
        const isTrackedFile = state.aggregateFiles.some((file) => file.filePath === filePath);

        if (!isTrackedFile) {
          return;
        }

        if (parseErrors > 0) {
          recordAggregateTailParseErrors(filePath, parseErrors);
          console.warn(
            `Tail parsing reported ${parseErrors} coverage gap(s) for ${filePath}`,
          );
        }

        // A truncation reset must clear stale entries even when the fresh read
        // is empty, so it cannot be gated behind the empty-batch guard below.
        if (reset) {
          resetAggregateEntries(filePath, newEntries);
          if (observedThroughLine !== null) {
            observeAggregateTailLine(filePath, observedThroughLine);
          }
          return;
        }

        for (const amendment of amendments) {
          amendAggregateEntry(filePath, amendment);
        }

        if (newEntries.length > 0) {
          appendAggregateEntries(filePath, newEntries);
        }

        if (observedThroughLine !== null) {
          observeAggregateTailLine(filePath, observedThroughLine);
        }
        return;
      }

      const currentPath = state.openFilePath;

      if (!currentPath || currentPath !== filePath) {
        return;
      }

      if (parseErrors > 0) {
        console.warn(
          `Tail parsing reported ${parseErrors} coverage gap(s) for ${filePath}`,
        );
      }

      if (parserSelection) {
        setParserSelection(parserSelection);
      }

      if (reset) {
        resetEntries(newEntries);
        if (observedThroughLine !== null) {
          setTotalLines(observedThroughLine);
        }
        return;
      }

      for (const amendment of amendments) {
        amendEntry(amendment);
      }

      if (newEntries.length > 0) {
        appendEntries(newEntries);
      }

      if (observedThroughLine !== null) {
        setTotalLines(
          Math.max(useLogStore.getState().totalLines, observedThroughLine),
        );
      }
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, [
    amendAggregateEntry,
    amendEntry,
    appendAggregateEntries,
    appendEntries,
    observeAggregateTailLine,
    recordAggregateTailParseErrors,
    resetAggregateEntries,
    resetEntries,
    setParserSelection,
    setTotalLines,
  ]);
}
