import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { useIntuneStore } from "../stores/intune-store";
import { startIntuneTail, stopIntuneTail } from "../lib/commands";
import type { IntuneTailPayload } from "../types/intune";

/**
 * Hook that manages the Intune workspace live-tail lifecycle:
 * - After analysis completes ("ready") and live tailing is enabled, starts tailing all source files
 * - Listens for `intune-tail-update` events and appends incremental results
 * - Stops tailing on cleanup (workspace change or re-analysis)
 */
export function useIntuneTailWatcher() {
  const analysisPhase = useIntuneStore((s) => s.analysisState.phase);
  const sourceFiles = useIntuneStore((s) => s.sourceFiles);
  const enableLiveTailing = useIntuneStore((s) => s.analysisOptions.enableLiveTailing);
  const setTailing = useIntuneStore((s) => s.setTailing);
  const appendResults = useIntuneStore((s) => s.appendResults);

  // Start/stop tailing when analysis phase, source files, or option changes
  useEffect(() => {
    if (analysisPhase !== "ready" || sourceFiles.length === 0 || !enableLiveTailing) {
      return;
    }

    startIntuneTail(sourceFiles)
      .then(() => setTailing(true))
      .catch((err) => console.error("Failed to start intune tail:", err));

    return () => {
      setTailing(false);
      stopIntuneTail(sourceFiles).catch((err) =>
        console.error("Failed to stop intune tail:", err)
      );
    };
  }, [analysisPhase, sourceFiles, enableLiveTailing, setTailing]);

  // Listen for incremental intune tail events
  useEffect(() => {
    const unlisten = listen<IntuneTailPayload>(
      "intune-tail-update",
      (event) => {
        const { events, downloads } = event.payload;
        appendResults(events, downloads);
      }
    );

    return () => {
      unlisten.then((fn) => fn());
    };
  }, [appendResults]);
}
