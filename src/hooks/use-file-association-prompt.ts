import { useEffect, useState } from "react";
import { getFileAssociationPromptStatus } from "../lib/commands";
import { hasOpenPriorityModal, useUiStore } from "../stores/ui-store";

/**
 * Shows the standalone Windows registration prompt when the app has not yet
 * registered as an available handler for its supported log file types.
 */
export function useFileAssociationPrompt() {
  const [isEligible, setIsEligible] = useState(false);
  const hasBlockingModal = useUiStore(hasOpenPriorityModal);
  const setShowFileAssociationPrompt = useUiStore(
    (state) => state.setShowFileAssociationPrompt
  );

  useEffect(() => {
    let isDisposed = false;
    const startupDelayHandle = window.setTimeout(() => {
      getFileAssociationPromptStatus()
        .then((status) => {
          if (isDisposed || !status.supported || !status.shouldPrompt) {
            return;
          }

          setIsEligible(true);
        })
        .catch((error) => {
          console.error("[file-association-prompt] failed to load prompt status", {
            error,
          });
        });
    }, 350);

    return () => {
      isDisposed = true;
      window.clearTimeout(startupDelayHandle);
    };
  }, []);

  useEffect(() => {
    if (isEligible && !hasBlockingModal) {
      setShowFileAssociationPrompt(true);
      if (useUiStore.getState().showFileAssociationPrompt) {
        setIsEligible(false);
      }
    }
  }, [hasBlockingModal, isEligible, setShowFileAssociationPrompt]);
}
