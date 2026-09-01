import { useEffect, useState } from "react";
import { getFileAssociationPromptStatus } from "../lib/commands";
import { useUiStore } from "../stores/ui-store";

/**
 * Shows the per-user Windows registration prompt when this edition has not yet
 * registered as an available handler for its supported log file types.
 */
export function useFileAssociationPrompt() {
  const [isEligible, setIsEligible] = useState(false);
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
    if (isEligible) {
      setShowFileAssociationPrompt(true);
      if (useUiStore.getState().showFileAssociationPrompt) {
        setIsEligible(false);
      }
    }
  }, [isEligible, setShowFileAssociationPrompt]);
}
