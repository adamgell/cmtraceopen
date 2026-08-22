import { useEffect, useRef, useState } from "react";
import {
  getFileAssociationPromptStatus,
  getSafeErrorMessage,
  openWindowsDefaultApps,
  registerLogFileHandler,
  setFileAssociationPromptSuppressed,
} from "../../lib/commands";
import { tokens } from "@fluentui/react-components";
import { useModalFocus } from "../../hooks/use-modal-focus";
import { useUiStore } from "../../stores/ui-store";

interface FileAssociationPromptDialogProps {
  isOpen: boolean;
  onClose: () => void;
}

export function FileAssociationPromptDialog({
  isOpen,
  onClose,
}: FileAssociationPromptDialogProps) {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const setFileAssociationPromptBusy = useUiStore(
    (state) => state.setFileAssociationPromptBusy,
  );
  const dialogRef = useRef<HTMLDivElement>(null);
  useEffect(
    () => () => setFileAssociationPromptBusy(false),
    [setFileAssociationPromptBusy],
  );
  useModalFocus(
    isOpen,
    dialogRef,
    undefined,
    isSubmitting ? "submitting" : "idle",
  );

  useEffect(() => {
    if (!isOpen) {
      setIsSubmitting(false);
      setErrorMessage(null);
      return;
    }

    const handleKey = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !isSubmitting) {
        onClose();
      }
    };

    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [isOpen, isSubmitting, onClose]);

  if (!isOpen) {
    return null;
  }

  const handleRegister = async () => {
    setIsSubmitting(true);
    setFileAssociationPromptBusy(true);
    setErrorMessage(null);

    try {
      await registerLogFileHandler();
    } catch (error) {
      setErrorMessage(
        `Failed to register CMTrace Open: ${getSafeErrorMessage(error, "Unknown error")}`,
      );
      setFileAssociationPromptBusy(false);
      setIsSubmitting(false);
      return;
    }

    try {
      const status = await getFileAssociationPromptStatus();
      if (!status.isRegistered) {
        setErrorMessage(
          "CMTrace Open registration could not be confirmed by Windows. Try again or check Windows Default Apps.",
        );
        setFileAssociationPromptBusy(false);
        setIsSubmitting(false);
        return;
      }
    } catch (error) {
      setErrorMessage(
        `CMTrace Open was registered, but Windows registration could not be confirmed: ${getSafeErrorMessage(error, "Unknown error")}`,
      );
      setFileAssociationPromptBusy(false);
      setIsSubmitting(false);
      return;
    }

    try {
      await openWindowsDefaultApps();
      setFileAssociationPromptBusy(false);
      onClose();
    } catch (error) {
      setErrorMessage(
        `CMTrace Open is registered, but Windows Default Apps could not be opened: ${getSafeErrorMessage(error, "Unknown error")}`,
      );
    } finally {
      setFileAssociationPromptBusy(false);
      setIsSubmitting(false);
    }
  };

  const handleDontAskAgain = async () => {
    setIsSubmitting(true);
    setFileAssociationPromptBusy(true);
    setErrorMessage(null);

    try {
      await setFileAssociationPromptSuppressed(true);
      setFileAssociationPromptBusy(false);
      onClose();
    } catch (error) {
      setErrorMessage(getSafeErrorMessage(error, "Unknown error"));
    } finally {
      setFileAssociationPromptBusy(false);
      setIsSubmitting(false);
    }
  };

  return (
    <div
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: "rgba(0,0,0,0.3)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000,
      }}
      onClick={(event) => {
        if (event.target === event.currentTarget && !isSubmitting) {
          onClose();
        }
      }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label="Make CMTrace Open available for log files?"
        tabIndex={-1}
        style={{
          backgroundColor: tokens.colorNeutralBackground1,
          color: tokens.colorNeutralForeground1,
          border: `1px solid ${tokens.colorNeutralStroke1}`,
          borderRadius: "4px",
          padding: "16px",
          minWidth: "440px",
          maxWidth: "540px",
          boxShadow: tokens.shadow16,
        }}
      >
        <div
          style={{
            fontSize: "16px",
            fontWeight: "bold",
            marginBottom: "10px",
          }}
        >
          Make CMTrace Open available for log files?
        </div>

        <div style={{ fontSize: "12px", lineHeight: 1.5, marginBottom: "12px" }}>
          This edition of CMTrace Open can register as a per-user available
          handler for <strong>.log</strong>,{" "}
          <strong>.log_</strong>, <strong>.lo_</strong>, and <strong>.cmtlog</strong>{" "}
          files.
        </div>

        <div
          style={{
            backgroundColor: tokens.colorNeutralBackground2,
            border: `1px solid ${tokens.colorNeutralStroke2}`,
            borderRadius: "2px",
            padding: "8px",
            marginBottom: "12px",
            fontSize: "11px",
            color: tokens.colorNeutralForeground1,
          }}
        >
          Windows keeps your current defaults until you choose CMTrace Open in
          Default Apps. This action registers CMTrace Open for the current user,
          then opens the Windows-owned picker.
        </div>

        {errorMessage && (
          <div
            role="alert"
            style={{
              color: tokens.colorPaletteRedForeground1,
              fontSize: "11px",
              marginBottom: "12px",
            }}
          >
            {errorMessage}
          </div>
        )}

        <div
          style={{
            display: "flex",
            justifyContent: "flex-end",
            gap: "8px",
          }}
        >
          <button
            onClick={onClose}
            disabled={isSubmitting}
            style={{
              padding: "2px 12px",
              fontSize: "12px",
              border: `1px solid ${tokens.colorNeutralStroke1}`,
              borderRadius: "2px",
              background: tokens.colorNeutralBackground3,
              color: tokens.colorNeutralForeground1,
              cursor: isSubmitting ? "default" : "pointer",
            }}
          >
            Ask Later
          </button>
          <button
            onClick={() => void handleDontAskAgain()}
            disabled={isSubmitting}
            style={{
              padding: "2px 12px",
              fontSize: "12px",
              border: `1px solid ${tokens.colorNeutralStroke1}`,
              borderRadius: "2px",
              background: tokens.colorNeutralBackground3,
              color: tokens.colorNeutralForeground1,
              cursor: isSubmitting ? "default" : "pointer",
            }}
          >
            Don&apos;t Ask Again
          </button>
          <button
            onClick={() => void handleRegister()}
            disabled={isSubmitting}
            style={{
              padding: "2px 12px",
              fontSize: "12px",
              border: `1px solid ${tokens.colorNeutralStroke1}`,
              borderRadius: "2px",
              background: tokens.colorNeutralBackground3,
              color: tokens.colorNeutralForeground1,
              cursor: isSubmitting ? "default" : "pointer",
            }}
          >
            {isSubmitting ? "Working..." : "Register and open Default Apps"}
          </button>
        </div>
      </div>
    </div>
  );
}
