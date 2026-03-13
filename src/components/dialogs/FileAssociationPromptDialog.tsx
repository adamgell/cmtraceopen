import { useEffect, useState } from "react";
import {
  associateLogFilesWithApp,
  setFileAssociationPromptSuppressed,
} from "../../lib/commands";

interface FileAssociationPromptDialogProps {
  isOpen: boolean;
  onClose: () => void;
}

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return "Unknown error";
}

export function FileAssociationPromptDialog({
  isOpen,
  onClose,
}: FileAssociationPromptDialogProps) {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

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

  const handleAssociate = async () => {
    setIsSubmitting(true);
    setErrorMessage(null);

    try {
      await associateLogFilesWithApp();
      onClose();
    } catch (error) {
      setErrorMessage(getErrorMessage(error));
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDontAskAgain = async () => {
    setIsSubmitting(true);
    setErrorMessage(null);

    try {
      await setFileAssociationPromptSuppressed(true);
      onClose();
    } catch (error) {
      setErrorMessage(getErrorMessage(error));
    } finally {
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
        style={{
          backgroundColor: "#f0f0f0",
          border: "1px solid #999",
          borderRadius: "4px",
          padding: "16px",
          minWidth: "440px",
          maxWidth: "540px",
          boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
        }}
      >
        <div
          style={{
            fontSize: "16px",
            fontWeight: "bold",
            marginBottom: "10px",
          }}
        >
          Associate log files with CMTrace Open?
        </div>

        <div style={{ fontSize: "12px", lineHeight: 1.5, marginBottom: "12px" }}>
          This standalone copy of CMTrace Open can associate <strong>.log</strong>{" "}
          and <strong>.lo_</strong> files so they open directly in the app, similar
          to classic CMTrace.exe.
        </div>

        <div
          style={{
            backgroundColor: "#fff",
            border: "1px solid #ccc",
            borderRadius: "2px",
            padding: "8px",
            marginBottom: "12px",
            fontSize: "11px",
            color: "#333",
          }}
        >
          If you choose <strong>Associate</strong>, CMTrace Open will register
          itself for the current Windows user.
        </div>

        {errorMessage && (
          <div
            style={{
              color: "#8b0000",
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
          <button onClick={onClose} disabled={isSubmitting}>
            Ask Later
          </button>
          <button onClick={() => void handleDontAskAgain()} disabled={isSubmitting}>
            Don&apos;t Ask Again
          </button>
          <button onClick={() => void handleAssociate()} disabled={isSubmitting}>
            {isSubmitting ? "Working..." : "Associate"}
          </button>
        </div>
      </div>
    </div>
  );
}
