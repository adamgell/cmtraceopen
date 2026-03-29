import { useEffect } from "react";
import { tokens } from "@fluentui/react-components";
import type { UpdateInfo } from "../../hooks/use-update-checker";

interface UpdateDialogProps {
  isOpen: boolean;
  onClose: () => void;
  updateInfo: UpdateInfo | null;
  isChecking: boolean;
  isDownloading: boolean;
  downloadProgress: number;
  onCheckForUpdates: () => Promise<UpdateInfo | null>;
  onDownloadAndInstall: () => void;
  onOpenReleasePage: () => void;
  onSkipVersion: (version: string) => void;
}

export function UpdateDialog({
  isOpen,
  onClose,
  updateInfo,
  isChecking,
  isDownloading,
  downloadProgress,
  onCheckForUpdates,
  onDownloadAndInstall,
  onOpenReleasePage,
  onSkipVersion,
}: UpdateDialogProps) {
  useEffect(() => {
    if (!isOpen) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !isDownloading) onClose();
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [isOpen, isDownloading, onClose]);

  // Trigger check when dialog opens via menu (no existing updateInfo)
  useEffect(() => {
    if (isOpen && !updateInfo && !isChecking) {
      void onCheckForUpdates();
    }
  }, [isOpen, updateInfo, isChecking, onCheckForUpdates]);

  if (!isOpen) return null;

  const overlayStyle: React.CSSProperties = {
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
  };

  const dialogStyle: React.CSSProperties = {
    backgroundColor: tokens.colorNeutralBackground1,
    color: tokens.colorNeutralForeground1,
    border: `1px solid ${tokens.colorNeutralStroke1}`,
    borderRadius: "4px",
    padding: "16px",
    minWidth: "420px",
    maxWidth: "520px",
    boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
  };

  const buttonStyle: React.CSSProperties = {
    padding: "2px 12px",
    fontSize: "12px",
    border: `1px solid ${tokens.colorNeutralStroke1}`,
    borderRadius: "2px",
    background: tokens.colorNeutralBackground3,
    color: tokens.colorNeutralForeground1,
    cursor: "pointer",
  };

  const primaryButtonStyle: React.CSSProperties = {
    ...buttonStyle,
    background: tokens.colorBrandBackground,
    color: tokens.colorNeutralForegroundOnBrand,
    border: `1px solid ${tokens.colorBrandBackground}`,
  };

  const renderContent = () => {
    // State 1: Checking
    if (isChecking) {
      return (
        <>
          <div style={{ fontSize: "16px", fontWeight: "bold", marginBottom: "12px" }}>
            Check for Updates
          </div>
          <div style={{ fontSize: "12px", marginBottom: "16px", color: tokens.colorNeutralForeground2 }}>
            Checking for updates...
          </div>
          <div style={{ display: "flex", justifyContent: "flex-end" }}>
            <button onClick={onClose} style={buttonStyle}>Cancel</button>
          </div>
        </>
      );
    }

    // State 4: Downloading
    if (isDownloading) {
      const percent = Math.round(downloadProgress * 100);
      return (
        <>
          <div style={{ fontSize: "16px", fontWeight: "bold", marginBottom: "12px" }}>
            Downloading Update
          </div>
          <div style={{ fontSize: "12px", marginBottom: "8px", color: tokens.colorNeutralForeground2 }}>
            Downloading and installing update...
          </div>
          <div
            style={{
              height: "6px",
              backgroundColor: tokens.colorNeutralBackground5,
              borderRadius: "3px",
              overflow: "hidden",
              marginBottom: "8px",
            }}
          >
            <div
              style={{
                width: `${percent}%`,
                height: "100%",
                backgroundColor: tokens.colorBrandBackground,
                borderRadius: "3px",
                transition: "width 0.3s ease",
              }}
            />
          </div>
          <div style={{ fontSize: "11px", color: tokens.colorNeutralForeground3, marginBottom: "4px", textAlign: "right" }}>
            {percent}%
          </div>
        </>
      );
    }

    // State 2: Update available
    if (updateInfo?.available) {
      return (
        <>
          <div style={{ fontSize: "16px", fontWeight: "bold", marginBottom: "2px" }}>
            Update Available
          </div>
          <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3, marginBottom: "10px" }}>
            v{updateInfo.currentVersion} &rarr; v{updateInfo.newVersion}
          </div>

          {updateInfo.releaseNotes && (
            <div
              style={{
                backgroundColor: tokens.colorNeutralBackground2,
                border: `1px solid ${tokens.colorNeutralStroke2}`,
                borderRadius: "2px",
                padding: "8px",
                marginBottom: "10px",
                fontSize: "11px",
                maxHeight: "150px",
                overflow: "auto",
                whiteSpace: "pre-wrap",
                lineHeight: 1.5,
              }}
            >
              {updateInfo.releaseNotes}
            </div>
          )}

          {updateInfo.error && (
            <div style={{ fontSize: "11px", color: "#d13438", marginBottom: "10px" }}>
              Auto-update failed: {updateInfo.error}
            </div>
          )}

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <button
              onClick={() => updateInfo.newVersion && onSkipVersion(updateInfo.newVersion)}
              style={{
                background: "none",
                border: "none",
                color: tokens.colorNeutralForeground3,
                fontSize: "11px",
                cursor: "pointer",
                textDecoration: "underline",
                padding: 0,
              }}
            >
              Skip this version
            </button>
            <div style={{ display: "flex", gap: "6px" }}>
              <button onClick={onClose} style={buttonStyle}>Later</button>
              {updateInfo.canAutoUpdate && !updateInfo.error ? (
                <button onClick={onDownloadAndInstall} style={primaryButtonStyle}>
                  Download &amp; Install
                </button>
              ) : (
                <button onClick={onOpenReleasePage} style={primaryButtonStyle}>
                  Download from GitHub
                </button>
              )}
            </div>
          </div>
        </>
      );
    }

    // State 3: Up to date or error
    return (
      <>
        <div style={{ fontSize: "16px", fontWeight: "bold", marginBottom: "12px" }}>
          Check for Updates
        </div>
        {updateInfo?.error ? (
          <div style={{ fontSize: "12px", marginBottom: "16px", color: "#d13438" }}>
            Unable to check for updates: {updateInfo.error}
          </div>
        ) : (
          <div style={{ fontSize: "12px", marginBottom: "16px", color: tokens.colorNeutralForeground2 }}>
            You're running the latest version (v{updateInfo?.currentVersion ?? "?"}).
          </div>
        )}
        <div style={{ display: "flex", justifyContent: "flex-end" }}>
          <button onClick={onClose} style={buttonStyle}>OK</button>
        </div>
      </>
    );
  };

  return (
    <div
      style={overlayStyle}
      onClick={(e) => {
        if (e.target === e.currentTarget && !isDownloading) onClose();
      }}
    >
      <div style={dialogStyle}>
        {renderContent()}
      </div>
    </div>
  );
}
