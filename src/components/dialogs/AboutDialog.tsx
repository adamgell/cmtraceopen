import { useEffect, useState } from "react";
import { getIdentifier, getName, getTauriVersion, getVersion } from "@tauri-apps/api/app";

interface AboutDialogProps {
  isOpen: boolean;
  onClose: () => void;
}

export function AboutDialog({ isOpen, onClose }: AboutDialogProps) {
  const [appName, setAppName] = useState("CMTrace Open");
  const [appVersion, setAppVersion] = useState("0.2.0");
  const [tauriVersion, setTauriVersion] = useState("-");
  const [identifier, setIdentifier] = useState("com.cmtrace.open");

  useEffect(() => {
    if (!isOpen) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [isOpen, onClose]);

  useEffect(() => {
    if (!isOpen) return;

    let isCancelled = false;

    const loadMetadata = async () => {
      try {
        const [name, version, tauri, appIdentifier] = await Promise.all([
          getName(),
          getVersion(),
          getTauriVersion(),
          getIdentifier(),
        ]);

        if (isCancelled) return;

        setAppName(name);
        setAppVersion(version);
        setTauriVersion(tauri);
        setIdentifier(appIdentifier);
      } catch (error) {
        console.error("Failed to load about dialog metadata", { error });
      }
    };

    void loadMetadata();

    return () => {
      isCancelled = true;
    };
  }, [isOpen]);

  if (!isOpen) return null;

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
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        style={{
          backgroundColor: "#f0f0f0",
          border: "1px solid #999",
          borderRadius: "4px",
          padding: "16px",
          minWidth: "420px",
          maxWidth: "520px",
          boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
        }}
      >
        <div
          style={{
            fontSize: "16px",
            fontWeight: "bold",
            marginBottom: "2px",
          }}
        >
          {appName}
        </div>
        <div style={{ fontSize: "12px", color: "#666", marginBottom: "10px" }}>
          Version {appVersion}
        </div>

        <div style={{ fontSize: "12px", marginBottom: "10px", lineHeight: 1.5 }}>
          Open-source CMTrace log viewer inspired by Microsoft CMTrace.exe,
          with built-in Intune Management Extension diagnostics.
        </div>

        <div
          style={{
            backgroundColor: "#fff",
            border: "1px solid #ccc",
            borderRadius: "2px",
            padding: "8px",
            marginBottom: "10px",
            fontSize: "11px",
          }}
        >
          <div style={{ marginBottom: "4px" }}>
            <strong>Runtime:</strong> Tauri {tauriVersion}, React, TypeScript, Rust
          </div>
          <div style={{ marginBottom: "4px" }}>
            <strong>License:</strong> MIT
          </div>
          <div>
            <strong>Application ID:</strong> {identifier}
          </div>
        </div>

        <div style={{ fontSize: "11px", color: "#555", marginBottom: "14px" }}>
          Project repository: github.com/adamgell/homelab-code
        </div>

        <div style={{ display: "flex", justifyContent: "flex-end" }}>
          <button onClick={onClose}>OK</button>
        </div>
      </div>
    </div>
  );
}
