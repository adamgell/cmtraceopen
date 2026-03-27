import { useState, useCallback } from "react";
import { tokens } from "@fluentui/react-components";
import type { CollectionResult } from "../../lib/commands";
import { loadPathAsLogSource } from "../../lib/log-source";

interface CollectionCompleteDialogProps {
  result: CollectionResult | null;
  onClose: () => void;
}

export function CollectionCompleteDialog({ result, onClose }: CollectionCompleteDialogProps) {
  const [showGaps, setShowGaps] = useState(false);

  const handleOpenBundle = useCallback(async () => {
    if (result?.bundlePath) {
      onClose();
      await loadPathAsLogSource(result.bundlePath, { preferFolder: true });
    }
  }, [result, onClose]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      onClose();
    }
  }, [onClose]);

  if (!result) return null;

  const { artifactCounts, durationMs, bundleId, gaps } = result;
  const durationSec = (durationMs / 1000).toFixed(1);
  const isError = artifactCounts.total === 0 && gaps.length > 0;

  return (
    <div
      onKeyDown={handleKeyDown}
      tabIndex={-1}
      style={{
        position: "fixed",
        inset: 0,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        backgroundColor: "rgba(0, 0, 0, 0.3)",
        zIndex: 1000,
      }}
    >
      <div
        style={{
          width: "420px",
          backgroundColor: tokens.colorNeutralBackground1,
          border: `1px solid ${tokens.colorNeutralStroke1}`,
          borderRadius: "8px",
          boxShadow: tokens.shadow16,
          padding: "24px",
        }}
      >
        {/* Header */}
        <div style={{ textAlign: "center", marginBottom: "20px" }}>
          <div style={{ fontSize: "24px", marginBottom: "4px" }}>
            {isError ? "✕" : "✓"}
          </div>
          <div style={{ fontSize: "16px", fontWeight: 600, color: tokens.colorNeutralForeground1 }}>
            {isError ? "Collection Failed" : "Collection Complete"}
          </div>
          {!isError && (
            <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3, marginTop: "4px" }}>
              Finished in {durationSec}s
            </div>
          )}
        </div>

        {/* Stat Cards */}
        {!isError && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "12px", marginBottom: "16px" }}>
            <StatCard label="Collected" value={artifactCounts.collected} color="#4ade80" bgColor="rgba(74, 222, 128, 0.1)" />
            <StatCard label="Missing" value={artifactCounts.missing} color="#facc15" bgColor="rgba(250, 204, 21, 0.1)" />
            <StatCard label="Failed" value={artifactCounts.failed} color="#f87171" bgColor="rgba(248, 113, 113, 0.1)" />
          </div>
        )}

        {/* Error message */}
        {isError && gaps.length > 0 && (
          <div style={{
            padding: "12px",
            borderRadius: "6px",
            backgroundColor: "rgba(248, 113, 113, 0.1)",
            color: "#f87171",
            fontSize: "13px",
            marginBottom: "16px",
            wordBreak: "break-word",
          }}>
            {gaps[0].reason}
          </div>
        )}

        {/* Bundle ID */}
        {bundleId && (
          <div style={{ fontSize: "11px", color: tokens.colorNeutralForeground4, textAlign: "center", marginBottom: "12px" }}>
            {bundleId}
          </div>
        )}

        {/* Gaps detail */}
        {!isError && gaps.length > 0 && (
          <div style={{ marginBottom: "12px" }}>
            <button
              onClick={() => setShowGaps(!showGaps)}
              style={{
                background: "none",
                border: "none",
                color: tokens.colorBrandForeground1,
                fontSize: "12px",
                cursor: "pointer",
                padding: 0,
              }}
            >
              {showGaps ? "Hide" : "Show"} {gaps.length} missing/failed details
            </button>
            {showGaps && (
              <div style={{
                marginTop: "8px",
                maxHeight: "150px",
                overflowY: "auto",
                fontSize: "11px",
                color: tokens.colorNeutralForeground3,
                border: `1px solid ${tokens.colorNeutralStroke2}`,
                borderRadius: "4px",
                padding: "8px",
              }}>
                {gaps.map((gap, i) => (
                  <div key={i} style={{ padding: "2px 0" }}>
                    <span style={{ fontWeight: 600 }}>{gap.artifactId}</span>
                    <span style={{ color: tokens.colorNeutralForeground4 }}> ({gap.category})</span>
                    : {gap.reason}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Actions */}
        <div style={{ display: "flex", gap: "8px", justifyContent: "center" }}>
          <button
            onClick={onClose}
            style={{
              padding: "6px 16px",
              borderRadius: "4px",
              border: `1px solid ${tokens.colorNeutralStroke1}`,
              background: "transparent",
              color: tokens.colorNeutralForeground1,
              fontSize: "13px",
              cursor: "pointer",
            }}
          >
            Close
          </button>
          {result.bundlePath && (
            <button
              onClick={handleOpenBundle}
              style={{
                padding: "6px 20px",
                borderRadius: "4px",
                border: "none",
                background: tokens.colorBrandBackground,
                color: tokens.colorNeutralForegroundOnBrand,
                fontSize: "13px",
                fontWeight: 600,
                cursor: "pointer",
              }}
            >
              Open Bundle
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, color, bgColor }: { label: string; value: number; color: string; bgColor: string }) {
  return (
    <div style={{ backgroundColor: bgColor, borderRadius: "6px", padding: "10px", textAlign: "center" }}>
      <div style={{ fontSize: "20px", fontWeight: 700, color }}>{value}</div>
      <div style={{ fontSize: "11px", color: tokens.colorNeutralForeground3 }}>{label}</div>
    </div>
  );
}
