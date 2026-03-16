import { useEffect, useMemo, useRef, useState } from "react";
import { inspectEvidenceArtifact, inspectEvidenceBundle } from "../../lib/commands";
import { useDsregcmdStore } from "../../stores/dsregcmd-store";
import { useIntuneStore } from "../../stores/intune-store";
import { useLogStore } from "../../stores/log-store";
import { isIntuneWorkspace, useUiStore } from "../../stores/ui-store";
import { formatDisplayDateTime } from "../../lib/date-time-format";
import { useAppActions } from "../layout/Toolbar";
import type {
  EvidenceArtifactRecord,
  EvidenceArtifactPreview,
  EvidenceBundleDetails,
} from "../../types/evidence";
import type { ParseQuality } from "../../types/log";
import type { WorkspaceId } from "../../stores/ui-store";

interface EvidenceBundleDialogProps {
  isOpen: boolean;
  onClose: () => void;
}

type EvidenceBundleTab = "summary" | "inventory" | "notes" | "manifest";

interface ArtifactNavigationState {
  canOpen: boolean;
  reason: string;
  actionLabel: string | null;
}

const TEXT_LIKE_EXTENSIONS = new Set([".log", ".lo_", ".txt"]);

function getBaseName(path: string | null): string {
  if (!path) {
    return "";
  }

  return path.split(/[\\/]/).pop() ?? path;
}

function getDirectoryName(path: string | null): string | null {
  if (!path) {
    return null;
  }

  const normalized = path.replace(/\\/g, "/");
  const lastSeparator = normalized.lastIndexOf("/");
  if (lastSeparator <= 0) {
    return null;
  }

  return path.slice(0, lastSeparator);
}

function formatUtcDateTime(value: string | null): string {
  if (!value) {
    return "Not reported";
  }

  return formatDisplayDateTime(value) ?? value;
}

function formatCategoryLabel(category: string): string {
  return category
    .split(/[-_]/)
    .filter((part) => part.length > 0)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function formatArtifactStatusTone(status: EvidenceArtifactRecord["status"]) {
  switch (status) {
    case "collected":
      return { backgroundColor: "#dcfce7", color: "#166534" };
    case "missing":
      return { backgroundColor: "#fef3c7", color: "#92400e" };
    case "failed":
      return { backgroundColor: "#fee2e2", color: "#991b1b" };
    case "skipped":
      return { backgroundColor: "#e0f2fe", color: "#0f766e" };
    default:
      return { backgroundColor: "#e5e7eb", color: "#374151" };
  }
}

function formatIntakeStatusTone(status: EvidenceArtifactRecord["intake"]["status"]) {
  switch (status) {
    case "recognized":
      return { backgroundColor: "#dbeafe", color: "#1d4ed8" };
    case "generic":
      return { backgroundColor: "#fef3c7", color: "#92400e" };
    case "unsupported":
      return { backgroundColor: "#fee2e2", color: "#991b1b" };
    case "missing":
      return { backgroundColor: "#e5e7eb", color: "#374151" };
    default:
      return { backgroundColor: "#e5e7eb", color: "#374151" };
  }
}

function formatIntakeStatusLabel(status: EvidenceArtifactRecord["intake"]["status"]) {
  switch (status) {
    case "recognized":
      return "Recognized";
    case "generic":
      return "Generic text";
    case "unsupported":
      return "Unsupported";
    case "missing":
      return "Missing on disk";
    default:
      return status;
  }
}

function formatParseQualityLabel(value: ParseQuality | null | undefined) {
  switch (value) {
    case "structured":
      return "Structured";
    case "semiStructured":
      return "Semi-structured";
    case "textFallback":
      return "Text fallback";
    default:
      return null;
  }
}

function formatParseDiagnosticsSummary(artifact: EvidenceArtifactRecord): string | null {
  const diagnostics = artifact.intake.parseDiagnostics;
  if (!diagnostics) {
    return null;
  }

  const lineLabel = diagnostics.totalLines === 1 ? "line" : "lines";
  const entryLabel = diagnostics.entryCount === 1 ? "entry" : "entries";
  const errorLabel = diagnostics.parseErrors === 1 ? "issue" : "issues";

  if (diagnostics.cleanParse) {
    return `${diagnostics.entryCount} ${entryLabel} from ${diagnostics.totalLines} ${lineLabel} with no parse issues`;
  }

  return `${diagnostics.entryCount} ${entryLabel} from ${diagnostics.totalLines} ${lineLabel} with ${diagnostics.parseErrors} parse ${errorLabel}`;
}

function formatFileSize(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value)) {
    return "Not reported";
  }

  if (value < 1024) {
    return `${value} B`;
  }

  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`;
  }

  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function getFileExtension(path: string): string {
  const fileName = getBaseName(path);
  const lastDot = fileName.lastIndexOf(".");
  if (lastDot < 0) {
    return "";
  }

  return fileName.slice(lastDot).toLowerCase();
}

function isTextLikeArtifactPath(path: string | null): boolean {
  if (!path) {
    return false;
  }

  return TEXT_LIKE_EXTENSIONS.has(getFileExtension(path));
}

function includesAny(value: string | null | undefined, terms: string[]): boolean {
  if (!value) {
    return false;
  }

  const normalized = value.toLowerCase();
  return terms.some((term) => normalized.includes(term));
}

function artifactMatchesTerms(artifact: EvidenceArtifactRecord, terms: string[]): boolean {
  if (includesAny(artifact.family, terms)) {
    return true;
  }

  if (includesAny(artifact.relativePath, terms)) {
    return true;
  }

  if (includesAny(artifact.originPath, terms)) {
    return true;
  }

  if (includesAny(artifact.notes, terms)) {
    return true;
  }

  return artifact.parseHints.some((hint) => includesAny(hint, terms));
}

function canPreviewAdjacentEvidence(artifact: EvidenceArtifactRecord): boolean {
  return (
    artifact.existsOnDisk &&
    artifact.absolutePath != null &&
    (artifact.intake.kind === "registrySnapshot" ||
      artifact.intake.kind === "eventLogExport")
  );
}

function getArtifactActionLabel(
  artifact: EvidenceArtifactRecord,
  navigation: ArtifactNavigationState
): string {
  if (navigation.canOpen) {
    return navigation.actionLabel ?? navigation.reason;
  }

  if (canPreviewAdjacentEvidence(artifact)) {
    return artifact.intake.kind === "registrySnapshot"
      ? "Review registry snapshot"
      : "Review event export";
  }

  return navigation.reason;
}

function getArtifactNavigationState(
  artifact: EvidenceArtifactRecord,
  activeView: WorkspaceId
): ArtifactNavigationState {
  if (artifact.status !== "collected") {
    return {
      canOpen: false,
      reason: "Only collected artifacts can be opened.",
      actionLabel: null,
    };
  }

  if (!artifact.existsOnDisk || !artifact.absolutePath) {
    return {
      canOpen: false,
      reason: "This artifact is not available on disk.",
      actionLabel: null,
    };
  }

  if (activeView === "log") {
    if (artifact.category !== "logs" || !isTextLikeArtifactPath(artifact.absolutePath)) {
      return {
        canOpen: false,
        reason: "The log workspace currently opens collected text log artifacts only.",
        actionLabel: null,
      };
    }

    return {
      canOpen: true,
      reason: "Open this artifact in the log workspace.",
      actionLabel: "Open in log workspace",
    };
  }

  if (isIntuneWorkspace(activeView)) {
    if (artifact.category !== "logs" || !isTextLikeArtifactPath(artifact.absolutePath)) {
      return {
        canOpen: false,
        reason: "The Intune workspace currently opens IME-style text log artifacts only.",
        actionLabel: null,
      };
    }

    if (!artifactMatchesTerms(artifact, ["intune", "ime", "appworkload", "agentexecutor", "healthscripts", "appactionprocessor"])) {
      return {
        canOpen: false,
        reason: "This artifact does not look like an Intune IME log source.",
        actionLabel: null,
      };
    }

    return {
      canOpen: true,
      reason:
        activeView === "new-intune"
          ? "Open this artifact in New Intune Workspace."
          : "Open this artifact in the Intune workspace.",
      actionLabel:
        activeView === "new-intune"
          ? "Open in New Intune Workspace"
          : "Open in Intune workspace",
    };
  }

  if (!isTextLikeArtifactPath(artifact.absolutePath)) {
    return {
      canOpen: false,
      reason: "The dsregcmd workspace currently opens dsregcmd text captures only.",
      actionLabel: null,
    };
  }

  if (!artifactMatchesTerms(artifact, ["dsregcmd", "entra", "azuread", "join"])) {
    return {
      canOpen: false,
      reason: "This artifact does not look like a dsregcmd capture.",
      actionLabel: null,
    };
  }

  return {
    canOpen: true,
    reason: "Open this artifact in the dsregcmd workspace.",
    actionLabel: "Open in dsregcmd workspace",
  };
}

function MetadataRow({ label, value }: { label: string; value: string }) {
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "140px minmax(0, 1fr)",
        gap: "8px",
        fontSize: "12px",
        lineHeight: 1.45,
      }}
    >
      <div style={{ color: "#4b5563", fontWeight: 600 }}>{label}</div>
      <div style={{ color: "#111827", wordBreak: "break-word" }}>{value}</div>
    </div>
  );
}

function PreviewPane({ content }: { content: string | null }) {
  if (!content) {
    return (
      <div style={{ fontSize: "12px", color: "#64748b", lineHeight: 1.5 }}>
        No content was available for this file.
      </div>
    );
  }

  return (
    <pre
      style={{
        margin: 0,
        whiteSpace: "pre-wrap",
        wordBreak: "break-word",
        fontSize: "12px",
        lineHeight: 1.55,
        fontFamily: "'Consolas', 'Cascadia Mono', 'Courier New', monospace",
        color: "#111827",
      }}
    >
      {content}
    </pre>
  );
}

export function EvidenceBundleDialog({ isOpen, onClose }: EvidenceBundleDialogProps) {
  const activeView = useUiStore((state) => state.activeView);
  const logBundleMetadata = useLogStore((state) => state.bundleMetadata);
  const logSourceEntries = useLogStore((state) => state.sourceEntries);
  const logSelectedSourceFilePath = useLogStore((state) => state.selectedSourceFilePath);
  const logActiveSource = useLogStore((state) => state.activeSource);
  const intuneEvidenceBundle = useIntuneStore((state) => state.evidenceBundle);
  const intuneSourceContext = useIntuneStore((state) => state.sourceContext);
  const dsregcmdSourceContext = useDsregcmdStore((state) => state.sourceContext);
  const { openPathForActiveWorkspace } = useAppActions();
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const previouslyFocusedElementRef = useRef<HTMLElement | null>(null);
  const [activeTab, setActiveTab] = useState<EvidenceBundleTab>("summary");
  const [details, setDetails] = useState<EvidenceBundleDetails | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [artifactActionMessage, setArtifactActionMessage] = useState<string | null>(null);
  const [selectedArtifact, setSelectedArtifact] = useState<EvidenceArtifactRecord | null>(null);
  const [artifactPreview, setArtifactPreview] = useState<EvidenceArtifactPreview | null>(null);
  const [isArtifactPreviewLoading, setIsArtifactPreviewLoading] = useState(false);

  const bundleRootPath = useMemo(() => {
    if (activeView === "log") {
      if (!logBundleMetadata) {
        return null;
      }

      if (logActiveSource?.kind === "folder") {
        return logActiveSource.path;
      }

      if (logActiveSource?.kind === "known" && logActiveSource.pathKind === "folder") {
        return logActiveSource.defaultPath;
      }

      return getDirectoryName(logBundleMetadata.manifestPath);
    }

    if (isIntuneWorkspace(activeView)) {
      return intuneEvidenceBundle ? getDirectoryName(intuneEvidenceBundle.manifestPath) : null;
    }

    return dsregcmdSourceContext.bundlePath;
  }, [
    activeView,
    dsregcmdSourceContext.bundlePath,
    intuneEvidenceBundle,
    logActiveSource,
    logBundleMetadata,
  ]);

  const selectedSourceFilePath =
    activeView === "log"
      ? logSelectedSourceFilePath
      : isIntuneWorkspace(activeView)
        ? intuneSourceContext.analyzedPath
        : null;
  const sourceEntries = activeView === "log" ? logSourceEntries : [];
  const bundleMetadata =
    details?.metadata ??
    (activeView === "log"
      ? logBundleMetadata
      : isIntuneWorkspace(activeView)
        ? intuneEvidenceBundle
        : null);

  useEffect(() => {
    if (!isOpen) {
      return;
    }

    const handleKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
      }
    };

    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [isOpen, onClose]);

  useEffect(() => {
    if (isOpen) {
      previouslyFocusedElementRef.current =
        document.activeElement instanceof HTMLElement ? document.activeElement : null;
      dialogRef.current?.focus();
      return;
    }

    previouslyFocusedElementRef.current?.focus();
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen || !bundleRootPath) {
      return;
    }

    let cancelled = false;
    setIsLoading(true);
    setErrorMessage(null);
    setArtifactActionMessage(null);
    setSelectedArtifact(null);
    setArtifactPreview(null);
    setIsArtifactPreviewLoading(false);

    inspectEvidenceBundle(bundleRootPath)
      .then((result) => {
        if (cancelled) {
          return;
        }

        setDetails(result);
      })
      .catch((error) => {
        if (cancelled) {
          return;
        }

        setDetails(null);
        setErrorMessage(
          error instanceof Error ? error.message : "Failed to inspect evidence bundle."
        );
      })
      .finally(() => {
        if (!cancelled) {
          setIsLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [bundleRootPath, isOpen]);

  if (!isOpen || !bundleMetadata) {
    return null;
  }

  const availableEntryPoints = new Set(bundleMetadata.availablePrimaryEntryPoints);
  const fileCount = sourceEntries.filter((entry) => !entry.isDir).length;
  const folderCount = sourceEntries.filter((entry) => entry.isDir).length;
  const artifacts = details?.artifacts ?? [];
  const expectedEvidence = details?.expectedEvidence ?? [];
  const requiredMissingEvidence = expectedEvidence.filter(
    (entry) => entry.required && !entry.available
  );
  const artifactCategoryCounts = Array.from(
    artifacts.reduce((counts, artifact) => {
      counts.set(artifact.category, (counts.get(artifact.category) ?? 0) + 1);
      return counts;
    }, new Map<string, number>())
  ).sort((left, right) => left[0].localeCompare(right[0]));
  const intakeStatusCounts = Array.from(
    artifacts.reduce((counts, artifact) => {
      counts.set(artifact.intake.status, (counts.get(artifact.intake.status) ?? 0) + 1);
      return counts;
    }, new Map<EvidenceArtifactRecord["intake"]["status"], number>())
  ).sort((left, right) => right[1] - left[1]);
  const recognizedFamilies = Array.from(
    artifacts.reduce((labels, artifact) => {
      if (artifact.intake.recognizedAs) {
        labels.add(artifact.intake.recognizedAs);
      }
      return labels;
    }, new Set<string>())
  ).sort((left, right) => left.localeCompare(right));
  const noisyParsedArtifacts = artifacts.filter(
    (artifact) => (artifact.intake.parseDiagnostics?.parseErrors ?? 0) > 0
  );

  const handleArtifactOpen = async (artifact: EvidenceArtifactRecord) => {
    const navigation = getArtifactNavigationState(artifact, activeView);
    const canPreview = canPreviewAdjacentEvidence(artifact);

    if (navigation.canOpen && artifact.absolutePath) {
      setArtifactActionMessage(null);

      try {
        await openPathForActiveWorkspace(artifact.absolutePath);
        onClose();
      } catch (error) {
        setArtifactActionMessage(
          error instanceof Error ? error.message : "The selected artifact could not be opened."
        );
      }
      return;
    }

    if (canPreview && artifact.absolutePath) {
      setArtifactActionMessage(null);
      setSelectedArtifact(artifact);
      setArtifactPreview(null);
      setIsArtifactPreviewLoading(true);

      try {
        const preview = await inspectEvidenceArtifact(
          artifact.absolutePath,
          artifact.intake.kind,
          artifact.originPath
        );
        setArtifactPreview(preview);
      } catch (error) {
        setArtifactActionMessage(
          error instanceof Error
            ? error.message
            : "The selected adjacent evidence could not be inspected."
        );
      } finally {
        setIsArtifactPreviewLoading(false);
      }
      return;
    }

    if (!artifact.absolutePath) {
      setArtifactActionMessage(navigation.reason);
      return;
    }

    setArtifactActionMessage(navigation.reason);
  };

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        backgroundColor: "rgba(15, 23, 42, 0.28)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000,
        padding: "20px",
      }}
      onClick={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label="Evidence bundle summary"
        tabIndex={-1}
        style={{
          width: "min(860px, 100%)",
          maxHeight: "min(88vh, 920px)",
          overflow: "auto",
          border: "1px solid #cbd5e1",
          borderRadius: "8px",
          backgroundColor: "#f8fafc",
          boxShadow: "0 22px 48px rgba(15, 23, 42, 0.22)",
          fontFamily: "'Segoe UI', Tahoma, sans-serif",
        }}
      >
        <div
          style={{
            padding: "16px 18px 14px",
            borderBottom: "1px solid #dbe3ee",
            background: "linear-gradient(135deg, #eff6ff 0%, #f8fafc 55%, #fefce8 100%)",
          }}
        >
          <div style={{ fontSize: "11px", fontWeight: 700, color: "#1d4ed8", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Evidence Bundle
          </div>
          <div style={{ marginTop: "4px", fontSize: "18px", fontWeight: 700, color: "#0f172a" }}>
            {bundleMetadata.bundleLabel ?? bundleMetadata.bundleId ?? "Collected evidence summary"}
          </div>
          <div style={{ marginTop: "6px", fontSize: "12px", color: "#475569", lineHeight: 1.5 }}>
            {bundleMetadata.summary ?? "This folder was recognized as a CMTrace Open evidence bundle."}
          </div>
        </div>

        <div style={{ padding: "18px", display: "grid", gap: "16px" }}>
          <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
            {([
              ["summary", "Summary"],
              ["inventory", "Inventory"],
              ["notes", "Notes"],
              ["manifest", "Manifest"],
            ] as const).map(([tabId, label]) => (
              <button
                key={tabId}
                onClick={() => setActiveTab(tabId)}
                aria-pressed={activeTab === tabId}
                style={{
                  border: "1px solid #cbd5e1",
                  borderRadius: "999px",
                  padding: "6px 10px",
                  backgroundColor: activeTab === tabId ? "#dbeafe" : "#ffffff",
                  color: activeTab === tabId ? "#1d4ed8" : "#334155",
                  fontSize: "12px",
                  fontWeight: activeTab === tabId ? 700 : 500,
                }}
              >
                {label}
              </button>
            ))}
          </div>

          {errorMessage && (
            <div style={{ padding: "10px 12px", border: "1px solid #fecaca", borderRadius: "6px", backgroundColor: "#fef2f2", color: "#991b1b", fontSize: "12px" }}>
              {errorMessage}
            </div>
          )}

          {artifactActionMessage && (
            <div style={{ padding: "10px 12px", border: "1px solid #fed7aa", borderRadius: "6px", backgroundColor: "#fff7ed", color: "#9a3412", fontSize: "12px" }}>
              {artifactActionMessage}
            </div>
          )}

          {isLoading && (
            <div style={{ padding: "10px 12px", border: "1px solid #bfdbfe", borderRadius: "6px", backgroundColor: "#eff6ff", color: "#1d4ed8", fontSize: "12px" }}>
              Loading evidence bundle details...
            </div>
          )}

          {requiredMissingEvidence.length > 0 && (
            <div style={{ padding: "10px 12px", border: "1px solid #fecaca", borderRadius: "6px", backgroundColor: "#fef2f2", color: "#991b1b", fontSize: "12px", lineHeight: 1.5 }}>
              <div style={{ fontWeight: 700 }}>
                {requiredMissingEvidence.length} required evidence item{requiredMissingEvidence.length === 1 ? " is" : "s are"} missing from this bundle.
              </div>
              <div style={{ marginTop: "4px" }}>
                {requiredMissingEvidence
                  .slice(0, 3)
                  .map((entry) => entry.relativePath)
                  .join(" • ")}
                {requiredMissingEvidence.length > 3
                  ? ` • +${requiredMissingEvidence.length - 3} more`
                  : ""}
              </div>
            </div>
          )}

          {activeTab === "summary" && (
            <>
              <section
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))",
                  gap: "10px",
                }}
              >
                {[
                  ["Collected", String(bundleMetadata.artifactCounts?.collected ?? 0), "#dcfce7", "#166534"],
                  ["Missing", String(bundleMetadata.artifactCounts?.missing ?? 0), "#fef3c7", "#92400e"],
                  ["Failed", String(bundleMetadata.artifactCounts?.failed ?? 0), "#fee2e2", "#991b1b"],
                  ["Skipped", String(bundleMetadata.artifactCounts?.skipped ?? 0), "#e0f2fe", "#0f766e"],
                ].map(([label, value, backgroundColor, color]) => (
                  <div
                    key={label}
                    style={{
                      padding: "12px",
                      border: "1px solid #dbe3ee",
                      borderRadius: "6px",
                      backgroundColor,
                    }}
                  >
                    <div style={{ fontSize: "11px", fontWeight: 700, color, textTransform: "uppercase", letterSpacing: "0.04em" }}>
                      {label}
                    </div>
                    <div style={{ marginTop: "4px", fontSize: "22px", fontWeight: 700, color: "#0f172a" }}>{value}</div>
                  </div>
                ))}
              </section>

              <section
                style={{
                  padding: "14px",
                  border: "1px solid #dbe3ee",
                  borderRadius: "6px",
                  backgroundColor: "#ffffff",
                  display: "grid",
                  gap: "10px",
                }}
              >
                <div style={{ fontSize: "13px", fontWeight: 700, color: "#111827" }}>Bundle metadata</div>
                <MetadataRow label="Bundle ID" value={bundleMetadata.bundleId ?? "Not reported"} />
                <MetadataRow label="Case reference" value={bundleMetadata.caseReference ?? "Not reported"} />
                <MetadataRow label="Device" value={bundleMetadata.deviceName ?? "Not reported"} />
                <MetadataRow label="Primary user" value={bundleMetadata.primaryUser ?? "Not reported"} />
                <MetadataRow label="Tenant" value={bundleMetadata.tenant ?? "Not reported"} />
                <MetadataRow label="Platform" value={bundleMetadata.platform ?? "Not reported"} />
                <MetadataRow label="OS version" value={bundleMetadata.osVersion ?? "Not reported"} />
                <MetadataRow label="Collected" value={formatUtcDateTime(bundleMetadata.collectedUtc ?? bundleMetadata.createdUtc)} />
                <MetadataRow label="Collector profile" value={bundleMetadata.collectorProfile ?? "Not reported"} />
                <MetadataRow label="Collector version" value={bundleMetadata.collectorVersion ?? "Not reported"} />
              </section>

              <section
                style={{
                  padding: "14px",
                  border: "1px solid #dbe3ee",
                  borderRadius: "6px",
                  backgroundColor: "#ffffff",
                  display: "grid",
                  gap: "10px",
                }}
              >
                <div style={{ fontSize: "13px", fontWeight: 700, color: "#111827" }}>Current intake view</div>
                <MetadataRow label="Manifest" value={bundleMetadata.manifestPath} />
                <MetadataRow label="Notes" value={bundleMetadata.notesPath ?? "Not reported"} />
                <MetadataRow label="Evidence root" value={bundleMetadata.evidenceRoot ?? "Not reported"} />
                <MetadataRow label="Folder contents" value={`${fileCount} files, ${folderCount} folders visible at bundle root`} />
                <MetadataRow label="Selected source" value={selectedSourceFilePath ? getBaseName(selectedSourceFilePath) : "No file selected"} />
              </section>

              <section
                style={{
                  padding: "14px",
                  border: "1px solid #dbe3ee",
                  borderRadius: "6px",
                  backgroundColor: "#ffffff",
                }}
              >
                <div style={{ fontSize: "13px", fontWeight: 700, color: "#111827" }}>Primary evidence entry points</div>
                <div style={{ marginTop: "10px", display: "grid", gap: "8px" }}>
                  {bundleMetadata.primaryEntryPoints.map((entryPath: string) => {
                    const isAvailable = availableEntryPoints.has(entryPath);
                    return (
                      <div
                        key={entryPath}
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: "10px",
                          padding: "9px 10px",
                          border: "1px solid #e2e8f0",
                          borderRadius: "6px",
                          backgroundColor: isAvailable ? "#f0fdf4" : "#fff7ed",
                        }}
                      >
                        <div
                          style={{
                            minWidth: "72px",
                            fontSize: "11px",
                            fontWeight: 700,
                            textTransform: "uppercase",
                            letterSpacing: "0.04em",
                            color: isAvailable ? "#166534" : "#9a3412",
                          }}
                        >
                          {isAvailable ? "Available" : "Missing"}
                        </div>
                        <div style={{ fontSize: "12px", color: "#1f2937", wordBreak: "break-word" }}>
                          {entryPath}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </section>

              {details && (
                <section
                  style={{
                    padding: "14px",
                    border: "1px solid #dbe3ee",
                    borderRadius: "6px",
                    backgroundColor: "#ffffff",
                    display: "grid",
                    gap: "8px",
                  }}
                >
                  <div style={{ fontSize: "13px", fontWeight: 700, color: "#111827" }}>Investigation guidance</div>
                  {details.handoffSummary && <div style={{ fontSize: "12px", color: "#334155", lineHeight: 1.5 }}>{details.handoffSummary}</div>}
                  {details.priorityQuestions.length > 0 && (
                    <div style={{ display: "grid", gap: "6px" }}>
                      {details.priorityQuestions.map((question) => (
                        <div key={question} style={{ fontSize: "12px", color: "#1f2937" }}>
                          {question}
                        </div>
                      ))}
                    </div>
                  )}
                  {details.observedGaps.length > 0 && (
                    <div style={{ display: "grid", gap: "6px", marginTop: "2px" }}>
                      {details.observedGaps.map((gap) => (
                        <div key={gap} style={{ fontSize: "12px", color: "#92400e" }}>
                          {gap}
                        </div>
                      ))}
                    </div>
                  )}
                </section>
              )}
            </>
          )}

          {activeTab === "inventory" && (
            <>
              <section
                style={{
                  padding: "14px",
                  border: "1px solid #dbe3ee",
                  borderRadius: "6px",
                  backgroundColor: "#ffffff",
                }}
              >
                <div style={{ fontSize: "13px", fontWeight: 700, color: "#111827" }}>Artifact inventory</div>
                <div style={{ marginTop: "10px", display: "flex", gap: "8px", flexWrap: "wrap" }}>
                  {artifactCategoryCounts.length === 0 ? (
                    <div style={{ fontSize: "12px", color: "#64748b" }}>No artifact records were found in the manifest.</div>
                  ) : (
                    artifactCategoryCounts.map(([category, count]) => (
                      <div key={category} style={{ padding: "6px 10px", border: "1px solid #e2e8f0", borderRadius: "999px", backgroundColor: "#f8fafc", fontSize: "12px", color: "#334155" }}>
                        {formatCategoryLabel(category)}: {count}
                      </div>
                    ))
                  )}
                </div>
                <div style={{ marginTop: "10px", display: "flex", gap: "8px", flexWrap: "wrap" }}>
                  {intakeStatusCounts.length === 0 ? (
                    <div style={{ fontSize: "12px", color: "#64748b" }}>No intake diagnostics are available yet.</div>
                  ) : (
                    intakeStatusCounts.map(([status, count]) => {
                      const tone = formatIntakeStatusTone(status);
                      return (
                        <div key={status} style={{ padding: "6px 10px", borderRadius: "999px", backgroundColor: tone.backgroundColor, color: tone.color, fontSize: "12px", fontWeight: 700 }}>
                          {formatIntakeStatusLabel(status)}: {count}
                        </div>
                      );
                    })
                  )}
                </div>
                {recognizedFamilies.length > 0 && (
                  <div style={{ marginTop: "10px", fontSize: "11px", color: "#475569" }}>
                    Recognized intake families: {recognizedFamilies.join(", ")}
                  </div>
                )}
                {noisyParsedArtifacts.length > 0 && (
                  <div style={{ marginTop: "8px", fontSize: "11px", color: "#92400e" }}>
                    Parser quality watchlist: {noisyParsedArtifacts.length} recognized log artifact{noisyParsedArtifacts.length === 1 ? "" : "s"} reported parse issues.
                  </div>
                )}
              </section>

              <section
                style={{
                  padding: "14px",
                  border: "1px solid #dbe3ee",
                  borderRadius: "6px",
                  backgroundColor: "#ffffff",
                  display: "grid",
                  gap: "8px",
                }}
              >
                <div style={{ fontSize: "13px", fontWeight: 700, color: "#111827" }}>Artifacts</div>
                {artifacts.length === 0 ? (
                  <div style={{ fontSize: "12px", color: "#64748b" }}>No artifact detail was available.</div>
                ) : (
                  artifacts.map((artifact) => {
                    const tone = formatArtifactStatusTone(artifact.status);
                    const intakeTone = formatIntakeStatusTone(artifact.intake.status);
                    const parseQualityLabel = formatParseQualityLabel(artifact.intake.parserSelection?.parseQuality);
                    const parseDiagnosticsSummary = formatParseDiagnosticsSummary(artifact);
                    const navigation = getArtifactNavigationState(artifact, activeView);
                    const canPreview = canPreviewAdjacentEvidence(artifact);
                    const canInteract = navigation.canOpen || canPreview;
                    const isSelected =
                      selectedArtifact?.absolutePath != null &&
                      selectedArtifact.absolutePath === artifact.absolutePath;
                    return (
                      <button
                        key={`${artifact.relativePath}:${artifact.status}`}
                        type="button"
                        onClick={() => {
                          void handleArtifactOpen(artifact);
                        }}
                        disabled={!canInteract}
                        title={getArtifactActionLabel(artifact, navigation)}
                        style={{
                          border: isSelected
                            ? "1px solid #2563eb"
                            : canInteract
                              ? "1px solid #bfdbfe"
                              : "1px solid #e2e8f0",
                          borderRadius: "6px",
                          padding: "10px",
                          display: "grid",
                          gap: "6px",
                          textAlign: "left",
                          backgroundColor: isSelected
                            ? "#eff6ff"
                            : canInteract
                              ? "#f8fbff"
                              : "#f8fafc",
                          cursor: canInteract ? "pointer" : "not-allowed",
                          opacity: canInteract ? 1 : 0.78,
                        }}
                      >
                        <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                          <span style={{ padding: "3px 8px", borderRadius: "999px", backgroundColor: tone.backgroundColor, color: tone.color, fontSize: "11px", fontWeight: 700, textTransform: "uppercase" }}>
                            {artifact.status}
                          </span>
                          <span style={{ fontSize: "11px", color: "#475569", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                            {formatCategoryLabel(artifact.category)}
                          </span>
                          <span style={{ padding: "3px 8px", borderRadius: "999px", backgroundColor: intakeTone.backgroundColor, color: intakeTone.color, fontSize: "11px", fontWeight: 700 }}>
                            {formatIntakeStatusLabel(artifact.intake.status)}
                          </span>
                          {artifact.family && <span style={{ fontSize: "12px", color: "#0f172a", fontWeight: 600 }}>{artifact.family}</span>}
                        </div>
                        <div style={{ fontSize: "12px", color: "#111827", wordBreak: "break-word", fontWeight: 600 }}>
                          {artifact.relativePath}
                        </div>
                        <div style={{ fontSize: "11px", color: "#0f172a" }}>
                          {artifact.intake.recognizedAs ?? "Unclassified artifact"}
                          {parseQualityLabel ? ` • ${parseQualityLabel}` : ""}
                        </div>
                        <div style={{ fontSize: "11px", color: "#475569", wordBreak: "break-word" }}>
                          {artifact.intake.summary}
                        </div>
                        {parseDiagnosticsSummary && (
                          <div style={{ fontSize: "11px", color: artifact.intake.parseDiagnostics?.cleanParse ? "#166534" : "#92400e" }}>
                            {parseDiagnosticsSummary}
                          </div>
                        )}
                        <div style={{ fontSize: "11px", color: canInteract ? "#1d4ed8" : "#64748b", fontWeight: canInteract ? 600 : 500 }}>
                          {getArtifactActionLabel(artifact, navigation)}
                        </div>
                        {artifact.intake.parserSelection && (
                          <div style={{ fontSize: "11px", color: "#475569" }}>
                            Parser: {artifact.intake.parserSelection.parser}
                            {artifact.intake.parserSelection.specialization ? ` (${artifact.intake.parserSelection.specialization})` : ""}
                          </div>
                        )}
                        {artifact.originPath && <div style={{ fontSize: "11px", color: "#475569", wordBreak: "break-word" }}>Origin: {artifact.originPath}</div>}
                        {artifact.notes && <div style={{ fontSize: "11px", color: "#475569", wordBreak: "break-word" }}>Notes: {artifact.notes}</div>}
                      </button>
                    );
                  })
                )}
              </section>

              {(selectedArtifact || isArtifactPreviewLoading) && (
                <section
                  style={{
                    padding: "14px",
                    border: "1px solid #dbe3ee",
                    borderRadius: "6px",
                    backgroundColor: "#ffffff",
                    display: "grid",
                    gap: "10px",
                  }}
                >
                  <div style={{ fontSize: "13px", fontWeight: 700, color: "#111827" }}>
                    Adjacent evidence preview
                  </div>
                  {selectedArtifact && (
                    <div style={{ display: "grid", gap: "4px" }}>
                      <div style={{ fontSize: "12px", fontWeight: 600, color: "#0f172a", wordBreak: "break-word" }}>
                        {selectedArtifact.relativePath}
                      </div>
                      <div style={{ fontSize: "11px", color: "#475569", wordBreak: "break-word" }}>
                        {selectedArtifact.originPath ?? selectedArtifact.intake.recognizedAs ?? "Selected artifact"}
                      </div>
                    </div>
                  )}
                  {isArtifactPreviewLoading ? (
                    <div style={{ fontSize: "12px", color: "#1d4ed8" }}>
                      Inspecting adjacent evidence...
                    </div>
                  ) : artifactPreview?.registrySnapshot ? (
                    <>
                      <div style={{ fontSize: "12px", color: "#334155", lineHeight: 1.5 }}>
                        {artifactPreview.summary}
                      </div>
                      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))", gap: "10px" }}>
                        <div style={{ padding: "10px", borderRadius: "6px", border: "1px solid #dbeafe", backgroundColor: "#eff6ff" }}>
                          <div style={{ fontSize: "11px", fontWeight: 700, color: "#1d4ed8", textTransform: "uppercase", letterSpacing: "0.04em" }}>Keys</div>
                          <div style={{ marginTop: "4px", fontSize: "20px", fontWeight: 700, color: "#0f172a" }}>
                            {artifactPreview.registrySnapshot.keyCount}
                          </div>
                        </div>
                        <div style={{ padding: "10px", borderRadius: "6px", border: "1px solid #dbeafe", backgroundColor: "#eff6ff" }}>
                          <div style={{ fontSize: "11px", fontWeight: 700, color: "#1d4ed8", textTransform: "uppercase", letterSpacing: "0.04em" }}>Values</div>
                          <div style={{ marginTop: "4px", fontSize: "20px", fontWeight: 700, color: "#0f172a" }}>
                            {artifactPreview.registrySnapshot.valueCount}
                          </div>
                        </div>
                      </div>
                      <div style={{ display: "grid", gap: "8px" }}>
                        {artifactPreview.registrySnapshot.keys.map((keyPreview) => (
                          <div key={keyPreview.path} style={{ border: "1px solid #e2e8f0", borderRadius: "6px", padding: "10px", backgroundColor: "#f8fafc", display: "grid", gap: "6px" }}>
                            <div style={{ fontSize: "11px", color: "#475569", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                              {keyPreview.valueCount} value{keyPreview.valueCount === 1 ? "" : "s"}
                            </div>
                            <div style={{ fontSize: "12px", fontWeight: 600, color: "#111827", wordBreak: "break-word" }}>
                              {keyPreview.path}
                            </div>
                            <div style={{ display: "grid", gap: "4px" }}>
                              {keyPreview.values.map((valuePreview) => (
                                <div key={`${keyPreview.path}:${valuePreview.name}`} style={{ fontSize: "11px", color: "#334155", lineHeight: 1.45, wordBreak: "break-word" }}>
                                  <strong>{valuePreview.name}</strong> [{valuePreview.valueType}]: {valuePreview.value}
                                </div>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </>
                  ) : artifactPreview?.eventLogExport ? (
                    <div style={{ display: "grid", gap: "10px" }}>
                      <div style={{ fontSize: "12px", color: "#334155", lineHeight: 1.5 }}>
                        {artifactPreview.summary}
                      </div>
                      <MetadataRow
                        label="Channel"
                        value={artifactPreview.eventLogExport.channel ?? "Not reported"}
                      />
                      <MetadataRow
                        label="Format"
                        value={artifactPreview.eventLogExport.exportFormat.toUpperCase()}
                      />
                      <MetadataRow
                        label="File size"
                        value={formatFileSize(artifactPreview.eventLogExport.fileSizeBytes)}
                      />
                      <MetadataRow
                        label="Modified"
                        value={formatUtcDateTime(
                          artifactPreview.eventLogExport.modifiedUnixMs != null
                            ? new Date(artifactPreview.eventLogExport.modifiedUnixMs).toISOString()
                            : null
                        )}
                      />
                    </div>
                  ) : (
                    <div style={{ fontSize: "12px", color: "#64748b" }}>
                      Select a registry snapshot or curated event export to inspect it here.
                    </div>
                  )}
                </section>
              )}

              <section
                style={{
                  padding: "14px",
                  border: "1px solid #dbe3ee",
                  borderRadius: "6px",
                  backgroundColor: "#ffffff",
                  display: "grid",
                  gap: "8px",
                }}
              >
                <div style={{ fontSize: "13px", fontWeight: 700, color: "#111827" }}>Expected evidence</div>
                {expectedEvidence.length === 0 ? (
                  <div style={{ fontSize: "12px", color: "#64748b" }}>No expected-evidence detail was recorded in the manifest.</div>
                ) : (
                  expectedEvidence.map((entry) => (
                    <div key={`${entry.category}:${entry.relativePath}`} style={{ display: "grid", gap: "4px", padding: "9px 10px", border: "1px solid #e2e8f0", borderRadius: "6px", backgroundColor: entry.available ? "#f0fdf4" : entry.required ? "#fef2f2" : "#fff7ed" }}>
                      <div style={{ fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.04em", color: entry.available ? "#166534" : entry.required ? "#991b1b" : "#9a3412", fontWeight: 700 }}>
                        {entry.available ? "Available" : entry.required ? "Required gap" : "Optional gap"}
                      </div>
                      <div style={{ fontSize: "12px", color: "#111827", fontWeight: 600 }}>{entry.relativePath}</div>
                      {entry.reason && <div style={{ fontSize: "11px", color: "#475569" }}>{entry.reason}</div>}
                    </div>
                  ))
                )}
              </section>
            </>
          )}

          {activeTab === "notes" && (
            <section style={{ padding: "14px", border: "1px solid #dbe3ee", borderRadius: "6px", backgroundColor: "#ffffff" }}>
              <div style={{ fontSize: "13px", fontWeight: 700, color: "#111827", marginBottom: "10px" }}>Notes preview</div>
              <PreviewPane content={details?.notesContent ?? null} />
            </section>
          )}

          {activeTab === "manifest" && (
            <section style={{ padding: "14px", border: "1px solid #dbe3ee", borderRadius: "6px", backgroundColor: "#ffffff" }}>
              <div style={{ fontSize: "13px", fontWeight: 700, color: "#111827", marginBottom: "10px" }}>Manifest preview</div>
              <PreviewPane content={details?.manifestContent ?? null} />
            </section>
          )}
        </div>

        <div
          style={{
            padding: "14px 18px",
            borderTop: "1px solid #dbe3ee",
            backgroundColor: "#ffffff",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            gap: "10px",
          }}
        >
          <div style={{ fontSize: "11px", color: "#64748b" }}>
            Notes file: {getBaseName(bundleMetadata.notesPath)}
          </div>
          <button onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}