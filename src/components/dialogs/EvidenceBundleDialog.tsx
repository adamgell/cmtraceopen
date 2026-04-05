import { useEffect, useMemo, useRef, useState } from "react";
import { tokens } from "@fluentui/react-components";
import { inspectEvidenceArtifact, inspectEvidenceBundle } from "../../lib/commands";
import { useDsregcmdStore } from "../../workspaces/dsregcmd/dsregcmd-store";
import { useIntuneStore } from "../../workspaces/intune/intune-store";
import { useLogStore } from "../../stores/log-store";
import { isIntuneWorkspace, useUiStore } from "../../stores/ui-store";
import { formatDisplayDateTime } from "../../lib/date-time-format";
import { getBaseName, getDirectoryName } from "../../lib/file-paths";
import { useAppActions } from "../layout/Toolbar";
import type {
  EvidenceArtifactRecord,
  EvidenceArtifactPreview,
  EvidenceBundleDetails,
} from "../../types/evidence";
import type { ParseQuality } from "../../types/log";
import type { WorkspaceId } from "../../stores/ui-store";

const BUNDLE_COLORS = {
  successBg: tokens.colorPaletteGreenBackground1,
  warningBg: tokens.colorPaletteYellowBackground1,
  errorBg: tokens.colorPaletteRedBackground1,
  infoBg: tokens.colorPaletteBlueBorderActive,
  neutralBg: tokens.colorNeutralBackground3,
  successFg: tokens.colorPaletteGreenForeground1,
  warningFg: tokens.colorPaletteMarigoldForeground2,
  errorFg: tokens.colorPaletteRedForeground1,
  infoFg: tokens.colorBrandForeground1,
  neutralFg: tokens.colorNeutralForeground2,
  textPrimary: tokens.colorNeutralForeground1,
  textSecondary: tokens.colorNeutralForeground2,
  textTertiary: tokens.colorNeutralForeground3,
  textMuted: tokens.colorNeutralForeground4,
  cardBg: tokens.colorNeutralCardBackground,
  surfaceBg: tokens.colorNeutralBackground1,
  subtleBg: tokens.colorNeutralBackground2,
  borderDefault: tokens.colorNeutralStroke1,
  borderSubtle: tokens.colorNeutralStroke2,
  borderError: tokens.colorPaletteRedBorder2,
  borderWarning: tokens.colorPaletteYellowBorder2,
  borderInfo: tokens.colorPaletteBlueBackground2,
  headerFg: tokens.colorNeutralForeground2,
  accentFg: tokens.colorBrandForeground1,
} as const;

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
      return { backgroundColor: BUNDLE_COLORS.successBg, color: BUNDLE_COLORS.successFg };
    case "missing":
      return { backgroundColor: BUNDLE_COLORS.warningBg, color: BUNDLE_COLORS.warningFg };
    case "failed":
      return { backgroundColor: BUNDLE_COLORS.errorBg, color: BUNDLE_COLORS.errorFg };
    case "skipped":
      return { backgroundColor: BUNDLE_COLORS.infoBg, color: BUNDLE_COLORS.infoFg };
    default:
      return { backgroundColor: BUNDLE_COLORS.neutralBg, color: BUNDLE_COLORS.neutralFg };
  }
}

function formatIntakeStatusTone(status: EvidenceArtifactRecord["intake"]["status"]) {
  switch (status) {
    case "recognized":
      return { backgroundColor: BUNDLE_COLORS.infoBg, color: BUNDLE_COLORS.accentFg };
    case "generic":
      return { backgroundColor: BUNDLE_COLORS.warningBg, color: BUNDLE_COLORS.warningFg };
    case "unsupported":
      return { backgroundColor: BUNDLE_COLORS.errorBg, color: BUNDLE_COLORS.errorFg };
    case "missing":
      return { backgroundColor: BUNDLE_COLORS.neutralBg, color: BUNDLE_COLORS.neutralFg };
    default:
      return { backgroundColor: BUNDLE_COLORS.neutralBg, color: BUNDLE_COLORS.neutralFg };
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
      <div style={{ color: BUNDLE_COLORS.headerFg, fontWeight: 600 }}>{label}</div>
      <div style={{ color: BUNDLE_COLORS.textPrimary, wordBreak: "break-word" }}>{value}</div>
    </div>
  );
}

function PreviewPane({ content }: { content: string | null }) {
  if (!content) {
    return (
      <div style={{ fontSize: "12px", color: BUNDLE_COLORS.textTertiary, lineHeight: 1.5 }}>
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
        color: BUNDLE_COLORS.textPrimary,
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
          border: `1px solid ${BUNDLE_COLORS.borderSubtle}`,
          borderRadius: "8px",
          backgroundColor: BUNDLE_COLORS.cardBg,
          boxShadow: "0 22px 48px rgba(15, 23, 42, 0.22)",
          fontFamily: "'Segoe UI', Tahoma, sans-serif",
        }}
      >
        <div
          style={{
            padding: "16px 18px 14px",
            borderBottom: `1px solid ${BUNDLE_COLORS.borderSubtle}`,
            background: `linear-gradient(135deg, ${BUNDLE_COLORS.infoBg} 0%, ${BUNDLE_COLORS.cardBg} 55%, ${BUNDLE_COLORS.warningBg} 100%)`,
          }}
        >
          <div style={{ fontSize: "11px", fontWeight: 700, color: BUNDLE_COLORS.accentFg, textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Evidence Bundle
          </div>
          <div style={{ marginTop: "4px", fontSize: "18px", fontWeight: 700, color: BUNDLE_COLORS.textPrimary }}>
            {bundleMetadata.bundleLabel ?? bundleMetadata.bundleId ?? "Collected evidence summary"}
          </div>
          <div style={{ marginTop: "6px", fontSize: "12px", color: BUNDLE_COLORS.textTertiary, lineHeight: 1.5 }}>
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
                  border: `1px solid ${BUNDLE_COLORS.borderSubtle}`,
                  borderRadius: "999px",
                  padding: "6px 10px",
                  backgroundColor: activeTab === tabId ? BUNDLE_COLORS.infoBg : BUNDLE_COLORS.cardBg,
                  color: activeTab === tabId ? BUNDLE_COLORS.accentFg : BUNDLE_COLORS.textSecondary,
                  fontSize: "12px",
                  fontWeight: activeTab === tabId ? 700 : 500,
                }}
              >
                {label}
              </button>
            ))}
          </div>

          {errorMessage && (
            <div style={{ padding: "10px 12px", border: `1px solid ${BUNDLE_COLORS.borderError}`, borderRadius: "6px", backgroundColor: BUNDLE_COLORS.errorBg, color: BUNDLE_COLORS.errorFg, fontSize: "12px" }}>
              {errorMessage}
            </div>
          )}

          {artifactActionMessage && (
            <div style={{ padding: "10px 12px", border: `1px solid ${BUNDLE_COLORS.borderWarning}`, borderRadius: "6px", backgroundColor: BUNDLE_COLORS.warningBg, color: BUNDLE_COLORS.warningFg, fontSize: "12px" }}>
              {artifactActionMessage}
            </div>
          )}

          {isLoading && (
            <div style={{ padding: "10px 12px", border: `1px solid ${BUNDLE_COLORS.borderInfo}`, borderRadius: "6px", backgroundColor: BUNDLE_COLORS.infoBg, color: BUNDLE_COLORS.accentFg, fontSize: "12px" }}>
              Loading evidence bundle details...
            </div>
          )}

          {requiredMissingEvidence.length > 0 && (
            <div style={{ padding: "10px 12px", border: `1px solid ${BUNDLE_COLORS.borderError}`, borderRadius: "6px", backgroundColor: BUNDLE_COLORS.errorBg, color: BUNDLE_COLORS.errorFg, fontSize: "12px", lineHeight: 1.5 }}>
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
                  ["Collected", String(bundleMetadata.artifactCounts?.collected ?? 0), BUNDLE_COLORS.successBg, BUNDLE_COLORS.successFg],
                  ["Missing", String(bundleMetadata.artifactCounts?.missing ?? 0), BUNDLE_COLORS.warningBg, BUNDLE_COLORS.warningFg],
                  ["Failed", String(bundleMetadata.artifactCounts?.failed ?? 0), BUNDLE_COLORS.errorBg, BUNDLE_COLORS.errorFg],
                  ["Skipped", String(bundleMetadata.artifactCounts?.skipped ?? 0), BUNDLE_COLORS.infoBg, BUNDLE_COLORS.infoFg],
                ].map(([label, value, backgroundColor, color]) => (
                  <div
                    key={label}
                    style={{
                      padding: "12px",
                      border: `1px solid ${BUNDLE_COLORS.borderSubtle}`,
                      borderRadius: "6px",
                      backgroundColor,
                    }}
                  >
                    <div style={{ fontSize: "11px", fontWeight: 700, color, textTransform: "uppercase", letterSpacing: "0.04em" }}>
                      {label}
                    </div>
                    <div style={{ marginTop: "4px", fontSize: "22px", fontWeight: 700, color: BUNDLE_COLORS.textPrimary }}>{value}</div>
                  </div>
                ))}
              </section>

              <section
                style={{
                  padding: "14px",
                  border: `1px solid ${BUNDLE_COLORS.borderSubtle}`,
                  borderRadius: "6px",
                  backgroundColor: BUNDLE_COLORS.cardBg,
                  display: "grid",
                  gap: "10px",
                }}
              >
                <div style={{ fontSize: "13px", fontWeight: 700, color: BUNDLE_COLORS.textPrimary }}>Bundle metadata</div>
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
                  border: `1px solid ${BUNDLE_COLORS.borderSubtle}`,
                  borderRadius: "6px",
                  backgroundColor: BUNDLE_COLORS.cardBg,
                  display: "grid",
                  gap: "10px",
                }}
              >
                <div style={{ fontSize: "13px", fontWeight: 700, color: BUNDLE_COLORS.textPrimary }}>Current intake view</div>
                <MetadataRow label="Manifest" value={bundleMetadata.manifestPath} />
                <MetadataRow label="Notes" value={bundleMetadata.notesPath ?? "Not reported"} />
                <MetadataRow label="Evidence root" value={bundleMetadata.evidenceRoot ?? "Not reported"} />
                <MetadataRow label="Folder contents" value={`${fileCount} files, ${folderCount} folders visible at bundle root`} />
                <MetadataRow label="Selected source" value={selectedSourceFilePath ? getBaseName(selectedSourceFilePath) : "No file selected"} />
              </section>

              <section
                style={{
                  padding: "14px",
                  border: `1px solid ${BUNDLE_COLORS.borderSubtle}`,
                  borderRadius: "6px",
                  backgroundColor: BUNDLE_COLORS.cardBg,
                }}
              >
                <div style={{ fontSize: "13px", fontWeight: 700, color: BUNDLE_COLORS.textPrimary }}>Primary evidence entry points</div>
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
                          border: `1px solid ${BUNDLE_COLORS.borderSubtle}`,
                          borderRadius: "6px",
                          backgroundColor: isAvailable ? BUNDLE_COLORS.successBg : BUNDLE_COLORS.warningBg,
                        }}
                      >
                        <div
                          style={{
                            minWidth: "72px",
                            fontSize: "11px",
                            fontWeight: 700,
                            textTransform: "uppercase",
                            letterSpacing: "0.04em",
                            color: isAvailable ? BUNDLE_COLORS.successFg : BUNDLE_COLORS.warningFg,
                          }}
                        >
                          {isAvailable ? "Available" : "Missing"}
                        </div>
                        <div style={{ fontSize: "12px", color: BUNDLE_COLORS.textSecondary, wordBreak: "break-word" }}>
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
                    border: `1px solid ${BUNDLE_COLORS.borderSubtle}`,
                    borderRadius: "6px",
                    backgroundColor: BUNDLE_COLORS.cardBg,
                    display: "grid",
                    gap: "8px",
                  }}
                >
                  <div style={{ fontSize: "13px", fontWeight: 700, color: BUNDLE_COLORS.textPrimary }}>Investigation guidance</div>
                  {details.handoffSummary && <div style={{ fontSize: "12px", color: BUNDLE_COLORS.textSecondary, lineHeight: 1.5 }}>{details.handoffSummary}</div>}
                  {details.priorityQuestions.length > 0 && (
                    <div style={{ display: "grid", gap: "6px" }}>
                      {details.priorityQuestions.map((question) => (
                        <div key={question} style={{ fontSize: "12px", color: BUNDLE_COLORS.textSecondary }}>
                          {question}
                        </div>
                      ))}
                    </div>
                  )}
                  {details.observedGaps.length > 0 && (
                    <div style={{ display: "grid", gap: "6px", marginTop: "2px" }}>
                      {details.observedGaps.map((gap) => (
                        <div key={gap} style={{ fontSize: "12px", color: BUNDLE_COLORS.warningFg }}>
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
                  border: `1px solid ${BUNDLE_COLORS.borderSubtle}`,
                  borderRadius: "6px",
                  backgroundColor: BUNDLE_COLORS.cardBg,
                }}
              >
                <div style={{ fontSize: "13px", fontWeight: 700, color: BUNDLE_COLORS.textPrimary }}>Artifact inventory</div>
                <div style={{ marginTop: "10px", display: "flex", gap: "8px", flexWrap: "wrap" }}>
                  {artifactCategoryCounts.length === 0 ? (
                    <div style={{ fontSize: "12px", color: BUNDLE_COLORS.textTertiary }}>No artifact records were found in the manifest.</div>
                  ) : (
                    artifactCategoryCounts.map(([category, count]) => (
                      <div key={category} style={{ padding: "6px 10px", border: `1px solid ${BUNDLE_COLORS.borderSubtle}`, borderRadius: "999px", backgroundColor: BUNDLE_COLORS.cardBg, fontSize: "12px", color: BUNDLE_COLORS.textSecondary }}>
                        {formatCategoryLabel(category)}: {count}
                      </div>
                    ))
                  )}
                </div>
                <div style={{ marginTop: "10px", display: "flex", gap: "8px", flexWrap: "wrap" }}>
                  {intakeStatusCounts.length === 0 ? (
                    <div style={{ fontSize: "12px", color: BUNDLE_COLORS.textTertiary }}>No intake diagnostics are available yet.</div>
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
                  <div style={{ marginTop: "10px", fontSize: "11px", color: BUNDLE_COLORS.textTertiary }}>
                    Recognized intake families: {recognizedFamilies.join(", ")}
                  </div>
                )}
                {noisyParsedArtifacts.length > 0 && (
                  <div style={{ marginTop: "8px", fontSize: "11px", color: BUNDLE_COLORS.warningFg }}>
                    Parser quality watchlist: {noisyParsedArtifacts.length} recognized log artifact{noisyParsedArtifacts.length === 1 ? "" : "s"} reported parse issues.
                  </div>
                )}
              </section>

              <section
                style={{
                  padding: "14px",
                  border: `1px solid ${BUNDLE_COLORS.borderSubtle}`,
                  borderRadius: "6px",
                  backgroundColor: BUNDLE_COLORS.cardBg,
                  display: "grid",
                  gap: "8px",
                }}
              >
                <div style={{ fontSize: "13px", fontWeight: 700, color: BUNDLE_COLORS.textPrimary }}>Artifacts</div>
                {artifacts.length === 0 ? (
                  <div style={{ fontSize: "12px", color: BUNDLE_COLORS.textTertiary }}>No artifact detail was available.</div>
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
                            ? `1px solid ${BUNDLE_COLORS.accentFg}`
                            : canInteract
                              ? `1px solid ${BUNDLE_COLORS.borderInfo}`
                              : `1px solid ${BUNDLE_COLORS.borderSubtle}`,
                          borderRadius: "6px",
                          padding: "10px",
                          display: "grid",
                          gap: "6px",
                          textAlign: "left",
                          backgroundColor: isSelected
                            ? BUNDLE_COLORS.infoBg
                            : canInteract
                              ? BUNDLE_COLORS.subtleBg
                              : BUNDLE_COLORS.cardBg,
                          cursor: canInteract ? "pointer" : "not-allowed",
                          opacity: canInteract ? 1 : 0.78,
                        }}
                      >
                        <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                          <span style={{ padding: "3px 8px", borderRadius: "999px", backgroundColor: tone.backgroundColor, color: tone.color, fontSize: "11px", fontWeight: 700, textTransform: "uppercase" }}>
                            {artifact.status}
                          </span>
                          <span style={{ fontSize: "11px", color: BUNDLE_COLORS.textTertiary, textTransform: "uppercase", letterSpacing: "0.04em" }}>
                            {formatCategoryLabel(artifact.category)}
                          </span>
                          <span style={{ padding: "3px 8px", borderRadius: "999px", backgroundColor: intakeTone.backgroundColor, color: intakeTone.color, fontSize: "11px", fontWeight: 700 }}>
                            {formatIntakeStatusLabel(artifact.intake.status)}
                          </span>
                          {artifact.family && <span style={{ fontSize: "12px", color: BUNDLE_COLORS.textPrimary, fontWeight: 600 }}>{artifact.family}</span>}
                        </div>
                        <div style={{ fontSize: "12px", color: BUNDLE_COLORS.textPrimary, wordBreak: "break-word", fontWeight: 600 }}>
                          {artifact.relativePath}
                        </div>
                        <div style={{ fontSize: "11px", color: BUNDLE_COLORS.textPrimary }}>
                          {artifact.intake.recognizedAs ?? "Unclassified artifact"}
                          {parseQualityLabel ? ` • ${parseQualityLabel}` : ""}
                        </div>
                        <div style={{ fontSize: "11px", color: BUNDLE_COLORS.textTertiary, wordBreak: "break-word" }}>
                          {artifact.intake.summary}
                        </div>
                        {parseDiagnosticsSummary && (
                          <div style={{ fontSize: "11px", color: artifact.intake.parseDiagnostics?.cleanParse ? BUNDLE_COLORS.successFg : BUNDLE_COLORS.warningFg }}>
                            {parseDiagnosticsSummary}
                          </div>
                        )}
                        <div style={{ fontSize: "11px", color: canInteract ? BUNDLE_COLORS.accentFg : BUNDLE_COLORS.textTertiary, fontWeight: canInteract ? 600 : 500 }}>
                          {getArtifactActionLabel(artifact, navigation)}
                        </div>
                        {artifact.intake.parserSelection && (
                          <div style={{ fontSize: "11px", color: BUNDLE_COLORS.textTertiary }}>
                            Parser: {artifact.intake.parserSelection.parser}
                            {artifact.intake.parserSelection.specialization ? ` (${artifact.intake.parserSelection.specialization})` : ""}
                          </div>
                        )}
                        {artifact.originPath && <div style={{ fontSize: "11px", color: BUNDLE_COLORS.textTertiary, wordBreak: "break-word" }}>Origin: {artifact.originPath}</div>}
                        {artifact.notes && <div style={{ fontSize: "11px", color: BUNDLE_COLORS.textTertiary, wordBreak: "break-word" }}>Notes: {artifact.notes}</div>}
                      </button>
                    );
                  })
                )}
              </section>

              {(selectedArtifact || isArtifactPreviewLoading) && (
                <section
                  style={{
                    padding: "14px",
                    border: `1px solid ${BUNDLE_COLORS.borderSubtle}`,
                    borderRadius: "6px",
                    backgroundColor: BUNDLE_COLORS.cardBg,
                    display: "grid",
                    gap: "10px",
                  }}
                >
                  <div style={{ fontSize: "13px", fontWeight: 700, color: BUNDLE_COLORS.textPrimary }}>
                    Adjacent evidence preview
                  </div>
                  {selectedArtifact && (
                    <div style={{ display: "grid", gap: "4px" }}>
                      <div style={{ fontSize: "12px", fontWeight: 600, color: BUNDLE_COLORS.textPrimary, wordBreak: "break-word" }}>
                        {selectedArtifact.relativePath}
                      </div>
                      <div style={{ fontSize: "11px", color: BUNDLE_COLORS.textTertiary, wordBreak: "break-word" }}>
                        {selectedArtifact.originPath ?? selectedArtifact.intake.recognizedAs ?? "Selected artifact"}
                      </div>
                    </div>
                  )}
                  {isArtifactPreviewLoading ? (
                    <div style={{ fontSize: "12px", color: BUNDLE_COLORS.accentFg }}>
                      Inspecting adjacent evidence...
                    </div>
                  ) : artifactPreview?.registrySnapshot ? (
                    <>
                      <div style={{ fontSize: "12px", color: BUNDLE_COLORS.textSecondary, lineHeight: 1.5 }}>
                        {artifactPreview.summary}
                      </div>
                      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))", gap: "10px" }}>
                        <div style={{ padding: "10px", borderRadius: "6px", border: `1px solid ${BUNDLE_COLORS.borderInfo}`, backgroundColor: BUNDLE_COLORS.infoBg }}>
                          <div style={{ fontSize: "11px", fontWeight: 700, color: BUNDLE_COLORS.accentFg, textTransform: "uppercase", letterSpacing: "0.04em" }}>Keys</div>
                          <div style={{ marginTop: "4px", fontSize: "20px", fontWeight: 700, color: BUNDLE_COLORS.textPrimary }}>
                            {artifactPreview.registrySnapshot.keyCount}
                          </div>
                        </div>
                        <div style={{ padding: "10px", borderRadius: "6px", border: `1px solid ${BUNDLE_COLORS.borderInfo}`, backgroundColor: BUNDLE_COLORS.infoBg }}>
                          <div style={{ fontSize: "11px", fontWeight: 700, color: BUNDLE_COLORS.accentFg, textTransform: "uppercase", letterSpacing: "0.04em" }}>Values</div>
                          <div style={{ marginTop: "4px", fontSize: "20px", fontWeight: 700, color: BUNDLE_COLORS.textPrimary }}>
                            {artifactPreview.registrySnapshot.valueCount}
                          </div>
                        </div>
                      </div>
                      <div style={{ display: "grid", gap: "8px" }}>
                        {artifactPreview.registrySnapshot.keys.map((keyPreview) => (
                          <div key={keyPreview.path} style={{ border: `1px solid ${BUNDLE_COLORS.borderSubtle}`, borderRadius: "6px", padding: "10px", backgroundColor: BUNDLE_COLORS.cardBg, display: "grid", gap: "6px" }}>
                            <div style={{ fontSize: "11px", color: BUNDLE_COLORS.textTertiary, textTransform: "uppercase", letterSpacing: "0.04em" }}>
                              {keyPreview.valueCount} value{keyPreview.valueCount === 1 ? "" : "s"}
                            </div>
                            <div style={{ fontSize: "12px", fontWeight: 600, color: BUNDLE_COLORS.textPrimary, wordBreak: "break-word" }}>
                              {keyPreview.path}
                            </div>
                            <div style={{ display: "grid", gap: "4px" }}>
                              {keyPreview.values.map((valuePreview) => (
                                <div key={`${keyPreview.path}:${valuePreview.name}`} style={{ fontSize: "11px", color: BUNDLE_COLORS.textSecondary, lineHeight: 1.45, wordBreak: "break-word" }}>
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
                      <div style={{ fontSize: "12px", color: BUNDLE_COLORS.textSecondary, lineHeight: 1.5 }}>
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
                    <div style={{ fontSize: "12px", color: BUNDLE_COLORS.textTertiary }}>
                      Select a registry snapshot or curated event export to inspect it here.
                    </div>
                  )}
                </section>
              )}

              <section
                style={{
                  padding: "14px",
                  border: `1px solid ${BUNDLE_COLORS.borderSubtle}`,
                  borderRadius: "6px",
                  backgroundColor: BUNDLE_COLORS.cardBg,
                  display: "grid",
                  gap: "8px",
                }}
              >
                <div style={{ fontSize: "13px", fontWeight: 700, color: BUNDLE_COLORS.textPrimary }}>Expected evidence</div>
                {expectedEvidence.length === 0 ? (
                  <div style={{ fontSize: "12px", color: BUNDLE_COLORS.textTertiary }}>No expected-evidence detail was recorded in the manifest.</div>
                ) : (
                  expectedEvidence.map((entry) => (
                    <div key={`${entry.category}:${entry.relativePath}`} style={{ display: "grid", gap: "4px", padding: "9px 10px", border: `1px solid ${BUNDLE_COLORS.borderSubtle}`, borderRadius: "6px", backgroundColor: entry.available ? BUNDLE_COLORS.successBg : entry.required ? BUNDLE_COLORS.errorBg : BUNDLE_COLORS.warningBg }}>
                      <div style={{ fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.04em", color: entry.available ? BUNDLE_COLORS.successFg : entry.required ? BUNDLE_COLORS.errorFg : BUNDLE_COLORS.warningFg, fontWeight: 700 }}>
                        {entry.available ? "Available" : entry.required ? "Required gap" : "Optional gap"}
                      </div>
                      <div style={{ fontSize: "12px", color: BUNDLE_COLORS.textPrimary, fontWeight: 600 }}>{entry.relativePath}</div>
                      {entry.reason && <div style={{ fontSize: "11px", color: BUNDLE_COLORS.textTertiary }}>{entry.reason}</div>}
                    </div>
                  ))
                )}
              </section>
            </>
          )}

          {activeTab === "notes" && (
            <section style={{ padding: "14px", border: `1px solid ${BUNDLE_COLORS.borderSubtle}`, borderRadius: "6px", backgroundColor: BUNDLE_COLORS.cardBg }}>
              <div style={{ fontSize: "13px", fontWeight: 700, color: BUNDLE_COLORS.textPrimary, marginBottom: "10px" }}>Notes preview</div>
              <PreviewPane content={details?.notesContent ?? null} />
            </section>
          )}

          {activeTab === "manifest" && (
            <section style={{ padding: "14px", border: `1px solid ${BUNDLE_COLORS.borderSubtle}`, borderRadius: "6px", backgroundColor: BUNDLE_COLORS.cardBg }}>
              <div style={{ fontSize: "13px", fontWeight: 700, color: BUNDLE_COLORS.textPrimary, marginBottom: "10px" }}>Manifest preview</div>
              <PreviewPane content={details?.manifestContent ?? null} />
            </section>
          )}
        </div>

        <div
          style={{
            padding: "14px 18px",
            borderTop: "1px solid #dbe3ee",
            backgroundColor: BUNDLE_COLORS.cardBg,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            gap: "10px",
          }}
        >
          <div style={{ fontSize: "11px", color: BUNDLE_COLORS.textTertiary }}>
            Notes file: {getBaseName(bundleMetadata.notesPath)}
          </div>
          <button onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}