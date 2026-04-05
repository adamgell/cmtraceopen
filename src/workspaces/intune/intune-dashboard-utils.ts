import { tokens } from "@fluentui/react-components";
import { formatDisplayDateTime } from "../../lib/date-time-format";
import type {
  IntuneDiagnosticCategory,
  IntuneDiagnosticSeverity,
  IntuneDiagnosticsConfidence,
  IntuneDiagnosticsFileCoverage,
  IntuneLogSourceKind,
  IntuneRemediationPriority,
  IntuneSourceFamilySummary,
  IntuneTimestampBounds,
} from "./types";

export function getFileName(path: string): string {
  const normalized = path.replace(/\\/g, "/");
  const segments = normalized.split("/");
  return segments[segments.length - 1] || path;
}

export function buildSourceFamilySummary(
  files: IntuneDiagnosticsFileCoverage[]
): IntuneSourceFamilySummary[] {
  const families = new Map<IntuneLogSourceKind, IntuneSourceFamilySummary>();

  for (const file of files) {
    const kind = getIntuneSourceKind(file.filePath);
    const existing = families.get(kind) ?? {
      kind,
      label: getIntuneSourceKindLabel(kind),
      fileCount: 0,
      contributingFileCount: 0,
      eventCount: 0,
      downloadCount: 0,
    };

    existing.fileCount += 1;
    existing.eventCount += file.eventCount;
    existing.downloadCount += file.downloadCount;
    if (file.eventCount > 0 || file.downloadCount > 0) {
      existing.contributingFileCount += 1;
    }

    families.set(kind, existing);
  }

  return Array.from(families.values()).sort((left, right) => {
    const leftSignals = left.eventCount + left.downloadCount;
    const rightSignals = right.eventCount + right.downloadCount;
    return (
      right.contributingFileCount - left.contributingFileCount ||
      rightSignals - leftSignals ||
      right.fileCount - left.fileCount ||
      left.label.localeCompare(right.label)
    );
  });
}

export function getIntuneSourceKind(filePath: string): IntuneLogSourceKind {
  const fileName = getFileName(filePath).toLowerCase();

  if (fileName.includes("appworkload")) {
    return "appworkload";
  }
  if (fileName.includes("appactionprocessor")) {
    return "appactionprocessor";
  }
  if (fileName.includes("agentexecutor")) {
    return "agentexecutor";
  }
  if (fileName.includes("healthscripts")) {
    return "healthscripts";
  }
  if (fileName.includes("clienthealth")) {
    return "clienthealth";
  }
  if (fileName.includes("clientcertcheck")) {
    return "clientcertcheck";
  }
  if (fileName.includes("devicehealthmonitoring")) {
    return "devicehealthmonitoring";
  }
  if (fileName.includes("sensor")) {
    return "sensor";
  }
  if (fileName.includes("win32appinventory")) {
    return "win32appinventory";
  }
  if (fileName.includes("intunemanagementextension")) {
    return "intunemanagementextension";
  }
  return "other";
}

export function getIntuneSourceKindLabel(kind: IntuneLogSourceKind): string {
  switch (kind) {
    case "appworkload":
      return "AppWorkload";
    case "appactionprocessor":
      return "AppActionProcessor";
    case "agentexecutor":
      return "AgentExecutor";
    case "healthscripts":
      return "HealthScripts";
    case "clienthealth":
      return "ClientHealth";
    case "clientcertcheck":
      return "ClientCertCheck";
    case "devicehealthmonitoring":
      return "DeviceHealthMonitoring";
    case "sensor":
      return "Sensor";
    case "win32appinventory":
      return "Win32AppInventory";
    case "intunemanagementextension":
      return "IME core";
    case "other":
    default:
      return "Other IME";
  }
}

export function getSourceKindTone(kind: IntuneLogSourceKind) {
  switch (kind) {
    case "appworkload":
      return {
        border: tokens.colorPalettePeachBorderActive,
        background: tokens.colorPalettePeachBackground2,
        label: tokens.colorPalettePeachForeground2,
        value: tokens.colorPalettePeachForeground2,
      };
    case "appactionprocessor":
      return {
        border: tokens.colorPaletteBlueBorderActive,
        background: tokens.colorPaletteBlueBackground2,
        label: tokens.colorPaletteBlueForeground2,
        value: tokens.colorPaletteBlueForeground2,
      };
    case "agentexecutor":
    case "healthscripts":
      return {
        border: tokens.colorPaletteGreenBorder2,
        background: tokens.colorPaletteGreenBackground1,
        label: tokens.colorPaletteGreenForeground1,
        value: tokens.colorPaletteGreenForeground1,
      };
    case "clientcertcheck":
    case "devicehealthmonitoring":
      return {
        border: tokens.colorPaletteRedBorder2,
        background: tokens.colorPaletteRedBackground1,
        label: tokens.colorPaletteRedForeground1,
        value: tokens.colorPaletteRedForeground1,
      };
    case "sensor":
    case "win32appinventory":
      return {
        border: tokens.colorPaletteTealBorderActive,
        background: tokens.colorPaletteTealBackground2,
        label: tokens.colorPaletteTealForeground2,
        value: tokens.colorPaletteTealForeground2,
      };
    case "clienthealth":
    case "intunemanagementextension":
    case "other":
    default:
      return {
        border: tokens.colorNeutralStroke2,
        background: tokens.colorNeutralBackground2,
        label: tokens.colorNeutralForeground3,
        value: tokens.colorNeutralForeground2,
      };
  }
}

export function formatTimestampBounds(bounds: IntuneTimestampBounds): string {
  const start = bounds.firstTimestamp ? formatTimestamp(bounds.firstTimestamp) : "Unknown start";
  const end = bounds.lastTimestamp ? formatTimestamp(bounds.lastTimestamp) : "Unknown end";
  return `${start} to ${end}`;
}

function formatTimestamp(value: string): string {
  return formatDisplayDateTime(value) ?? value;
}

export function formatEventShare(value: number): string {
  return `${(value * 100).toFixed(value >= 0.1 ? 0 : 1)}%`;
}

export function getConfidenceTone(level: IntuneDiagnosticsConfidence["level"]) {
  switch (level) {
    case "High":
      return {
        border: tokens.colorPaletteGreenBorder2,
        background: tokens.colorPaletteGreenBackground1,
        labelColor: tokens.colorPaletteGreenForeground1,
        valueColor: tokens.colorPaletteGreenForeground1,
      };
    case "Medium":
      return {
        border: tokens.colorPaletteYellowBorder2,
        background: tokens.colorPaletteYellowBackground1,
        labelColor: tokens.colorPaletteMarigoldForeground2,
        valueColor: tokens.colorPaletteMarigoldForeground2,
      };
    case "Low":
      return {
        border: tokens.colorPaletteRedBorder2,
        background: tokens.colorPaletteRedBackground1,
        labelColor: tokens.colorPaletteRedForeground1,
        valueColor: tokens.colorPaletteRedForeground1,
      };
    case "Unknown":
    default:
      return {
        border: tokens.colorNeutralStroke2,
        background: tokens.colorNeutralBackground2,
        labelColor: tokens.colorNeutralForeground3,
        valueColor: tokens.colorNeutralForeground2,
      };
  }
}

export function getDiagnosticAccent(severity: IntuneDiagnosticSeverity) {
  switch (severity) {
    case "Error":
      return {
        accent: tokens.colorPaletteRedForeground1,
        border: tokens.colorPaletteRedBorder2,
        background: tokens.colorPaletteRedBackground1,
      };
    case "Warning":
      return {
        accent: tokens.colorPaletteMarigoldForeground2,
        border: tokens.colorPaletteYellowBorder2,
        background: tokens.colorPaletteYellowBackground1,
      };
    case "Info":
    default:
      return {
        accent: tokens.colorPaletteBlueForeground2,
        border: tokens.colorPaletteBlueBorderActive,
        background: tokens.colorPaletteBlueBackground2,
      };
  }
}

export function getPriorityTone(priority: IntuneRemediationPriority) {
  switch (priority) {
    case "Immediate":
      return tokens.colorPaletteRedForeground1;
    case "High":
      return tokens.colorPaletteMarigoldForeground2;
    case "Medium":
      return tokens.colorPaletteBlueForeground2;
    case "Monitor":
    default:
      return tokens.colorNeutralForeground3;
  }
}

export function getCategoryTone(category: IntuneDiagnosticCategory) {
  switch (category) {
    case "Download":
      return tokens.colorPalettePeachForeground2;
    case "Install":
      return tokens.colorPalettePurpleForeground2;
    case "Timeout":
      return tokens.colorPaletteMarigoldForeground2;
    case "Script":
      return tokens.colorPaletteTealForeground2;
    case "Policy":
      return tokens.colorBrandForeground1;
    case "State":
      return tokens.colorPaletteTealForeground2;
    case "General":
    default:
      return tokens.colorNeutralForeground3;
  }
}

export function getConclusionTone(tone: "neutral" | "info" | "warning" | "critical") {
  switch (tone) {
    case "critical":
      return {
        accent: tokens.colorPaletteRedForeground1,
        border: tokens.colorPaletteRedBorder2,
        background: tokens.colorPaletteRedBackground1,
        label: tokens.colorPaletteRedForeground1,
      };
    case "warning":
      return {
        accent: tokens.colorPaletteMarigoldForeground2,
        border: tokens.colorPaletteYellowBorder2,
        background: tokens.colorPaletteYellowBackground1,
        label: tokens.colorPaletteMarigoldForeground2,
      };
    case "info":
      return {
        accent: tokens.colorBrandForeground1,
        border: tokens.colorPaletteBlueBorderActive,
        background: tokens.colorPaletteBlueBackground2,
        label: tokens.colorPaletteBlueForeground2,
      };
    case "neutral":
    default:
      return {
        accent: tokens.colorNeutralForeground3,
        border: tokens.colorNeutralStroke2,
        background: tokens.colorNeutralCardBackground,
        label: tokens.colorNeutralForeground3,
      };
  }
}

export function toSentence(value: string): string {
  const normalized = value.trim().replace(/\s+/g, " ");
  if (!normalized) {
    return "No further detail was available.";
  }

  const firstSentence = normalized.match(/^.+?[.!?](?:\s|$)/)?.[0]?.trim() ?? normalized;
  return /[.!?]$/.test(firstSentence) ? firstSentence : `${firstSentence}.`;
}

export function truncateText(value: string, maxLength: number): string {
  if (value.length <= maxLength) {
    return value;
  }

  return `${value.slice(0, Math.max(0, maxLength - 3)).trimEnd()}...`;
}

export function formatSourceFamilyDetail(family: IntuneSourceFamilySummary): string {
  const parts: string[] = [];
  if (family.eventCount > 0) {
    parts.push(`${family.eventCount} event${family.eventCount === 1 ? "" : "s"}`);
  }
  if (family.downloadCount > 0) {
    parts.push(`${family.downloadCount} download${family.downloadCount === 1 ? "" : "s"}`);
  }
  if (parts.length > 0) {
    return parts.join(" • ");
  }

  return `${family.fileCount} file${family.fileCount === 1 ? "" : "s"}`;
}

export function buildDominantSourceLabel(
  dominantSource: NonNullable<import("./types").IntuneDiagnosticsCoverage["dominantSource"]>
): string {
  const share = dominantSource.eventShare != null ? ` (${formatEventShare(dominantSource.eventShare)})` : "";
  return `${getFileName(dominantSource.filePath)}${share}`;
}

export function remediationPriorityRank(priority: IntuneRemediationPriority): number {
  switch (priority) {
    case "Immediate":
      return 4;
    case "High":
      return 3;
    case "Medium":
      return 2;
    case "Monitor":
    default:
      return 1;
  }
}

export const selectStyle: React.CSSProperties = {
  fontSize: "11px",
  padding: "2px 6px",
  borderRadius: "3px",
  border: `1px solid ${tokens.colorNeutralStroke2}`,
  backgroundColor: tokens.colorNeutralCardBackground,
};

export const secondaryToggleButtonStyle: React.CSSProperties = {
  fontSize: "11px",
  padding: "4px 8px",
  borderRadius: "4px",
  border: `1px solid ${tokens.colorNeutralStroke2}`,
  backgroundColor: tokens.colorNeutralCardBackground,
  color: tokens.colorNeutralForeground2,
  cursor: "pointer",
};
