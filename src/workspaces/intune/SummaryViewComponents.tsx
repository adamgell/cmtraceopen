import { tokens } from "@fluentui/react-components";
import type {
  IntuneDiagnosticInsight,
  IntuneDiagnosticsConfidence,
  IntuneDiagnosticsFileCoverage,
  IntuneLogSourceKind,
  IntuneRepeatedFailureGroup,
  IntuneSourceFamilySummary,
} from "./types";
import {
  formatSourceFamilyDetail,
  formatTimestampBounds,
  getCategoryTone,
  getConfidenceTone,
  getConclusionTone,
  getDiagnosticAccent,
  getFileName,
  getIntuneSourceKind,
  getIntuneSourceKindLabel,
  getPriorityTone,
  getSourceKindTone,
} from "./intune-dashboard-utils";
import { formatEventTypeLabel } from "./useTimeWindowFilter";
import type { SummaryConclusion } from "./summary-view-logic";

export function DiagnosticMetaBadge({ label, tone }: { label: string; tone: string }) {
  return (
    <span
      style={{
        fontSize: "10px",
        textTransform: "uppercase",
        letterSpacing: "0.06em",
        color: tone,
        border: `1px solid color-mix(in srgb, ${tone} 20%, transparent)`,
        backgroundColor: `color-mix(in srgb, ${tone} 7%, transparent)`,
        fontWeight: 700,
        borderRadius: "999px",
        padding: "3px 8px",
      }}
    >
      {label}
    </span>
  );
}

export function DiagnosticChipRow({
  label,
  items,
  itemTone,
  background,
  border,
}: {
  label: string;
  items: string[];
  itemTone: string;
  background: string;
  border: string;
}) {
  return (
    <div>
      <div style={{ fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.05em", color: tokens.colorNeutralForeground3, marginBottom: "4px" }}>
        {label}
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
        {items.map((item) => (
          <span
            key={`${label}-${item}`}
            style={{
              fontSize: "10px",
              borderRadius: "999px",
              padding: "3px 8px",
              color: itemTone,
              backgroundColor: background,
              border: `1px solid ${border}`,
              fontWeight: 600,
            }}
            title={item}
          >
            {item}
          </span>
        ))}
      </div>
    </div>
  );
}

export function ConclusionButton({
  conclusion,
  onClick,
}: {
  conclusion: SummaryConclusion;
  onClick: () => void;
}) {
  const tone = getConclusionTone(conclusion.tone);

  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        width: "100%",
        display: "grid",
        gridTemplateColumns: "auto minmax(0, 1fr) auto",
        gap: "10px",
        alignItems: "center",
        textAlign: "left",
        padding: "8px 10px",
        borderRadius: "6px",
        border: `1px solid ${tone.border}`,
        backgroundColor: tone.background,
        cursor: "pointer",
      }}
    >
      <span
        style={{
          width: "8px",
          height: "8px",
          borderRadius: "999px",
          backgroundColor: tone.accent,
          flexShrink: 0,
        }}
      />
      <span style={{ fontSize: "12px", color: tokens.colorNeutralForeground1, lineHeight: 1.35 }}>{conclusion.text}</span>
      <span
        style={{
          fontSize: "10px",
          fontWeight: 700,
          textTransform: "uppercase",
          letterSpacing: "0.05em",
          color: tone.label,
          whiteSpace: "nowrap",
        }}
      >
        {conclusion.hint}
      </span>
    </button>
  );
}

export function SectionCard({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children: React.ReactNode;
}) {
  return (
    <div
      style={{
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        borderRadius: "8px",
        backgroundColor: tokens.colorNeutralCardBackground,
        padding: "12px 14px",
      }}
    >
      <div style={{ marginBottom: "10px" }}>
        <div style={{ fontSize: "13px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}>{title}</div>
        <div style={{ fontSize: "11px", color: tokens.colorNeutralForeground3, marginTop: "2px" }}>{subtitle}</div>
      </div>
      {children}
    </div>
  );
}

export function CompactFact({
  label,
  value,
  color,
}: {
  label: string;
  value: string;
  color?: string;
}) {
  return (
    <div
      style={{
        display: "inline-flex",
        alignItems: "baseline",
        gap: "6px",
        padding: "5px 8px",
        borderRadius: "999px",
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        backgroundColor: tokens.colorNeutralBackground2,
      }}
    >
      <span style={{ fontSize: "10px", fontWeight: 700, color: tokens.colorNeutralForeground3, textTransform: "uppercase" }}>
        {label}
      </span>
      <span style={{ fontSize: "12px", fontWeight: 700, color: color ?? tokens.colorNeutralForeground1 }}>{value}</span>
    </div>
  );
}

export function SourceFamilyBadge({ family }: { family: IntuneSourceFamilySummary }) {
  const tone = getSourceKindTone(family.kind);

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "6px",
        padding: "4px 8px",
        borderRadius: "999px",
        border: `1px solid ${tone.border}`,
        backgroundColor: tone.background,
        color: tone.label,
        fontSize: "10px",
        fontWeight: 700,
      }}
    >
      <span>{family.label}</span>
      <span style={{ color: tone.value }}>{formatSourceFamilyDetail(family)}</span>
    </span>
  );
}

function SourceKindBadge({ kind }: { kind: IntuneLogSourceKind }) {
  const tone = getSourceKindTone(kind);

  return (
    <span
      style={{
        fontSize: "10px",
        padding: "2px 6px",
        borderRadius: "999px",
        border: `1px solid ${tone.border}`,
        backgroundColor: tone.background,
        color: tone.label,
        fontWeight: 700,
      }}
    >
      {getIntuneSourceKindLabel(kind)}
    </span>
  );
}

export function CoverageRow({ file }: { file: IntuneDiagnosticsFileCoverage }) {
  const hasActivity = file.eventCount > 0 || file.downloadCount > 0;
  const sourceKind = getIntuneSourceKind(file.filePath);

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "minmax(0, 1fr) auto",
        gap: "8px",
        alignItems: "center",
        padding: "8px 10px",
        borderRadius: "6px",
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        backgroundColor: hasActivity ? tokens.colorNeutralCardBackground : tokens.colorNeutralBackground2,
      }}
    >
      <div style={{ minWidth: 0 }}>
        <div
          title={file.filePath}
          style={{
            fontSize: "12px",
            fontWeight: 600,
            color: tokens.colorNeutralForeground1,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {getFileName(file.filePath)}
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginTop: "4px" }}>
          <SourceKindBadge kind={sourceKind} />
          <RowStat label="Events" value={file.eventCount} color={tokens.colorBrandForeground1} />
          <RowStat label="Downloads" value={file.downloadCount} color={tokens.colorPalettePeachForeground2} />
          {file.rotationGroup && (
            <span
              style={{
                fontSize: "10px",
                padding: "2px 6px",
                borderRadius: "999px",
                backgroundColor: file.isRotatedSegment ? tokens.colorPaletteYellowBackground1 : tokens.colorPaletteBlueBackground2,
                color: file.isRotatedSegment ? tokens.colorPaletteMarigoldForeground2 : tokens.colorPaletteTealForeground2,
                fontWeight: 700,
              }}
            >
              {file.isRotatedSegment ? "Rotated segment" : "Rotation base"}
            </span>
          )}
        </div>
      </div>
      <div style={{ textAlign: "right", fontSize: "11px", color: tokens.colorNeutralForeground3 }}>
        {file.timestampBounds ? formatTimestampBounds(file.timestampBounds) : "No timestamps"}
      </div>
    </div>
  );
}

function RowStat({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: string;
}) {
  return (
    <span
      style={{
        fontSize: "10px",
        padding: "2px 6px",
        borderRadius: "999px",
        backgroundColor: tokens.colorPaletteBlueBackground2,
        color,
        fontWeight: 700,
      }}
    >
      {label} {value}
    </span>
  );
}

export function ConfidenceBadge({ confidence }: { confidence: IntuneDiagnosticsConfidence }) {
  const tone = getConfidenceTone(confidence.level);
  return (
    <div
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "8px",
        padding: "6px 10px",
        borderRadius: "999px",
        border: `1px solid ${tone.border}`,
        backgroundColor: tone.background,
      }}
    >
      <span style={{ fontSize: "10px", fontWeight: 700, color: tone.labelColor, textTransform: "uppercase" }}>
        Confidence
      </span>
      <span style={{ fontSize: "12px", fontWeight: 700, color: tone.valueColor }}>{confidence.level}</span>
    </div>
  );
}

export function RepeatedFailureRow({ group }: { group: IntuneRepeatedFailureGroup }) {
  return (
    <div
      style={{
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        borderRadius: "6px",
        padding: "10px 12px",
        backgroundColor: tokens.colorNeutralCardBackground,
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          gap: "12px",
          alignItems: "baseline",
          flexWrap: "wrap",
        }}
      >
        <div style={{ fontSize: "12px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}>
          {buildRepeatedFailureConclusion(group)}
        </div>
        <span style={{ fontSize: "11px", color: tokens.colorPaletteRedForeground1, fontWeight: 700 }}>
          {group.occurrences} occurrence{group.occurrences === 1 ? "" : "s"}
        </span>
      </div>

      <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground2, marginTop: "4px" }}>{group.name}</div>

      <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginTop: "6px", fontSize: "11px", color: tokens.colorNeutralForeground3 }}>
        <span>{formatEventTypeLabel(group.eventType)}</span>
        <span>{group.sourceFiles.length} file(s)</span>
        {group.errorCode && <span>Error {group.errorCode}</span>}
        {group.timestampBounds && <span>{formatTimestampBounds(group.timestampBounds)}</span>}
      </div>
    </div>
  );
}

function buildRepeatedFailureConclusion(group: IntuneRepeatedFailureGroup): string {
  const subject =
    group.eventType === "Win32App" || group.eventType === "WinGetApp"
      ? "Repeated app failures for the same reason"
      : group.eventType === "PowerShellScript" || group.eventType === "Remediation"
        ? "Repeated script failures for the same reason"
        : "Repeated failures for the same reason";

  return subject;
}

export function EmptyStateText({ label }: { label: string }) {
  return <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3 }}>{label}</div>;
}

export function DiagnosticCard({
  diagnostic,
}: {
  diagnostic: IntuneDiagnosticInsight;
}) {
  const accent = getDiagnosticAccent(diagnostic.severity);
  const priorityTone = getPriorityTone(diagnostic.remediationPriority);
  const categoryTone = getCategoryTone(diagnostic.category);

  return (
    <div
      style={{
        border: `1px solid ${accent.border}`,
        borderLeft: `4px solid ${accent.accent}`,
        borderRadius: "6px",
        backgroundColor: accent.background,
        padding: "12px 14px",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "12px",
          marginBottom: "6px",
        }}
      >
        <div style={{ fontSize: "13px", fontWeight: 600, color: tokens.colorNeutralForeground1 }}>
          {diagnostic.title}
        </div>
        <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", justifyContent: "flex-end" }}>
          <DiagnosticMetaBadge label={diagnostic.severity} tone={accent.accent} />
          <DiagnosticMetaBadge label={diagnostic.category} tone={categoryTone} />
          <DiagnosticMetaBadge label={diagnostic.remediationPriority} tone={priorityTone} />
        </div>
      </div>

      <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground2, marginBottom: "10px" }}>
        {diagnostic.summary}
      </div>

      {diagnostic.likelyCause && (
        <div
          style={{
            marginBottom: "10px",
            padding: "8px 10px",
            borderRadius: "6px",
            backgroundColor: "rgba(255,255,255,0.55)",
            border: `1px solid ${accent.border}`,
          }}
        >
          <div style={{ fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.05em", color: tokens.colorNeutralForeground3, marginBottom: "4px" }}>
            Likely Cause
          </div>
          <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground1, lineHeight: 1.45 }}>{diagnostic.likelyCause}</div>
        </div>
      )}

      {(diagnostic.focusAreas.length > 0 || diagnostic.affectedSourceFiles.length > 0 || diagnostic.relatedErrorCodes.length > 0) && (
        <div style={{ display: "grid", gap: "8px", marginBottom: "10px" }}>
          {diagnostic.focusAreas.length > 0 && (
            <DiagnosticChipRow
              label="Focus Areas"
              items={diagnostic.focusAreas}
              itemTone={tokens.colorPaletteTealForeground2}
              background={tokens.colorPaletteTealBackground2}
              border={tokens.colorPaletteTealBorderActive}
            />
          )}
          {diagnostic.affectedSourceFiles.length > 0 && (
            <DiagnosticChipRow
              label="Affected Sources"
              items={diagnostic.affectedSourceFiles.map((file) => getFileName(file))}
              itemTone={tokens.colorPaletteBlueForeground2}
              background={tokens.colorPaletteBlueBackground2}
              border={tokens.colorPaletteBlueBorderActive}
            />
          )}
          {diagnostic.relatedErrorCodes.length > 0 && (
            <DiagnosticChipRow
              label="Error Codes"
              items={diagnostic.relatedErrorCodes}
              itemTone={tokens.colorPaletteMarigoldForeground2}
              background={tokens.colorPaletteYellowBackground1}
              border={tokens.colorPaletteYellowBorder2}
            />
          )}
        </div>
      )}

      <div style={{ display: "grid", gap: "8px" }}>
        <div>
          <div
            style={{
              fontSize: "11px",
              textTransform: "uppercase",
              letterSpacing: "0.05em",
              color: tokens.colorNeutralForeground3,
              marginBottom: "4px",
            }}
          >
            Evidence
          </div>
          <ul style={{ margin: 0, paddingLeft: "18px", color: tokens.colorNeutralForeground1 }}>
            {diagnostic.evidence.map((item) => (
              <li key={item} style={{ marginBottom: "2px" }}>
                {item}
              </li>
            ))}
          </ul>
        </div>

        <div>
          <div
            style={{
              fontSize: "11px",
              textTransform: "uppercase",
              letterSpacing: "0.05em",
              color: tokens.colorNeutralForeground3,
              marginBottom: "4px",
            }}
          >
            Next Checks
          </div>
          <ul style={{ margin: 0, paddingLeft: "18px", color: tokens.colorNeutralForeground1 }}>
            {diagnostic.nextChecks.map((item) => (
              <li key={item} style={{ marginBottom: "2px" }}>
                {item}
              </li>
            ))}
          </ul>
        </div>

        {diagnostic.suggestedFixes.length > 0 && (
          <div>
            <div
              style={{
                fontSize: "11px",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
                color: tokens.colorNeutralForeground3,
                marginBottom: "4px",
              }}
            >
              Suggested Fixes
            </div>
            <ul style={{ margin: 0, paddingLeft: "18px", color: tokens.colorNeutralForeground1 }}>
              {diagnostic.suggestedFixes.map((item) => (
                <li key={item} style={{ marginBottom: "2px" }}>
                  {item}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}

export function SummaryCard({
  title,
  value,
  color,
}: {
  title: string;
  value: number;
  color?: string;
}) {
  return (
    <div
      style={{
        padding: "10px 11px",
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        borderRadius: "6px",
        borderLeft: `3px solid ${color || tokens.colorNeutralStroke1}`,
        backgroundColor: tokens.colorNeutralCardBackground,
      }}
    >
      <div
        style={{
          fontSize: "11px",
          color: tokens.colorNeutralForeground3,
          textTransform: "uppercase",
          letterSpacing: "0.05em",
        }}
      >
        {title}
      </div>
      <div
        style={{
          fontSize: "20px",
          fontWeight: "bold",
          color: color || tokens.colorNeutralForeground1,
          marginTop: "4px",
        }}
      >
        {value}
      </div>
    </div>
  );
}
