import { tokens } from "@fluentui/react-components";
import { LinkRegular, PulseRegular } from "@fluentui/react-icons";
import {
  LOG_MONOSPACE_FONT_FAMILY,
  LOG_UI_FONT_FAMILY,
} from "../../lib/log-accessibility";
import { requestEspEvidenceNavigation } from "./evidence-navigation";
import type {
  EspDiagnosticsSnapshot,
  EspEvidenceRef,
  EspInstallerCorrelation,
  EspProcessObservation,
} from "./types";

function redactCommandLine(commandLine: string | null): string | null {
  if (!commandLine) return null;
  return commandLine
    .replace(
      /\b(password|passwd|pwd|token|secret|api[_-]?key|authorization)\s*=\s*(?:"[^"]*"|'[^']*'|[^\s]+)/gi,
      (_match, key: string) => `${key}=[REDACTED]`,
    )
    .replace(/\bbearer\s+[^\s]+/gi, "Bearer [REDACTED]");
}

function correlationLabel(correlation: EspInstallerCorrelation): string {
  switch (correlation.confidence) {
    case "exact":
      return "Exact match";
    case "strong":
      return "Strong process match";
    case "temporal":
      return "Temporal match";
    case "uncorrelated":
      return correlation.candidateWorkloadIds.length > 1
        ? `Ambiguous — ${correlation.candidateWorkloadIds.length} candidates`
        : "Uncorrelated";
  }
}

function uniqueEvidence(
  correlation: EspInstallerCorrelation,
  process: EspProcessObservation,
): EspEvidenceRef[] {
  const all = [...correlation.evidence, process.context.evidenceRef];
  return all.filter(
    (evidence, index) =>
      all.findIndex(
        (candidate) => candidate.evidenceId === evidence.evidenceId,
      ) === index,
  );
}

interface InstallerRowProps {
  correlation: EspInstallerCorrelation;
  process: EspProcessObservation;
  snapshot: EspDiagnosticsSnapshot;
  sequence: number;
}

function InstallerRow({
  correlation,
  process,
  snapshot,
  sequence,
}: InstallerRowProps) {
  const workload = correlation.workloadId
    ? snapshot.workloads.find(
        (candidate) => candidate.workloadId === correlation.workloadId,
      )
    : null;
  const commandLine = redactCommandLine(process.sanitizedCommandLine);
  const displayName = workload?.displayName ?? "Unknown installer workload";
  const rawIdentifier = workload?.rawIdentifier ?? process.appId;
  const evidence = uniqueEvidence(correlation, process);

  return (
    <article
      className="esp-msi-row"
      data-testid="esp-installer-row"
      style={{
        display: "grid",
        gap: 0,
        borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
        backgroundColor: tokens.colorNeutralBackground1,
      }}
    >
      <div
        className="esp-msi-cell"
        style={{
          padding: "9px 11px",
          borderRight: `1px solid ${tokens.colorNeutralStroke2}`,
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            color: tokens.colorNeutralForeground3,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: 10,
            fontWeight: 700,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
          }}
        >
          <PulseRegular aria-hidden="true" /> Process {sequence}
        </div>
        <div
          style={{
            marginTop: 5,
            fontFamily: LOG_UI_FONT_FAMILY,
            fontSize: 12,
            fontWeight: 650,
          }}
        >
          {process.executableName} · PID {process.pid}
        </div>
        <div
          style={{
            marginTop: 3,
            color: tokens.colorNeutralForeground2,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: 10,
          }}
        >
          {process.parentPid === null
            ? "Parent unknown"
            : `Parent PID ${process.parentPid}`}
        </div>
        <div
          style={{
            marginTop: 2,
            color: tokens.colorNeutralForeground3,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: 10,
          }}
        >
          Started {process.processStartTime.rawText}
        </div>
      </div>

      <div
        className="esp-msi-cell"
        style={{
          minWidth: 0,
          padding: "9px 11px",
          borderRight: `1px solid ${tokens.colorNeutralStroke2}`,
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "baseline",
            justifyContent: "space-between",
            gap: 10,
          }}
        >
          <strong
            style={{
              overflow: "hidden",
              fontFamily: LOG_UI_FONT_FAMILY,
              fontSize: 12,
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {displayName}
          </strong>
          <span
            style={{
              flexShrink: 0,
              padding: "1px 5px",
              border: `1px solid ${
                correlation.confidence === "uncorrelated"
                  ? tokens.colorPaletteRedBorder2
                  : correlation.confidence === "temporal"
                    ? tokens.colorPaletteYellowBorder2
                    : tokens.colorPaletteGreenBorder2
              }`,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              fontSize: 10,
              fontWeight: 700,
              lineHeight: "14px",
            }}
          >
            {correlationLabel(correlation)}
          </span>
        </div>
        {rawIdentifier ? (
          <div
            style={{
              marginTop: 2,
              overflowWrap: "anywhere",
              color: tokens.colorNeutralForeground3,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              fontSize: 10,
            }}
          >
            Raw app ID · {rawIdentifier}
          </div>
        ) : null}
        {process.productCode ? (
          <div
            style={{
              marginTop: 2,
              overflowWrap: "anywhere",
              color: tokens.colorNeutralForeground3,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              fontSize: 10,
            }}
          >
            Product code · {process.productCode}
          </div>
        ) : null}
        <div
          style={{
            marginTop: 5,
            color: tokens.colorNeutralForeground2,
            fontSize: 10,
            lineHeight: "14px",
          }}
        >
          {correlation.reason}
        </div>
        <code
          title={commandLine ?? undefined}
          style={{
            display: "block",
            marginTop: 5,
            overflow: "hidden",
            color: tokens.colorNeutralForeground2,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: 10,
            lineHeight: "14px",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {commandLine ?? "Command line unavailable"}
        </code>
      </div>

      <div
        className="esp-msi-cell"
        style={{ minWidth: 0, padding: "9px 11px" }}
      >
        <div
          style={{
            color: tokens.colorNeutralForeground3,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: 10,
            fontWeight: 700,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
          }}
        >
          Active MSI log
        </div>
        <div
          className="esp-msi-log-path"
          title={process.referencedLogPath ?? undefined}
          style={{
            marginTop: 4,
            overflow: "hidden",
            color: process.referencedLogPath
              ? tokens.colorNeutralForeground1
              : tokens.colorNeutralForeground3,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: 10,
            lineHeight: "14px",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {process.referencedLogPath ?? "No active MSI log referenced"}
        </div>
        <div
          style={{ display: "flex", flexWrap: "wrap", gap: 7, marginTop: 6 }}
        >
          {evidence.map((reference) => (
            <a
              key={reference.evidenceId}
              href={`#evidence-${reference.evidenceId}`}
              onClick={() =>
                requestEspEvidenceNavigation({
                  kind: "evidence",
                  id: reference.evidenceId,
                })
              }
              aria-label={`Open evidence ${reference.evidenceId}`}
              title={`${reference.sourceArtifactId} · ${reference.evidenceId}`}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 3,
                color: tokens.colorBrandForegroundLink,
                fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                fontSize: 10,
                fontWeight: 650,
                textDecoration: "none",
              }}
            >
              <LinkRegular aria-hidden="true" /> {reference.sourceArtifactId}
            </a>
          ))}
        </div>
      </div>
    </article>
  );
}

interface MsiexecStatusProps {
  snapshot: EspDiagnosticsSnapshot;
}

export function MsiexecStatus({ snapshot }: MsiexecStatusProps) {
  const observed = snapshot.installerCorrelations.flatMap((correlation) =>
    correlation.processObservations.map((process) => ({
      correlation,
      process,
    })),
  );

  return (
    <section
      role="region"
      aria-labelledby="msiexec-status-heading"
      className="esp-msi-status"
      style={{
        border: `1px solid ${tokens.colorNeutralStroke1}`,
        backgroundColor: tokens.colorNeutralBackground1,
        boxShadow: tokens.shadow2,
      }}
    >
      <div
        style={{
          minHeight: 36,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
          padding: "0 11px",
          borderLeft: `3px solid ${
            observed.length > 0
              ? tokens.colorBrandStroke1
              : tokens.colorNeutralStrokeAccessible
          }`,
          backgroundColor: tokens.colorNeutralBackground3,
        }}
      >
        <div>
          <div
            style={{
              color: tokens.colorNeutralForeground3,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              fontSize: 10,
              fontWeight: 700,
              letterSpacing: "0.09em",
              lineHeight: "11px",
              textTransform: "uppercase",
            }}
          >
            Installer process sampler
          </div>
          <h2
            id="msiexec-status-heading"
            style={{
              margin: 0,
              fontFamily: LOG_UI_FONT_FAMILY,
              fontSize: 13,
              fontWeight: 650,
              lineHeight: "17px",
            }}
          >
            What MSIEXEC is doing now
          </h2>
        </div>
        <strong style={{ fontFamily: LOG_MONOSPACE_FONT_FAMILY, fontSize: 10 }}>
          {observed.length} active{" "}
          {observed.length === 1 ? "process" : "processes"}
        </strong>
      </div>

      {observed.length === 0 ? (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            minHeight: 52,
            padding: "0 12px",
            color: tokens.colorNeutralForeground2,
            fontFamily: LOG_UI_FONT_FAMILY,
            fontSize: 12,
          }}
        >
          <PulseRegular aria-hidden="true" />
          <strong>No active MSI installer process observed</strong>
          <span style={{ color: tokens.colorNeutralForeground3 }}>
            The status reflects the latest process sample; it is not proof that
            installation has completed.
          </span>
        </div>
      ) : (
        observed.map(({ correlation, process }, index) => (
          <InstallerRow
            key={`${correlation.correlationId}:${process.pid}:${process.processStartTime.rawText}`}
            correlation={correlation}
            process={process}
            snapshot={snapshot}
            sequence={index + 1}
          />
        ))
      )}
    </section>
  );
}
