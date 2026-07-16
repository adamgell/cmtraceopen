import { useMemo, useState } from "react";
import { Button, tokens } from "@fluentui/react-components";
import {
  CheckmarkRegular,
  ErrorCircleRegular,
  InfoRegular,
  WarningRegular,
} from "@fluentui/react-icons";
import {
  LOG_MONOSPACE_FONT_FAMILY,
  LOG_UI_FONT_FAMILY,
} from "../../lib/log-accessibility";
import {
  buildEspEvidenceViewModel,
  type EspEvidenceItemViewModel,
  type EspEvidenceSourceState,
} from "./esp-view-model";
import type { EspDiagnosticsSnapshot } from "./types";

interface EvidenceSectionsProps {
  snapshot: EspDiagnosticsSnapshot;
}

function sourceStateLabel(state: EspEvidenceSourceState): string {
  switch (state) {
    case "available":
      return "Available";
    case "notObserved":
      return "No records";
    case "missing":
      return "Missing source";
    case "permissionDenied":
      return "Permission denied";
    case "parseFailed":
      return "Parse failed";
    case "unsupported":
      return "Unsupported source";
  }
}

function sourceStateColor(state: EspEvidenceSourceState): string {
  switch (state) {
    case "available":
      return tokens.colorPaletteGreenForeground1;
    case "permissionDenied":
    case "parseFailed":
      return tokens.colorPaletteRedForeground1;
    case "missing":
      return tokens.colorPaletteYellowForeground2;
    case "unsupported":
    case "notObserved":
      return tokens.colorNeutralForeground3;
  }
}

function SourceStateIcon({ state }: { state: EspEvidenceSourceState }) {
  switch (state) {
    case "available":
      return <CheckmarkRegular aria-hidden="true" />;
    case "permissionDenied":
    case "parseFailed":
      return <ErrorCircleRegular aria-hidden="true" />;
    case "missing":
      return <WarningRegular aria-hidden="true" />;
    case "unsupported":
    case "notObserved":
      return <InfoRegular aria-hidden="true" />;
  }
}

function EvidenceReferences({ item }: { item: EspEvidenceItemViewModel }) {
  if (item.evidence.length === 0) return null;
  return (
    <div
      aria-label="Evidence references"
      style={{
        display: "flex",
        flexWrap: "wrap",
        gap: 5,
        marginTop: 7,
      }}
    >
      {item.evidence.map((reference) => (
        <span
          key={`${reference.sourceArtifactId}:${reference.evidenceId}`}
          id={`evidence-${reference.evidenceId}`}
          title={`${reference.sourceArtifactId} · ${reference.evidenceId}`}
          style={{
            padding: "1px 5px",
            border: `1px solid ${tokens.colorNeutralStroke2}`,
            backgroundColor: tokens.colorNeutralBackground3,
            color: tokens.colorNeutralForeground2,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: 9,
            lineHeight: "13px",
          }}
        >
          {reference.sourceArtifactId} · {reference.evidenceId}
        </span>
      ))}
    </div>
  );
}

function EvidenceItem({ item }: { item: EspEvidenceItemViewModel }) {
  return (
    <article
      id={item.id.startsWith("coverage-") ? item.id : undefined}
      style={{
        minWidth: 0,
        padding: "9px 10px",
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        borderLeft: `3px solid ${tokens.colorNeutralStrokeAccessible}`,
        backgroundColor: tokens.colorNeutralBackground1,
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
            minWidth: 0,
            overflow: "hidden",
            fontFamily: LOG_UI_FONT_FAMILY,
            fontSize: 12,
            lineHeight: "16px",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
          title={item.title}
        >
          {item.title}
        </strong>
        {item.rawId ? (
          <code
            style={{
              flex: "0 1 auto",
              minWidth: 0,
              overflow: "hidden",
              color: tokens.colorNeutralForeground2,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              fontSize: 9,
              lineHeight: "13px",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
            title={item.rawId}
          >
            Raw ID · {item.rawId}
          </code>
        ) : null}
      </div>
      {item.graphName ? (
        <div
          style={{
            marginTop: 2,
            color: tokens.colorBrandForeground1,
            fontSize: 10,
            fontWeight: 650,
            lineHeight: "14px",
          }}
        >
          Microsoft Graph · {item.graphName}
        </div>
      ) : null}
      <dl
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
          gap: "5px 12px",
          margin: "8px 0 0",
        }}
      >
        {item.fields.map((field, index) => (
          <div key={`${field.label}:${index}`} style={{ minWidth: 0 }}>
            <dt
              style={{
                color: tokens.colorNeutralForeground3,
                fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                fontSize: 8,
                fontWeight: 700,
                letterSpacing: "0.06em",
                lineHeight: "11px",
                textTransform: "uppercase",
              }}
            >
              {field.label}
            </dt>
            <dd
              style={{
                margin: 0,
                overflowWrap: "anywhere",
                color:
                  field.sensitivity === "restricted"
                    ? tokens.colorPaletteRedForeground1
                    : field.sensitivity === "sensitive"
                      ? tokens.colorPaletteYellowForeground2
                      : tokens.colorNeutralForeground1,
                fontFamily:
                  field.sensitivity === "public"
                    ? LOG_UI_FONT_FAMILY
                    : LOG_MONOSPACE_FONT_FAMILY,
                fontSize: 10,
                fontWeight: field.sensitivity === "public" ? 500 : 650,
                lineHeight: "14px",
              }}
            >
              {field.value}
            </dd>
          </div>
        ))}
      </dl>
      <EvidenceReferences item={item} />
    </article>
  );
}

export function EvidenceSections({ snapshot }: EvidenceSectionsProps) {
  const [revealSensitive, setRevealSensitive] = useState(false);
  const viewModel = useMemo(
    () => buildEspEvidenceViewModel(snapshot, { revealSensitive }),
    [revealSensitive, snapshot],
  );

  return (
    <section
      role="region"
      aria-labelledby="esp-evidence-heading"
      style={{
        minWidth: 0,
        border: `1px solid ${tokens.colorNeutralStroke1}`,
        backgroundColor: tokens.colorNeutralBackground1,
        boxShadow: tokens.shadow2,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 14,
          padding: "9px 10px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
          backgroundColor: tokens.colorNeutralBackground2,
        }}
      >
        <div style={{ minWidth: 0 }}>
          <div
            style={{
              color: tokens.colorBrandForeground1,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              fontSize: 8,
              fontWeight: 700,
              letterSpacing: "0.12em",
              lineHeight: "11px",
              textTransform: "uppercase",
            }}
          >
            Collapsible source detail · read-only
          </div>
          <h2
            id="esp-evidence-heading"
            style={{
              margin: "1px 0 0",
              fontFamily: LOG_UI_FONT_FAMILY,
              fontSize: 13,
              fontWeight: 650,
              lineHeight: "17px",
            }}
          >
            ESP evidence
          </h2>
          <p
            style={{
              margin: "2px 0 0",
              color: tokens.colorNeutralForeground2,
              fontSize: 10,
              lineHeight: "14px",
            }}
          >
            {viewModel.disclosurePolicy}
          </p>
        </div>
        <Button
          appearance={revealSensitive ? "primary" : "secondary"}
          size="small"
          aria-pressed={revealSensitive}
          onClick={() => setRevealSensitive((current) => !current)}
        >
          {revealSensitive ? "Mask sensitive values" : "Reveal sensitive values"}
        </Button>
      </div>

      <div style={{ display: "grid", gap: 1, backgroundColor: tokens.colorNeutralStroke2 }}>
        {viewModel.sections.map((section) => (
          <details
            key={section.id}
            data-source-state={section.sourceState}
            style={{ backgroundColor: tokens.colorNeutralBackground1 }}
          >
            <summary
              style={{
                display: "grid",
                gridTemplateColumns: "minmax(170px, 0.7fr) minmax(240px, 1.3fr) auto",
                alignItems: "center",
                gap: 12,
                minHeight: 36,
                padding: "4px 10px",
                cursor: "pointer",
                fontFamily: LOG_UI_FONT_FAMILY,
              }}
            >
              <span style={{ fontSize: 11, fontWeight: 650 }}>{section.title}</span>
              <span
                style={{
                  color: tokens.colorNeutralForeground2,
                  fontSize: 10,
                  lineHeight: "14px",
                }}
              >
                {section.description}
              </span>
              <span
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "flex-end",
                  gap: 4,
                  color: sourceStateColor(section.sourceState),
                  fontSize: 9,
                  fontWeight: 700,
                  lineHeight: "13px",
                  textTransform: "uppercase",
                  whiteSpace: "nowrap",
                }}
              >
                <SourceStateIcon state={section.sourceState} />
                {sourceStateLabel(section.sourceState)} · {section.items.length}
              </span>
            </summary>
            <div
              style={{
                display: "grid",
                gap: 7,
                padding: "8px 10px 10px",
                borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
                backgroundColor: tokens.colorNeutralBackground2,
              }}
            >
              <div
                role="status"
                style={{
                  color: sourceStateColor(section.sourceState),
                  fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                  fontSize: 9,
                  fontWeight: 650,
                  lineHeight: "13px",
                }}
              >
                {sourceStateLabel(section.sourceState)} · {section.sourceNote}
              </div>
              {section.items.map((evidenceItem) => (
                <EvidenceItem key={evidenceItem.id} item={evidenceItem} />
              ))}
            </div>
          </details>
        ))}
      </div>
    </section>
  );
}
