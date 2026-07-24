import { useEffect, useMemo, useState } from "react";
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
  getLogListMetrics,
} from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import {
  buildEspEvidenceViewModel,
  type EspEvidenceItemViewModel,
  type EspEvidenceSectionViewModel,
  type EspEvidenceSourceState,
} from "./esp-view-model";
import {
  ESP_EVIDENCE_NAVIGATION_EVENT,
  type EspEvidenceNavigationTarget,
} from "./evidence-navigation";
import type { EspDiagnosticsSnapshot } from "./types";

interface EvidenceSectionsProps {
  snapshot: EspDiagnosticsSnapshot;
}

export const ESP_EVIDENCE_ITEM_WINDOW_SIZE = 80;

interface CanonicalEvidenceTarget {
  sectionId: string;
  itemId: string;
}

type CanonicalEvidenceTargets = Map<string, CanonicalEvidenceTarget>;

interface EvidenceFontMetrics {
  /** Dense value/label text — one tier below the standard log row (10px at the default). */
  body: number;
  /** Slightly emphasized text such as section titles (11px at the default). */
  strong: number;
  /** Evidence item titles (12px at the default). */
  title: number;
  /** Section headings, matched to the standard log row size (13px at the default). */
  heading: number;
}

/**
 * Derives the evidence surface's font tiers from the shared accessibility
 * font-size control so every dense row tracks `logListFontSize` while keeping
 * its compact CMTrace layout. Unitless line heights at the call sites let the
 * vertical rhythm scale with the font without clipping at larger sizes.
 */
function getEvidenceFontMetrics(logListFontSize: number): EvidenceFontMetrics {
  const { fontSize } = getLogListMetrics(logListFontSize);
  return {
    body: Math.max(9, fontSize - 3),
    strong: Math.max(10, fontSize - 2),
    title: Math.max(11, fontSize - 1),
    heading: fontSize,
  };
}

function useEvidenceFontMetrics(): EvidenceFontMetrics {
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  return useMemo(() => getEvidenceFontMetrics(logListFontSize), [logListFontSize]);
}

function sourceStateLabel(state: EspEvidenceSourceState): string {
  switch (state) {
    case "available":
      return "Available";
    case "partial":
      return "Partial coverage";
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
    case "partial":
      return tokens.colorPaletteYellowForeground2;
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
    case "partial":
      return <WarningRegular aria-hidden="true" />;
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

function EvidenceReferences({
  item,
  sectionId,
  canonicalTargets,
  fontSize,
}: {
  item: EspEvidenceItemViewModel;
  sectionId: string;
  canonicalTargets: CanonicalEvidenceTargets;
  fontSize: number;
}) {
  if (item.evidence.length === 0) return null;
  const references = item.evidence.filter(
    (reference, index, all) =>
      all.findIndex(
        (candidate) => candidate.evidenceId === reference.evidenceId,
      ) === index,
  );
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
      {references.map((reference) => {
        const canonical = canonicalTargets.get(reference.evidenceId);
        const isCanonical =
          canonical?.sectionId === sectionId && canonical.itemId === item.id;
        return (
          <span
            key={`${reference.sourceArtifactId}:${reference.evidenceId}`}
            id={isCanonical ? `evidence-${reference.evidenceId}` : undefined}
            data-evidence-id={reference.evidenceId}
            tabIndex={isCanonical ? -1 : undefined}
            title={`${reference.sourceArtifactId} · ${reference.evidenceId}`}
            style={{
              padding: "1px 5px",
              border: `1px solid ${tokens.colorNeutralStroke2}`,
              backgroundColor: tokens.colorNeutralBackground3,
              color: tokens.colorNeutralForeground2,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              fontSize,
              lineHeight: 1.3,
            }}
          >
            {reference.sourceArtifactId} · {reference.evidenceId}
          </span>
        );
      })}
    </div>
  );
}

function EvidenceItem({
  item,
  sectionId,
  canonicalTargets,
}: {
  item: EspEvidenceItemViewModel;
  sectionId: string;
  canonicalTargets: CanonicalEvidenceTargets;
}) {
  const fonts = useEvidenceFontMetrics();
  const coverageTarget = item.id.startsWith("coverage-");
  return (
    <article
      id={coverageTarget ? item.id : undefined}
      data-testid="esp-evidence-item"
      data-evidence-item-id={item.id}
      tabIndex={coverageTarget ? -1 : undefined}
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
            fontSize: fonts.title,
            lineHeight: 1.3,
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
              fontSize: fonts.body,
              lineHeight: 1.3,
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
            fontSize: fonts.body,
            fontWeight: 650,
            lineHeight: 1.4,
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
                fontSize: fonts.body,
                fontWeight: 700,
                letterSpacing: "0.06em",
                lineHeight: 1.1,
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
                fontSize: fonts.body,
                fontWeight: field.sensitivity === "public" ? 500 : 650,
                lineHeight: 1.4,
              }}
            >
              {field.value}
            </dd>
          </div>
        ))}
      </dl>
      <EvidenceReferences
        item={item}
        sectionId={sectionId}
        canonicalTargets={canonicalTargets}
        fontSize={fonts.body}
      />
    </article>
  );
}

function EvidenceSectionBody({
  section,
  page,
  canonicalTargets,
  onPageChange,
}: {
  section: EspEvidenceSectionViewModel;
  page: number;
  canonicalTargets: CanonicalEvidenceTargets;
  onPageChange(page: number): void;
}) {
  const fonts = useEvidenceFontMetrics();
  const maximumPage = Math.max(
    0,
    Math.ceil(section.items.length / ESP_EVIDENCE_ITEM_WINDOW_SIZE) - 1,
  );
  const safePage = Math.min(page, maximumPage);
  const start = safePage * ESP_EVIDENCE_ITEM_WINDOW_SIZE;
  const end = Math.min(
    start + ESP_EVIDENCE_ITEM_WINDOW_SIZE,
    section.items.length,
  );
  const visibleItems = section.items.slice(start, end);

  return (
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
          fontSize: fonts.body,
          fontWeight: 650,
          lineHeight: 1.3,
        }}
      >
        {sourceStateLabel(section.sourceState)} · {section.sourceNote}
      </div>
      {section.items.length > ESP_EVIDENCE_ITEM_WINDOW_SIZE ? (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 8,
            color: tokens.colorNeutralForeground2,
            fontSize: fonts.body,
          }}
        >
          <span>
            Showing {start + 1}–{end} of {section.items.length} records
          </span>
          <span style={{ display: "inline-flex", gap: 5 }}>
            <Button
              size="small"
              disabled={safePage === 0}
              onClick={() => onPageChange(Math.max(0, safePage - 1))}
            >
              Previous records
            </Button>
            <Button
              size="small"
              disabled={safePage >= maximumPage}
              onClick={() => onPageChange(Math.min(maximumPage, safePage + 1))}
            >
              Next records
            </Button>
          </span>
        </div>
      ) : null}
      {visibleItems.map((evidenceItem) => (
        <EvidenceItem
          key={evidenceItem.id}
          item={evidenceItem}
          sectionId={section.id}
          canonicalTargets={canonicalTargets}
        />
      ))}
    </div>
  );
}

export function EvidenceSections({ snapshot }: EvidenceSectionsProps) {
  const fonts = useEvidenceFontMetrics();
  const [revealSensitive, setRevealSensitive] = useState(false);
  const [openSections, setOpenSections] = useState<Set<string>>(
    () => new Set(),
  );
  const [sectionPages, setSectionPages] = useState<Record<string, number>>({});
  const [pendingTargetId, setPendingTargetId] = useState<string | null>(null);
  const viewModel = useMemo(
    () => buildEspEvidenceViewModel(snapshot, { revealSensitive }),
    [revealSensitive, snapshot],
  );
  const canonicalTargets = useMemo(() => {
    const targets: CanonicalEvidenceTargets = new Map();
    const rawSection = viewModel.sections.find(
      (section) => section.id === "raw-provenance",
    );
    const orderedSections = rawSection
      ? [
          rawSection,
          ...viewModel.sections.filter((section) => section !== rawSection),
        ]
      : viewModel.sections;
    for (const section of orderedSections) {
      for (const evidenceItem of section.items) {
        for (const reference of evidenceItem.evidence) {
          if (!targets.has(reference.evidenceId)) {
            targets.set(reference.evidenceId, {
              sectionId: section.id,
              itemId: evidenceItem.id,
            });
          }
        }
      }
    }
    return targets;
  }, [viewModel]);

  useEffect(() => {
    const handleNavigation = (event: Event) => {
      const target = (event as CustomEvent<EspEvidenceNavigationTarget>).detail;
      const destination =
        target.kind === "evidence"
          ? (canonicalTargets.get(target.id) ?? null)
          : {
              sectionId: "source-coverage",
              itemId: `coverage-${target.id}`,
            };
      if (!destination) return;
      const section = viewModel.sections.find(
        (candidate) => candidate.id === destination.sectionId,
      );
      const itemIndex =
        section?.items.findIndex((item) => item.id === destination.itemId) ??
        -1;
      if (!section || itemIndex < 0) return;

      setOpenSections((current) => {
        const next = new Set(current);
        next.add(section.id);
        return next;
      });
      setSectionPages((current) => ({
        ...current,
        [section.id]: Math.floor(itemIndex / ESP_EVIDENCE_ITEM_WINDOW_SIZE),
      }));
      setPendingTargetId(
        target.kind === "evidence"
          ? `evidence-${target.id}`
          : `coverage-${target.id}`,
      );
    };

    window.addEventListener(ESP_EVIDENCE_NAVIGATION_EVENT, handleNavigation);
    return () =>
      window.removeEventListener(
        ESP_EVIDENCE_NAVIGATION_EVENT,
        handleNavigation,
      );
  }, [canonicalTargets, viewModel.sections]);

  useEffect(() => {
    if (!pendingTargetId) return;
    const target = document.getElementById(pendingTargetId);
    if (!target) return;
    target.focus({ preventScroll: true });
    if (typeof target.scrollIntoView === "function") {
      target.scrollIntoView({ block: "center", inline: "nearest" });
    }
    setPendingTargetId(null);
  }, [openSections, pendingTargetId, sectionPages]);

  return (
    <section
      className="esp-evidence-sections"
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
              fontSize: fonts.body,
              fontWeight: 700,
              letterSpacing: "0.12em",
              lineHeight: 1.1,
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
              fontSize: fonts.heading,
              fontWeight: 650,
              lineHeight: 1.3,
            }}
          >
            ESP evidence
          </h2>
          <p
            style={{
              margin: "2px 0 0",
              color: tokens.colorNeutralForeground2,
              fontSize: fonts.body,
              lineHeight: 1.4,
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
          {revealSensitive
            ? "Mask sensitive values"
            : "Reveal sensitive values"}
        </Button>
      </div>

      <div
        style={{
          display: "grid",
          gap: 1,
          backgroundColor: tokens.colorNeutralStroke2,
        }}
      >
        {viewModel.sections.map((section) => (
          <details
            key={section.id}
            id={`esp-evidence-section-${section.id}`}
            open={openSections.has(section.id)}
            data-source-state={section.sourceState}
            style={{ backgroundColor: tokens.colorNeutralBackground1 }}
          >
            <summary
              className="esp-evidence-summary"
              onClick={(event) => {
                event.preventDefault();
                setOpenSections((current) => {
                  const next = new Set(current);
                  if (next.has(section.id)) next.delete(section.id);
                  else next.add(section.id);
                  return next;
                });
              }}
              style={{
                display: "grid",
                alignItems: "center",
                gap: 12,
                minHeight: 36,
                padding: "4px 10px",
                cursor: "pointer",
                fontFamily: LOG_UI_FONT_FAMILY,
              }}
            >
              <span style={{ fontSize: fonts.strong, fontWeight: 650 }}>
                {section.title}
              </span>
              <span
                style={{
                  color: tokens.colorNeutralForeground2,
                  fontSize: fonts.body,
                  lineHeight: 1.4,
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
                  fontSize: fonts.body,
                  fontWeight: 700,
                  lineHeight: 1.3,
                  textTransform: "uppercase",
                  whiteSpace: "nowrap",
                }}
              >
                <SourceStateIcon state={section.sourceState} />
                {sourceStateLabel(section.sourceState)} · {section.items.length}
              </span>
            </summary>
            {openSections.has(section.id) ? (
              <EvidenceSectionBody
                section={section}
                page={sectionPages[section.id] ?? 0}
                canonicalTargets={canonicalTargets}
                onPageChange={(page) =>
                  setSectionPages((current) => ({
                    ...current,
                    [section.id]: page,
                  }))
                }
              />
            ) : null}
          </details>
        ))}
      </div>
    </section>
  );
}
