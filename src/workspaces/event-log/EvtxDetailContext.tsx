/**
 * The Details tab's "Context ±5 min" section (spec 8.13 Details item 7, #843): the 12 timeline
 * entries nearest the selected event, events and text-log lines interleaved by time, with a link icon
 * on the entries that share an Exact or Candidate edge with it, and the way to the full Correlation
 * view.
 *
 * Presentation only. Every decision (which entries, in which order, which carry the icon, what is
 * said about what could not be shown) is `buildDetailContext`'s, and the window it reads comes from
 * the caller: this component runs no query and holds no state of its own, so a test, the Details
 * pane and a screenshot all hand it the same facts.
 *
 * Rules, all enforced here:
 * - No row carries a relationship word. The icon is the only mark, and it is a role="img" with its
 *   own name; everything else in a row is its time, its kind, its message, its offset and its source.
 * - Nothing is announced: no live region, no status. A reader finds the section; it does not speak.
 * - Text sizes come from the log list font size through the shared correlation sizes, with the
 *   spec's floor of 10 px. The time column is as wide as eight digits of its own size (`8ch`), so it
 *   never clips.
 * - Every text sets its color, and sits on a surface whose pair was measured at 4.5:1 in all seven
 *   themes (the rail text colors on the rail, the card text colors on the card, the selection
 *   triplet on the selected row); the link icons reach 3:1.
 */
import { useId, useMemo } from "react";
import { Link, tokens } from "@fluentui/react-components";
import { ArrowRight12Regular, Link12Regular } from "@fluentui/react-icons";
import { LOG_UI_FONT_FAMILY } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { EvtxKindChip } from "./EvtxKindChip";
import { correlationSizes } from "./evtx-correlation-sizes";
import { openCorrelationView } from "./evtx-correlation-store";
import {
  DETAIL_CONTEXT_KINDS_LABEL,
  DETAIL_CONTEXT_TITLE,
  buildDetailContext,
  type DetailContextInput,
  type DetailContextRow,
} from "./evtx-detail-context-model";
import { evtxViewTabId } from "./evtx-layout-store";
import { useRailTextColors } from "./evtx-rail-text";
import { formatClock, type EvtxTimeZoneMode } from "./evtx-time";
import { useEvtxVisualTokens } from "./evtx-visual-tokens";

export interface EvtxDetailContextProps extends DetailContextInput {
  /** The record the Details tab shows; the section is about this event. */
  record: NonNullable<DetailContextInput["record"]>;
  timeZoneMode: EvtxTimeZoneMode;
}

/** The "Open full correlation timeline" action: the Correlation view, with the chain selection left alone. */
function openFullTimeline(): void {
  openCorrelationView();
  document.getElementById(evtxViewTabId("correlation"))?.focus();
}

export function EvtxDetailContext({
  record,
  window,
  counts,
  unreadSources,
  session,
  timeZoneMode,
}: EvtxDetailContextProps) {
  const titleId = useId();
  const railText = useRailTextColors();
  const visuals = useEvtxVisualTokens();
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  // The correlation surfaces' sizes (f - 2, max(10, f - 3), max(9, f - 4)), with the 10 px floor the
  // spec puts on text: the message is f - 2 and the chip f - 4, and neither may go under it.
  const sizes = useMemo(() => {
    const correlation = correlationSizes(logListFontSize);
    return {
      message: Math.max(10, correlation.lane),
      label: correlation.label,
      chip: Math.max(10, correlation.tick),
    };
  }, [logListFontSize]);

  // `counts` is a new object on every run change, scan progress included; the model reads only these.
  const model = useMemo(
    () => buildDetailContext({ record, window, counts, unreadSources, session }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [
      record,
      window,
      counts?.model,
      counts?.builtFor,
      counts?.gaps,
      counts?.scope,
      counts?.unplacedList,
      counts?.updating,
      unreadSources,
      session,
    ],
  );
  if (model.kind === "none") return null;

  const small = { fontSize: `${sizes.label}px` } as const;
  const note = { ...small, color: railText.cardSecondary, lineHeight: 1.4 } as const;

  const renderRow = (row: DetailContextRow) => {
    const text = row.isSelected ? visuals.selection.foreground : undefined;
    return (
      <li
        key={row.id}
        aria-current={row.isSelected ? "true" : undefined}
        data-evtx-ctx="row"
        style={{
          display: "flex",
          alignItems: "flex-start",
          gap: "8px",
          padding: "6px 10px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          ...(row.isSelected
            ? {
                backgroundColor: visuals.selection.background,
                color: visuals.selection.foreground,
                boxShadow: `inset 3px 0 0 ${visuals.selection.border}`,
              }
            : {}),
        }}
      >
        <span
          data-evtx-ctx="time"
          style={{
            ...small,
            width: "8ch",
            flexShrink: 0,
            fontFamily: tokens.fontFamilyNumeric,
            color: text ?? railText.cardSecondary,
          }}
        >
          {formatClock(row.timestampMs, timeZoneMode, true)}
        </span>
        <EvtxKindChip chip={row.chip} fontSize={sizes.chip} />
        <span style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column", gap: "2px" }}>
          <span
            data-evtx-ctx="message"
            title={row.message}
            style={{
              fontSize: `${sizes.message}px`,
              color: text ?? tokens.colorNeutralForeground1,
              lineHeight: 1.4,
              overflowWrap: "anywhere",
              display: "-webkit-box",
              WebkitLineClamp: 2,
              WebkitBoxOrient: "vertical",
              overflow: "hidden",
            }}
          >
            {row.message}
          </span>
          <span
            data-evtx-ctx="offset"
            style={{ ...small, color: text ?? railText.cardSecondary, fontFamily: tokens.fontFamilyNumeric }}
          >
            {`${row.offsetText} · ${row.entry}`}
          </span>
        </span>
        {row.link !== null && (
          <span
            role="img"
            aria-label={row.link.name}
            title={row.link.name}
            style={{ color: visuals.strengthBars[row.link.strength], display: "inline-flex", flexShrink: 0 }}
          >
            <Link12Regular aria-hidden="true" />
          </span>
        )}
      </li>
    );
  };

  return (
    <div
      role="group"
      aria-labelledby={titleId}
      aria-busy={model.kind === "reading"}
      style={{ display: "grid", gap: "4px", flexShrink: 0, fontFamily: LOG_UI_FONT_FAMILY }}
    >
      <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: "8px" }}>
        <span
          id={titleId}
          data-evtx-ctx="eyebrow"
          style={{
            ...small,
            color: railText.secondary,
            fontWeight: 700,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
          }}
        >
          {DETAIL_CONTEXT_TITLE}
        </span>
        <span data-evtx-ctx="kinds" style={{ ...small, color: railText.secondary }}>
          {DETAIL_CONTEXT_KINDS_LABEL}
        </span>
      </div>
      <div
        style={{
          backgroundColor: tokens.colorNeutralBackground1,
          border: `1px solid ${tokens.colorNeutralStroke2}`,
          borderRadius: "6px",
          overflow: "hidden",
        }}
      >
        {model.kind !== "ready" ? (
          <div data-evtx-ctx="state" style={{ ...note, padding: "8px 10px" }}>
            {model.text}
          </div>
        ) : (
          <>
            {model.caption !== null && (
              <div data-evtx-ctx="caption" style={{ ...note, padding: "6px 10px 0" }}>
                {model.caption}
              </div>
            )}
            {model.rows.length > 0 && (
              <ul
                aria-label="Entries around this event"
                style={{ listStyle: "none", margin: "6px 0 0", padding: 0, borderTop: `1px solid ${tokens.colorNeutralStroke2}` }}
              >
                {model.rows.map(renderRow)}
              </ul>
            )}
            {model.empty !== null && (
              <div data-evtx-ctx="empty" style={{ ...note, padding: "6px 10px" }}>
                {model.empty.text}
              </div>
            )}
            {model.legend !== null && (
              <div data-evtx-ctx="legend" style={{ ...note, padding: "6px 10px 0" }}>
                {model.legend}
              </div>
            )}
            {model.notices.map((text) => (
              <div key={text} data-evtx-ctx="notice" style={{ ...note, padding: "6px 10px 0" }}>
                {text}
              </div>
            ))}
          </>
        )}
        <div style={{ padding: "6px 10px 8px" }}>
          <Link
            as="button"
            type="button"
            data-evtx-ctx="open"
            aria-description="Switches the main view to Correlation."
            onClick={openFullTimeline}
            style={{
              fontSize: `${sizes.message}px`,
              fontWeight: 600,
              color: tokens.colorBrandForegroundLink,
              fontFamily: LOG_UI_FONT_FAMILY,
            }}
          >
            Open full correlation timeline{" "}
            <ArrowRight12Regular aria-hidden="true" style={{ verticalAlign: "middle" }} />
          </Link>
        </div>
      </div>
    </div>
  );
}
