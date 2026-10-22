/**
 * One row of the rail's Chains tab (spec 8.13): a card for an exact or candidate chain, with its steps
 * and its two actions, or a compact row for an ambiguous or coverage blocked one, with no steps.
 *
 * Presentation only. `buildRailChains` decided every word and every claim; this draws them, so a test,
 * the rail and a screenshot all hand it the same facts.
 *
 * Rules, all enforced here:
 * - A step shows the kind chip its entry was given (`EvtxKindChip`), and never writes EVT or LOG.
 * - A compact row has no steps and no Show in table: it establishes no link. It may be opened.
 * - Every text sets its color, and sits on a surface whose pair was measured at 4.5:1 in all seven
 *   themes (the card text colors on the card, the selection triplet on the selected card); the dots
 *   reach 3:1, with the selection foreground as their outline on the selected card.
 * - The time column is as wide as eight digits of its own size (`8ch`), so it never clips at a large
 *   font. Text sizes come from the log list font size through the shared correlation sizes.
 * - Both actions wait (`disabledFocusable`, the reason in the tooltip) while the model on show is an
 *   earlier session's or its entries were not read; a failure of Show in table is an alert.
 */
import { Button, Link, tokens } from "@fluentui/react-components";
import { ArrowRight12Regular, Filter16Regular } from "@fluentui/react-icons";
import { LOG_MONOSPACE_FONT_FAMILY, LOG_UI_FONT_FAMILY } from "../../lib/log-accessibility";
import { EvtxKindChip } from "./EvtxKindChip";
import { EvtxStrengthBadge } from "./EvtxStrengthBadge";
import { SAME_TIME_NOTE } from "./evtx-correlation-copy";
import type { CorrelationSizes } from "./evtx-correlation-sizes";
import type { RailCardRow, RailChainsReady, RailCompactRow, RailRow } from "./evtx-rail-chains-model";
import type { RailTextColors } from "./evtx-rail-text";
import type { EvtxVisualTokens } from "./evtx-visual-tokens";

const SHOW_IN_TABLE = "Show in table";
const OPEN_IN_CORRELATION = "Open in correlation view";

export interface RailChainRowProps {
  row: RailRow;
  sizes: CorrelationSizes;
  visuals: EvtxVisualTokens;
  railText: RailTextColors;
  actions: RailChainsReady["actions"];
  /** The rows are an earlier session's: dimmed, and marked busy. */
  stale: boolean;
  /** Why Show in table did not filter the table, for this row, as an alert. */
  failure: string | null;
  onShowInTable: (row: RailCardRow) => void;
  onOpen: (row: RailRow) => void;
}

interface Palette {
  /** Title and message. */
  primary: string;
  /** Span, time, notes: the muted card color. */
  secondary: string;
  /** The key line. */
  key: string;
  link: string;
}

function paletteOf(row: RailRow, visuals: EvtxVisualTokens, railText: RailTextColors): Palette {
  // On the selected card the selection foreground is the one text color that reaches 4.5:1.
  if (row.selected) {
    const foreground = visuals.selection.foreground;
    return { primary: foreground, secondary: foreground, key: foreground, link: foreground };
  }
  return {
    primary: tokens.colorNeutralForeground1,
    secondary: railText.cardSecondary,
    key: tokens.colorNeutralForeground2,
    link: tokens.colorBrandForegroundLink,
  };
}

function Steps({
  row,
  sizes,
  visuals,
  palette,
}: {
  row: RailCardRow;
  sizes: CorrelationSizes;
  visuals: EvtxVisualTokens;
  palette: Palette;
}) {
  return (
    <ol
      aria-label={`Entries of ${row.title}, in recorded time order`}
      style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: "4px" }}
    >
      {row.steps.map((step) => (
        <li
          key={step.id}
          data-step={step.id}
          style={{ display: "flex", alignItems: "flex-start", gap: "6px", minWidth: 0 }}
        >
          <span
            role="img"
            aria-label={step.level}
            data-step-part="dot"
            style={{
              flexShrink: 0,
              boxSizing: "border-box",
              width: "8px",
              height: "8px",
              marginTop: `${Math.max(2, Math.round((Math.max(10, sizes.lane) * 1.4 - 8) / 2))}px`,
              borderRadius: "50%",
              backgroundColor: visuals.levels[step.level].dotColor,
              border: row.selected ? `1px solid ${visuals.markOutline("selected")}` : "none",
            }}
          />
          <span
            data-step-part="time"
            style={{
              flexShrink: 0,
              minWidth: "8ch",
              fontSize: `${sizes.label}px`,
              lineHeight: 1.4,
              fontFamily: tokens.fontFamilyNumeric,
              fontVariantNumeric: "tabular-nums",
              color: palette.secondary,
            }}
          >
            {step.timeText}
          </span>
          <EvtxKindChip chip={step.chip} />
          <span style={{ flex: 1, minWidth: 0, display: "grid", gap: "2px" }}>
            <span
              data-step-part="message"
              title={step.message}
              style={{
                fontSize: `${Math.max(10, sizes.lane)}px`,
                lineHeight: 1.4,
                color: palette.primary,
                overflowWrap: "anywhere",
                display: "-webkit-box",
                WebkitLineClamp: 2,
                WebkitBoxOrient: "vertical",
                overflow: "hidden",
              }}
            >
              {step.message}
            </span>
            {step.sameTimeAsPrevious && (
              <span style={{ fontSize: `${sizes.label}px`, color: palette.secondary }}>{SAME_TIME_NOTE}</span>
            )}
          </span>
        </li>
      ))}
    </ol>
  );
}

export function EvtxRailChainRow(props: RailChainRowProps) {
  const { row, sizes, visuals, railText, actions, stale, failure, onShowInTable, onOpen } = props;
  const palette = paletteOf(row, visuals, railText);
  const open = (
    <Link
      as="button"
      type="button"
      disabledFocusable={!actions.canAct}
      title={actions.canAct ? undefined : actions.reason}
      aria-label={`${OPEN_IN_CORRELATION}: ${row.title}`}
      onClick={actions.canAct ? () => onOpen(row) : undefined}
      style={{
        justifySelf: "start",
        fontSize: `${Math.max(10, sizes.lane)}px`,
        fontWeight: 600,
        color: palette.link,
        fontFamily: LOG_UI_FONT_FAMILY,
      }}
    >
      {OPEN_IN_CORRELATION} <ArrowRight12Regular aria-hidden="true" style={{ verticalAlign: "middle" }} />
    </Link>
  );
  return (
    <li style={{ listStyle: "none" }}>
      <section
        aria-label={row.name}
        aria-current={row.selected ? "true" : undefined}
        aria-busy={stale || undefined}
        data-rail-chain={row.chain.id}
        data-rail-kind={row.kind}
        style={{
          opacity: stale ? 0.6 : 1,
          display: "grid",
          gap: "6px",
          padding: "10px 12px",
          borderRadius: "6px",
          border: `1px solid ${tokens.colorNeutralStroke2}`,
          backgroundColor: row.selected ? visuals.selection.background : tokens.colorNeutralBackground1,
          boxShadow: row.selected ? `inset 3px 0 0 ${visuals.selection.border}` : undefined,
          color: palette.primary,
          fontFamily: LOG_UI_FONT_FAMILY,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "8px" }}>
          <EvtxStrengthBadge
            strength={row.strength}
            selected={row.selected}
            visuals={visuals}
            textSize={sizes.label}
          />
          <span
            data-rail-part="span"
            style={{
              fontSize: `${sizes.label}px`,
              fontFamily: tokens.fontFamilyNumeric,
              fontVariantNumeric: "tabular-nums",
              color: palette.secondary,
              whiteSpace: "nowrap",
            }}
          >
            {row.span}
          </span>
        </div>
        <h3
          data-rail-part="title"
          title={row.title}
          style={{ margin: 0, fontSize: `${sizes.f}px`, fontWeight: 600, color: palette.primary, overflowWrap: "anywhere" }}
        >
          {row.title}
        </h3>
        {row.kind === "compact" ? (
          <CompactBody row={row} sizes={sizes} palette={palette} />
        ) : (
          <>
            {row.key !== null && (
              <div
                data-rail-part="key"
                style={{ fontSize: `${sizes.label}px`, color: palette.key, fontFamily: LOG_MONOSPACE_FONT_FAMILY }}
              >
                {row.key.label}{" "}
                <span title={row.key.fullValue}>{row.key.shortValue}</span>
                {row.key.more > 0 ? ` and ${row.key.more.toLocaleString()} more` : ""}
              </div>
            )}
            {row.steps.length > 0 && <Steps row={row} sizes={sizes} visuals={visuals} palette={palette} />}
            {row.more !== null && (
              <div data-rail-part="more" style={{ fontSize: `${sizes.label}px`, color: palette.secondary }}>
                {row.more}
              </div>
            )}
            {row.stepsText !== null && (
              <div data-rail-part="steps-text" style={{ fontSize: `${Math.max(10, sizes.lane)}px`, color: palette.secondary }}>
                {row.stepsText}
              </div>
            )}
            {row.partialNote !== null && (
              <div data-rail-part="partial" style={{ fontSize: `${Math.max(10, sizes.lane)}px`, color: palette.secondary }}>
                {row.partialNote}
              </div>
            )}
          </>
        )}
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "8px 12px" }}>
          {row.kind === "card" && (
            <Button
              size="small"
              appearance="secondary"
              icon={<Filter16Regular />}
              disabledFocusable={!actions.canAct}
              title={actions.canAct ? undefined : actions.reason}
              aria-label={`${SHOW_IN_TABLE}: ${row.title}`}
              onClick={actions.canAct ? () => onShowInTable(row) : undefined}
            >
              {SHOW_IN_TABLE}
            </Button>
          )}
          {open}
        </div>
        {failure !== null && (
          <div
            role="alert"
            data-testid="rail-chains-action-alert"
            style={{ fontSize: `${Math.max(10, sizes.lane)}px`, color: palette.primary }}
          >
            {failure}
          </div>
        )}
      </section>
    </li>
  );
}

function CompactBody({
  row,
  sizes,
  palette,
}: {
  row: RailCompactRow;
  sizes: CorrelationSizes;
  palette: Palette;
}) {
  return (
    <>
      <div data-rail-part="entries" style={{ fontSize: `${sizes.label}px`, color: palette.secondary }}>
        {row.entries}
        {row.partial ? " (partial)" : ""}
      </div>
      <div data-rail-part="description" style={{ fontSize: `${Math.max(10, sizes.lane)}px`, color: palette.secondary }}>
        {row.description}
      </div>
    </>
  );
}
