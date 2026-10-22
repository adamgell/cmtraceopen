/**
 * The rail's Chains tab (spec 8.13): the chains of the session as cards, strongest first, with the
 * ambiguous and coverage blocked rows after them as compact rows, what is nearby by time alone, the
 * entries that could not be placed, and the way into the Correlation view and the table.
 *
 * It reads the workspace's shared correlation data (`useEvtxCorrelationData`) and nothing else about
 * correlation, so it shows the same rows, in the same order and under the same cap, as the Correlation
 * view: `buildRailChains` decides them from the one snapshot, and `EvtxRailChainRow` draws them.
 * Loaded lazily by the rail, and nothing here imports from the lazily loaded view or from the plot.
 *
 * Rules the component itself keeps:
 * - It has no live region. Unsolicited updates are the Correlation view's announcer's; here the
 *   updating and reading lines are plain text and the tab is marked busy. A failed action is an alert.
 * - Show in table moves focus to the Table tab, Open in correlation view to the Correlation tab, and
 *   Review unplaced lines to the Correlation tab (`evtx-correlation-actions`). Open goes through
 *   `openChain`, so the view drops a lost-selection record it holds.
 * - The selected event's chain is found with the origin join, for the throttled selection, and only
 *   when exactly one entry names the record.
 * - A tab left and come back to starts closed and at the top: nothing here is kept across a switch.
 */
import { useEffect, useMemo, useState } from "react";
import { Button, Link, tokens } from "@fluentui/react-components";
import { ArrowRight12Regular } from "@fluentui/react-icons";
import { LOG_UI_FONT_FAMILY } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { EvtxRailChainRow } from "./EvtxRailChainCard";
import { ConnectorSwatch, LegendItem, MarkerSwatch } from "./EvtxCorrelationLegendParts";
import { Disclosure, useRailSizes } from "./EvtxRailParts";
import {
  filterTableToChain,
  openChainInCorrelationView,
  openUnplacedInCorrelationView,
} from "./evtx-correlation-actions";
import { correlationSizes } from "./evtx-correlation-sizes";
import { findRecordById } from "./evtx-insights-data";
import {
  buildRailChains,
  selectedRecordRowId,
  type RailCardRow,
  type RailChainsReady,
  type RailRow,
} from "./evtx-rail-chains-model";
import { useRailTextColors } from "./evtx-rail-text";
import { useEvtxStore } from "./evtx-store";
import { DERIVATION_THROTTLE_MS, useThrottledValue } from "./evtx-throttle";
import { useEvtxVisualTokens } from "./evtx-visual-tokens";
import type { TimelineItem } from "./unified-timeline";
import { useEvtxCorrelationData } from "./useEvtxCorrelation";
import { useUnreadSources } from "./useUnreadSources";

const NO_NEARBY: readonly TimelineItem[] = [];

/**
 * The Not placed card is a note, not a chain card (spec 8.13 names Background4). Background4 and the
 * brand link color miss 4.5:1 in solarized-dark, nord and dracula (3.69 to 4.36), and Background3 with
 * Foreground1 or the brand link still misses in solarized-dark and dracula (4.11 and 4.35), so the card
 * sits on Background3, every text on it is Foreground2, and its link is underlined: the underline, not
 * a color, says it is a link. A recorded deviation from the spec, measured in all seven themes.
 */
const NOT_PLACED_SURFACE = tokens.colorNeutralBackground3;
const NOT_PLACED_TEXT = tokens.colorNeutralForeground2;

export interface EvtxRailChainsProps {
  /**
   * Context entries listed as "Nearby, not linked". Nothing produces them in this version (decision A
   * on issue 838), so the rail passes none and the group is not drawn; the seam exists so that what
   * the group may say is wired and tested through the tab.
   */
  nearby?: readonly TimelineItem[];
}

export default function EvtxRailChains({ nearby = NO_NEARBY }: EvtxRailChainsProps = {}) {
  const data = useEvtxCorrelationData();
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const sizes = useMemo(() => correlationSizes(logListFontSize), [logListFontSize]);
  const railSizes = useRailSizes();
  const visuals = useEvtxVisualTokens();
  const railText = useRailTextColors();
  const timeZoneMode = useEvtxStore((s) => s.timeZoneMode);
  const unreadSources = useUnreadSources();
  const selectedRecord = useEvtxStore((s) => findRecordById(s.records, s.selectedRecordId));
  const record = useThrottledValue(selectedRecord, DERIVATION_THROTTLE_MS);
  const selectedRowId = useMemo(
    () => selectedRecordRowId(record, data),
    // The join reads the model, whether its entries were read, and the entries.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [record, data.model, data.hasItems, data.itemsById],
  );
  const model = useMemo(
    () => buildRailChains({ data, timeZoneMode, unreadSources, selectedRowId, nearby }),
    [data, timeZoneMode, unreadSources, selectedRowId, nearby],
  );

  // Why Show in table did not filter the table, for the row it was pressed on. A new model drops it.
  const [failure, setFailure] = useState<{ id: string; text: string } | null>(null);
  useEffect(() => setFailure(null), [data.model]);
  const [nearbyOpen, setNearbyOpen] = useState(false);

  const showInTable = (row: RailCardRow) => {
    if (data.model === null) return;
    const result = filterTableToChain({
      chain: row.chain,
      origins: data.origins,
      edgeInputComplete: data.model.edgeInputComplete,
    });
    setFailure(result.applied ? null : { id: row.chain.id, text: result.text });
  };
  const open = (row: RailRow) => openChainInCorrelationView(row.chain.id);

  const text = { fontSize: `${Math.max(10, sizes.lane)}px` };
  const shell = {
    display: "grid",
    gridAutoRows: "max-content",
    gap: "12px",
    fontFamily: LOG_UI_FONT_FAMILY,
  } as const;

  if (model.kind !== "ready") {
    return (
      <div data-testid="rail-chains" style={shell}>
        {model.kind === "failed" ? (
          <div role="alert" style={{ ...text, color: railText.primary }}>
            {model.text}
          </div>
        ) : (
          <div style={{ ...text, color: railText.primary }}>{model.text}</div>
        )}
      </div>
    );
  }

  const reading = model.readingText !== null;
  return (
    <div data-testid="rail-chains" aria-busy={model.updating || reading || undefined} style={shell}>
      <Status model={model} text={text} color={railText.secondary} />
      {model.error !== null && (
        <div role="alert" style={{ ...text, color: railText.primary }}>
          {model.error}
        </div>
      )}
      {model.notices.length > 0 && (
        <ul
          data-testid="rail-chains-notices"
          style={{ margin: 0, paddingLeft: "18px", ...text, color: railText.primary }}
        >
          {model.notices.map((notice) => (
            <li key={notice}>{notice}</li>
          ))}
        </ul>
      )}
      {model.retry && (
        <div>
          <Button size="small" appearance="secondary" onClick={data.retry}>
            Retry
          </Button>
        </div>
      )}
      {model.legend !== null && (
        <div
          role="group"
          aria-label="Legend"
          data-testid="rail-chains-legend"
          style={{ display: "flex", flexWrap: "wrap", columnGap: "14px", rowGap: "4px" }}
        >
          <LegendItem label={model.legend.exact} color={railText.secondary} size={sizes.label}>
            <ConnectorSwatch strength="exact" />
          </LegendItem>
          <LegendItem label={model.legend.candidate} color={railText.secondary} size={sizes.label}>
            <ConnectorSwatch strength="candidate" />
          </LegendItem>
          {model.legend.notLinked !== null && (
            <LegendItem label={model.legend.notLinked} color={railText.secondary} size={sizes.label}>
              <MarkerSwatch radius="50%" outlined />
            </LegendItem>
          )}
        </div>
      )}
      {model.orderNote !== null && (
        <div data-testid="rail-chains-order-note" style={{ fontSize: `${sizes.label}px`, color: railText.secondary }}>
          {model.orderNote}
        </div>
      )}
      {model.rowsLine !== null && (
        <div data-testid="rail-chains-rows-line" style={{ ...text, color: railText.primary }}>
          {model.rowsLine}
        </div>
      )}
      {model.rows.length > 0 && (
        <ul
          aria-label="Chains in this session, strongest first"
          style={{ margin: 0, padding: 0, display: "grid", gridAutoRows: "max-content", gap: "12px" }}
        >
          {model.rows.map((row) => (
            <EvtxRailChainRow
              key={row.chain.id}
              row={row}
              sizes={sizes}
              visuals={visuals}
              railText={railText}
              actions={model.actions}
              stale={model.updating}
              failure={failure !== null && failure.id === row.chain.id ? failure.text : null}
              onShowInTable={showInTable}
              onOpen={open}
            />
          ))}
        </ul>
      )}
      {model.emptyText !== null && (
        <div data-testid="rail-chains-empty" style={{ ...text, color: railText.primary }}>
          {model.emptyText}
        </div>
      )}
      {model.nearby !== null && (
        <Disclosure
          label={model.nearby.heading}
          open={nearbyOpen}
          onOpenChange={setNearbyOpen}
          sizes={railSizes}
          stale={model.updating}
        >
          <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: "6px" }}>
            {model.nearby.rows.map((entry) => (
              <li key={entry.id} data-nearby={entry.id} style={{ display: "grid", gap: "2px", ...text }}>
                <span style={{ color: tokens.colorNeutralForeground1 }}>
                  <span style={{ fontFamily: tokens.fontFamilyNumeric }}>{entry.timeText}</span> {entry.entry}
                </span>
                <span style={{ color: tokens.colorNeutralForeground1 }}>{entry.message}</span>
                <span style={{ fontSize: `${sizes.label}px`, color: railText.cardSecondary }}>{entry.reason}</span>
              </li>
            ))}
          </ul>
        </Disclosure>
      )}
      {model.notPlaced !== null && (
        <section
          aria-label="Not placed"
          aria-busy={model.updating || undefined}
          data-testid="rail-chains-not-placed"
          style={{
            opacity: model.updating ? 0.6 : 1,
            display: "grid",
            gap: "6px",
            padding: "10px 12px",
            borderRadius: "6px",
            backgroundColor: NOT_PLACED_SURFACE,
          }}
        >
          <div style={{ fontSize: `${sizes.f}px`, fontWeight: 600, color: NOT_PLACED_TEXT }}>
            {model.notPlaced.heading}
          </div>
          <div style={{ ...text, color: NOT_PLACED_TEXT }}>{model.notPlaced.body}</div>
          <Link
            as="button"
            type="button"
            onClick={() => openUnplacedInCorrelationView()}
            style={{
              justifySelf: "start",
              ...text,
              fontWeight: 600,
              color: NOT_PLACED_TEXT,
              textDecorationLine: "underline",
            }}
          >
            Review unplaced lines <ArrowRight12Regular aria-hidden="true" style={{ verticalAlign: "middle" }} />
          </Link>
        </section>
      )}
    </div>
  );
}

function Status({
  model,
  text,
  color,
}: {
  model: RailChainsReady;
  text: { fontSize: string };
  color: string;
}) {
  if (model.statusText === null && model.readingText === null) return null;
  return (
    <div data-testid="rail-chains-status" style={{ ...text, color }}>
      {model.statusText !== null ? `${model.statusText} ` : ""}
      {model.readingText ?? ""}
    </div>
  );
}
