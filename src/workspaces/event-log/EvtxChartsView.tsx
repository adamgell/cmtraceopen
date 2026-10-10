/**
 * The Event Logs Charts view (spec 8.10): a KPI grid and four figures.
 *
 * Takes plain data and the resolved visual tokens, so wiring it into the
 * workspace is one line and no figure reads a store. Meant to be loaded with
 * `React.lazy` (default export).
 *
 * Spike (spec 8.10, Library choice): all four figures are token-styled
 * markup. `HeatMapChart` takes hex color stops and interpolates them in d3, so
 * the `color-mix()` heat steps cannot be passed through (the interpolated
 * stop comes out as a mangled `color-mix` string), and it has no cell gap,
 * radius, cell size or empty-cell props. `VerticalStackedBarChart` takes
 * token colors but draws its own axes, tick sizes, legend and tooltip, which
 * would need `styles` overrides to follow `f - 4`, and it sizes from measured
 * width and canvas text, which jsdom cannot test. Figures 3 and 4 also share
 * one 24-column hour axis here, so they line up.
 */
import { useMemo, type CSSProperties, type ReactNode } from "react";
import { tokens } from "@fluentui/react-components";
import {
  LOG_UI_FONT_FAMILY,
  type LogListMetrics,
} from "../../lib/log-accessibility";
import {
  buildEvtxChartData,
  HOURS_PER_DAY,
  TOP_EVENT_ID_LIMIT,
  type EvtxChartData,
  type EvtxChartInput,
  type EvtxChartKpi,
} from "./evtx-chart-data";
import { timeZoneLabel, type EvtxTimeZoneMode } from "./evtx-time";
import type { EvtxVisualTokens } from "./evtx-visual-tokens";

export interface EvtxChartsViewProps {
  records: EvtxChartInput["records"];
  chains: EvtxChartInput["chains"];
  hideRules: EvtxChartInput["hideRules"];
  channelOrder: EvtxChartInput["channelOrder"];
  timeZoneMode: EvtxTimeZoneMode;
  /** The loaded window, for the Events KPI label, for example "24 h". */
  windowLabel?: string;
  metrics: LogListMetrics;
  visualTokens: EvtxVisualTokens;
}

/**
 * An empty heat-map cell: no fill, a dashed accessible outline. Fills alone
 * cannot separate "no events" from the faintest step (the 15 percent mix is
 * only 1.2 to 1.5:1 from the surface), so the outline carries the difference
 * and the shape differs too: filled cells have no border at all.
 */
export const HEAT_EMPTY_CELL: CSSProperties = {
  background: "transparent",
  border: `1px dashed ${tokens.colorNeutralStrokeAccessible}`,
};

const hh = (hour: number) => String(hour).padStart(2, "0");

const numeric: CSSProperties = {
  fontFamily: tokens.fontFamilyNumeric,
  fontVariantNumeric: "tabular-nums",
};

const visuallyHidden: CSSProperties = {
  position: "absolute",
  width: 1,
  height: 1,
  margin: -1,
  padding: 0,
  overflow: "hidden",
  clip: "rect(0 0 0 0)",
  whiteSpace: "nowrap",
  border: 0,
};

const ellipsis: CSSProperties = {
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
};

function Figure({
  label,
  title,
  qualifier,
  metrics,
  children,
}: {
  label: string;
  title: string;
  qualifier?: string | null;
  metrics: LogListMetrics;
  children: ReactNode;
}) {
  const f = metrics.fontSize;
  return (
    <figure
      aria-label={label}
      style={{
        position: "relative",
        margin: 0,
        minWidth: 0,
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        borderRadius: 6,
        padding: "10px 12px",
        display: "flex",
        flexDirection: "column",
        gap: 8,
      }}
    >
      <figcaption style={{ display: "flex", flexWrap: "wrap", gap: "0 8px", alignItems: "baseline" }}>
        <span style={{ fontSize: f - 1, fontWeight: 600, color: tokens.colorNeutralForeground1 }}>
          {title}
        </span>
        {qualifier ? (
          <span style={{ fontSize: Math.max(10, f - 3), color: tokens.colorNeutralForeground3 }}>
            {qualifier}
          </span>
        ) : null}
      </figcaption>
      {children}
    </figure>
  );
}

function KpiCard({
  kpi,
  windowLabel,
  metrics,
}: {
  kpi: EvtxChartKpi;
  windowLabel?: string;
  metrics: LogListMetrics;
}) {
  const f = metrics.fontSize;
  const label =
    kpi.id === "events" && windowLabel ? `${kpi.label} (${windowLabel})` : kpi.label;
  return (
    <div
      data-kpi={kpi.id}
      style={{
        minWidth: 0,
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        borderRadius: 6,
        padding: "10px 12px",
      }}
    >
      <div style={{ fontSize: f - 2, color: tokens.colorNeutralForeground2 }}>{label}</div>
      <div
        data-testid={`kpi-value-${kpi.id}`}
        style={{
          ...numeric,
          fontSize: f + 9,
          fontWeight: 600,
          lineHeight: 1.2,
          color: tokens.colorNeutralForeground1,
        }}
      >
        {kpi.value === null ? "n/a" : kpi.value.toLocaleString()}
      </div>
      {kpi.sublabel ? (
        <div style={{ fontSize: Math.max(10, f - 3), color: tokens.colorNeutralForeground3 }}>
          {kpi.sublabel}
        </div>
      ) : null}
    </div>
  );
}

function ChannelFigure({
  data,
  metrics,
  visualTokens,
}: {
  data: EvtxChartData;
  metrics: LogListMetrics;
  visualTokens: EvtxVisualTokens;
}) {
  const f = metrics.fontSize;
  const max = data.channels.reduce((m, c) => Math.max(m, c.count), 0);
  const { channels, events } = data.omittedChannels;
  return (
    <Figure
      label={`Events by channel: ${data.channels.length} channels, bar length is the event count`}
      title="Events by channel"
      metrics={metrics}
    >
      <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 6 }}>
        {data.channels.map((c) => {
          const text = `${c.channel}: ${c.count} events, ${c.errors} errors, ${c.warnings} warnings`;
          return (
            <li
              key={c.channel}
              aria-label={text}
              title={text}
              style={{ display: "flex", alignItems: "center", gap: 8, fontSize: f - 1 }}
            >
              <span style={{ ...ellipsis, flex: "0 1 150px", width: 150, color: tokens.colorNeutralForeground2 }}>
                {c.channel}
              </span>
              <span style={{ flex: 1, minWidth: 0 }}>
                <span
                  data-bar="channel"
                  style={{
                    display: "block",
                    height: 14,
                    width: `${max === 0 ? 0 : (c.count / max) * 100}%`,
                    minWidth: 2,
                    background: visualTokens.channelColor(c.colorIndex),
                    borderRadius: "0 4px 4px 0",
                  }}
                />
              </span>
              <span style={{ ...numeric, flex: "0 0 40px", textAlign: "right", color: tokens.colorNeutralForeground1 }}>
                {c.count.toLocaleString()}
              </span>
            </li>
          );
        })}
      </ul>
      {channels > 0 ? (
        <div style={{ fontSize: Math.max(10, f - 3), color: tokens.colorNeutralForeground3 }}>
          {`+${channels} more ${channels === 1 ? "channel" : "channels"} (${events.toLocaleString()} events) not shown`}
        </div>
      ) : null}
    </Figure>
  );
}

function TopIdsFigure({
  data,
  metrics,
  visualTokens,
}: {
  data: EvtxChartData;
  metrics: LogListMetrics;
  visualTokens: EvtxVisualTokens;
}) {
  const f = metrics.fontSize;
  const max = data.topIds.reduce((m, t) => Math.max(m, t.count), 0);
  return (
    <Figure
      label={`Top ${TOP_EVENT_ID_LIMIT} event IDs by count${data.topIdsQualifier ? `, ${data.topIdsQualifier}` : ""}`}
      title="Top event IDs"
      qualifier={data.topIdsQualifier}
      metrics={metrics}
    >
      <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 6 }}>
        {data.topIds.map((t) => {
          const text = `${t.eventId} ${t.provider}: ${t.count} events`;
          return (
            <li
              key={`${t.provider}|${t.eventId}`}
              aria-label={text}
              title={text}
              style={{ display: "flex", alignItems: "center", gap: 8, fontSize: f - 1 }}
            >
              <span style={{ ...numeric, flex: "0 0 44px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}>
                {t.eventId}
              </span>
              <span style={{ ...ellipsis, flex: "0 1 170px", width: 170, color: tokens.colorNeutralForeground2 }}>
                {t.provider}
              </span>
              <span style={{ flex: 1, minWidth: 0 }}>
                <span
                  data-bar="top-id"
                  style={{
                    display: "block",
                    height: 12,
                    width: `${max === 0 ? 0 : (t.count / max) * 100}%`,
                    minWidth: 2,
                    background: visualTokens.singleSeries,
                    borderRadius: "0 4px 4px 0",
                  }}
                />
              </span>
              <span style={{ ...numeric, flex: "0 0 34px", textAlign: "right", color: tokens.colorNeutralForeground1 }}>
                {t.count.toLocaleString()}
              </span>
            </li>
          );
        })}
      </ul>
    </Figure>
  );
}

function unplacedNote(count: number): string | null {
  if (count === 0) return null;
  return `${count.toLocaleString()} ${count === 1 ? "event has" : "events have"} no timestamp and ${count === 1 ? "is" : "are"} not placed`;
}

function HourAxis({ metrics, leading }: { metrics: LogListMetrics; leading: number }) {
  return (
    <div aria-hidden="true" style={{ display: "flex", gap: 8, fontSize: Math.max(9, metrics.fontSize - 4), color: tokens.colorNeutralForeground3 }}>
      {leading > 0 ? <span style={{ flex: `0 0 ${leading}px` }} /> : null}
      <div style={{ ...numeric, flex: 1, minWidth: 0, display: "grid", gridTemplateColumns: `repeat(${HOURS_PER_DAY}, minmax(0, 1fr))`, gap: 2 }}>
        {Array.from({ length: HOURS_PER_DAY }, (_, hour) => (
          <span key={hour} style={{ overflow: "visible", whiteSpace: "nowrap" }}>
            {hour % 6 === 0 ? hh(hour) : ""}
          </span>
        ))}
      </div>
    </div>
  );
}

function HeatMapFigure({
  data,
  metrics,
  visualTokens,
  timeZoneMode,
}: {
  data: EvtxChartData;
  metrics: LogListMetrics;
  visualTokens: EvtxVisualTokens;
  timeZoneMode: EvtxTimeZoneMode;
}) {
  const f = metrics.fontSize;
  const small = Math.max(10, f - 3);
  const qualifier = [`hour of day, ${timeZoneLabel(timeZoneMode)}`, unplacedNote(data.unplacedCount)]
    .filter(Boolean)
    .join(" · ");
  return (
    <Figure
      label="Activity by hour of day and channel, heat map: darker cells have more events"
      title="Activity by hour and channel"
      qualifier={qualifier}
      metrics={metrics}
    >
      <div aria-hidden="true" style={{ display: "flex", flexDirection: "column", gap: 2 }}>
        {data.heatMap.rows.map((row) => (
          <div key={row.channel} style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ ...ellipsis, flex: "0 0 120px", width: 120, fontSize: f - 2, color: tokens.colorNeutralForeground2 }}>
              {row.channel}
            </span>
            <div style={{ flex: 1, minWidth: 0, display: "grid", gridTemplateColumns: `repeat(${HOURS_PER_DAY}, minmax(0, 1fr))`, gap: 2 }}>
              {row.counts.map((count, hour) => (
                <span
                  key={hour}
                  data-cell={count === 0 ? "empty" : `step-${row.steps[hour]}`}
                  title={`${row.channel} · ${hh(hour)}:00 · ${count} events`}
                  style={{
                    height: 18,
                    borderRadius: 2,
                    boxSizing: "border-box",
                    ...(count === 0
                      ? HEAT_EMPTY_CELL
                      : { background: visualTokens.heatSteps[row.steps[hour]] }),
                  }}
                />
              ))}
            </div>
          </div>
        ))}
        <HourAxis metrics={metrics} leading={128} />
      </div>
      <div aria-hidden="true" style={{ display: "flex", alignItems: "center", gap: 4, fontSize: small, color: tokens.colorNeutralForeground3 }}>
        <span>None</span>
        <span style={{ width: 14, height: 10, borderRadius: 2, boxSizing: "border-box", ...HEAT_EMPTY_CELL }} />
        <span style={{ marginLeft: 6 }}>Fewer</span>
        {visualTokens.heatSteps.map((fill, i) => (
          <span key={i} style={{ width: 14, height: 10, borderRadius: 2, background: fill }} />
        ))}
        <span>More</span>
      </div>
      <table style={visuallyHidden}>
        <caption>Events per hour of day by channel</caption>
        <thead>
          <tr>
            <th scope="col">Channel</th>
            {Array.from({ length: HOURS_PER_DAY }, (_, hour) => (
              <th key={hour} scope="col">{`${hh(hour)}:00`}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.heatMap.rows.map((row) => (
            <tr key={row.channel}>
              <th scope="row">{row.channel}</th>
              {row.counts.map((count, hour) => (
                <td key={hour}>{count}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </Figure>
  );
}

const COLUMN_HEIGHT = 120;
const MIN_SEGMENT = 2;

function HourlyFigure({
  data,
  metrics,
  visualTokens,
  timeZoneMode,
}: {
  data: EvtxChartData;
  metrics: LogListMetrics;
  visualTokens: EvtxVisualTokens;
  timeZoneMode: EvtxTimeZoneMode;
}) {
  const f = metrics.fontSize;
  const small = Math.max(10, f - 3);
  const max = data.hourly.reduce((m, b) => Math.max(m, b.errors + b.warnings), 0);
  const scale = (n: number) =>
    n === 0 || max === 0 ? 0 : Math.max(MIN_SEGMENT, Math.round((n / max) * COLUMN_HEIGHT));
  const qualifier = [`hour of day, ${timeZoneLabel(timeZoneMode)}`, unplacedNote(data.unplacedCount)]
    .filter(Boolean)
    .join(" · ");
  const swatch = (color: string): CSSProperties => ({
    width: 8,
    height: 8,
    borderRadius: 2,
    background: color,
    display: "inline-block",
  });
  return (
    <Figure
      label="Errors and warnings per hour of day, stacked columns with errors below warnings"
      title="Errors and warnings per hour"
      qualifier={qualifier}
      metrics={metrics}
    >
      <div
        aria-hidden="true"
        style={{ display: "grid", gridTemplateColumns: `repeat(${HOURS_PER_DAY}, minmax(0, 1fr))`, gap: 2, height: COLUMN_HEIGHT, alignItems: "end" }}
      >
        {data.hourly.map((b) => (
          <div
            key={b.hour}
            data-hour={b.hour}
            title={`${hh(b.hour)}:00 · ${b.errors} errors, ${b.warnings} warnings`}
            style={{ display: "flex", flexDirection: "column-reverse", height: "100%" }}
          >
            {b.errors > 0 ? (
              <span
                data-segment="error"
                style={{ height: scale(b.errors), background: visualTokens.levels.Error.barColor, borderRadius: "0 0 2px 2px", flex: "0 0 auto" }}
              />
            ) : null}
            {b.warnings > 0 ? (
              <span
                data-segment="warning"
                style={{
                  height: scale(b.warnings),
                  background: visualTokens.levels.Warning.barColor,
                  borderBottom: b.errors > 0 ? `1px solid ${tokens.colorNeutralBackground1}` : undefined,
                  boxSizing: "content-box",
                  borderRadius: "2px 2px 0 0",
                  flex: "0 0 auto",
                }}
              />
            ) : null}
          </div>
        ))}
      </div>
      <HourAxis metrics={metrics} leading={0} />
      <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", gap: 8, fontSize: small, color: tokens.colorNeutralForeground3 }}>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 10 }}>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
            <span style={swatch(visualTokens.levels.Error.barColor)} />
            Error
          </span>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
            <span style={swatch(visualTokens.levels.Warning.barColor)} />
            Warning
          </span>
        </span>
        <span style={numeric}>
          {data.peak
            ? `Peak: ${data.peak.label} (${data.peak.count.toLocaleString()})`
            : "No errors or warnings placed in an hour"}
        </span>
      </div>
      <table style={visuallyHidden}>
        <caption>Errors and warnings per hour of day</caption>
        <thead>
          <tr>
            <th scope="col">Hour</th>
            <th scope="col">Errors</th>
            <th scope="col">Warnings</th>
          </tr>
        </thead>
        <tbody>
          {data.hourly.map((b) => (
            <tr key={b.hour}>
              <th scope="row">{`${hh(b.hour)}:00`}</th>
              <td>{b.errors}</td>
              <td>{b.warnings}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Figure>
  );
}

export function EvtxChartsView({
  records,
  chains,
  hideRules,
  channelOrder,
  timeZoneMode,
  windowLabel,
  metrics,
  visualTokens,
}: EvtxChartsViewProps) {
  const data = useMemo(
    () => buildEvtxChartData({ records, chains, hideRules, channelOrder, timeZoneMode }),
    [records, chains, hideRules, channelOrder, timeZoneMode],
  );

  if (data.totalEvents === 0) {
    return (
      <div
        role="status"
        style={{ padding: 24, fontFamily: LOG_UI_FONT_FAMILY, fontSize: metrics.fontSize, color: tokens.colorNeutralForeground3 }}
      >
        No events to chart. Load events or relax the filters.
      </div>
    );
  }

  return (
    <div
      data-testid="evtx-charts-view"
      style={{ padding: 12, display: "flex", flexDirection: "column", gap: 12, fontFamily: LOG_UI_FONT_FAMILY, overflow: "auto", minHeight: 0 }}
    >
      <div style={{ display: "grid", gridTemplateColumns: "repeat(6, minmax(0, 1fr))", gap: 10 }}>
        {data.kpis.map((kpi) => (
          <KpiCard key={kpi.id} kpi={kpi} windowLabel={windowLabel} metrics={metrics} />
        ))}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 12 }}>
        <ChannelFigure data={data} metrics={metrics} visualTokens={visualTokens} />
        <TopIdsFigure data={data} metrics={metrics} visualTokens={visualTokens} />
        <HeatMapFigure data={data} metrics={metrics} visualTokens={visualTokens} timeZoneMode={timeZoneMode} />
        <HourlyFigure data={data} metrics={metrics} visualTokens={visualTokens} timeZoneMode={timeZoneMode} />
      </div>
    </div>
  );
}

export default EvtxChartsView;
