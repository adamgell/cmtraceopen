/**
 * The lane plot draws what `buildChainPlot` decided, and nothing it did not: a connector only for
 * a backed exact or candidate edge, styled by ITS strength; a "Not linked" marker with no
 * connector; a pinned entry with a faded fill and a full-strength ring and label. Real engine
 * output (`__fixtures__/correlation-edges.json`) drives the shapes; synthetic edges cover the
 * mixed chain the engine cannot yet produce.
 */
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { tokens } from "@fluentui/react-components";
import fixtureDocument from "./__fixtures__/correlation-edges.json";
import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
import {
  CONNECTOR_STYLES,
  CORRELATION_LANE_LABEL_PX,
  CORRELATION_MARKER_HIT_PX,
  CORRELATION_MARKER_PX,
  CorrelationLegend,
  EvtxCorrelationLanes,
  PINNED_FILL_OPACITY,
  correlationSizes,
} from "./EvtxCorrelationLanes";
import { buildCorrelationChains, type CorrelationChain } from "./evtx-correlation-chains";
import { classifyCoverageGaps } from "./evtx-correlation-gaps";
import { pickRailTextColors } from "./evtx-rail-text";
import { buildChainPlot, type ChainPlot, type PlotMarker } from "./evtx-correlation-view-model";
import { formatClock } from "./evtx-time";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";
import lanesSource from "./EvtxCorrelationLanes.tsx?raw";
import {
  assertUnifiedTimelineShape,
  timelineOriginId,
  type TimelineCorrelationEdge,
  type TimelineItem,
  type TimelineSeverity,
} from "./unified-timeline";

const rid = (n: number) => `source4:Live|machine10:DESKTOP-01|channel6:System|record${n}`;
const T0 = Date.UTC(2026, 9, 6, 10, 20, 0);
const VIEW = { edgeInputComplete: true, narrowed: false, gaps: classifyCoverageGaps([], 0) };
const SIZES = correlationSizes(14);

function fixtureEdges(name: string): TimelineCorrelationEdge[] {
  const scenarios = fixtureDocument.scenarios as unknown as Record<
    string,
    { edges: unknown[]; coverageGaps: unknown[] }
  >;
  const scenario = scenarios[name];
  if (scenario === undefined) throw new Error(`no fixture scenario ${name}`);
  return assertUnifiedTimelineShape({
    items: [],
    unplaced: [],
    edges: scenario.edges,
    coverageGaps: scenario.coverageGaps,
  }).edges;
}

function eventItem(
  n: number,
  timestampMs: number,
  severity: TimelineSeverity = "info",
  channel = "System",
): TimelineItem {
  return {
    timestampMs,
    severity,
    message: `message ${n}`,
    origin: {
      kind: "event",
      stableId: rid(n),
      source: "Live",
      machine: "DESKTOP-01",
      bundle: null,
      channel,
      provider: "P",
      processId: null,
      eventId: 100 + n,
      recordId: n,
    },
  };
}

function logItem(file: string, line: number, timestampMs: number): TimelineItem {
  return {
    timestampMs,
    severity: "info",
    message: `log line ${line}`,
    origin: {
      kind: "log",
      file,
      component: null,
      line,
      source: "writer.cpp",
      machine: null,
      bundle: null,
      recordId: line,
    },
  };
}

const mapOf = (items: TimelineItem[]) =>
  new Map(items.map((item) => [timelineOriginId(item.origin), item]));

function synthetic(
  id: string,
  fromId: string,
  toId: string,
  strength: TimelineCorrelationEdge["strength"] = "exact",
): TimelineCorrelationEdge {
  return {
    id,
    fromId,
    toId,
    key: { kind: "activityId", value: `key-${id}` },
    strength,
    confidence: "high",
    candidateIds: [],
    evidence: [
      { originId: fromId, field: "activityId", value: `key-${id}` },
      { originId: toId, field: "activityId", value: `key-${id}` },
    ],
    coverage: { state: "covered" },
  };
}

function chainOf(edges: TimelineCorrelationEdge[], items: TimelineItem[]): CorrelationChain {
  const model = buildCorrelationChains({
    items,
    timelineEdges: edges,
    totalTimelineEdges: edges.length,
    findings: [],
  });
  const chain = model.chains[0];
  if (chain === undefined) throw new Error("no chain");
  return chain;
}

const markerName = (marker: PlotMarker) =>
  `${marker.entry}, ${marker.level}${marker.linkLabel === null ? "" : `, ${marker.linkLabel}`}`;

function draw(plot: ChainPlot, extra: Partial<Parameters<typeof EvtxCorrelationLanes>[0]> = {}) {
  return render(
    <EvtxCorrelationLanes
      plot={plot}
      timeZoneMode="utc"
      sizes={SIZES}
      label="Lane plot for test chain"
      markerName={markerName}
      {...extra}
    />,
  );
}

const pair = () => [eventItem(1, T0), eventItem(2, T0 + 6_000)];
const exactPlot = (extra: { nearby?: TimelineItem[]; window?: { startMs: number; endMs: number } } = {}) =>
  buildChainPlot({
    chain: chainOf(fixtureEdges("exactPair"), pair()),
    itemsById: mapOf(pair()),
    ...VIEW,
    ...extra,
  });

beforeEach(() => {
  useUiStore.setState({ themeId: "light" });
});
afterEach(cleanup);

describe("the lanes and markers", () => {
  it("names the figure and draws one lane per source with a marker per drawn entry", () => {
    const logs = [logItem("C:\\Logs\\AppEnforce.log", 3, T0 + 1_000)];
    const items = [...pair(), ...logs, eventItem(4, T0 + 2_000, "info", "Application")];
    const plot = buildChainPlot({
      chain: chainOf(fixtureEdges("exactPair"), pair()),
      itemsById: mapOf(items),
      ...VIEW,
      nearby: [...logs, items[3]!],
    });
    draw(plot);
    expect(screen.getByRole("figure", { name: "Lane plot for test chain" })).toBeInTheDocument();
    expect(Array.from(document.querySelectorAll("[data-lane-label]")).map((n) => n.textContent)).toEqual([
      "Application",
      "System",
      "AppEnforce.log",
    ]);
    expect(Array.from(document.querySelectorAll("[data-marker]")).map((n) => n.getAttribute("data-marker"))).toHaveLength(4);
    expect(document.querySelectorAll('[data-kind="event"]')).toHaveLength(3);
    expect(document.querySelectorAll('[data-kind="log"]')).toHaveLength(1);
  });

  it("says plainly that nothing can be plotted when no entry has a loaded position", () => {
    const plot = buildChainPlot({
      chain: chainOf(fixtureEdges("exactPair"), []),
      itemsById: new Map(),
      ...VIEW,
    });
    draw(plot);
    expect(screen.getByRole("figure")).toHaveTextContent(
      "No entry of this chain has a loaded timeline position, so there is nothing to plot.",
    );
    expect(document.querySelectorAll("[data-marker]")).toHaveLength(0);
    expect(screen.getByRole("figure").textContent).not.toMatch(/not placed|no timestamp/i);
  });

  it("gives every marker its accessible name and a 24 px box around a 14 px glyph", () => {
    draw(exactPlot());
    const first = screen.getByRole("button", { name: "101 · System, Information" });
    expect(first).toBeInTheDocument();
    expect(CORRELATION_MARKER_PX).toBe(14);
    expect(first.className).toBeTruthy();
    expect(CORRELATION_MARKER_HIT_PX).toBeGreaterThanOrEqual(24);
    const glyph = first.firstElementChild as HTMLElement;
    expect(glyph.style.width).toBe("14px");
    expect(glyph.style.height).toBe("14px");
  });

  it("draws an event as a circle and a log line as a 3 px rounded square", () => {
    const items = [eventItem(1, T0), logItem("C:\\Logs\\A.log", 1, T0 + 1_000)];
    const plot = buildChainPlot({
      chain: chainOf(fixtureEdges("exactPair"), pair()),
      itemsById: mapOf([...pair(), items[1]!]),
      ...VIEW,
      nearby: [items[1]!],
    });
    draw(plot);
    const glyph = (selector: string) =>
      (document.querySelector(selector) as HTMLElement).firstElementChild as HTMLElement;
    expect(glyph('[data-kind="event"]').style.borderRadius).toBe("50%");
    expect(glyph('[data-kind="log"]').style.borderRadius).toBe("3px");
  });

  it("sizes the text by spec 7.1 from the log list font size: literal numbers at the default 13 px, and at both ends", () => {
    // f - 2 for lane labels, max(10, f - 3) for captions, max(9, f - 4) for axis ticks.
    expect(correlationSizes(13)).toEqual({ f: 13, lane: 11, label: 10, tick: 9 });
    expect(correlationSizes(11)).toEqual({ f: 11, lane: 9, label: 10, tick: 9 });
    expect(correlationSizes(20)).toEqual({ f: 20, lane: 18, label: 17, tick: 16 });
  });

  it("paints the lane label, marker label and axis tick at those sizes at the default 13 px", () => {
    draw(exactPlot({ window: { startMs: T0 + 2_000, endMs: T0 + 3_000 } }), { sizes: correlationSizes(13) });
    expect((document.querySelector("[data-lane-label]") as HTMLElement).style.fontSize).toBe("11px");
    expect((document.querySelector("[data-marker-label]") as HTMLElement).style.fontSize).toBe("10px");
    expect(((document.querySelector("[data-axis]") as HTMLElement).firstElementChild as HTMLElement).style.fontSize).toBe(
      "9px",
    );
  });

  it("follows the font size when it is raised, and labels the lane column at 184 px", () => {
    draw(exactPlot(), { sizes: correlationSizes(20) });
    expect((document.querySelector("[data-lane-label]") as HTMLElement).style.fontSize).toBe("18px");
    expect(((document.querySelector("[data-axis]") as HTMLElement).firstElementChild as HTMLElement).style.fontSize).toBe(
      "16px",
    );
    expect(CORRELATION_LANE_LABEL_PX).toBe(184);
  });

  it("draws five axis ticks in the chosen time zone", () => {
    const plot = exactPlot();
    draw(plot);
    const ticks = Array.from((document.querySelector("[data-axis]") as HTMLElement).children).map((n) => n.textContent);
    expect(ticks).toEqual(plot.ticks.map((tick) => formatClock(tick, "utc", true)));
    expect(ticks).toHaveLength(5);
  });
});

describe("connectors (acceptance 3 and 4)", () => {
  it("draws an exact connector 2.5 px solid with a non-scaling stroke in the exact color", () => {
    const visuals = buildEvtxVisualTokens(getAllThemes()[0]!);
    draw(exactPlot());
    const lines = document.querySelectorAll<SVGLineElement>("line[data-connector]");
    expect(lines).toHaveLength(1);
    const line = lines[0]!;
    expect(line.getAttribute("data-strength")).toBe("exact");
    expect(line.getAttribute("stroke-width")).toBe("2.5");
    expect(line.getAttribute("stroke-dasharray")).toBeNull();
    expect(line.style.vectorEffect).toBe("non-scaling-stroke");
    expect(line.style.stroke).toBe(visuals.strengths.exact.border);
    expect(line.closest("svg")?.getAttribute("aria-hidden")).toBe("true");
  });

  it("styles each connector by ITS edge, so a candidate chain with an exact edge draws both", () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 2_000), eventItem(3, T0 + 4_000)];
    const edges = [
      synthetic("e1", rid(1), rid(2), "exact"),
      synthetic("e2", rid(2), rid(3), "candidate"),
    ];
    const chain = chainOf(edges, items);
    expect(chain.strength).toBe("candidate");
    draw(buildChainPlot({ chain, itemsById: mapOf(items), ...VIEW }));
    const lines = Array.from(document.querySelectorAll<SVGLineElement>("line[data-connector]"));
    expect(lines.map((line) => line.getAttribute("data-strength")).sort()).toEqual(["candidate", "exact"]);
    const candidate = lines.find((line) => line.getAttribute("data-strength") === "candidate")!;
    expect(candidate.getAttribute("stroke-width")).toBe("1.5");
    expect(candidate.getAttribute("stroke-dasharray")).toBe("5 4");
    const exact = lines.find((line) => line.getAttribute("data-strength") === "exact")!;
    expect(exact.getAttribute("stroke-width")).toBe("2.5");
    expect(exact.getAttribute("stroke-dasharray")).toBeNull();
    expect(exact.style.stroke).not.toBe(candidate.style.stroke);
    expect(CONNECTOR_STYLES.exact.width).toBe(2.5);
    expect(CONNECTOR_STYLES.candidate.dash).toBe("5 4");
  });

  it.each([
    ["an ambiguous group", "group3"],
    ["a coverage blocked pair", "gappedPair"],
  ])("draws no connector for %s, only unconnected markers", (_why, scenario) => {
    const edges = fixtureEdges(scenario);
    const ids = [...new Set(edges.flatMap((edge) => [edge.fromId, edge.toId].filter((id): id is string => typeof id === "string")))];
    const items = ids.map((id, index) => {
      const n = Number(/record(\d+)$/.exec(id)?.[1] ?? index + 1);
      return eventItem(n, T0 + index * 1_000);
    });
    const chain = chainOf(edges, items);
    expect(["ambiguous", "coverageBlocked"]).toContain(chain.strength);
    draw(buildChainPlot({ chain, itemsById: mapOf(items), ...VIEW }));
    expect(document.querySelectorAll("line[data-connector]")).toHaveLength(0);
    expect(document.querySelectorAll('[data-role="member"]').length).toBeGreaterThan(0);
  });

  it("draws no connector for an edge whose evidence is missing", () => {
    const items = pair();
    const edge = { ...synthetic("e1", rid(1), rid(2)), evidence: [] };
    draw(buildChainPlot({ chain: chainOf([edge], items), itemsById: mapOf(items), ...VIEW }));
    expect(document.querySelectorAll("line[data-connector]")).toHaveLength(0);
  });
});

describe("a 'Not linked' marker (acceptance 2, decision A on #838)", () => {
  const stray = () => eventItem(9, T0 + 3_000, "warning");
  const withStray = (gaps = VIEW.gaps) =>
    buildChainPlot({
      chain: chainOf(fixtureEdges("exactPair"), pair()),
      itemsById: mapOf([...pair(), stray()]),
      ...VIEW,
      gaps,
      nearby: [stray()],
    });

  it("is drawn with a dotted outline, no fill and no connector, labelled by the plot", () => {
    draw(withStray());
    const marker = document.querySelector<HTMLElement>('[data-role="nearby"]')!;
    expect(marker).not.toBeNull();
    expect(marker.getAttribute("aria-label")).toBe("109 · System, Warning, Not linked");
    const glyph = marker.firstElementChild as HTMLElement;
    // Spec 6.3: a 1 px dotted outline.
    expect(glyph.style.border).toContain("1px dotted");
    expect(glyph.style.backgroundColor).toBe("transparent");
    expect(glyph.querySelector("[data-marker-fill]")).toBeNull();
    // The chain's own connector is the only line: the context marker has none.
    expect(document.querySelectorAll("line[data-connector]")).toHaveLength(1);
  });

  it("draws nothing when there is no context entry, which is what production passes", () => {
    draw(exactPlot());
    expect(document.querySelectorAll('[data-role="nearby"]')).toHaveLength(0);
  });

  it("shows its legend entry only when such a marker is drawn, in the plot's own words", () => {
    const { rerender } = render(<CorrelationLegend plot={exactPlot()} sizes={SIZES} />);
    let legend = screen.getByRole("group", { name: "Legend" });
    expect(legend.textContent).not.toMatch(/not linked|no loaded link/i);
    rerender(<CorrelationLegend plot={withStray()} sizes={SIZES} />);
    legend = screen.getByRole("group", { name: "Legend" });
    expect(legend).toHaveTextContent("not linked (no line)");
    rerender(<CorrelationLegend plot={withStray(classifyCoverageGaps([], null))} sizes={SIZES} />);
    legend = screen.getByRole("group", { name: "Legend" });
    expect(legend).toHaveTextContent("no loaded link (no line)");
    expect(legend.textContent).not.toMatch(/not linked/i);
  });

  it("lists exact, candidate and the two marker shapes in the legend", () => {
    render(<CorrelationLegend plot={exactPlot()} sizes={SIZES} />);
    const legend = screen.getByRole("group", { name: "Legend" });
    for (const word of ["exact", "candidate", "Event", "Log line"]) {
      expect(within(legend).getByText(word)).toBeInTheDocument();
    }
    expect(legend.querySelectorAll("line")).toHaveLength(2);
  });

  it("draws the not-linked entry as a 1 px dotted outline, like the marker (spec 6.3)", () => {
    render(<CorrelationLegend plot={withStray()} sizes={SIZES} />);
    const swatch = Array.from(screen.getByRole("group", { name: "Legend" }).querySelectorAll<HTMLElement>("span[aria-hidden='true']")).find(
      (node) => node.style.border.includes("dotted"),
    );
    expect(swatch).toBeDefined();
    expect(swatch!.style.border).toContain("1px dotted");
  });
});

describe("a pinned entry (acceptance 14, ruling 15)", () => {
  // A window that leaves 101 outside to the left and 102 outside to the right.
  const window = { startMs: T0 + 2_000, endMs: T0 + 3_000 };

  it("is pinned at the edge with an arrow and how far outside the window it is", () => {
    draw(exactPlot({ window }));
    const before = document.querySelector<HTMLElement>(`[data-marker="${rid(1)}"]`)!;
    const after = document.querySelector<HTMLElement>(`[data-marker="${rid(2)}"]`)!;
    expect(before.getAttribute("data-pinned")).toBe("before");
    expect(after.getAttribute("data-pinned")).toBe("after");
    const labels = Array.from(document.querySelectorAll("[data-marker-label]"));
    expect(labels.map((n) => n.textContent?.trim())).toEqual(["101 · 2 s earlier", "102 · 3 s later"]);
    expect(labels[0]?.querySelector("svg")).not.toBeNull();
    expect(labels[1]?.querySelector("svg")).not.toBeNull();
    // The arrow is a decoration; the words carry the direction.
    expect(labels[0]?.querySelector("svg")?.getAttribute("aria-hidden")).toBe("true");
  });

  it("fades the fill alone: the ring and the label stay at full strength", () => {
    draw(exactPlot({ window }));
    const pinned = document.querySelector<HTMLElement>(`[data-marker="${rid(1)}"]`)!;
    const ring = pinned.firstElementChild as HTMLElement;
    const fill = pinned.querySelector<HTMLElement>("[data-marker-fill]")!;
    expect(fill.style.opacity).toBe(String(PINNED_FILL_OPACITY));
    expect(ring.style.opacity).toBe("");
    expect(ring.style.boxShadow).toContain("0 0 0 3px");
    expect(pinned.style.opacity).toBe("");
    for (const label of document.querySelectorAll<HTMLElement>("[data-marker-label]")) {
      expect(label.style.opacity).toBe("");
    }
  });

  it("draws an entry inside the window with a fully opaque fill", () => {
    draw(exactPlot());
    for (const fill of document.querySelectorAll<HTMLElement>("[data-marker-fill]")) {
      expect(fill.style.opacity).toBe("1");
    }
    expect(document.querySelector("[data-pinned]")).toBeNull();
  });
});

describe("keyboard", () => {
  const three = () => {
    const items = [eventItem(1, T0), eventItem(2, T0 + 2_000), eventItem(3, T0 + 4_000)];
    const edges = [synthetic("e1", rid(1), rid(2)), synthetic("e2", rid(2), rid(3))];
    return buildChainPlot({ chain: chainOf(edges, items), itemsById: mapOf(items), ...VIEW });
  };
  const buttons = () => Array.from(document.querySelectorAll<HTMLButtonElement>("button[data-marker]"));

  it("is one tab stop: the first marker, then whichever has focus", () => {
    draw(three());
    expect(buttons().map((b) => b.tabIndex)).toEqual([0, -1, -1]);
    fireEvent.focus(buttons()[2]!);
    expect(buttons().map((b) => b.tabIndex)).toEqual([-1, -1, 0]);
  });

  it("moves between markers in sequence order with the arrow keys, Home and End", () => {
    draw(three());
    const [a, b, c] = buttons() as [HTMLButtonElement, HTMLButtonElement, HTMLButtonElement];
    a.focus();
    fireEvent.keyDown(a, { key: "ArrowRight" });
    expect(b).toHaveFocus();
    fireEvent.keyDown(b, { key: "ArrowRight" });
    expect(c).toHaveFocus();
    fireEvent.keyDown(c, { key: "ArrowRight" });
    expect(c).toHaveFocus();
    fireEvent.keyDown(c, { key: "ArrowLeft" });
    expect(b).toHaveFocus();
    fireEvent.keyDown(b, { key: "Home" });
    expect(a).toHaveFocus();
    fireEvent.keyDown(a, { key: "End" });
    expect(c).toHaveFocus();
  });

  it("activates a marker on click, and lets Enter and Space through to the button's own activation", () => {
    const onActivate = vi.fn();
    draw(three(), { onActivate });
    const [a] = buttons();
    // A browser turns Enter (on keydown) and Space (on keyup) on a button into this click; jsdom
    // does not, so the click is what it dispatches.
    fireEvent.click(a!);
    expect(onActivate).toHaveBeenCalledTimes(1);
    expect(onActivate.mock.calls[0]?.[0].id).toBe(rid(1));
    // The component must not swallow the keys that make the browser dispatch it.
    expect(fireEvent.keyDown(a!, { key: "Enter" })).toBe(true);
    expect(fireEvent.keyDown(a!, { key: " " })).toBe(true);
    expect(fireEvent.keyUp(a!, { key: " " })).toBe(true);
    expect(fireEvent.keyUp(a!, { key: "Enter" })).toBe(true);
    expect(a!.tagName).toBe("BUTTON");
    expect(a!.getAttribute("type")).toBe("button");
  });

  it("hands Escape to the view and prevents the default, so the workspace does not clear the time range", () => {
    const onEscape = vi.fn();
    draw(three(), { onEscape });
    const workspaceEscape = vi.fn();
    window.addEventListener("keydown", workspaceEscape);
    const notCancelled = fireEvent.keyDown(buttons()[0]!, { key: "Escape" });
    window.removeEventListener("keydown", workspaceEscape);
    expect(onEscape).toHaveBeenCalledTimes(1);
    expect(notCancelled).toBe(false);
    expect(workspaceEscape.mock.calls[0]?.[0].defaultPrevented).toBe(true);
  });

  it("prevents the default of the keys it handles so the page does not scroll", () => {
    draw(three());
    for (const key of ["ArrowRight", "ArrowLeft", "Home", "End"]) {
      expect(fireEvent.keyDown(buttons()[1]!, { key }), key).toBe(false);
    }
    expect(fireEvent.keyDown(buttons()[1]!, { key: "a" })).toBe(true);
  });
});

describe("colors are tokens, never literals", () => {
  it("has no color literal in the component source", () => {
    expect(lanesSource).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
    expect(lanesSource).not.toMatch(/\brgba?\(/);
    expect(lanesSource).not.toMatch(/\bhsla?\(/);
  });
});

/**
 * Contrast in all seven themes (spec 10). Each pair is measured on resolved theme colors; the DOM
 * half compares the painted element's own color (stroke, ring, outline, label text) with the same
 * token. The surface the pair sits on (the plot's background) is not read back from the DOM, so a
 * change to that token alone would not fail here. The 55% fill is not measured: it is the one
 * thing that fades, and the full-strength ring beside it is what is measured (this is the
 * deviation from the spec's whole-marker fade).
 */
describe.each(getAllThemes().map((theme) => [theme.id, theme] as const))(
  "lane plot contrast in the %s theme",
  (id, theme) => {
    const r = (token: string) => resolveToken(token, theme);
    const atLeast = (label: string, a: string, b: string, minimum: number) => {
      expect(contrastRatio(r(a), r(b)), `${id}: ${label}`).toBeGreaterThanOrEqual(minimum);
    };

    beforeEach(() => {
      useUiStore.setState({ themeId: theme.id });
    });

    it("keeps the connectors, the level rings and the not-linked outline at 3:1 on the plot", () => {
      const visuals = buildEvtxVisualTokens(theme);
      atLeast("exact connector", visuals.strengths.exact.border, tokens.colorNeutralBackground1, 3);
      atLeast("candidate connector", visuals.strengths.candidate.border, tokens.colorNeutralBackground1, 3);
      atLeast("not-linked outline", visuals.strengths.notCausal.border, tokens.colorNeutralBackground1, 3);
      for (const level of ["Critical", "Error", "Warning", "Information", "Verbose"] as const) {
        atLeast(`${level} ring`, visuals.levels[level].dotColor, tokens.colorNeutralBackground1, 3);
      }
    });

    it("paints the connectors, rings and outline with exactly those tokens", () => {
      const visuals = buildEvtxVisualTokens(theme);
      const items = [eventItem(1, T0, "error"), eventItem(2, T0 + 2_000), eventItem(3, T0 + 4_000)];
      const chain = chainOf(
        [synthetic("e1", rid(1), rid(2), "exact"), synthetic("e2", rid(2), rid(3), "candidate")],
        items,
      );
      draw(
        buildChainPlot({
          chain,
          itemsById: mapOf([...items, eventItem(9, T0 + 3_000)]),
          ...VIEW,
          nearby: [eventItem(9, T0 + 3_000)],
        }),
      );
      const strokes = Object.fromEntries(
        Array.from(document.querySelectorAll<SVGLineElement>("line[data-connector]")).map((line) => [
          line.getAttribute("data-strength"),
          line.style.stroke,
        ]),
      );
      expect(strokes).toEqual({
        exact: visuals.strengths.exact.border,
        candidate: visuals.strengths.candidate.border,
      });
      const error = document.querySelector<HTMLElement>(`[data-marker="${rid(1)}"]`)!;
      expect(error.firstElementChild?.getAttribute("style")).toContain(visuals.levels.Error.dotColor);
      const nearby = document.querySelector<HTMLElement>('[data-role="nearby"]')!;
      expect((nearby.firstElementChild as HTMLElement).style.border).toContain(visuals.strengths.notCausal.border);
    });

    it("reads the lane labels, marker labels and axis at 4.5:1 on the plot", () => {
      const rail = pickRailTextColors(theme);
      atLeast("lane label", tokens.colorNeutralForeground2, tokens.colorNeutralBackground1, 4.5);
      atLeast("caption text", rail.cardSecondary, tokens.colorNeutralBackground1, 4.5);
      draw(exactPlot({ window: { startMs: T0 + 2_000, endMs: T0 + 3_000 } }));
      expect((document.querySelector("[data-lane-label]") as HTMLElement).style.color).toBe(
        tokens.colorNeutralForeground2,
      );
      for (const label of document.querySelectorAll<HTMLElement>("[data-marker-label]")) {
        expect(label.style.color).toBe(rail.cardSecondary);
      }
      expect(((document.querySelector("[data-axis]") as HTMLElement).firstElementChild as HTMLElement).style.color).toBe(
        rail.cardSecondary,
      );
    });
  },
);
