/**
 * Contrast of what the correlation dock draws, in all seven themes (spec 10, #842): every text at
 * 4.5:1 and every non-text graphic at 3:1, measured on resolved theme colors for the surface it sits
 * on. The DOM half compares the painted element's own color with the token the pair was measured
 * with, so a color changed in the component alone fails here. The dock's own surface (Background2)
 * is read back from the DOM; the lanes' (Background1) is the lanes' test's.
 *
 * The lanes' own pairs (markers, rings, connectors, the dotted outline, lane labels, axis, the center
 * rule) are measured in EvtxCorrelationLanes.test.tsx; the strength badge's tokens in
 * evtx-visual-tokens.test.ts and EvtxStrengthBadge.test.tsx. This file measures what the dock adds:
 * its header, summary, notices, messages and the legend it draws on its own surface.
 */
import { cleanup, render, screen, within } from "@testing-library/react";
import { tokens } from "@fluentui/react-components";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { EventLogAnalysisTimelineWindow } from "../../lib/commands";
import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
import EvtxCorrelationDock from "./EvtxCorrelationDock";
import { EvtxAnalysisSessionProvider } from "./evtx-analysis-session";
import { CONNECTOR_STYLES } from "./EvtxCorrelationLanes";
import { useEvtxCorrelationStore } from "./evtx-correlation-store";
import { sanitizeLayout, useEvtxLayoutStore } from "./evtx-layout-store";
import { pickRailTextColors } from "./evtx-rail-text";
import { useEvtxStore } from "./evtx-store";
import {
  eventItem,
  fixtureEdges,
  makeData,
  recordFor,
  rid,
  synthetic,
} from "./evtx-correlation-test-fixtures";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";
import type { CorrelationWindowDeps } from "./evtx-correlation-window";
import { EvtxCorrelationProvider } from "./useEvtxCorrelation";
import type { TimelineItem } from "./unified-timeline";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

type QueryWindow = CorrelationWindowDeps["queryWindow"];
const STATUS = { sessionId: "session", revision: 1 };
const T = recordFor(1).timestampEpoch;

function reply(items: TimelineItem[], startMs: number, endMs: number): EventLogAnalysisTimelineWindow {
  const inside = items
    .filter((item) => item.timestampMs >= startMs && item.timestampMs <= endMs)
    .sort((a, b) => a.timestampMs - b.timestampMs);
  return {
    sessionId: STATUS.sessionId,
    revision: STATUS.revision,
    startMs,
    endMs,
    offset: 0,
    nextOffset: null,
    totalItems: items.length,
    windowItems: inside.length,
    omittedItems: 0,
    items: inside,
    serializedBytes: 1_000,
  };
}

async function draw(items: TimelineItem[], options: { unreadSources?: boolean; status?: typeof STATUS | null } = {}) {
  const queryWindow = vi.fn<QueryWindow>(async (_s, startMs, endMs) => reply(items, startMs, endMs));
  useEvtxStore.setState({
    coverageDetails: options.unreadSources === true ? [{ source: "Security", kind: "accessDenied", reason: "needs elevation" }] : [],
  });
  render(
    <EvtxAnalysisSessionProvider value={options.status === undefined ? STATUS : options.status}>
      <EvtxCorrelationProvider
        value={makeData({ items, edges: [...fixtureEdges("exactPair"), synthetic("o", rid(10), rid(11))] })}
      >
        <EvtxCorrelationDock windowDeps={{ queryWindow }} selectionSettleMs={0} sessionSettleMs={0} />
      </EvtxCorrelationProvider>
    </EvtxAnalysisSessionProvider>,
  );
  if (options.status !== null) await screen.findByRole("figure");
}

const scene = (): TimelineItem[] => [
  eventItem(1, T, "error", "the selected event failed"),
  eventItem(2, T + 6_000),
  eventItem(9, T + 3_000, "warning", "context"),
  eventItem(10, T + 4_000),
];

function select(id: number | null) {
  useEvtxStore.getState().reset();
  useEvtxStore.setState({
    records: [1, 2, 9, 10].map(recordFor),
    selectedRecordId: id,
    isLoading: false,
    timeZoneMode: "utc",
  });
}

beforeEach(() => {
  localStorage.clear();
  useEvtxCorrelationStore.setState({ selectedChainId: null, unplacedOpen: false, openedCount: 0 });
  useEvtxLayoutStore.setState({ ...sanitizeLayout(undefined), dockCollapsed: false });
  useUiStore.setState({ logListFontSize: 13 });
  select(1);
});
afterEach(cleanup);

describe.each(getAllThemes().map((theme) => [theme.id, theme] as const))(
  "the correlation dock's contrast in the %s theme",
  (id, theme) => {
    const r = (token: string) => resolveToken(token, theme);
    const surface = r(tokens.colorNeutralBackground2);
    const panel = r(tokens.colorNeutralBackground1);
    const text = (label: string, token: string) =>
      expect(contrastRatio(r(token), surface), `${id}: ${label} on the dock`).toBeGreaterThanOrEqual(4.5);
    const graphic = (label: string, token: string, on: string) =>
      expect(contrastRatio(r(token), on), `${id}: ${label}`).toBeGreaterThanOrEqual(3);
    const rail = pickRailTextColors(theme);

    beforeEach(() => {
      useUiStore.setState({ themeId: theme.id });
    });

    it("reads the title and the summary in the rail's primary text and the subtitle in Foreground2, at 4.5:1", async () => {
      await draw(scene());
      const dock = screen.getByRole("region", { name: "Correlation dock" });
      // The surface every pair below was measured on.
      expect(dock.style.backgroundColor).toBe(tokens.colorNeutralBackground2);
      const title = within(dock).getByText("Correlation");
      expect(title.style.color).toBe(rail.primary);
      text("title", rail.primary);
      expect(screen.getByTestId("correlation-dock-subtitle").style.color).toBe(tokens.colorNeutralForeground2);
      text("subtitle", tokens.colorNeutralForeground2);
      expect(screen.getByTestId("correlation-dock-summary").style.color).toBe(rail.primary);
      text("summary", rail.primary);
    });

    it("reads the key, the steps, 'Also nearby' and the reason in the rail's secondary text, at 4.5:1", async () => {
      await draw(scene());
      expect(screen.getByTestId("correlation-dock-steps").style.color).toBe(rail.secondary);
      expect(screen.getByTestId("correlation-dock-nearby").style.color).toBe(rail.secondary);
      text("steps and nearby", rail.secondary);
      cleanup();
      select(9);
      await draw(scene());
      expect(screen.getByTestId("correlation-dock-open-reason").style.color).toBe(rail.secondary);
    });

    it("reads the notices at Foreground2 and the empty window's sentence in primary, at 4.5:1", async () => {
      await draw(scene(), { unreadSources: true });
      expect(screen.getByTestId("correlation-dock-notices").style.color).toBe(tokens.colorNeutralForeground2);
      text("notices", tokens.colorNeutralForeground2);
      cleanup();
      await draw([eventItem(1, T, "error", "alone")]);
      expect(screen.getByTestId("correlation-dock-empty").style.color).toBe(rail.primary);
    });

    it("reads the messages before a window is drawn in the rail's secondary text, at 4.5:1", async () => {
      select(null);
      await draw(scene(), { status: null });
      expect(screen.getByTestId("correlation-dock-message").style.color).toBe(rail.secondary);
      text("message", rail.secondary);
    });

    it("draws the legend on the dock's own surface: its text at 4.5:1, its lines and dotted outline at 3:1", async () => {
      await draw(scene());
      const legend = screen.getByTestId("correlation-legend");
      for (const label of ["exact", "candidate", "Event", "Log line"]) {
        const item = within(legend).getByText(label);
        expect(item.style.color, label).toBe(rail.cardSecondary);
      }
      text("legend text", rail.cardSecondary);
      const visuals = buildEvtxVisualTokens(theme);
      const lines = Array.from(legend.querySelectorAll<SVGLineElement>("line"));
      expect(lines.map((line) => line.style.stroke)).toEqual([
        visuals.strengths.exact.border,
        visuals.strengths.candidate.border,
      ]);
      expect(CONNECTOR_STYLES.exact.width).toBeGreaterThan(CONNECTOR_STYLES.candidate.width);
      graphic("exact line", visuals.strengths.exact.border, surface);
      graphic("candidate line", visuals.strengths.candidate.border, surface);
      graphic("not-linked outline", visuals.strengths.notCausal.border, surface);
    });

    it("draws the summary's badge in the tokens the 'rail' placement was measured with", async () => {
      await draw(scene());
      const visuals = buildEvtxVisualTokens(theme);
      const badge = screen
        .getByTestId("correlation-dock-summary")
        .querySelector<HTMLElement>('[data-strength-badge="exact"]')!;
      const probe = document.createElement("span");
      probe.style.backgroundColor = visuals.strengths.exact.background;
      probe.style.color = visuals.strengths.exact.foreground;
      expect(badge.style.backgroundColor).toBe(probe.style.backgroundColor);
      expect(badge.style.color).toBe(probe.style.color);
    });

    it("keeps the center rule at 3:1 on the lanes' surface in the dock", async () => {
      await draw(scene());
      const rule = document.querySelector<HTMLElement>("[data-center-rule]")!;
      expect(rule.style.backgroundColor).toBe(tokens.colorNeutralStrokeAccessible);
      graphic("center rule", tokens.colorNeutralStrokeAccessible, panel);
    });
  },
);
