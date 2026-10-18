/**
 * Contrast in all seven themes for the rail's Chains tab (spec 10, #841): every text reaches 4.5:1
 * and every mark 3:1, measured on what the component DRAWS (the colors and surfaces it wrote into the
 * DOM, resolved in each theme), not on a copy of its rules. A scene holds every surface the tab has: a
 * plain card, the selected event's card (the selection triplet), compact rows, the legend with its
 * dotted entry, the notices, the open nearby group, and the Not placed card.
 *
 * The pair a text sits on is read from the DOM: its own color, or the nearest ancestor's, against its
 * own surface, or the nearest ancestor's, or the rail's (`colorNeutralBackground2`) where none is set.
 * The kind chip and the strength badge write their own pair and are measured in their own tests as
 * well as here.
 */
import { tokens } from "@fluentui/react-components";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes } from "../../lib/themes";
import type { ThemeId } from "../../lib/themes/types";
import { useUiStore } from "../../stores/ui-store";
import EvtxRailChains from "./EvtxRailChains";
import { T0, eventItem, fixtureEdges, idsOf, makeData, numberOf, recordFor } from "./evtx-correlation-test-fixtures";
import { useEvtxCorrelationStore } from "./evtx-correlation-store";
import { useEvtxStore } from "./evtx-store";
import { resolveToken } from "./evtx-visual-tokens";
import { EvtxCorrelationProvider } from "./useEvtxCorrelation";

const TEXT_FLOOR = 4.5;
const MARK_FLOOR = 3;
const themes = getAllThemes();
const { themeId: INITIAL_THEME_ID, logListFontSize: INITIAL_FONT_SIZE } = useUiStore.getState();

beforeEach(() => {
  useEvtxCorrelationStore.setState({ selectedChainId: null, unplacedOpen: false, openedCount: 0 });
});
afterEach(() => {
  cleanup();
  useUiStore.setState({ themeId: INITIAL_THEME_ID, logListFontSize: INITIAL_FONT_SIZE });
});

/** `rgb(r, g, b)` as `#rrggbb`; anything else as it is. */
function toHex(color: string): string {
  const rgb = /^rgb\(\s*(\d+),\s*(\d+),\s*(\d+)\s*\)$/.exec(color);
  if (!rgb) return color;
  return `#${[rgb[1], rgb[2], rgb[3]].map((part) => Number(part).toString(16).padStart(2, "0")).join("")}`;
}

function scene() {
  const edges = [
    ...fixtureEdges("pairAndGroupDisjoint"),
    ...fixtureEdges("secondaryPair", 10),
    ...fixtureEdges("gappedPair", 20),
  ];
  const items = idsOf(edges).map((id) => eventItem(numberOf(id), T0 + numberOf(id) * 1_000, numberOf(id) % 2 === 0 ? "error" : "warning"));
  return makeData({
    items,
    edges,
    totalEdges: edges.length + 5,
    scope: { visibleCount: 3, loadedCount: 9, textLogCount: 2 },
    unplacedList: { items: [], total: 3 },
    scan: { state: "incomplete", stoppedBy: "budget", error: null },
  });
}

function renderIn(themeId: string, fontSize = 13) {
  useUiStore.setState({ themeId: themeId as ThemeId, logListFontSize: fontSize });
  useEvtxStore.getState().reset();
  const records = [recordFor(1), recordFor(2)];
  useEvtxStore.setState({ records, selectedRecordId: 1, isLoading: false, timeZoneMode: "utc" });
  const view = render(
    <EvtxCorrelationProvider value={scene()}>
      <EvtxRailChains nearby={[eventItem(60, T0 + 3_000)]} />
    </EvtxCorrelationProvider>,
  );
  // The nearby group is collapsed until opened: its rows are measured open.
  fireEvent.click(screen.getByText(/^Nearby, /));
  return view;
}

const colorOf = (node: HTMLElement): string | null => {
  for (let current: HTMLElement | null = node; current !== null; current = current.parentElement) {
    if (current.style.color !== "") return current.style.color;
  }
  return null;
};
const surfaceOf = (node: HTMLElement): string => {
  for (let current: HTMLElement | null = node; current !== null; current = current.parentElement) {
    const background = current.style.backgroundColor;
    if (background !== "" && background !== "transparent") return background;
  }
  // The rail's own surface, where the tab sits.
  return tokens.colorNeutralBackground2;
};

/** Every element that holds text of its own and is not decoration. */
function textNodes(container: HTMLElement): HTMLElement[] {
  const found: HTMLElement[] = [];
  const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT);
  for (let node = walker.nextNode(); node !== null; node = walker.nextNode()) {
    const owner = node.parentElement;
    if (owner === null || (node.textContent ?? "").trim() === "") continue;
    if (owner.closest("[aria-hidden='true']") !== null) continue;
    if (owner.closest("button:not([data-rail-chain] a)") !== null && owner.closest("[class*='fui-Button']") !== null) continue;
    if (!found.includes(owner)) found.push(owner);
  }
  return found;
}

describe.each(themes.map((theme) => [theme.id, theme] as const))("the Chains tab in %s", (themeId, theme) => {
  const resolve = (value: string) => toHex(resolveToken(value, theme));

  it("reaches 4.5:1 for every text it draws, on the surface it sits on", () => {
    const { container } = renderIn(themeId);
    const measured: string[] = [];
    const failing: string[] = [];
    for (const owner of textNodes(container)) {
      const color = colorOf(owner);
      // The text of a library control (a Fluent button) takes its color from the library's class.
      if (color === null) continue;
      const ratio = contrastRatio(resolve(color), resolve(surfaceOf(owner)));
      measured.push(owner.textContent!.trim().slice(0, 24));
      if (ratio < TEXT_FLOOR) failing.push(`${ratio.toFixed(2)}:1 "${owner.textContent!.trim().slice(0, 40)}"`);
    }
    // Not vacuous: the scene's titles, spans, steps, notices, legend, notes and the card are all read.
    expect(measured.length).toBeGreaterThan(40);
    expect(failing).toEqual([]);
  });

  it("reaches 3:1 for the level dots, against the card they sit on", () => {
    const { container } = renderIn(themeId);
    const dots = Array.from(container.querySelectorAll<HTMLElement>('[data-step-part="dot"]'));
    expect(dots.length).toBeGreaterThan(3);
    const failing: string[] = [];
    for (const dot of dots) {
      const surface = resolve(surfaceOf(dot.parentElement!));
      const onSelected = dot.closest("[data-rail-chain]")?.getAttribute("aria-current") === "true";
      // On the selected card the mark is the dot AND its 1 px outline in the selection foreground:
      // the outline is what must stand off the card; elsewhere the fill is.
      const mark = onSelected
        ? resolve(/var\([^)]*\)|rgb\([^)]*\)|#[0-9a-f]{6}/i.exec(dot.style.border)![0])
        : resolve(dot.style.backgroundColor);
      const ratio = contrastRatio(mark, surface);
      if (ratio < MARK_FLOOR) failing.push(`${ratio.toFixed(2)}:1 ${dot.getAttribute("aria-label")} (${onSelected ? "outline" : "fill"})`);
    }
    expect(failing).toEqual([]);
    expect(dots.some((dot) => dot.closest("[data-rail-chain]")?.getAttribute("aria-current") === "true")).toBe(true);
  });

  it("reaches 3:1 for the legend's lines and its dotted marker, against the rail", () => {
    const { container } = renderIn(themeId);
    const legend = screen.getByRole("group", { name: "Legend" });
    const rail = resolve(tokens.colorNeutralBackground2);
    const lines = Array.from(legend.querySelectorAll<SVGLineElement>("line"));
    expect(lines).toHaveLength(2);
    for (const line of lines) {
      expect(contrastRatio(resolve(line.style.stroke), rail), `${line.getAttribute("stroke-dasharray") ?? "solid"}`).toBeGreaterThanOrEqual(MARK_FLOOR);
    }
    const dotted = Array.from(legend.querySelectorAll<HTMLElement>("span[aria-hidden='true']")).find((node) =>
      node.style.border.includes("dotted"),
    )!;
    const outline = /var\([^)]*\)|rgb\([^)]*\)|#[0-9a-f]{6}/i.exec(dotted.style.border)![0];
    expect(contrastRatio(resolve(outline), rail)).toBeGreaterThanOrEqual(MARK_FLOOR);
    void container;
  });

  it("draws the selected event's card in the selection triplet, with its text in the selection foreground", () => {
    const { container } = renderIn(themeId);
    const selected = container.querySelector<HTMLElement>("[data-rail-chain][aria-current='true']")!;
    expect(selected).not.toBeNull();
    expect(selected.style.backgroundColor).toBe(tokens.colorPaletteBlueBackground2);
    const title = selected.querySelector<HTMLElement>('[data-rail-part="title"]')!;
    expect(colorOf(title)).toBe(tokens.colorPaletteBlueForeground2);
    const message = selected.querySelector<HTMLElement>('[data-step-part="message"]')!;
    expect(colorOf(message)).toBe(tokens.colorPaletteBlueForeground2);
  });

  it("reaches 4.5:1 for the strength badge of every row, on the card it is on", () => {
    const { container } = renderIn(themeId);
    for (const badge of container.querySelectorAll<HTMLElement>("[data-strength-badge]")) {
      const surface = surfaceOf(badge.parentElement!);
      expect(contrastRatio(resolve(badge.style.color), resolve(badge.style.backgroundColor)), badge.getAttribute("data-strength-badge")!).toBeGreaterThanOrEqual(TEXT_FLOOR);
      void surface;
    }
  });
});
