import { tokens } from "@fluentui/react-components";
import { act, cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
import { EvtxHistogram } from "./EvtxHistogram";
import { buildHistogram } from "./evtx-histogram";
import { BRUSH_MIN_CONTRAST, brushPaletteFor, compositeOver, solveBrushOpacity } from "./evtx-histogram-brush";
import { useEvtxStore } from "./evtx-store";
import { resolveToken } from "./evtx-visual-tokens";
import type { EvtxLevel, EvtxRecord } from "./types";

const MINUTE = 60 * 1000;
const FIRST = Date.UTC(2026, 9, 6, 10, 20, 0);
const LEVELS: EvtxLevel[] = ["Critical", "Error", "Warning", "Information", "Verbose"];

const rec = (timestampEpoch: number, level: EvtxLevel, id: number): EvtxRecord =>
  ({
    id,
    eventRecordId: id,
    timestamp: "",
    timestampEpoch,
    provider: "P",
    channel: "System",
    eventId: 1,
    level,
    computer: "C",
    message: "m",
    eventData: [],
    rawXml: "",
    sourceLabel: "System",
  }) as EvtxRecord;

/** Every level in every bucket of a day, so every level's bar is in the range. */
const records = Array.from({ length: 72 * 5 }, (_, i) =>
  rec(FIRST + Math.floor(i / 5) * 20 * MINUTE + (i % 5) * 1000, LEVELS[i % 5], i),
);

beforeEach(() => {
  useEvtxStore.setState({
    timeZoneMode: "utc",
    timeRange: null,
    isLoading: false,
    coverageGaps: [],
    coverageDetails: [],
    tailCoverageGaps: [],
  });
});

afterEach(() => {
  cleanup();
  useEvtxStore.setState({ timeRange: null });
});

const themes = getAllThemes();
type ThemeId = (typeof themes)[number]["id"];

/** `rgb(r, g, b)` or `#rrggbb` as `#rrggbb`. */
function toHex(color: string): string {
  const rgb = /^rgb\(\s*(\d+),\s*(\d+),\s*(\d+)\s*\)$/.exec(color);
  if (!rgb) return color;
  return `#${[rgb[1], rgb[2], rgb[3]].map((part) => Number(part).toString(16).padStart(2, "0")).join("")}`;
}

/** The resolved colour of a `var(--token)` the component wrote, or the plain colour. */
function resolved(value: string, themeId: string): string {
  const theme = themes.find((candidate) => candidate.id === themeId)!;
  return toHex(resolveToken(value, theme));
}

interface PaintModel {
  /** Layers in the order the DOM paints them. */
  order: string[];
  /** Contrast of each level's bar against what is behind it, bars read from the DOM. */
  bars: Record<string, number>;
  /** Contrast of each edge border against the surface and against the wash. */
  edges: { onSurface: number; onWash: number }[];
  opacity: number;
}

/**
 * Paints the rendered layers in the order they appear in the document, onto two sample points: one
 * on empty plot and one inside a bar. A layer that is later in the document paints over the ones
 * before it, so a wash placed after the bars would wash the bars as well.
 */
function paintModel(container: HTMLElement, themeId: string, order?: string[]): PaintModel {
  const surface = resolved(tokens.colorNeutralBackground1, themeId);
  const layers = [...container.querySelectorAll<HTMLElement>("[data-evtx-layer]")];
  const documentOrder = layers.map((layer) => layer.dataset.evtxLayer!);
  const sequence = order ?? documentOrder;
  const washLayer = layers.find((layer) => layer.dataset.evtxLayer === "wash")!;
  const opacity = Number(washLayer.style.opacity);
  const fill = resolved(washLayer.style.backgroundColor, themeId);
  const barColors = new Map<string, string>();
  for (const segment of container.querySelectorAll<HTMLElement>("[data-evtx-level]")) {
    barColors.set(segment.dataset.evtxLevel!, toHex(segment.style.backgroundColor));
  }
  const bars: Record<string, number> = {};
  for (const [level, color] of barColors) {
    let empty = surface;
    let inBar = surface;
    for (const layer of sequence) {
      if (layer === "wash") {
        empty = compositeOver(empty, fill, opacity);
        inBar = compositeOver(inBar, fill, opacity);
      } else if (layer === "bars") {
        inBar = color;
      }
    }
    bars[level] = contrastRatio(inBar, empty);
  }
  const wash = compositeOver(surface, fill, opacity);
  const edges = layers
    .filter((layer) => layer.dataset.evtxLayer === "edge")
    .map((layer) => {
      const color = resolved(/var\([^)]*\)/.exec(layer.style.borderLeft)![0], themeId);
      return { onSurface: contrastRatio(color, surface), onWash: contrastRatio(color, wash) };
    });
  return { order: documentOrder, bars, edges, opacity };
}

function renderBrushed(themeId: ThemeId) {
  useUiStore.setState({ themeId, logListFontSize: 13 });
  const view = render(<EvtxHistogram records={records} loading={false} />);
  const histogram = buildHistogram(records, "utc");
  act(() => {
    useEvtxStore.setState({ timeRange: { startMs: histogram.edges[10], endMs: histogram.edges[40] } });
  });
  return view;
}

describe("the brushed range keeps every level bar at 3:1 (issue #835, Adam's criterion)", () => {
  it("draws the wash first, then the bars, then the edge borders", () => {
    const { container } = renderBrushed("light");
    expect(paintModel(container, "light").order).toEqual(["wash", "bars", "edge", "edge"]);
  });

  it.each(themes.map((theme) => [theme.id] as const))(
    "keeps all five level bars at 3:1 against the composited wash in %s",
    (themeId) => {
      const { container } = renderBrushed(themeId);
      const model = paintModel(container, themeId);
      expect(Object.keys(model.bars).sort()).toEqual([...LEVELS].sort());
      for (const level of LEVELS) {
        expect(model.bars[level], `${themeId} ${level}`).toBeGreaterThanOrEqual(BRUSH_MIN_CONTRAST);
      }
    },
  );

  it.each(themes.map((theme) => [theme.id] as const))(
    "draws the wash at the opacity solved from the token map in %s",
    (themeId) => {
      const { container } = renderBrushed(themeId);
      const theme = themes.find((candidate) => candidate.id === themeId)!;
      expect(paintModel(container, themeId).opacity).toBe(solveBrushOpacity(brushPaletteFor(theme)));
    },
  );

  it("uses the spec's 60% wherever it holds and 25% in high contrast", () => {
    const opacities = Object.fromEntries(
      themes.map((theme) => [theme.id, paintModel(renderBrushed(theme.id).container, theme.id).opacity]),
    );
    expect(opacities).toEqual({
      light: 0.6,
      dark: 0.6,
      "high-contrast": 0.25,
      "classic-cmtrace": 0.6,
      "solarized-dark": 0.6,
      nord: 0.6,
      dracula: 0.6,
    });
  });

  it("would fail in every theme if the wash were painted over the bars", () => {
    for (const theme of themes) {
      cleanup();
      const { container } = renderBrushed(theme.id);
      const swapped = paintModel(container, theme.id, ["bars", "wash", "edge", "edge"]);
      const worst = Math.min(...LEVELS.map((level) => swapped.bars[level]));
      expect(worst, theme.id).toBeLessThan(BRUSH_MIN_CONTRAST);
    }
  });

  it("keeps the edge borders at 3:1 on the surface and on the wash in every theme", () => {
    for (const theme of themes) {
      cleanup();
      const { container } = renderBrushed(theme.id);
      const { edges } = paintModel(container, theme.id);
      expect(edges).toHaveLength(2);
      for (const edge of edges) {
        expect(edge.onSurface, theme.id).toBeGreaterThanOrEqual(BRUSH_MIN_CONTRAST);
        expect(edge.onWash, theme.id).toBeGreaterThanOrEqual(BRUSH_MIN_CONTRAST);
      }
    }
  });

  it("paints the wash behind the bars in the document, not by a z-index that could be changed alone", () => {
    const { container } = renderBrushed("light");
    const wash = container.querySelector<HTMLElement>('[data-evtx-layer="wash"]')!;
    const bars = container.querySelector<HTMLElement>('[data-evtx-layer="bars"]')!;
    expect(wash.compareDocumentPosition(bars) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(wash.style.zIndex).toBe("");
    expect(bars.style.zIndex).toBe("");
  });

  it("names the brush colours by token: the wash, and the borders on colorNeutralStrokeAccessible", () => {
    const { container } = renderBrushed("light");
    const wash = container.querySelector<HTMLElement>('[data-evtx-layer="wash"]')!;
    expect(wash.style.backgroundColor).toBe("var(--colorNeutralBackground1Selected)");
    for (const edge of container.querySelectorAll<HTMLElement>('[data-evtx-layer="edge"]')) {
      expect(edge.style.borderLeft).toContain("var(--colorNeutralStrokeAccessible)");
    }
  });
});
