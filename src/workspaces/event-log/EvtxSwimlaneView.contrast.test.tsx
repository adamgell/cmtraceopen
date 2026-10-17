import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
import {
  installRecordingCanvas,
  markCalls,
  type MarkSummary,
  type RecordingCanvases,
} from "./__fixtures__/recording-canvas";
import { EvtxSwimlaneView } from "./EvtxSwimlaneView";
import { buildHistogram } from "./evtx-histogram";
import {
  BRUSH_MIN_CONTRAST,
  brushPaletteFor,
  compositeOver,
  solveBrushOpacity,
} from "./evtx-histogram-brush";
import { DOT_MARKS, swimlaneColors } from "./evtx-swimlane-canvas";
import { buildSwimlanes } from "./evtx-swimlanes";
import { useEvtxStore } from "./evtx-store";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";
import type { EvtxLevel, EvtxRecord } from "./types";

const MINUTE = 60 * 1000;
const FIRST = Date.UTC(2026, 9, 6, 10, 20, 0);
const LEVELS: EvtxLevel[] = ["Critical", "Error", "Warning", "Information", "Verbose"];
const LEFT = 100;
const PLOT_W = 720;
const PINNED_NOW = Date.UTC(2026, 9, 16, 12, 0);

let nextId = 0;
const rec = (timestampEpoch: number, level: EvtxLevel, provider: string): EvtxRecord =>
  ({
    id: nextId++,
    eventRecordId: nextId,
    timestamp: "",
    timestampEpoch,
    provider,
    channel: "System",
    eventId: 1,
    level,
    computer: "C",
    message: "m",
    eventData: [],
    rawXml: "",
    sourceLabel: "System",
  }) as EvtxRecord;

/** Every level in every bucket of a day, in two lanes, so every level's mark is in the range. */
const records = Array.from({ length: 72 * 5 }, (_, i) =>
  rec(FIRST + Math.floor(i / 5) * 20 * MINUTE + (i % 5) * 1000, LEVELS[i % 5], i % 2 === 0 ? "A" : "B"),
);

let canvases: RecordingCanvases;

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(PINNED_NOW);
  canvases = installRecordingCanvas();
  vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(
    () =>
      ({
        left: LEFT,
        top: 0,
        right: LEFT + PLOT_W,
        bottom: 200,
        width: PLOT_W,
        height: 200,
        x: LEFT,
        y: 0,
        toJSON: () => ({}),
      }) as DOMRect,
  );
  Object.defineProperty(window, "devicePixelRatio", { value: 1, configurable: true });
  useEvtxStore.setState({
    timeZoneMode: "utc",
    timeRange: null,
    isLoading: false,
    selectedRecordId: null,
    coverageGaps: [],
    coverageDetails: [],
    tailCoverageGaps: [],
  });
});

afterEach(() => {
  cleanup();
  canvases.restore();
  vi.restoreAllMocks();
  vi.useRealTimers();
  useEvtxStore.setState({ timeRange: null, selectedRecordId: null });
});

const themes = getAllThemes();
type ThemeId = (typeof themes)[number]["id"];
const themeOf = (themeId: string) => themes.find((candidate) => candidate.id === themeId)!;

/** `rgb(r, g, b)` or `#rrggbb` as `#rrggbb`. */
function toHex(color: string): string {
  const rgb = /^rgb\(\s*(\d+),\s*(\d+),\s*(\d+)\s*\)$/.exec(color);
  if (!rgb) return color;
  return `#${[rgb[1], rgb[2], rgb[3]].map((part) => Number(part).toString(16).padStart(2, "0")).join("")}`;
}

/** The resolved colour of a `var(--token)` the component wrote, or the plain colour. */
function resolved(value: string, themeId: string): string {
  return toHex(resolveToken(value, themeOf(themeId)));
}

/** The level a mark call drew, told by its shape and size alone (never by its colour). */
function levelOfCall(call: MarkSummary): EvtxLevel | null {
  if (call.shape === "circle" && call.action === "fill") {
    if (call.extent === 10) return "Critical";
    if (call.extent === 9) return "Error";
    if (call.extent === 7) return "Warning";
    if (call.extent === 5) return "Information";
  }
  if (call.shape === "circle" && call.action === "stroke" && call.lineWidth === 1.5) return "Verbose";
  return null;
}

interface PaintModel {
  /** Layers in the order the DOM paints them. */
  order: string[];
  opacity: number;
  surface: string;
  wash: string;
  /** The colour each level's mark was drawn in, from the canvas calls, and the alpha it was drawn at. */
  marks: Partial<Record<EvtxLevel, { color: string; alpha: number }>>;
  /** The levels that were knocked out around before being drawn. */
  knockouts: EvtxLevel[];
  /** Contrast of each mark, at its own alpha, against the wash behind it. */
  contrast: Partial<Record<EvtxLevel, number>>;
  edges: { onSurface: number; onWash: number }[];
}

function paintModel(container: HTMLElement, themeId: string): PaintModel {
  const surface = resolved("var(--colorNeutralBackground1)", themeId);
  const layers = [...container.querySelectorAll<HTMLElement>("[data-evtx-layer]")];
  const washLayer = layers.find((layer) => layer.dataset.evtxLayer === "wash")!;
  const opacity = Number(washLayer.style.opacity);
  const fill = resolved(washLayer.style.backgroundColor, themeId);
  const wash = compositeOver(surface, fill, opacity);
  const canvas = container.querySelector<HTMLCanvasElement>('canvas[data-evtx-layer="marks"]')!;
  const calls = markCalls(canvases.contextOf(canvas)!);
  const marks: PaintModel["marks"] = {};
  const knockouts: EvtxLevel[] = [];
  calls.forEach((call, index) => {
    if (call.composite === "destination-out") {
      const next = levelOfCall(calls[index + 1]);
      if (next !== null) knockouts.push(next);
      return;
    }
    const level = levelOfCall(call);
    if (level !== null) marks[level] = { color: toHex(call.color), alpha: call.alpha };
  });
  const contrast: PaintModel["contrast"] = {};
  for (const [level, mark] of Object.entries(marks) as [EvtxLevel, { color: string; alpha: number }][]) {
    // A mark drawn at an alpha lands on the wash blended with it.
    contrast[level] = contrastRatio(compositeOver(wash, mark.color, mark.alpha), wash);
  }
  const edges = layers
    .filter((layer) => layer.dataset.evtxLayer === "edge")
    .map((layer) => {
      const color = resolved(/var\([^)]*\)/.exec(layer.style.borderLeft)![0], themeId);
      return { onSurface: contrastRatio(color, surface), onWash: contrastRatio(color, wash) };
    });
  return {
    order: layers.map((layer) => layer.dataset.evtxLayer!),
    opacity,
    surface,
    wash,
    marks,
    knockouts,
    contrast,
    edges,
  };
}

function renderBrushed(themeId: ThemeId) {
  useUiStore.setState({ themeId, logListFontSize: 13 });
  // The records the lanes draw are the store's, under ids that are their indexes.
  records.forEach((record, index) => {
    record.id = index;
  });
  useEvtxStore.setState({ records: [...records] });
  const view = render(<EvtxSwimlaneView records={records} loading={false} />);
  const histogram = buildHistogram(records, "utc");
  act(() => {
    useEvtxStore.setState({ timeRange: { startMs: histogram.edges[10], endMs: histogram.edges[40] } });
  });
  return view;
}

describe("the brushed range keeps every dot at 3:1 (issue #845, Adam's criterion)", () => {
  it("draws the wash first, then the canvas of dots, then the edge borders", () => {
    const { container } = renderBrushed("light");
    expect(paintModel(container, "light").order).toEqual(["wash", "marks", "edge", "edge"]);
  });

  it("paints every level, in a mark of its own, so the model reads all five", () => {
    const { container } = renderBrushed("light");
    expect(Object.keys(paintModel(container, "light").marks).sort()).toEqual([...LEVELS].sort());
  });

  it.each(themes.map((theme) => [theme.id] as const))(
    "keeps every level but Information at 3:1 against the composited wash in %s",
    (themeId) => {
      const { container } = renderBrushed(themeId);
      const model = paintModel(container, themeId);
      for (const level of LEVELS.filter((candidate) => candidate !== "Information")) {
        expect(model.contrast[level], `${themeId} ${level}`).toBeGreaterThanOrEqual(BRUSH_MIN_CONTRAST);
      }
    },
  );

  it.each(themes.map((theme) => [theme.id] as const))(
    "draws each mark in its level's colour in %s: the contrast measured is the one painted",
    (themeId) => {
      const { container } = renderBrushed(themeId);
      const model = paintModel(container, themeId);
      const visual = buildEvtxVisualTokens(themeOf(themeId));
      for (const level of LEVELS) {
        expect(model.marks[level]!.color, `${themeId} ${level}`).toBe(
          toHex(resolveToken(visual.levels[level].dotColor, themeOf(themeId))),
        );
        expect(model.marks[level]!.color).toBe(toHex(swimlaneColors(themeOf(themeId)).dots[level]));
      }
    },
  );

  it.each(themes.map((theme) => [theme.id] as const))(
    "draws the wash at the opacity the histogram's solver gives in %s: one wash for both figures",
    (themeId) => {
      const { container } = renderBrushed(themeId);
      expect(paintModel(container, themeId).opacity).toBe(solveBrushOpacity(brushPaletteFor(themeOf(themeId))));
    },
  );

  it("uses the spec's 60% wherever it holds and 25% in high contrast", () => {
    const opacities = Object.fromEntries(
      themes.map((theme) => {
        cleanup();
        return [theme.id, paintModel(renderBrushed(theme.id).container, theme.id).opacity];
      }),
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

  it("measures high contrast at 1.01:1 for Error where the spec's 60% would put it, and passes at 25%", () => {
    const palette = brushPaletteFor(themeOf("high-contrast"));
    const at60 = compositeOver(palette.surface, palette.fill, 0.6);
    expect(at60).toBe("#108d99");
    const error = swimlaneColors(themeOf("high-contrast")).dots.Error;
    expect(contrastRatio(error, at60)).toBeLessThan(1.1);
    const { container } = renderBrushed("high-contrast");
    expect(paintModel(container, "high-contrast").contrast.Error).toBeGreaterThanOrEqual(BRUSH_MIN_CONTRAST);
  });

  it("would fail in every theme if the wash were painted over the dots", () => {
    for (const theme of themes) {
      cleanup();
      const { container } = renderBrushed(theme.id);
      const model = paintModel(container, theme.id);
      const visual = buildEvtxVisualTokens(theme);
      const fill = resolved("var(--colorNeutralBackground1Selected)", theme.id);
      const swapped = LEVELS.filter((level) => level !== "Information").map((level) => {
        // The dot first, the wash over it: the dot is washed by the same fraction as its surroundings.
        const washedDot = compositeOver(toHex(resolveToken(visual.levels[level].dotColor, theme)), fill, model.opacity);
        return contrastRatio(washedDot, model.wash);
      });
      expect(Math.min(...swapped), theme.id).toBeLessThan(BRUSH_MIN_CONTRAST);
    }
  });

  it("exempts Information alone: it is the one level drawn below full opacity, at the spec's 55%", () => {
    for (const theme of themes) {
      cleanup();
      const { container } = renderBrushed(theme.id);
      const { marks } = paintModel(container, theme.id);
      expect(marks.Information!.alpha, theme.id).toBe(0.55);
      for (const level of LEVELS.filter((candidate) => candidate !== "Information")) {
        expect(marks[level]!.alpha, `${theme.id} ${level}`).toBe(1);
      }
    }
  });

  it("would fall to 1.75:1 in light if Verbose were drawn at 55% like Information", () => {
    const palette = brushPaletteFor(themeOf("light"));
    const wash = compositeOver(palette.surface, palette.fill, 0.6);
    const verbose = swimlaneColors(themeOf("light")).dots.Verbose;
    expect(contrastRatio(compositeOver(wash, verbose, 0.55), wash)).toBeLessThan(2);
    expect(contrastRatio(verbose, wash)).toBeGreaterThanOrEqual(BRUSH_MIN_CONTRAST);
  });

  it("rings every level but Information with a knockout, Verbose included", () => {
    const { container } = renderBrushed("light");
    const { knockouts } = paintModel(container, "light");
    expect([...knockouts].sort()).toEqual(["Critical", "Error", "Verbose", "Warning"]);
    for (const level of LEVELS) expect(DOT_MARKS[level].knockout).toBe(level !== "Information");
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

  it("keeps the keyboard cursor, the focus ring, the selection ring and the hover ring at 3:1 on the wash and the surface in every theme", () => {
    for (const theme of themes) {
      cleanup();
      const { container } = renderBrushed(theme.id);
      const model = paintModel(container, theme.id);
      const slider = screen.getByRole("slider", { name: "Time range, by lane" });
      // Rings are read from the DOM the view drew: the cursor cell, the selected dot, the hovered dot.
      const scene = buildSwimlanes(records, "provider", "utc");
      const x = LEFT + scene.lanes[0].fractions[5] * PLOT_W;
      fireEvent.pointerDown(slider, { clientX: x, clientY: 18, button: 0, buttons: 1, isPrimary: true, pointerId: 1 });
      fireEvent.pointerUp(slider, { clientX: x, clientY: 18, pointerId: 1 });
      fireEvent.pointerMove(slider, { clientX: x, clientY: 18, buttons: 0, pointerId: 1 });
      fireEvent.focus(slider);
      const colorOf = (which: string, property: "outline" | "border") => {
        const layer = container.querySelector<HTMLElement>(`[data-evtx-layer="${which}"]`);
        expect(layer, `${theme.id} ${which}`).not.toBeNull();
        return resolved(/var\([^)]*\)/.exec(layer!.style[property])![0], theme.id);
      };
      const colors = [
        colorOf("cursor", "outline"),
        colorOf("selected", "border"),
        colorOf("hover", "border"),
        brushPaletteFor(theme).focus,
      ];
      for (const color of colors) {
        expect(contrastRatio(color, model.wash), theme.id).toBeGreaterThanOrEqual(BRUSH_MIN_CONTRAST);
        expect(contrastRatio(color, model.surface), theme.id).toBeGreaterThanOrEqual(BRUSH_MIN_CONTRAST);
      }
    }
  });

  it("paints the wash behind the canvas in the document, not by a z-index that could be changed alone", () => {
    const { container } = renderBrushed("light");
    const wash = container.querySelector<HTMLElement>('[data-evtx-layer="wash"]')!;
    const marks = container.querySelector<HTMLElement>('[data-evtx-layer="marks"]')!;
    expect(wash.compareDocumentPosition(marks) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(wash.style.zIndex).toBe("");
    expect(marks.style.zIndex).toBe("");
  });

  it("names the brush colours by token: the wash, and the borders on colorNeutralStrokeAccessible", () => {
    const { container } = renderBrushed("light");
    const wash = container.querySelector<HTMLElement>('[data-evtx-layer="wash"]')!;
    expect(wash.style.backgroundColor).toBe("var(--colorNeutralBackground1Selected)");
    for (const edge of container.querySelectorAll<HTMLElement>('[data-evtx-layer="edge"]')) {
      expect(edge.style.borderLeft).toContain("var(--colorNeutralStrokeAccessible)");
    }
  });

  it("draws the lane baselines in Stroke2 and the lane edges in Stroke3, decorative and below 3:1 by the spec's choice", () => {
    for (const theme of themes) {
      cleanup();
      const { container } = renderBrushed(theme.id);
      const canvas = container.querySelector<HTMLCanvasElement>('canvas[data-evtx-layer="marks"]')!;
      const lines = canvases
        .contextOf(canvas)!
        .calls.filter((call) => call.path.every((item) => item.kind === "move" || item.kind === "line"))
        .map((call) => call.strokeStyle);
      expect(lines, theme.id).toEqual([
        resolveToken("var(--colorNeutralStroke2)", theme),
        resolveToken("var(--colorNeutralStroke3)", theme),
      ]);
    }
  });
});
