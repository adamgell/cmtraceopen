import { describe, expect, it } from "vitest";
import { getAllThemes } from "../../lib/themes";
import { createRecordingContext, lineCalls, markCalls, summarizeCall } from "./__fixtures__/recording-canvas";
import {
  DOT_MARKS,
  KNOCKOUT_PX,
  MAX_MARK_RADIUS_PX,
  PLOT_INSET_PX,
  canvasWidthFor,
  hitRadiusOf,
  hitTest,
  paintSwimlanes,
  planPaint,
  swimlaneColors,
  xOfFraction,
  yOfLane,
  type LaneGeometry,
  type SwimlaneColors,
} from "./evtx-swimlane-canvas";
import { buildHistogram, HISTOGRAM_STACK_ORDER } from "./evtx-histogram";
import {
  HIT_SLOP_PX,
  LEVEL_SLOT,
  buildSwimlanes,
  laneHeightFor,
  type SwimlaneLane,
  type SwimlaneScene,
} from "./evtx-swimlanes";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";
import type { EvtxLevel, EvtxRecord } from "./types";

const LEVELS: readonly EvtxLevel[] = ["Critical", "Error", "Warning", "Information", "Verbose"];
const GEOMETRY: LaneGeometry = { plotWidth: 1000, laneHeight: 36, dpr: 1 };
const COLORS: SwimlaneColors = {
  baseline: "#bbbbbb",
  separator: "#dddddd",
  dots: { Critical: "#c00000", Error: "#d00000", Warning: "#e0a000", Information: "#808080", Verbose: "#a0a0a0" },
};
const T0 = Date.UTC(2026, 9, 6, 10, 20, 0);

let nextId = 0;
const rec = (partial: Partial<EvtxRecord> = {}): EvtxRecord =>
  ({
    id: nextId++,
    eventRecordId: nextId,
    timestamp: "",
    timestampEpoch: T0,
    provider: "P",
    channel: "System",
    eventId: 1,
    level: "Information",
    computer: "C",
    message: "m",
    eventData: [],
    rawXml: "",
    sourceLabel: "System",
    ...partial,
  }) as EvtxRecord;

interface DotSpec {
  f: number;
  level?: EvtxLevel;
  epoch?: number;
  tag?: string;
}

/** A scene built by hand, so a dot sits at an exact fraction and the pixel arithmetic is exact. */
function sceneOf(lanes: DotSpec[][]): SwimlaneScene {
  const built: SwimlaneLane[] = lanes.map((dots, laneIndex) => {
    const sorted = [...dots].sort((a, b) => a.f - b.f);
    const records = sorted.map((dot, index) =>
      rec({
        level: dot.level ?? "Information",
        timestampEpoch: dot.epoch ?? T0 + index,
        message: dot.tag ?? `${laneIndex}:${index}`,
      }),
    );
    return {
      id: `lane-${laneIndex}`,
      label: `lane-${laneIndex}`,
      isOther: false,
      foldedLaneCount: 0,
      foldedKeys: [],
      count: sorted.length,
      levelCounts: { Critical: 0, Error: 0, Warning: 0, Information: 0, Verbose: 0 },
      epochs: Float64Array.from(records, (record) => record.timestampEpoch),
      fractions: Float64Array.from(sorted, (dot) => dot.f),
      levels: Uint8Array.from(sorted, (dot) => LEVEL_SLOT[dot.level ?? "Information"]),
      records,
    };
  });
  return {
    field: "provider",
    axis: buildHistogram([], "utc"),
    lanes: built,
    placed: built.reduce((sum, lane) => sum + lane.count, 0),
    untimed: 0,
    keyCount: built.length,
  };
}

/** Canvas x of a fraction on the 1000 px plot used here. */
const px = (fraction: number) => xOfFraction(fraction, GEOMETRY.plotWidth);
const py = (lane: number) => yOfLane(lane, GEOMETRY.laneHeight);

describe("the marks", () => {
  it("are the spec's ladder of 10, 9, 7 and 5 px for Critical down to Information, and a 5 px ring for Verbose", () => {
    expect(LEVELS.map((level) => [level, DOT_MARKS[level].shape, DOT_MARKS[level].size])).toEqual([
      ["Critical", "diamond", 10],
      ["Error", "circle", 9],
      ["Warning", "circle", 7],
      ["Information", "circle", 5],
      ["Verbose", "ring", 5],
    ]);
  });

  it("draw only Information at 55%, and give every other level a knockout ring", () => {
    for (const level of LEVELS) {
      expect(DOT_MARKS[level].opacity, level).toBe(level === "Information" ? 0.55 : 1);
      expect(DOT_MARKS[level].knockout, level).toBe(level !== "Information");
    }
    expect(KNOCKOUT_PX).toBe(1);
  });

  it("differ pairwise in shape, size or opacity, so a level is never told by colour alone", () => {
    const signatures = LEVELS.map((level) => {
      const { shape, size, opacity } = DOT_MARKS[level];
      return `${shape}/${size}/${opacity}`;
    });
    expect(new Set(signatures).size).toBe(LEVELS.length);
  });

  it("keep Critical and Error apart by shape, since their sizes are one pixel apart", () => {
    expect(DOT_MARKS.Critical.size - DOT_MARKS.Error.size).toBe(1);
    expect(DOT_MARKS.Critical.shape).not.toBe(DOT_MARKS.Error.shape);
  });

  it("have a largest radius the plot inset and the hit reach are built on", () => {
    expect(Math.max(...LEVELS.map(hitRadiusOf))).toBe(MAX_MARK_RADIUS_PX);
    expect(PLOT_INSET_PX).toBe(MAX_MARK_RADIUS_PX + KNOCKOUT_PX);
  });
});

describe("the colours", () => {
  it.each(getAllThemes().map((theme) => [theme.id] as const))(
    "resolve to hex from the theme object in %s",
    (themeId) => {
      const theme = getAllThemes().find((candidate) => candidate.id === themeId)!;
      const colors = swimlaneColors(theme);
      const visual = buildEvtxVisualTokens(theme);
      for (const level of LEVELS) {
        expect(colors.dots[level]).toBe(resolveToken(visual.levels[level].dotColor, theme));
        expect(colors.dots[level]).toMatch(/^#[0-9a-f]{3}([0-9a-f]{3})?$/i);
      }
      expect(colors.baseline).toBe(resolveToken("var(--colorNeutralStroke2)", theme));
      expect(colors.separator).toBe(resolveToken("var(--colorNeutralStroke3)", theme));
      expect(colors.baseline).toMatch(/^#/);
    },
  );

  it("differ between themes, so a theme switch has something to re-resolve", () => {
    const [light, dark] = [getAllThemes().find((t) => t.id === "light")!, getAllThemes().find((t) => t.id === "dark")!];
    expect(swimlaneColors(light).dots.Error).not.toBe(swimlaneColors(dark).dots.Error);
    expect(swimlaneColors(light).baseline).not.toBe(swimlaneColors(dark).baseline);
  });
});

describe("the plan", () => {
  it("sizes the canvas to the plot plus its inset, and a lane stack of lane heights", () => {
    const plan = planPaint(sceneOf([[{ f: 0.5 }], [{ f: 0.25 }], []]), GEOMETRY);
    expect(plan.width).toBe(canvasWidthFor(1000));
    expect(plan.width).toBe(1000 + 2 * PLOT_INSET_PX);
    expect(plan.height).toBe(3 * 36);
    expect(plan.laneCount).toBe(3);
  });

  it("places a dot at the inset plus its fraction of the plot, centred in its lane", () => {
    const plan = planPaint(sceneOf([[], [{ f: 0.25, level: "Error" }]]), GEOMETRY);
    expect(plan.draws).toHaveLength(1);
    expect(plan.draws[0].level).toBe("Error");
    expect(Array.from(plan.draws[0].xs)).toEqual([px(0.25)]);
    expect(Array.from(plan.draws[0].ys)).toEqual([py(1)]);
    expect(py(1)).toBe(54);
  });

  it("keeps a dot on the first and last instant of the axis whole on the canvas", () => {
    const plan = planPaint(sceneOf([[{ f: 0 }, { f: 1 }]]), GEOMETRY);
    const [first, last] = Array.from(plan.draws[0].xs);
    expect(first - MAX_MARK_RADIUS_PX - KNOCKOUT_PX).toBeGreaterThanOrEqual(0);
    expect(last + MAX_MARK_RADIUS_PX + KNOCKOUT_PX).toBeLessThanOrEqual(plan.width);
  });

  it("draws dots on one device-pixel column of a lane and level once", () => {
    const dots = Array.from({ length: 500 }, (_, i) => ({ f: 0.5 + i * 1e-7, level: "Error" as const }));
    const plan = planPaint(sceneOf([dots]), GEOMETRY);
    expect(plan.drawCount).toBe(1);
  });

  it("keeps dots of different levels, lanes and columns apart", () => {
    const plan = planPaint(
      sceneOf([
        [{ f: 0.5, level: "Error" }, { f: 0.5, level: "Warning" }, { f: 0.5001, level: "Error" }, { f: 0.6, level: "Error" }],
        [{ f: 0.5, level: "Error" }],
      ]),
      GEOMETRY,
    );
    // Lane 0: Error at column 506 (twice: 0.5 and 0.5001 are 0.1 px apart), Warning, Error at 606; lane 1: Error.
    expect(plan.drawCount).toBe(4);
  });

  it("counts device pixels, so a sharper screen shows more of the same dots", () => {
    const dots = Array.from({ length: 40 }, (_, i) => ({ f: 0.5 + i * 0.0001, level: "Error" as const }));
    const at = (dpr: number) => planPaint(sceneOf([dots]), { ...GEOMETRY, dpr }).drawCount;
    expect(at(1)).toBeLessThan(at(2));
  });

  it("bounds the draws by lanes x levels x device columns, whatever the number of events", () => {
    const records: EvtxRecord[] = [];
    for (let i = 0; i < 100_000; i += 1) {
      records.push(
        rec({
          provider: `p${i % 5}`,
          level: LEVELS[i % 5],
          // Only 7 distinct instants in a long span: far fewer columns than events.
          timestampEpoch: T0 + (i % 7) * 60 * 60 * 1000,
        }),
      );
    }
    const scene = buildSwimlanes(records, "provider", "utc", undefined, T0);
    const plan = planPaint(scene, GEOMETRY);
    const bound = scene.lanes.length * HISTOGRAM_STACK_ORDER.length * 7;
    expect(plan.drawCount).toBeLessThanOrEqual(bound);
    expect(plan.drawCount).toBeLessThan(records.length / 100);
    // And the painter issues one path op per planned mark, not per event.
    const context = createRecordingContext();
    paintSwimlanes(context, plan, COLORS, null);
    const arcs = context.calls.reduce((sum, call) => sum + call.path.filter((item) => item.kind === "arc").length, 0);
    expect(arcs).toBeLessThanOrEqual(3 * plan.drawCount);
  });
});

describe("painting", () => {
  const plan = () =>
    planPaint(
      sceneOf([
        [
          { f: 0.1, level: "Verbose" },
          { f: 0.2, level: "Information" },
          { f: 0.3, level: "Warning" },
          { f: 0.4, level: "Error" },
          { f: 0.5, level: "Critical" },
        ],
        [{ f: 0.6, level: "Error" }],
      ]),
      { ...GEOMETRY, dpr: 2 },
    );
  const paint = (forced: string | null = null) => {
    const context = createRecordingContext();
    paintSwimlanes(context, plan(), COLORS, forced);
    return context;
  };

  it("scales to the device pixel ratio and clears the whole canvas first", () => {
    const context = paint();
    expect(context.transforms).toEqual([[2, 0, 0, 2, 0, 0]]);
    expect(context.clears).toEqual([[0, 0, plan().width, plan().height]]);
  });

  it("draws the lane baselines in the baseline colour and the lane edges in the separator colour, before any dot", () => {
    const lines = lineCalls(paint());
    expect(lines.map((call) => [call.action, call.color])).toEqual([
      ["stroke", COLORS.baseline],
      ["stroke", COLORS.separator],
    ]);
    const context = paint();
    expect(context.calls[0].strokeStyle).toBe(COLORS.baseline);
    expect(context.calls[1].strokeStyle).toBe(COLORS.separator);
  });

  it("paints the levels from Verbose to Critical, so the more severe is on top", () => {
    const fills = markCalls(paint()).filter((call) => call.composite === "source-over");
    expect(fills.map((call) => call.color)).toEqual(
      ["Verbose", "Information", "Warning", "Error", "Critical"].map((level) => COLORS.dots[level as EvtxLevel]),
    );
  });

  it("draws each level at its own size and shape", () => {
    const byColor = Object.fromEntries(
      markCalls(paint())
        .filter((call) => call.composite === "source-over")
        .map((call) => [call.color, call]),
    );
    expect(byColor[COLORS.dots.Critical]).toMatchObject({ shape: "diamond", extent: 10, action: "fill", alpha: 1 });
    expect(byColor[COLORS.dots.Error]).toMatchObject({ shape: "circle", extent: 9, action: "fill", alpha: 1 });
    expect(byColor[COLORS.dots.Warning]).toMatchObject({ shape: "circle", extent: 7, action: "fill", alpha: 1 });
    expect(byColor[COLORS.dots.Information]).toMatchObject({ shape: "circle", extent: 5, action: "fill", alpha: 0.55 });
    // Verbose is hollow: stroked, 1.5 px, on a circle whose outer edge is 5 px.
    expect(byColor[COLORS.dots.Verbose]).toMatchObject({ shape: "circle", action: "stroke", lineWidth: 1.5, alpha: 1 });
    expect(byColor[COLORS.dots.Verbose].extent! + 1.5).toBe(5);
  });

  it("knocks out a ring 1 px larger than the mark before every level but Information", () => {
    const calls = markCalls(paint());
    const knockouts = calls.filter((call) => call.composite === "destination-out");
    expect(knockouts.map((call) => [call.shape, call.extent])).toEqual([
      ["circle", 7], // Verbose: 5 + 2
      ["circle", 9], // Warning: 7 + 2
      ["circle", 11], // Error
      ["diamond", 12], // Critical
    ]);
    // Each knockout is directly before the call that draws its level.
    calls.forEach((call, index) => {
      if (call.composite === "destination-out") expect(calls[index + 1].composite).toBe("source-over");
    });
    // Information has none: nothing between the Verbose mark and the Information mark clears.
    const order = calls.map((call) => `${call.composite}:${call.extent}`);
    expect(order.indexOf("source-over:5")).toBeGreaterThanOrEqual(0);
  });

  it("puts a mark's knockout on the mark's own centres", () => {
    const calls = markCalls(paint());
    const critical = calls.filter((call) => call.shape === "diamond");
    expect(critical).toHaveLength(2);
    expect(critical[0].centers).toEqual(critical[1].centers);
    expect(critical[0].centers).toEqual([[px(0.5), py(0)]]);
  });

  it("leaves the context as it found it: opaque and compositing normally", () => {
    const context = paint();
    expect(context.globalAlpha).toBe(1);
    expect(context.globalCompositeOperation).toBe("source-over");
  });

  it("draws nothing but a clear for no lanes", () => {
    const context = createRecordingContext();
    paintSwimlanes(context, planPaint(sceneOf([]), GEOMETRY), COLORS, null);
    expect(context.calls).toEqual([]);
    expect(context.clears).toHaveLength(1);
  });

  it("outlines every mark in the forced-colors text colour, 1 px, 1 px larger, and only then", () => {
    expect(markCalls(paint()).some((call) => call.color === "#123456")).toBe(false);
    const ringed = markCalls(paint("#123456")).filter((call) => call.color === "#123456");
    expect(ringed).toHaveLength(5);
    for (const call of ringed) {
      expect(call.action).toBe("stroke");
      expect(call.lineWidth).toBe(1);
      expect(call.alpha).toBe(1);
    }
    expect(ringed.map((call) => [call.shape, call.extent])).toEqual([
      ["circle", 6], // Verbose
      ["circle", 6], // Information
      ["circle", 8], // Warning
      ["circle", 10], // Error
      ["diamond", 11], // Critical
    ]);
  });

  it("is a different signature per level even when every level has the same colour", () => {
    const same: SwimlaneColors = {
      ...COLORS,
      dots: Object.fromEntries(LEVELS.map((level) => [level, "#445566"])) as Record<EvtxLevel, string>,
    };
    const context = createRecordingContext();
    paintSwimlanes(context, plan(), same, null);
    const signatures = context.calls
      .map(summarizeCall)
      .filter((call) => (call.shape === "circle" || call.shape === "diamond") && call.composite === "source-over")
      .map((call) => `${call.shape}/${call.extent}/${call.alpha}/${call.action}`);
    expect(new Set(signatures).size).toBe(5);
  });
});

describe("hit-testing", () => {
  it("allows 4 CSS pixels (spec 8.9, acceptance)", () => {
    expect(HIT_SLOP_PX).toBe(4);
  });

  it("hits a dot's centre", () => {
    const hit = hitTest(sceneOf([[{ f: 0.5, level: "Error" }]]), GEOMETRY, px(0.5), py(0));
    expect(hit).not.toBeNull();
    expect(hit!.distance).toBe(0);
    expect(hit!.lane).toBe(0);
    expect(hit!.dot).toBe(0);
  });

  it.each(LEVELS.map((level) => [level] as const))(
    "hits at 4.00 px from the edge of a %s dot and misses just beyond",
    (level) => {
      const scene = sceneOf([[{ f: 0.5, level }]]);
      // The spec's number, written out: the constant is not what the acceptance item names.
      const reach = hitRadiusOf(level) + 4;
      expect(hitTest(scene, GEOMETRY, px(0.5) + reach, py(0))).not.toBeNull();
      expect(hitTest(scene, GEOMETRY, px(0.5) - reach, py(0))).not.toBeNull();
      expect(hitTest(scene, GEOMETRY, px(0.5) + reach + 0.01, py(0))).toBeNull();
      expect(hitTest(scene, GEOMETRY, px(0.5), py(0) + reach + 0.01)).toBeNull();
      expect(hitTest(scene, GEOMETRY, px(0.5), py(0) - reach)).not.toBeNull();
    },
  );

  it("hits anywhere on the visible disc, rim included: the edge is the measure, not the centre", () => {
    const scene = sceneOf([[{ f: 0.5, level: "Critical" }]]);
    // 5 px from the centre of a 10 px dot is its rim, further than the 4 px slop is from the centre.
    const hit = hitTest(scene, GEOMETRY, px(0.5) + 5, py(0));
    expect(hit).not.toBeNull();
    expect(hit!.distance).toBe(0);
    expect(hit!.centerDistance).toBe(5);
  });

  it("returns the nearer of two dots", () => {
    const scene = sceneOf([[{ f: 0.5, level: "Warning", tag: "left" }, { f: 0.5 + 12 / 1000, level: "Warning", tag: "right" }]]);
    expect(hitTest(scene, GEOMETRY, px(0.5) + 2, py(0))!.record.message).toBe("left");
    expect(hitTest(scene, GEOMETRY, px(0.5) + 10, py(0))!.record.message).toBe("right");
  });

  it("prefers the smaller distance even over a more severe level", () => {
    const scene = sceneOf([
      [
        { f: 0.5, level: "Information", tag: "info" },
        { f: 0.5 + 10 / 1000, level: "Critical", tag: "critical" },
      ],
    ]);
    // On the Information disc (distance 0); the Critical dot's edge is 10 - 5 - 1 = 4 px away.
    expect(hitTest(scene, GEOMETRY, px(0.5) + 1, py(0))!.record.message).toBe("info");
  });

  describe("ties, in order", () => {
    it("(2) the more severe level wins when both discs hold the pointer: it is the one drawn on top", () => {
      const scene = sceneOf([
        [
          { f: 0.5, level: "Warning", tag: "warning" },
          { f: 0.5, level: "Critical", tag: "critical" },
          { f: 0.5, level: "Information", tag: "info" },
        ],
      ]);
      expect(hitTest(scene, GEOMETRY, px(0.5), py(0))!.record.message).toBe("critical");
    });

    it("(3) then the nearer centre", () => {
      // Two Error discs both holding the pointer (distance 0); the pointer is nearer the right one.
      const scene = sceneOf([
        [
          { f: 0.5, level: "Error", tag: "left" },
          { f: 0.5 + 4 / 1000, level: "Error", tag: "right" },
        ],
      ]);
      expect(hitTest(scene, GEOMETRY, px(0.5) + 3, py(0))!.record.message).toBe("right");
      expect(hitTest(scene, GEOMETRY, px(0.5) + 1, py(0))!.record.message).toBe("left");
    });

    it("(4) then the earlier time", () => {
      const scene = sceneOf([
        [
          { f: 0.5, level: "Error", epoch: T0 + 500, tag: "later" },
          { f: 0.5, level: "Error", epoch: T0 + 100, tag: "earlier" },
        ],
      ]);
      // The hand-built lane keeps dot order by fraction; give the later time the lower index.
      const lane = scene.lanes[0];
      expect(lane.records[0].message).toBe("later");
      expect(hitTest(scene, GEOMETRY, px(0.5), py(0))!.record.message).toBe("earlier");
    });

    it("(5) then the lower position in the lane", () => {
      const scene = sceneOf([
        [
          { f: 0.5, level: "Error", epoch: T0 + 100, tag: "first" },
          { f: 0.5, level: "Error", epoch: T0 + 100, tag: "second" },
        ],
      ]);
      expect(hitTest(scene, GEOMETRY, px(0.5), py(0))!.record.message).toBe("first");
    });

    it("does not let a record's id, which the store rewrites, decide a tie", () => {
      const scene = sceneOf([[{ f: 0.5, level: "Error", tag: "a" }, { f: 0.5, level: "Error", tag: "b" }]]);
      scene.lanes[0].records[0].id = 900;
      scene.lanes[0].records[1].id = 1;
      expect(hitTest(scene, GEOMETRY, px(0.5), py(0))!.record.message).toBe("a");
    });
  });

  it("counts the other dots within the slop, so an overplotted point can say so", () => {
    const scene = sceneOf([
      [
        { f: 0.5, level: "Error" },
        { f: 0.5, level: "Error" },
        { f: 0.5 + 2 / 1000, level: "Warning" },
        { f: 0.7, level: "Error" },
      ],
    ]);
    expect(hitTest(scene, GEOMETRY, px(0.5), py(0))!.more).toBe(2);
    expect(hitTest(scene, GEOMETRY, px(0.7), py(0))!.more).toBe(0);
  });

  it("searches only the lane under the pointer", () => {
    const scene = sceneOf([[{ f: 0.5, level: "Critical", tag: "above" }], [{ f: 0.5, level: "Critical", tag: "below" }]]);
    // On the boundary between the lanes, 18 px from either centre: further than any dot's reach.
    expect(hitTest(scene, GEOMETRY, px(0.5), 36)).toBeNull();
    expect(hitTest(scene, GEOMETRY, px(0.5), 36 + 18)!.record.message).toBe("below");
    expect(hitTest(scene, GEOMETRY, px(0.5), 36 + 18)!.lane).toBe(1);
  });

  it("can never reach a dot in another lane: half a lane is more than the largest rim plus the slop", () => {
    for (let fontSize = 11; fontSize <= 20; fontSize += 1) {
      expect(laneHeightFor(fontSize) / 2).toBeGreaterThan(MAX_MARK_RADIUS_PX + HIT_SLOP_PX);
    }
  });

  it("reaches dots on the first and last instant of the axis", () => {
    const scene = sceneOf([[{ f: 0, level: "Critical" }, { f: 1, level: "Critical" }]]);
    expect(hitTest(scene, GEOMETRY, px(0), py(0))!.dot).toBe(0);
    expect(hitTest(scene, GEOMETRY, px(1), py(0))!.dot).toBe(1);
  });

  it("is null for an empty lane, a point off the stack, a degenerate size and no lanes", () => {
    const scene = sceneOf([[], [{ f: 0.5 }]]);
    expect(hitTest(scene, GEOMETRY, px(0.5), py(0))).toBeNull();
    expect(hitTest(scene, GEOMETRY, px(0.5), -1)).toBeNull();
    expect(hitTest(scene, GEOMETRY, px(0.5), 2 * 36 + 1)).toBeNull();
    expect(hitTest(scene, { plotWidth: 0, laneHeight: 36 }, 5, 5)).toBeNull();
    expect(hitTest(sceneOf([]), GEOMETRY, 5, 5)).toBeNull();
  });

  it("hands back the record object it drew, whose id is read when the click happens", () => {
    const scene = sceneOf([[{ f: 0.5, level: "Error" }]]);
    const hit = hitTest(scene, GEOMETRY, px(0.5), py(0))!;
    expect(hit.record).toBe(scene.lanes[0].records[0]);
    scene.lanes[0].records[0].id = 4242;
    expect(hit.record.id).toBe(4242);
  });

  it("agrees with a brute-force search over every dot, thousands of times, on an overplotted scene", () => {
    // A seeded generator: the same scene every run.
    let seed = 20261017;
    const random = () => {
      seed = (seed * 1664525 + 1013904223) >>> 0;
      return seed / 2 ** 32;
    };
    const lanes: DotSpec[][] = [[], [], []];
    for (let i = 0; i < 3000; i += 1) {
      lanes[Math.floor(random() * 3)].push({
        f: Math.round(random() * 400) / 400, // 400 columns: heavy overplotting
        level: LEVELS[Math.floor(random() * 5)],
        epoch: T0 + Math.floor(random() * 50),
      });
    }
    const scene = sceneOf(lanes);
    const oracle = (x: number, y: number) => {
      const laneIndex = Math.floor(y / GEOMETRY.laneHeight);
      const lane = scene.lanes[laneIndex];
      if (!lane) return null;
      const cy = py(laneIndex);
      const found: { dot: number; distance: number; center: number; slot: number; epoch: number }[] = [];
      for (let dot = 0; dot < lane.count; dot += 1) {
        const level = HISTOGRAM_STACK_ORDER[lane.levels[dot]];
        const center = Math.hypot(x - px(lane.fractions[dot]), y - cy);
        const distance = Math.max(0, center - hitRadiusOf(level));
        if (distance <= HIT_SLOP_PX) {
          found.push({ dot, distance, center, slot: lane.levels[dot], epoch: lane.epochs[dot] });
        }
      }
      found.sort(
        (a, b) =>
          a.distance - b.distance || b.slot - a.slot || a.center - b.center || a.epoch - b.epoch || a.dot - b.dot,
      );
      return found.length === 0 ? null : { lane: laneIndex, dot: found[0].dot, more: found.length - 1 };
    };
    let hits = 0;
    for (let probe = 0; probe < 4000; probe += 1) {
      const x = random() * (GEOMETRY.plotWidth + 2 * PLOT_INSET_PX);
      const y = random() * 3 * GEOMETRY.laneHeight;
      const expected = oracle(x, y);
      const actual = hitTest(scene, GEOMETRY, x, y);
      expect(actual === null ? null : { lane: actual.lane, dot: actual.dot, more: actual.more }, `${x},${y}`).toEqual(
        expected,
      );
      if (expected !== null) hits += 1;
    }
    expect(hits).toBeGreaterThan(500);
  });
});
