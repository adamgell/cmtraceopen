/**
 * A canvas 2D context that records, for tests. jsdom has no canvas (`getContext` returns null), and
 * what a test should read is the sequence of calls a browser would receive: the colour, opacity and
 * compositing in force when a path was filled or stroked, and the path itself.
 *
 * `installRecordingCanvas` makes every canvas in the document hand out one of these, so a component
 * test renders the real view and reads what it painted.
 */
import { vi } from "vitest";
import type { Paint2D } from "../evtx-swimlane-canvas";

export type PathItem =
  | { kind: "move"; x: number; y: number }
  | { kind: "line"; x: number; y: number }
  | { kind: "arc"; x: number; y: number; radius: number }
  | { kind: "close" };

/** One `fill` or `stroke`, with the state and the path it applied to. */
export interface PaintCall {
  action: "fill" | "stroke";
  fillStyle: string;
  strokeStyle: string;
  lineWidth: number;
  alpha: number;
  composite: string;
  path: readonly PathItem[];
}

export interface RecordingContext extends Paint2D {
  /** Every fill and stroke since the last `reset`, in order. */
  calls: PaintCall[];
  /** `[a, b, c, d, e, f]` of every `setTransform`. */
  transforms: number[][];
  /** `[x, y, width, height]` of every `clearRect`. */
  clears: number[][];
  /** How many times a whole paint began: one per `clearRect`. */
  reset(): void;
}

export function createRecordingContext(): RecordingContext {
  let path: PathItem[] = [];
  const context: RecordingContext = {
    globalAlpha: 1,
    globalCompositeOperation: "source-over",
    fillStyle: "#000000",
    strokeStyle: "#000000",
    lineWidth: 1,
    calls: [],
    transforms: [],
    clears: [],
    reset() {
      context.calls = [];
      context.transforms = [];
      context.clears = [];
    },
    setTransform(...args: number[]) {
      context.transforms.push(args);
    },
    clearRect(...args: number[]) {
      context.clears.push(args);
    },
    beginPath() {
      path = [];
    },
    moveTo(x, y) {
      path.push({ kind: "move", x, y });
    },
    lineTo(x, y) {
      path.push({ kind: "line", x, y });
    },
    arc(x, y, radius) {
      path.push({ kind: "arc", x, y, radius });
    },
    closePath() {
      path.push({ kind: "close" });
    },
    fill() {
      context.calls.push(snapshot("fill"));
    },
    stroke() {
      context.calls.push(snapshot("stroke"));
    },
  };
  function snapshot(action: "fill" | "stroke"): PaintCall {
    return {
      action,
      fillStyle: String(context.fillStyle),
      strokeStyle: String(context.strokeStyle),
      lineWidth: context.lineWidth,
      alpha: context.globalAlpha,
      composite: context.globalCompositeOperation,
      path: [...path],
    };
  }
  return context;
}

/** What a mark call drew: its shape and extent, and where. */
export interface MarkSummary {
  action: "fill" | "stroke";
  /** The colour the call drew in: the fill for a fill, the stroke for a stroke. */
  color: string;
  alpha: number;
  composite: string;
  lineWidth: number;
  /** `circle` (arcs) or `lines` (baselines and edges). */
  shape: "circle" | "lines" | "none";
  /** Diameter of a circle (of its path: a stroke adds half its width on each side); null for lines. */
  extent: number | null;
  centers: [number, number][];
}

export function summarizeCall(call: PaintCall): MarkSummary {
  const centers: [number, number][] = [];
  let shape: MarkSummary["shape"] = "none";
  let extent: number | null = null;
  const arcs = call.path.filter((item): item is Extract<PathItem, { kind: "arc" }> => item.kind === "arc");
  if (arcs.length > 0) {
    shape = "circle";
    extent = arcs[0].radius * 2;
    for (const arc of arcs) centers.push([arc.x, arc.y]);
  } else if (call.path.length > 0) {
    shape = "lines";
  }
  return {
    action: call.action,
    color: call.action === "fill" ? call.fillStyle : call.strokeStyle,
    alpha: call.alpha,
    composite: call.composite,
    lineWidth: call.lineWidth,
    shape,
    extent,
    centers,
  };
}

/** Every call that drew marks (not the baselines and lane edges), summarized, in paint order. */
export function markCalls(context: RecordingContext): MarkSummary[] {
  return context.calls.map(summarizeCall).filter((summary) => summary.shape === "circle");
}

/** The calls that drew lines: lane baselines, then lane edges. */
export function lineCalls(context: RecordingContext): MarkSummary[] {
  return context.calls.map(summarizeCall).filter((summary) => summary.shape === "lines");
}

export interface RecordingCanvases {
  /** The context a canvas was handed, or undefined if it never asked. */
  contextOf(canvas: HTMLCanvasElement): RecordingContext | undefined;
  /** Every context handed out, in the order canvases first asked. */
  all: RecordingContext[];
  restore(): void;
}

/** Makes `HTMLCanvasElement.getContext("2d")` return a recording context, one per element. */
export function installRecordingCanvas(): RecordingCanvases {
  const byCanvas = new WeakMap<HTMLCanvasElement, RecordingContext>();
  const all: RecordingContext[] = [];
  const spy = vi
    .spyOn(HTMLCanvasElement.prototype, "getContext")
    .mockImplementation(function (this: HTMLCanvasElement, kind: string) {
      if (kind !== "2d") return null;
      let context = byCanvas.get(this);
      if (context === undefined) {
        context = createRecordingContext();
        byCanvas.set(this, context);
        all.push(context);
      }
      return context as unknown as CanvasRenderingContext2D;
    } as unknown as typeof HTMLCanvasElement.prototype.getContext);
  return {
    contextOf: (canvas) => byCanvas.get(canvas),
    all,
    restore: () => spy.mockRestore(),
  };
}
