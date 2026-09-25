/**
 * Story-mapped browser coverage for three surfaces:
 *
 *  - the Timeline workspace (empty drop target, swim lanes, ruler, incident
 *    chips and the incident detail panel),
 *  - the Event Log Viewer's source picker and channel sidebar,
 *  - the SCCM discovery console (environment strip and issue rail).
 *
 * Every test names the user-story ids it verifies (see
 * `docs/qa/user-stories.csv`). The suite runs in a plain browser against the
 * Tauri IPC shim, so it needs no Rust build and no Windows host; unmodified
 * commands are forwarded to the real backend when `npm run app:dev` happens to
 * be running behind the debug IPC bridge.
 *
 * `bootApp`'s override map is serialized into the page, so it only carries
 * JSON values. Overrides whose answer depends on the request or on page state
 * are installed with a `page.addInitScript` of their own, before `bootApp`
 * (init scripts run in the order they were added, and the fixture's shim
 * script is first, so `window.__e2e_ipc_overrides__` already exists).
 */
import type { Page } from "@playwright/test";
import { test, expect } from "../fixtures";
import {
  bootApp,
  emitBackendEvent,
  seedStore,
  selectWorkspace,
} from "./harness";
import type { ShimWindow } from "./harness";
import type {
  Incident,
  IncidentDetail,
  LaneBucket,
  TimelineBundle,
  TimelineSourceMeta,
} from "../../src/types/timeline";

const TIMELINE_STORE = "/src/stores/timeline-store.ts";
const EVTX_STORE = "/src/workspaces/event-log/evtx-store.ts";

/**
 * Extra globals the page-side overrides read. Casting the window once is the
 * only way to reach them from a serialized script.
 */
interface E2eWindow extends ShimWindow {
  __e2e_lane_buckets__?: { full: LaneBucket[]; ranged: LaneBucket[] };
  __e2e_dialog_mode__?: string;
  __e2e_dialog_calls__?: number;
  __e2e_detail__?: IncidentDetail;
  __e2e_detail_mode__?: string;
  __e2e_detail_calls__?: number;
  __e2e_clipboard__?: string;
  __e2e_tunables_calls__?: number;
  __e2e_sccm_discovery__?: unknown;
}

// A scale factor of 1 cannot tell a device-pixel-ratio-aware canvas from one
// that ignores it, so the whole file runs hi-DPI.
test.use({ deviceScaleFactor: 2 });

const T0 = Date.UTC(2026, 0, 15, 9, 0, 0);
const HOUR_MS = 3_600_000;
const LANE_HEIGHT = 22;

// ── Fixtures ────────────────────────────────────────────────────────────────

function timelineSource(
  idx: number,
  path: string,
  displayName: string,
  color: string,
  entryCount: number,
): TimelineSourceMeta {
  return { idx, kind: "intuneEvents", path, displayName, color, entryCount };
}

function timelineIncident(
  id: number,
  confidence: number,
  summary: string,
  startOffsetMs = 0,
  endOffsetMs = 5_000,
): Incident {
  return {
    id,
    tsStartMs: T0 + startOffsetMs,
    tsEndMs: T0 + endOffsetMs,
    signalCount: 3,
    sourceCount: 2,
    confidence,
    summary,
  };
}

function timelineBundle(
  overrides: Partial<TimelineBundle> = {},
): TimelineBundle {
  return {
    id: "tl-e2e",
    sources: [
      timelineSource(
        0,
        "C:/logs/agentexecutor.log",
        "agentexecutor.log",
        "#4f6bed",
        12,
      ),
      timelineSource(
        1,
        "C:/logs/IntuneManagementExtension.log",
        "IntuneManagementExtension.log",
        "#e07b39",
        4,
      ),
    ],
    timeRangeMs: [T0, T0 + HOUR_MS],
    totalEntries: 16,
    incidents: [],
    deniedGuids: [],
    errors: [],
    tunables: {
      overlapWindowMs: 5_000,
      minSourceCount: 2,
      maxIncidentSpanMs: 60_000,
      enabledSignalKinds: ["errorSeverity"],
    },
    ...overrides,
  };
}

/** Buckets used by the swim-lane tests: one set per brush state. */
const laneBuckets = (ranged: boolean): LaneBucket[] => {
  const at = (fraction: number) => T0 + Math.round(HOUR_MS * fraction);
  if (ranged) {
    return [
      {
        sourceIdx: 0,
        tsStartMs: T0,
        tsEndMs: T0 + HOUR_MS,
        totalCount: 99,
        errorCount: 7,
        warnCount: 0,
      },
    ];
  }
  return [
    {
      sourceIdx: 0,
      tsStartMs: at(0),
      tsEndMs: at(0.25),
      totalCount: 20,
      errorCount: 5,
      warnCount: 0,
    },
    {
      sourceIdx: 0,
      tsStartMs: at(0.3),
      tsEndMs: at(0.55),
      totalCount: 20,
      errorCount: 0,
      warnCount: 3,
    },
    {
      sourceIdx: 0,
      tsStartMs: at(0.6),
      tsEndMs: at(0.7),
      totalCount: 1,
      errorCount: 0,
      warnCount: 0,
    },
    {
      sourceIdx: 0,
      tsStartMs: at(0.75),
      tsEndMs: at(0.85),
      totalCount: 20,
      errorCount: 0,
      warnCount: 0,
    },
  ];
};

const laneLegendLanes = (page: Page) =>
  page.locator('[title^="Click: solo this lane"]');

const laneSpec = () => ({
  full: laneBuckets(false),
  ranged: laneBuckets(true),
});

/** Installs the lane-bucket override, which answers per brush range. */
async function installLaneBuckets(page: Page): Promise<void> {
  await page.addInitScript(
    ({ spec }: { spec: { full: LaneBucket[]; ranged: LaneBucket[] } }) => {
      const globals = window as unknown as E2eWindow;
      const ipc = globals.__e2e_ipc_overrides__;
      if (!ipc) throw new Error("Tauri IPC shim overrides are missing");
      globals.__e2e_lane_buckets__ = spec;
      ipc["query_lane_buckets_cmd"] = (args) =>
        args && typeof args === "object" && "rangeMs" in args && args.rangeMs
          ? spec.ranged
          : spec.full;
    },
    { spec: laneSpec() },
  );
}

// ── Store access ────────────────────────────────────────────────────────────

/**
 * Reads selected fields out of a live Vite store singleton. The module path is
 * chosen at call time so the dynamic import resolves to the very module the app
 * already loaded (a static import would not share the app's instance).
 */
async function storePick(
  page: Page,
  modulePath: string,
  storeName: string,
  keys: string[],
): Promise<Record<string, unknown>> {
  return page.evaluate(
    async ({ path, name, keys: wanted }) => {
      const mod = (await import(/* @vite-ignore */ path)) as Record<
        string,
        { getState: () => Record<string, unknown> }
      >;
      const state = mod[name].getState();
      const picked: Record<string, unknown> = {};
      for (const key of wanted) picked[key] = state[key];
      return picked;
    },
    { path: modulePath, name: storeName, keys },
  );
}

/** Dispatches a real drag-and-drop of files onto the timeline. */
async function dropTimelineFiles(
  page: Page,
  files: { name: string; path?: string }[],
  target: "empty-state" | "layout" = "empty-state",
): Promise<void> {
  await page.evaluate(
    ({ entries, host: which }) => {
      const dropHost =
        which === "empty-state"
          ? Array.from(document.querySelectorAll("div")).find(
              (el) =>
                el.children.length === 0 &&
                el.textContent === "Drop log files here",
            )
          : document.querySelector('[title^="Click: solo this lane"]')
              ?.parentElement?.parentElement;
      if (!dropHost) throw new Error(`timeline ${which} drop host not found`);

      const transfer = new DataTransfer();
      for (const entry of entries) {
        const file = new File(["log line"], entry.name, { type: "text/plain" });
        if (entry.path !== undefined) {
          Object.assign(file, { path: entry.path });
        }
        transfer.items.add(file);
      }
      dropHost.dispatchEvent(
        new DragEvent("drop", {
          bubbles: true,
          cancelable: true,
          dataTransfer: transfer,
        }),
      );
    },
    { entries: files, host: target },
  );
}

interface CanvasSample {
  cssWidth: number;
  cssHeight: number;
  backingWidth: number;
  backingHeight: number;
  dpr: number;
  /** Sampled `[r, g, b]` values, one per requested point, in order. */
  pixels: [number, number, number][];
}

async function sampleCanvas(
  page: Page,
  points: { x: number; y: number }[] = [],
): Promise<CanvasSample | null> {
  return page.evaluate((requested) => {
    const canvas = document.querySelector("canvas");
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return null;
    const dpr = window.devicePixelRatio;
    const pixels = requested.map((point) => {
      const x = Math.round(canvas.clientWidth * point.x * dpr);
      const y = Math.round(point.y * dpr);
      const data = ctx.getImageData(x, y, 1, 1).data;
      return [data[0], data[1], data[2]];
    });
    return {
      cssWidth: canvas.clientWidth,
      cssHeight: canvas.clientHeight,
      backingWidth: canvas.width,
      backingHeight: canvas.height,
      dpr,
      pixels,
    };
  }, points);
}

/** Manhattan distance between two sampled pixels. */
const l1 = (a: [number, number, number], b: [number, number, number]) =>
  Math.abs(a[0] - b[0]) + Math.abs(a[1] - b[1]) + Math.abs(a[2] - b[2]);

// ── Timeline: empty state and drop target ───────────────────────────────────

test.describe("timeline: empty state", () => {
  test("[TL-004] the empty timeline is a drop target that reports the last load error", async ({
    page,
  }) => {
    await page.addInitScript(() => {
      const globals = window as unknown as E2eWindow;
      const ipc = globals.__e2e_ipc_overrides__;
      if (!ipc) throw new Error("Tauri IPC shim overrides are missing");
      // Echo the requested paths back as sources: the lane legend then proves
      // which paths travelled through openTimelineFiles → build_timeline_cmd.
      ipc["build_timeline_cmd"] = (args) => {
        const requested: unknown =
          args && typeof args === "object" && "sources" in args
            ? args.sources
            : [];
        const paths = (Array.isArray(requested) ? requested : []).flatMap(
          (entry: unknown) => {
            if (
              entry &&
              typeof entry === "object" &&
              "path" in entry &&
              typeof entry.path === "string"
            ) {
              return [entry.path];
            }
            return [];
          },
        );
        return {
          id: "tl-drop",
          sources: paths.map((path, idx) => ({
            idx,
            kind: "intuneEvents",
            path,
            displayName: path,
            color: "#4f6bed",
            entryCount: 1,
          })),
          timeRangeMs: [0, 1000],
          totalEntries: paths.length,
          incidents: [],
          deniedGuids: [],
          errors: [],
          tunables: {
            overlapWindowMs: 5000,
            minSourceCount: 2,
            maxIncidentSpanMs: 60000,
            enabledSignalKinds: ["errorSeverity"],
          },
        };
      };
    });
    await bootApp(page, {
      overrides: { query_lane_buckets_cmd: [], query_timeline_entries_cmd: [] },
    });
    await selectWorkspace(page, "Timeline");

    await expect(
      page.getByText("Drop log files here", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByText("Or use File → New Timeline from Folder…", {
        exact: true,
      }),
    ).toBeVisible();

    // The last load error is surfaced inside the drop zone.
    await seedStore(page, TIMELINE_STORE, "useTimelineStore", {
      loadError: "Timeline build failed: no sources",
    });
    await expect(
      page
        .getByRole("alert")
        .filter({ hasText: "Timeline build failed: no sources" }),
    ).toBeVisible();

    // A drop with no filesystem path does nothing at all.
    await dropTimelineFiles(page, [{ name: "no-path.log" }]);
    await expect
      .poll(
        async () =>
          (
            await storePick(page, TIMELINE_STORE, "useTimelineStore", [
              "bundle",
            ])
          ).bundle,
      )
      .toBeNull();
    await expect(
      page.getByText("Drop log files here", { exact: true }),
    ).toBeVisible();

    // A dropped path reaches the backend and comes back as a timeline source.
    await dropTimelineFiles(page, [
      { name: "agentexecutor.log", path: "C:/logs/agentexecutor.log" },
    ]);
    await expect(
      laneLegendLanes(page).filter({ hasText: "C:/logs/agentexecutor.log" }),
    ).toHaveCount(1, { timeout: 15_000 });

    // Once a bundle exists the whole workspace layout is the drop target.
    await dropTimelineFiles(
      page,
      [{ name: "second.log", path: "C:/logs/second.log" }],
      "layout",
    );
    await expect(
      laneLegendLanes(page).filter({ hasText: "C:/logs/second.log" }),
    ).toHaveCount(1);
    await expect(laneLegendLanes(page)).toHaveCount(2);

    // …and a pathless drop on the layout changes nothing.
    await dropTimelineFiles(page, [{ name: "no-path.log" }], "layout");
    await expect(laneLegendLanes(page)).toHaveCount(2);
  });
});

// ── Timeline: swim lanes ────────────────────────────────────────────────────

test.describe("timeline: swim lanes", () => {
  test("[TL-007] lanes take the measured width, one per visible source", async ({
    page,
  }) => {
    await installLaneBuckets(page);
    // query_lane_buckets_cmd is answered by the init script above, so bootApp
    // must not overwrite it.
    await bootApp(page, { overrides: { query_timeline_entries_cmd: [] } });
    await selectWorkspace(page, "Timeline");
    await seedStore(page, TIMELINE_STORE, "useTimelineStore", {
      bundle: timelineBundle(),
    });
    await expect(laneLegendLanes(page)).toHaveCount(2);

    // The backing store follows the measured container width and the device
    // pixel ratio, one lane per visible source.
    const canvas = await sampleCanvas(page);
    expect(canvas).not.toBeNull();
    expect(canvas!.dpr).toBe(2);
    expect(canvas!.cssWidth).toBeGreaterThan(0);
    expect(canvas!.backingWidth).toBe(canvas!.cssWidth * canvas!.dpr);
    expect(canvas!.cssHeight).toBe(2 * LANE_HEIGHT);
    expect(canvas!.backingHeight).toBe(2 * LANE_HEIGHT * canvas!.dpr);
  });

  test("[TL-007] hovering a bucket reports its row and error counts", async ({
    page,
  }) => {
    await installLaneBuckets(page);
    await bootApp(page, { overrides: { query_timeline_entries_cmd: [] } });
    await selectWorkspace(page, "Timeline");
    await seedStore(page, TIMELINE_STORE, "useTimelineStore", {
      bundle: timelineBundle(),
    });
    await expect(laneLegendLanes(page)).toHaveCount(2);

    const readout = page.getByText("20 rows · 5 errors", { exact: true });
    const box = (await page.locator("canvas").boundingBox())!;
    const laneY = (lane: number) =>
      box.y + lane * LANE_HEIGHT + LANE_HEIGHT / 2;

    // Lane 1 carries no buckets, so hovering it reports nothing.
    await page.mouse.move(box.x + box.width * 0.125, laneY(1));
    await expect(readout).toHaveCount(0);

    // Lane 0's first bucket covers the first quarter of the range.
    await page.mouse.move(box.x + box.width * 0.125, laneY(0));
    await expect(readout).toBeVisible();

    // Leaving the canvas clears the readout.
    await page.mouse.move(box.x + box.width / 2, box.y - 40);
    await expect(readout).toHaveCount(0);
  });

  test("[TL-007] bucket fills follow severity and density, and the brush re-queries", async ({
    page,
  }) => {
    await installLaneBuckets(page);
    await bootApp(page, { overrides: { query_timeline_entries_cmd: [] } });
    await selectWorkspace(page, "Timeline");
    await seedStore(page, TIMELINE_STORE, "useTimelineStore", {
      bundle: timelineBundle(),
    });

    // Sample lane 0 (y=9 sits inside the drawn bucket band): 0.125 = 20 rows /
    // 5 errors, 0.425 = 20 rows / 3 warnings, 0.65 = source colour at 1 row,
    // 0.8 = source colour at 20 rows, 0.28 = empty lane background.
    const sparsePoint = { x: 0.65, y: 9 };
    const backgroundPoint = { x: 0.28, y: 9 };
    await expect
      .poll(async () => {
        const sample = await sampleCanvas(page, [sparsePoint, backgroundPoint]);
        const [sparsePixel, backgroundPixel] = sample?.pixels ?? [];
        if (!sparsePixel || !backgroundPixel) return 0;
        return l1(sparsePixel, backgroundPixel);
      })
      .toBeGreaterThan(4);

    const canvas = (await sampleCanvas(page, [
      { x: 0.125, y: 9 },
      { x: 0.425, y: 9 },
      sparsePoint,
      { x: 0.8, y: 9 },
      backgroundPoint,
    ]))!;
    const [errorBucket, warnBucket, sparseBucket, denseBucket, background] =
      canvas.pixels as [
        [number, number, number],
        [number, number, number],
        [number, number, number],
        [number, number, number],
        [number, number, number],
      ];

    // Error bucket: red fill.
    expect(errorBucket[0]).toBeGreaterThan(errorBucket[2] + 40);
    expect(errorBucket[0]).toBeGreaterThan(errorBucket[1] + 20);
    // Warning-only bucket: yellow/orange fill.
    expect(warnBucket[1]).toBeGreaterThan(warnBucket[2] + 30);
    expect(warnBucket[0]).toBeGreaterThanOrEqual(warnBucket[1]);
    // Clean bucket: the source colour (blue in this fixture).
    expect(sparseBucket[2]).toBeGreaterThan(sparseBucket[0]);
    // Density 20/20 paints far more opacity than density 1/20.
    expect(l1(denseBucket, background)).toBeGreaterThan(
      1.8 * l1(sparseBucket, background),
    );

    // A brush range re-queries the buckets for that range: the override answers
    // a brushed request with a single 99-row bucket holding errors, so the
    // formerly source-coloured band must repaint in the error fill.
    await page.evaluate(
      async ({ path, range }: { path: string; range: [number, number] }) => {
        const mod = (await import(/* @vite-ignore */ path)) as {
          useTimelineStore: {
            getState: () => { setBrushRange: (r: [number, number]) => void };
          };
        };
        mod.useTimelineStore.getState().setBrushRange(range);
      },
      { path: TIMELINE_STORE, range: [T0, T0 + 60_000] },
    );
    await expect
      .poll(async () => {
        const sample = await sampleCanvas(page, [sparsePoint]);
        const [repainted] = sample?.pixels ?? [];
        if (!repainted) return 0;
        return repainted[0] - repainted[2];
      })
      .toBeGreaterThan(40);
  });
});

// ── Timeline: ruler ─────────────────────────────────────────────────────────

test.describe("timeline: ruler", () => {
  test("[TL-008] the ruler spans the lane area with HH:MM:SS ticks", async ({
    page,
  }) => {
    await bootApp(page, {
      overrides: { query_lane_buckets_cmd: [], query_timeline_entries_cmd: [] },
    });
    await selectWorkspace(page, "Timeline");
    await seedStore(page, TIMELINE_STORE, "useTimelineStore", {
      bundle: timelineBundle(),
    });
    await expect(laneLegendLanes(page)).toHaveCount(2);

    const ruler = await page.evaluate(() => {
      const svg = Array.from(document.querySelectorAll("svg")).find((el) =>
        el.querySelector("text"),
      );
      const canvas = document.querySelector("canvas");
      if (!svg || !canvas) return null;
      return {
        width: Number(svg.getAttribute("width")),
        canvasWidth: canvas.clientWidth,
        ticks: Array.from(svg.querySelectorAll("g")).map((group) => ({
          label: group.querySelector("text")?.textContent ?? "",
          anchor: group.querySelector("text")?.getAttribute("text-anchor"),
          mark: group.querySelector("line")?.getAttribute("y2"),
          transform: group.getAttribute("transform") ?? "",
        })),
      };
    });

    expect(ruler).not.toBeNull();
    // As wide as the lane area it sits above.
    expect(ruler!.width).toBe(ruler!.canvasWidth);

    const hhmmss = (ts: number) => {
      const date = new Date(ts);
      return [date.getHours(), date.getMinutes(), date.getSeconds()]
        .map((part) => String(part).padStart(2, "0"))
        .join(":");
    };
    // One tick per ~120px of width, between 4 and 12 ticks.
    expect(ruler!.ticks).toHaveLength(
      Math.max(4, Math.min(12, Math.floor(ruler!.width / 120))) + 1,
    );

    for (const tick of ruler!.ticks) {
      expect(tick.label).toMatch(/^\d{2}:\d{2}:\d{2}$/);
      expect(tick.anchor).toBe("middle");
      expect(tick.mark).toBe("6");
      expect(tick.transform).toMatch(/^translate\(/);
    }

    // The ticks span the bundle's time range.
    expect(ruler!.ticks[0].label).toBe(hhmmss(T0));
    expect(ruler!.ticks.at(-1)!.label).toBe(hhmmss(T0 + HOUR_MS));
  });
});

// ── Timeline: incident chips ────────────────────────────────────────────────

test.describe("timeline: incident chips", () => {
  test("[TL-010] chips colour by confidence and toggle the selection", async ({
    page,
  }) => {
    await bootApp(page, {
      overrides: { query_lane_buckets_cmd: [], query_timeline_entries_cmd: [] },
    });
    await selectWorkspace(page, "Timeline");
    await seedStore(page, TIMELINE_STORE, "useTimelineStore", {
      bundle: timelineBundle({
        incidents: [
          timelineIncident(1, 0.9, "High confidence"),
          timelineIncident(2, 0.65, "Medium confidence"),
          timelineIncident(3, 0.3, "Low confidence"),
        ],
      }),
    });

    const chips = [
      page.getByRole("button", { name: "#1 · High confidence" }),
      page.getByRole("button", { name: "#2 · Medium confidence" }),
      page.getByRole("button", { name: "#3 · Low confidence" }),
    ];
    for (const chip of chips) await expect(chip).toBeVisible();

    // Confidence >= 0.8 is red, >= 0.6 yellow, otherwise neutral. The theme
    // custom properties only cascade inside the app, so the probe element goes
    // into the chip bar rather than the document body.
    const dots = await page.evaluate(() => {
      const observed = Array.from(document.querySelectorAll("button"))
        .filter((button) => /^#\d+ · /.test(button.textContent ?? ""))
        .map((button) => {
          const dot = button.querySelector("span");
          return dot ? getComputedStyle(dot).backgroundColor : null;
        });
      const chipButton = Array.from(document.querySelectorAll("button")).find(
        (button) => /^#\d+ · /.test(button.textContent ?? ""),
      );
      const host = chipButton?.parentElement ?? document.body;
      const probe = document.createElement("div");
      host.append(probe);
      const resolve = (token: string) => {
        probe.style.backgroundColor = token;
        return getComputedStyle(probe).backgroundColor;
      };
      const expected = {
        red: resolve("var(--colorPaletteRedForeground1)"),
        yellow: resolve("var(--colorPaletteYellowForeground2)"),
        neutral: resolve("var(--colorNeutralForeground3)"),
      };
      probe.remove();
      return { expected, observed };
    });
    expect(dots.observed).toEqual([
      dots.expected.red,
      dots.expected.yellow,
      dots.expected.neutral,
    ]);

    // Clicking a chip selects it and brushes its span…
    await chips[0].click();
    await expect
      .poll(
        async () =>
          (
            await storePick(page, TIMELINE_STORE, "useTimelineStore", [
              "selectedIncidentId",
            ])
          ).selectedIncidentId,
      )
      .toBe(1);
    expect(
      (
        await storePick(page, TIMELINE_STORE, "useTimelineStore", [
          "brushRange",
        ])
      ).brushRange,
    ).toEqual([T0 - 2_000, T0 + 5_000 + 2_000]);

    // …clicking a different chip moves the selection…
    await chips[1].click();
    await expect
      .poll(
        async () =>
          (
            await storePick(page, TIMELINE_STORE, "useTimelineStore", [
              "selectedIncidentId",
            ])
          ).selectedIncidentId,
      )
      .toBe(2);

    // …and clicking the selected chip clears it.
    await chips[1].click();
    await expect
      .poll(
        async () =>
          (
            await storePick(page, TIMELINE_STORE, "useTimelineStore", [
              "selectedIncidentId",
            ])
          ).selectedIncidentId,
      )
      .toBeNull();
  });

  test("[TL-010] the chip bar distinguishes no incidents from no bundle", async ({
    page,
  }) => {
    await bootApp(page, {
      overrides: { query_lane_buckets_cmd: [], query_timeline_entries_cmd: [] },
    });
    await selectWorkspace(page, "Timeline");

    // No bundle: the chip bar renders nothing at all.
    await expect(
      page.getByText("Drop log files here", { exact: true }),
    ).toBeVisible();
    await expect(page.getByText(/No incidents detected/)).toHaveCount(0);
    await expect(page.getByRole("button", { name: /^#\d+ · / })).toHaveCount(0);

    // Bundle without incidents: the empty-state hint appears.
    await seedStore(page, TIMELINE_STORE, "useTimelineStore", {
      bundle: timelineBundle(),
    });
    await expect(
      page.getByText(
        "No incidents detected — adjust signal settings in the gear menu.",
        {
          exact: true,
        },
      ),
    ).toBeVisible();
  });
});

// ── Timeline: incident detail panel ─────────────────────────────────────────

const DETAIL_ANCHOR_GUID = "11111111-2222-3333-4444-555555555555";
const DETAIL_INCIDENT = timelineIncident(
  7,
  0.852,
  "AgentExecutor install failed",
);
const DETAIL: IncidentDetail = {
  incident: {
    ...DETAIL_INCIDENT,
    anchorGuid: DETAIL_ANCHOR_GUID,
    anchorEventRef: [0, 42],
  },
  signals: [
    {
      sourceIdx: 0,
      sourceName: "agentexecutor.log",
      tsMs: T0 + 1_000,
      kind: "imeFailed",
      correlationId: DETAIL_ANCHOR_GUID,
      lineNumber: 42,
      preview: `Failed to install application with GUID ${DETAIL_ANCHOR_GUID}`,
    },
    {
      sourceIdx: 1,
      sourceName: "IntuneManagementExtension.log",
      tsMs: T0 + 2_000,
      kind: "errorSeverity",
      lineNumber: 7,
      preview: "ERROR: install context rejected",
    },
  ],
  perSourceSignalCounts: {
    "agentexecutor.log": 2,
    "IntuneManagementExtension.log": 1,
  },
};

/** Installs the incident-detail override, driven by page globals. */
async function installIncidentDetail(
  page: Page,
  options: { detail?: IncidentDetail; mode?: string },
): Promise<void> {
  await page.addInitScript(
    (init: { detail?: IncidentDetail; mode?: string }) => {
      const globals = window as unknown as E2eWindow;
      const ipc = globals.__e2e_ipc_overrides__;
      if (!ipc) throw new Error("Tauri IPC shim overrides are missing");
      globals.__e2e_detail__ = init.detail;
      globals.__e2e_detail_mode__ = init.mode ?? "ok";
      ipc["query_incident_details_cmd"] = () => {
        globals.__e2e_detail_calls__ = (globals.__e2e_detail_calls__ ?? 0) + 1;
        if (globals.__e2e_detail_mode__ === "reject") {
          return Promise.reject(new Error("incident detail query failed"));
        }
        return globals.__e2e_detail__;
      };
    },
    options,
  );
}

test.describe("timeline: incident detail", () => {
  test("[TL-011] the panel shows the anchor GUID, signals and copy action", async ({
    page,
  }) => {
    await installIncidentDetail(page, { detail: DETAIL });
    await page.addInitScript(() => {
      const globals = window as unknown as E2eWindow;
      const ipc = globals.__e2e_ipc_overrides__;
      if (!ipc) throw new Error("Tauri IPC shim overrides are missing");
      ipc["plugin:clipboard-manager|write_text"] = (args) => {
        globals.__e2e_clipboard__ =
          args &&
          typeof args === "object" &&
          "text" in args &&
          typeof args.text === "string"
            ? args.text
            : undefined;
        return null;
      };
    });
    await bootApp(page, {
      overrides: { query_lane_buckets_cmd: [], query_timeline_entries_cmd: [] },
    });
    await selectWorkspace(page, "Timeline");
    await seedStore(page, TIMELINE_STORE, "useTimelineStore", {
      bundle: timelineBundle({
        incidents: [{ ...DETAIL_INCIDENT, anchorGuid: DETAIL_ANCHOR_GUID }],
      }),
    });

    // The chrome's sidebar is an <aside> too, so the panel is identified by its
    // own content.
    const panel = page.locator("aside").filter({ hasText: "Incident #" });
    await expect(panel).toHaveCount(0);

    await page
      .getByRole("button", { name: "#7 · AgentExecutor install failed" })
      .click();
    await expect(panel).toBeVisible({ timeout: 15_000 });

    await expect(panel.getByText("Incident #7", { exact: true })).toBeVisible();
    await expect(
      panel.getByText("AgentExecutor install failed", { exact: true }),
    ).toBeVisible();
    await expect(panel.getByText(/· confidence 85%/).first()).toBeVisible();

    // Per-source signal counts.
    await expect(panel.getByText("Sources", { exact: true })).toBeVisible();
    await expect(
      panel.getByText("agentexecutor.log", { exact: true }),
    ).toBeVisible();
    await expect(
      panel.getByText("IntuneManagementExtension.log", { exact: true }),
    ).toBeVisible();
    await expect(panel.getByText("2", { exact: true })).toBeVisible();
    await expect(panel.getByText("1", { exact: true })).toBeVisible();

    // Anchor GUID plus its clipboard action.
    await expect(panel.getByText("Anchor GUID", { exact: true })).toBeVisible();
    await expect(panel.locator("code")).toHaveText(DETAIL_ANCHOR_GUID);
    await panel.getByRole("button", { name: "Copy" }).click();
    await expect
      .poll(async () =>
        page.evaluate(
          () => (window as unknown as E2eWindow).__e2e_clipboard__ ?? "",
        ),
      )
      .toBe(DETAIL_ANCHOR_GUID);

    // Each signal row is "<time> · <source> · <kind>" above its preview line.
    await expect(panel.getByText("Signals (2)", { exact: true })).toBeVisible();
    const rows = await panel.evaluate((aside) =>
      Array.from(aside.querySelectorAll("div"))
        .filter((row) =>
          (row.getAttribute("style") ?? "").includes("border-bottom"),
        )
        .map((row) => ({
          header: row.firstElementChild?.textContent?.trim() ?? "",
          preview: row.lastElementChild?.textContent?.trim() ?? "",
        })),
    );
    expect(rows).toHaveLength(2);
    const correlated = rows[0].header.split(" · ");
    expect(correlated).toHaveLength(4);
    expect(correlated[0]).not.toHaveLength(0);
    expect(correlated[1]).toBe("agentexecutor.log");
    expect(correlated[2]).toBe("imeFailed");
    expect(correlated[3]).toBe("(correlated)");
    expect(rows[0].preview).toBe(
      `Failed to install application with GUID ${DETAIL_ANCHOR_GUID}`,
    );

    const plain = rows[1].header.split(" · ");
    expect(plain).toHaveLength(3);
    expect(plain[1]).toBe("IntuneManagementExtension.log");
    expect(plain[2]).toBe("errorSeverity");
    expect(rows[1].preview).toBe("ERROR: install context rejected");

    // Close clears the selection and the panel.
    await panel.getByRole("button", { name: "Close" }).click();
    await expect(panel).toHaveCount(0);
    await expect
      .poll(
        async () =>
          (
            await storePick(page, TIMELINE_STORE, "useTimelineStore", [
              "selectedIncidentId",
            ])
          ).selectedIncidentId,
      )
      .toBeNull();
  });

  test("[TL-011] a failed detail query leaves no panel behind", async ({
    page,
  }) => {
    await installIncidentDetail(page, { mode: "reject" });
    await bootApp(page, {
      overrides: { query_lane_buckets_cmd: [], query_timeline_entries_cmd: [] },
    });
    await selectWorkspace(page, "Timeline");
    await seedStore(page, TIMELINE_STORE, "useTimelineStore", {
      bundle: timelineBundle({ incidents: [DETAIL_INCIDENT] }),
    });

    await page.evaluate(
      async ({ path, id }: { path: string; id: number }) => {
        const mod = (await import(/* @vite-ignore */ path)) as {
          useTimelineStore: {
            getState: () => { selectIncident: (value: number | null) => void };
          };
        };
        mod.useTimelineStore.getState().selectIncident(id);
      },
      { path: TIMELINE_STORE, id: 7 },
    );
    await expect
      .poll(
        async () =>
          (
            await storePick(page, TIMELINE_STORE, "useTimelineStore", [
              "selectedIncidentId",
            ])
          ).selectedIncidentId,
      )
      .toBe(7);
    // The rejected query still ran, so the absent panel is not a race artefact.
    await expect
      .poll(async () =>
        page.evaluate(
          () => (window as unknown as E2eWindow).__e2e_detail_calls__ ?? 0,
        ),
      )
      .toBeGreaterThan(0);

    await expect(
      page.locator("aside").filter({ hasText: "Incident #" }),
    ).toHaveCount(0);
    await expect(page.getByText("Incident #7", { exact: true })).toHaveCount(0);
  });
});

// ── Timeline: tunables ──────────────────────────────────────────────────────

test.describe("timeline: tunables", () => {
  test("[TL-018] no front-end action reaches update_timeline_tunables_cmd", async ({
    page,
  }) => {
    await page.addInitScript(() => {
      const globals = window as unknown as E2eWindow;
      const ipc = globals.__e2e_ipc_overrides__;
      if (!ipc) throw new Error("Tauri IPC shim overrides are missing");
      ipc["update_timeline_tunables_cmd"] = () => {
        globals.__e2e_tunables_calls__ =
          (globals.__e2e_tunables_calls__ ?? 0) + 1;
        return [];
      };
    });
    await bootApp(page, {
      overrides: { query_lane_buckets_cmd: [], query_timeline_entries_cmd: [] },
    });
    await selectWorkspace(page, "Timeline");
    await seedStore(page, TIMELINE_STORE, "useTimelineStore", {
      bundle: timelineBundle(),
    });

    // The empty chip bar advertises a gear menu for signal settings.
    await expect(
      page.getByText(
        "No incidents detected — adjust signal settings in the gear menu.",
        {
          exact: true,
        },
      ),
    ).toBeVisible();

    // No such control exists, and exercising every control the workspace does
    // offer never reaches the tunables command.
    const gearControls = await page.evaluate(() => {
      const workspace = document.querySelector(
        '[title^="Click: solo this lane"]',
      )?.parentElement?.parentElement;
      const scope = workspace ?? document.body;
      return Array.from(
        scope.querySelectorAll("button,[role='menuitem'],[role='button']"),
      )
        .map((el) =>
          `${el.getAttribute("aria-label") ?? ""} ${el.textContent ?? ""}`.trim(),
        )
        .filter((name) => /gear|tunab|signal setting/i.test(name));
    });
    expect(gearControls).toEqual([]);

    const lane = laneLegendLanes(page).first();
    await lane.click(); // solo the lane
    await lane.click(); // and release it
    expect(
      await page.evaluate(
        () => (window as unknown as E2eWindow).__e2e_tunables_calls__ ?? 0,
      ),
    ).toBe(0);
  });
});

// ── Event Log Viewer: source picker ─────────────────────────────────────────

test.describe("event log: source picker", () => {
  test("[EVTX-014] the picker runs one open operation at a time", async ({
    page,
  }) => {
    await page.addInitScript(() => {
      const globals = window as unknown as E2eWindow;
      const ipc = globals.__e2e_ipc_overrides__;
      if (!ipc) throw new Error("Tauri IPC shim overrides are missing");
      ipc["plugin:dialog|open"] = () => {
        globals.__e2e_dialog_calls__ = (globals.__e2e_dialog_calls__ ?? 0) + 1;
        if (globals.__e2e_dialog_mode__ === "reject") {
          return Promise.reject(new Error("dialog exploded"));
        }
        // Stands in for an operator staring at an open native dialog.
        const { promise, resolve } = Promise.withResolvers<null>();
        window.setTimeout(() => resolve(null), 1200);
        return promise;
      };
      ipc["evtx_enumerate_channels"] = () =>
        Promise.reject(new Error("channel enumeration exploded"));
    });
    await bootApp(page);
    await selectWorkspace(page, "Event Log Viewer (Preview)");
    await expect(
      page.getByText("Event Log Viewer", { exact: true }),
    ).toBeVisible();

    await page.getByLabel("Remote computer name").fill("SERVER01");
    const openFiles = page.getByRole("button", { name: "Open .evtx files..." });
    const openFolder = page.getByRole("button", {
      name: "Open folder recursively...",
    });
    const thisComputer = page.getByRole("button", { name: "This computer" });
    const remote = page.getByRole("button", { name: "Remote computer" });
    const dialogCalls = () =>
      page.evaluate(
        () => (window as unknown as E2eWindow).__e2e_dialog_calls__ ?? 0,
      );

    // Every entry point is disabled while one operation is in flight.
    await openFiles.click();
    await expect(openFiles).toBeDisabled();
    await expect(openFolder).toBeDisabled();
    await expect(thisComputer).toBeDisabled();
    await expect(remote).toBeDisabled();
    expect(await dialogCalls()).toBe(1);

    // A second activation is refused: the re-entrancy guard, not the disabled
    // attribute, is what keeps a second native dialog from opening.
    await openFolder.dispatchEvent("click");
    await expect(thisComputer).toBeDisabled();
    expect(await dialogCalls()).toBe(1);

    // Cancelling the dialog runs finishOpening in its finally block.
    await expect(openFiles).toBeEnabled({ timeout: 10_000 });
    await expect(openFolder).toBeEnabled();
    await expect(thisComputer).toBeEnabled();
    await expect(remote).toBeEnabled();

    // A dialog failure lands in the picker's own alert and still re-enables.
    await page.evaluate(() => {
      (window as unknown as E2eWindow).__e2e_dialog_mode__ = "reject";
    });
    await openFiles.click();
    await expect(
      page.getByRole("alert").filter({ hasText: "dialog exploded" }),
    ).toBeVisible();
    await expect(openFiles).toBeEnabled();
    await expect(thisComputer).toBeEnabled();

    // So does a failed channel enumeration.
    await thisComputer.click();
    await expect(
      page
        .getByRole("alert")
        .filter({ hasText: "channel enumeration exploded" }),
    ).toBeVisible({ timeout: 15_000 });
    await expect(thisComputer).toBeEnabled();
    await expect(openFolder).toBeEnabled();
  });
});

// ── Event Log Viewer: channel sidebar and live load ─────────────────────────

const LIVE_CHANNELS: {
  name: string;
  eventCount: number;
  sourceType: string;
}[] = [
  { name: "Application", eventCount: 3, sourceType: "live" },
  { name: "System", eventCount: 0, sourceType: "live" },
  {
    name: "Microsoft-Windows-AAD/Operational",
    eventCount: 0,
    sourceType: "live",
  },
];

/**
 * Answers a live channel query with records and publishes the terminal stream
 * marker the store waits for, exactly as the real backend does.
 */
async function installLiveQuery(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const globals = window as unknown as E2eWindow;
    const ipc = globals.__e2e_ipc_overrides__;
    if (!ipc) throw new Error("Tauri IPC shim overrides are missing");
    ipc["evtx_query_channels"] = (args) => {
      const query = (args ?? {}) as { channels?: string[]; requestId?: string };
      const channel = query.channels?.[0] ?? "";
      const requestId = query.requestId ?? "";
      // Deliberately outside the default 24h window: the status bar counts the
      // stored records, while keeping them off the table avoids depending on
      // the table's own rendering.
      const records =
        channel === "Application"
          ? [0, 1, 2].map((offset) => ({
              id: offset,
              eventRecordId: 100 + offset,
              timestamp: "2000-01-01T00:00:00.000Z",
              timestampEpoch: 946_684_800_000 + offset * 1_000,
              provider: "Microsoft-Windows-Demo",
              channel,
              eventId: 4_624,
              level: "Information",
              computer: "DEMO-HOST",
              message: `demo event ${offset}`,
              eventData: [],
              rawXml: "<Event/>",
              sourceLabel: channel,
            }))
          : [];
      globals.__e2e_emit__?.("evtx-record-stream-complete", {
        channel,
        requestId,
        sequenceCount: 0,
        totalRecords: records.length,
      });
      return {
        records,
        channels: [
          { name: channel, eventCount: records.length, sourceType: "live" },
        ],
        totalRecords: records.length,
        parseErrors: 0,
        errorMessages: [],
      };
    };
  });
}

test.describe("event log: channel sidebar", () => {
  test("[EVTX-036] the sidebar drag handle clamps between 200px and 500px", async ({
    page,
  }) => {
    await installLiveQuery(page);
    await bootApp(page, {
      overrides: { evtx_enumerate_channels: LIVE_CHANNELS },
    });
    await selectWorkspace(page, "Event Log Viewer (Preview)");
    await page.getByRole("button", { name: "This computer" }).click();
    await expect(page.getByPlaceholder("Filter channels...")).toBeVisible({
      timeout: 15_000,
    });

    const geometry = () =>
      page.evaluate(() => {
        const handle = document.querySelector('div[style*="col-resize"]');
        const sidebar = handle?.previousElementSibling ?? null;
        return {
          handleWidth: handle ? getComputedStyle(handle).width : null,
          sidebarWidth: sidebar ? getComputedStyle(sidebar).width : null,
          cursor: document.body.style.cursor,
          userSelect: document.body.style.userSelect,
        };
      });

    expect(await geometry()).toMatchObject({
      handleWidth: "4px",
      sidebarWidth: "300px",
      cursor: "",
      userSelect: "",
    });

    const handle = page.locator('div[style*="col-resize"]');
    const first = (await handle.boundingBox())!;
    await page.mouse.move(first.x + 2, first.y + 20);
    await page.mouse.down();
    await page.mouse.move(first.x + 2 + 250, first.y + 20, { steps: 4 });

    // Dragging signals col-resize and suppresses text selection…
    expect(await geometry()).toMatchObject({
      sidebarWidth: "500px",
      cursor: "col-resize",
      userSelect: "none",
    });

    // …and mouse-up restores both while keeping the clamped width.
    await page.mouse.up();
    expect(await geometry()).toMatchObject({
      sidebarWidth: "500px",
      cursor: "",
      userSelect: "",
    });

    // Dragging back past the minimum clamps at 200px.
    const second = (await handle.boundingBox())!;
    await page.mouse.move(second.x + 2, second.y + 20);
    await page.mouse.down();
    await page.mouse.move(second.x + 2 - 600, second.y + 20, { steps: 6 });
    expect(await geometry()).toMatchObject({
      sidebarWidth: "200px",
      cursor: "col-resize",
    });
    await page.mouse.up();
    expect(await geometry()).toMatchObject({
      sidebarWidth: "200px",
      cursor: "",
      userSelect: "",
    });
  });
});

test.describe("event log: live load", () => {
  test("[EVTX-026] progress events only apply to the current request", async ({
    page,
  }) => {
    await installLiveQuery(page);
    await bootApp(page, {
      overrides: { evtx_enumerate_channels: LIVE_CHANNELS },
    });
    await selectWorkspace(page, "Event Log Viewer (Preview)");
    await expect(
      page.getByText("Event Log Viewer", { exact: true }),
    ).toBeVisible();

    // No load has started yet, so the store's current request id is still its
    // module-level default; the listener runs synchronously with the emit.
    await emitBackendEvent(page, "evtx-query-progress", {
      requestId: "initial",
      channel: "Application",
      fetched: 128,
    });
    expect(
      await storePick(page, EVTX_STORE, "useEvtxStore", [
        "loadingChannel",
        "loadingProgress",
      ]),
    ).toMatchObject({ loadingChannel: "Application", loadingProgress: 128 });

    // A stale request id is ignored.
    await emitBackendEvent(page, "evtx-query-progress", {
      requestId: "event-log-9999",
      channel: "Security",
      fetched: 4_096,
    });
    expect(
      await storePick(page, EVTX_STORE, "useEvtxStore", [
        "loadingChannel",
        "loadingProgress",
      ]),
    ).toMatchObject({ loadingChannel: "Application", loadingProgress: 128 });

    // The load itself clears the pair on settle.
    await page.getByRole("button", { name: "This computer" }).click();
    await expect
      .poll(
        async () =>
          (await storePick(page, EVTX_STORE, "useEvtxStore", ["isLoading"]))
            .isLoading,
      )
      .toBe(false);
    expect(
      await storePick(page, EVTX_STORE, "useEvtxStore", [
        "loadingChannel",
        "loadingProgress",
      ]),
    ).toMatchObject({ loadingChannel: null, loadingProgress: null });
  });

  test("[EVTX-026] a settled load records its elapsed time for the status bar", async ({
    page,
  }) => {
    await installLiveQuery(page);
    await bootApp(page, {
      overrides: { evtx_enumerate_channels: LIVE_CHANNELS },
    });
    await selectWorkspace(page, "Event Log Viewer (Preview)");
    await page.getByRole("button", { name: "This computer" }).click();

    await expect
      .poll(
        async () =>
          (
            (await storePick(page, EVTX_STORE, "useEvtxStore", ["records"]))
              .records as unknown[]
          ).length,
        { timeout: 15_000 },
      )
      .toBe(3);

    // The read time is stamped when the whole load settles, not per channel.
    await expect
      .poll(
        async () =>
          (await storePick(page, EVTX_STORE, "useEvtxStore", ["isLoading"]))
            .isLoading,
      )
      .toBe(false);

    const elapsed = (
      await storePick(page, EVTX_STORE, "useEvtxStore", ["loadElapsedMs"])
    ).loadElapsedMs;
    expect(typeof elapsed).toBe("number");
    expect(Number.isFinite(elapsed as number)).toBe(true);
    expect(elapsed as number).toBeGreaterThanOrEqual(0);
    expect(
      (await storePick(page, EVTX_STORE, "useEvtxStore", ["loadStartTime"]))
        .loadStartTime,
    ).not.toBeNull();

    // The status bar reports that recorded read time.
    await expect(
      page.getByText(
        `3 events in ${((elapsed as number) / 1000).toFixed(1)}s`,
        { exact: true },
      ),
    ).toBeVisible({ timeout: 10_000 });
  });
});

// ── Event Log Viewer story whose contract lives outside the browser ─────────

// ── SCCM: discovery console ─────────────────────────────────────────────────

/** Installs the SCCM discovery override, fed by a page global. */
async function installSccmDiscovery(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const globals = window as unknown as E2eWindow;
    const ipc = globals.__e2e_ipc_overrides__;
    if (!ipc) throw new Error("Tauri IPC shim overrides are missing");
    ipc["discover_sccm_environment"] = () =>
      globals.__e2e_sccm_discovery__ ?? null;
  });
}

test.describe("sccm: discovery console", () => {
  test("[SCCM-007] the environment strip and issue rail render the discovered state", async ({
    page,
  }) => {
    await installSccmDiscovery(page);
    await bootApp(page);
    await selectWorkspace(page, "SCCM Diagnostics");

    const discover = page.getByRole("button", {
      name: /Discover(ing)? SCCM environment/,
    });
    const publish = async (discovery: unknown) => {
      await page.evaluate(
        ({ name, value }) => {
          (window as unknown as Record<string, unknown>)[name] = value;
        },
        { name: "__e2e_sccm_discovery__", value: discovery },
      );
      await discover.click();
    };

    await publish({
      supported: true,
      configmgrVersion: "5.00.9128.1007",
      roles: [
        { role: "siteServer", basis: "registry" },
        { role: "client", basis: "service" },
      ],
      sources: [],
      issues: [
        { code: "registryAccessDenied", role: "client" },
        { code: "discoveryFailed" },
      ],
      advancedSources: [],
    });

    const strip = page.getByRole("region", { name: "Discovered environment" });
    await expect(strip).toBeVisible();
    await expect(strip.getByText("Collector", { exact: true })).toBeVisible();
    await expect(strip.getByText("Supported", { exact: true })).toBeVisible();
    await expect(strip.getByText("ConfigMgr", { exact: true })).toBeVisible();
    await expect(
      strip.getByText("5.00.9128.1007", { exact: true }),
    ).toBeVisible();
    await expect(
      strip.getByText("Observed roles", { exact: true }),
    ).toBeVisible();
    await expect(strip.locator(".sccm-role-chip")).toHaveCount(2);
    await expect(strip.getByText("Site Server", { exact: true })).toBeVisible();
    await expect(strip.getByText("Registry", { exact: true })).toBeVisible();
    await expect(strip.getByText("Client", { exact: true })).toBeVisible();
    await expect(strip.getByText("Service", { exact: true })).toBeVisible();

    const rail = page.getByRole("region", { name: "Discovery issues" });
    await expect(rail).toBeVisible();
    await expect(
      rail.getByText("Registry access denied", { exact: true }),
    ).toBeVisible();
    await expect(rail.getByText("Client", { exact: true })).toBeVisible();
    await expect(
      rail.getByText("Discovery failed", { exact: true }),
    ).toBeVisible();

    // Unsupported collector, unreported version and no observed roles.
    await publish({
      supported: false,
      configmgrVersion: null,
      roles: [],
      sources: [],
      issues: [{ code: "unsupportedPlatform" }],
      advancedSources: [],
    });
    await expect(strip.getByText("Unavailable", { exact: true })).toBeVisible();
    await expect(
      strip.getByText("Not reported", { exact: true }),
    ).toBeVisible();
    await expect(
      strip.getByText("No SCCM roles observed", { exact: true }),
    ).toBeVisible();
    await expect(
      rail.getByText("Unsupported platform", { exact: true }),
    ).toBeVisible();

    // No issues means no rail at all.
    await publish({
      supported: true,
      configmgrVersion: null,
      roles: [],
      sources: [],
      issues: [],
      advancedSources: [],
    });
    await expect(
      page.getByRole("region", { name: "Discovery issues" }),
    ).toHaveCount(0);
    await expect(
      strip.getByText("No SCCM roles observed", { exact: true }),
    ).toBeVisible();
  });
});
