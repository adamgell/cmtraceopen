import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  buildComparisonPresentation,
  CLEARED_NOTICE,
  COMPARE_LABEL,
  type ComparisonPresentationInput,
} from "./evtx-chart-comparison";
import {
  compareLoadedFiles,
  computePriorWindow,
  eventIdentityKey,
  type ComparisonOutcome,
  type ComparisonState,
  type PriorWindow,
} from "./evtx-comparison";
import { DEFAULT_QUICK_FILTER } from "./evtx-filter";
import type { EvtxLevel, EvtxRecord } from "./types";

const ANCHOR = Date.parse("2026-08-10T12:00:00.000Z");
const HOUR = 60 * 60 * 1000;
const ALL_LEVELS: EvtxLevel[] = ["Critical", "Error", "Warning", "Information", "Verbose"];

let nextId = 1;
function record(overrides: Partial<EvtxRecord> = {}): EvtxRecord {
  const id = nextId++;
  return {
    id,
    eventRecordId: id,
    timestamp: "2026-08-09T06:00:00.000Z",
    timestampEpoch: ANCHOR - 30 * HOUR,
    provider: "Contoso-Provider",
    channel: "System",
    eventId: 12,
    level: "Information",
    computer: "CONTOSO-PC01",
    message: "synthetic",
    eventData: [],
    rawXml: "<Event/>",
    sourceLabel: "System.evtx",
    ...overrides,
  };
}

function priorFor(window: "1h" | "24h" | "7d" | "30d" = "24h"): PriorWindow {
  const result = computePriorWindow(window, ANCHOR);
  if (result.status !== "available") throw new Error("expected an available prior window");
  return result.prior;
}

/** A files comparison the way the store makes one: records spanning the previous period. */
function filesOutcome(extra: EvtxRecord[] = []): ComparisonOutcome {
  const prior = priorFor();
  return compareLoadedFiles({
    records: [
      record({ timestampEpoch: prior.fromMs, level: "Error", provider: "A", eventId: 1 }),
      record({ timestampEpoch: prior.fromMs + HOUR, level: "Error", provider: "A", eventId: 1 }),
      record({ timestampEpoch: prior.fromMs + 2 * HOUR, level: "Warning", provider: "B", eventId: 2 }),
      record({ timestampEpoch: prior.toMs }),
      record({ timestampEpoch: ANCHOR }),
      ...extra,
    ],
    window: "24h",
    anchorEpoch: ANCHOR,
    visibility: {
      selectedChannels: new Set(["System"]),
      filterLevels: new Set<EvtxLevel>(ALL_LEVELS),
      filterEventIds: "",
      filterSearch: "",
      quickFilter: DEFAULT_QUICK_FILTER,
    },
    coverageDetails: [],
    sourceCoverage: [],
  });
}

function settledState(outcome: ComparisonOutcome): ComparisonState {
  return { phase: "settled", outcome };
}

const TALLY = {
  errors: 6,
  distinctIds: new Set([eventIdentityKey("A", 1), eventIdentityKey("C", 3)]),
  tailExcluded: 0,
  unplacedRecords: 0,
};

function input(overrides: Partial<ComparisonPresentationInput> = {}): ComparisonPresentationInput {
  return {
    state: { phase: "idle" },
    availability: { available: true },
    timeZoneMode: "utc",
    snapshotEpoch: ANCHOR,
    countCurrent: () => TALLY,
    cleared: false,
    ...overrides,
  };
}

const PRIOR_LABEL =
  "Comparing with 2026-08-08 12:00:00.000 to 2026-08-09 11:59:59.999 (UTC)";

describe("not compared", () => {
  it("offers Compare, shows no label, no status and no delta", () => {
    const view = buildComparisonPresentation(input());
    expect(view).toMatchObject({
      phase: "off",
      label: null,
      status: null,
      deltas: null,
      canClear: false,
      clearedNotice: null,
      action: { label: "Compare with previous period", kind: "compare", disabled: false, reason: null },
    });
    expect(COMPARE_LABEL).toBe("Compare with previous period");
  });

  it("is disabled, with the reason the comparison itself gives, when the prior period is not loaded", () => {
    const view = buildComparisonPresentation(
      input({
        availability: { available: false, detail: "The loaded files do not cover the previous period." },
      }),
    );
    expect(view.action).toEqual({
      label: "Compare with previous period",
      kind: "compare",
      disabled: true,
      reason: "The loaded files do not cover the previous period.",
    });
    expect(view.deltas).toBeNull();
  });

  it("says a comparison was cleared, once, when what it measured changed", () => {
    expect(buildComparisonPresentation(input({ cleared: true })).clearedNotice).toBe(CLEARED_NOTICE);
    expect(CLEARED_NOTICE).toBe("The comparison was cleared because what it measured changed.");
    expect(buildComparisonPresentation(input()).clearedNotice).toBeNull();
  });
});

describe("comparing", () => {
  const prior = priorFor();
  const running = (scanned: number): ComparisonState => ({
    phase: "running",
    mode: "live",
    requestId: "event-log-compare-1",
    prior,
    channels: ["System"],
    scanned,
  });

  it("names the period being read and shows no delta and no action but Clear", () => {
    const view = buildComparisonPresentation(input({ state: running(0) }));
    expect(view).toMatchObject({
      phase: "running",
      label: PRIOR_LABEL,
      status: "Reading the previous period.",
      deltas: null,
      action: null,
      canClear: true,
    });
  });

  it("states how many events were scanned so far, as progress and not as a count of anything", () => {
    const view = buildComparisonPresentation(input({ state: running(12_345) }));
    expect(view.status).toBe(
      `Reading the previous period: ${(12_345).toLocaleString()} events scanned so far.`,
    );
    expect(buildComparisonPresentation(input({ state: running(1) })).status).toBe(
      "Reading the previous period: 1 event scanned so far.",
    );
  });

  it("never counts the current period while running", () => {
    const countCurrent = vi.fn(() => TALLY);
    buildComparisonPresentation(input({ state: running(5), countCurrent }));
    expect(countCurrent).not.toHaveBeenCalled();
  });
});

describe("complete and current", () => {
  it("shows the label, offers Clear, and hands the deltas their two periods", () => {
    const outcome = filesOutcome();
    expect(outcome.status).toBe("complete");
    const view = buildComparisonPresentation(input({ state: settledState(outcome) }));
    expect(view).toMatchObject({
      phase: "complete",
      label: PRIOR_LABEL,
      status: null,
      reasons: [],
      canClear: true,
      action: null,
    });
    if (outcome.status !== "complete") return;
    expect(view.deltas).toEqual({
      window: "24h",
      current: { errors: 6, distinctIds: TALLY.distinctIds },
      prior: {
        errors: outcome.result.counts.levels.Error,
        distinctIds: outcome.result.counts.distinctEvents,
      },
    });
    expect(outcome.result.counts.levels.Error).toBe(2);
  });

  it("repeats every note the comparison carries, as written", () => {
    const outcome = filesOutcome();
    if (outcome.status !== "complete") throw new Error("expected complete");
    const withNotes: ComparisonOutcome = {
      status: "complete",
      result: { ...outcome.result, notes: ["Periods are computed on this computer's clock", "Another note"] },
    };
    expect(buildComparisonPresentation(input({ state: settledState(withNotes) })).notes).toEqual([
      "Periods are computed on this computer's clock",
      "Another note",
    ]);
  });

  it("states how many tail events were left out of the current period, from the same tally", () => {
    const outcome = filesOutcome();
    const one = buildComparisonPresentation(
      input({ state: settledState(outcome), countCurrent: () => ({ ...TALLY, tailExcluded: 1 }) }),
    );
    expect(one.notes).toContain("Left out of the current period: 1 event appended by the live tail.");
    const many = buildComparisonPresentation(
      input({ state: settledState(outcome), countCurrent: () => ({ ...TALLY, tailExcluded: 4 }) }),
    );
    expect(many.notes).toContain("Left out of the current period: 4 events appended by the live tail.");
    expect(
      buildComparisonPresentation(input({ state: settledState(outcome) })).notes.join(" "),
    ).not.toContain("Left out");
  });

  it("counts the current period once", () => {
    const countCurrent = vi.fn(() => TALLY);
    buildComparisonPresentation(input({ state: settledState(filesOutcome()), countCurrent }));
    expect(countCurrent).toHaveBeenCalledTimes(1);
  });

  it("uses the clock the operator reads times in", () => {
    const view = buildComparisonPresentation(
      input({ state: settledState(filesOutcome()), timeZoneMode: "local" }),
    );
    expect(view.label).toMatch(/^Comparing with \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} to .* \(UTC[+-]\d{2}:\d{2}\)$/);
  });
});

describe("withheld, when the current period has entries that could not be placed", () => {
  const withheld = (unplacedRecords: number, tailExcluded = 0) =>
    buildComparisonPresentation(
      input({
        state: settledState(filesOutcome()),
        countCurrent: () => ({ ...TALLY, unplacedRecords, tailExcluded }),
      }),
    );

  it("shows no delta, and says in one true sentence why: the entries could not be placed", () => {
    const view = withheld(3);
    expect(view).toMatchObject({
      phase: "withheld",
      label: PRIOR_LABEL,
      deltas: null,
      action: null,
      canClear: true,
      status:
        "3 loaded entries have no usable timestamp or level and could not be placed in the current period, so no change is shown.",
    });
  });

  it("says entry and has for one", () => {
    expect(withheld(1).status).toBe(
      "1 loaded entry has no usable timestamp or level and could not be placed in the current period, so no change is shown.",
    );
  });

  it("keeps the comparison's notes and the tail events left out beside the reason", () => {
    const view = withheld(2, 4);
    expect(view.notes).toContain("Left out of the current period: 4 events appended by the live tail.");
  });

  it("is not triggered by an unplaced count of zero, which leaves the delta", () => {
    const view = withheld(0);
    expect(view.phase).toBe("complete");
    expect(view.deltas).not.toBeNull();
  });
});

describe("partial", () => {
  function partial(): ComparisonOutcome {
    // An event with no usable timestamp may belong to either period, so the counts are not whole.
    const outcome = filesOutcome([record({ timestampEpoch: 0 })]);
    expect(outcome.status).toBe("partial");
    return outcome;
  }

  it("withholds every delta and lists the comparison's own reasons, as written", () => {
    const outcome = partial();
    const view = buildComparisonPresentation(input({ state: settledState(outcome) }));
    expect(view.phase).toBe("partial");
    expect(view.deltas).toBeNull();
    expect(view.label).toBe(PRIOR_LABEL);
    expect(view.status).toBe(
      "Partial. No change is shown, because the counts for these periods are not complete:",
    );
    expect(view.reasons).toEqual(
      outcome.status === "partial" ? outcome.result.gaps : ["unreachable"],
    );
    expect(view.reasons.length).toBeGreaterThan(0);
    expect(view.canClear).toBe(true);
  });

  it("does not count the current period, because nothing would be shown from it", () => {
    const countCurrent = vi.fn(() => TALLY);
    buildComparisonPresentation(input({ state: settledState(partial()), countCurrent }));
    expect(countCurrent).not.toHaveBeenCalled();
  });

  it("does not claim a reason it does not have", () => {
    const outcome = partial();
    if (outcome.status !== "partial") return;
    const bare: ComparisonOutcome = { status: "partial", result: { ...outcome.result, gaps: [] } };
    const view = buildComparisonPresentation(input({ state: settledState(bare) }));
    expect(view.status).toBe("Partial. No change is shown.");
    expect(view.reasons).toEqual([]);
  });
});

describe("unavailable", () => {
  const refused = (detail: string): ComparisonState =>
    settledState({ status: "unavailable", reason: "currentPeriodIncomplete", detail });

  it("says why, in the comparison's own words, and keeps Compare available to try again", () => {
    const detail =
      "Security reached the automatic load's cap of 2,000 events, so the current period is only partly loaded. Deselect Security to compare the other channels.";
    const view = buildComparisonPresentation(input({ state: refused(detail) }));
    expect(view).toMatchObject({
      phase: "unavailable",
      label: null,
      status: `Comparison unavailable: ${detail}`,
      deltas: null,
      canClear: true,
      action: { kind: "compare", disabled: false },
    });
  });

  it("keeps Compare disabled when the prior period cannot be defined", () => {
    const view = buildComparisonPresentation(
      input({
        state: refused("x"),
        availability: { available: false, detail: "All time has no previous period." },
      }),
    );
    expect(view.action).toMatchObject({ disabled: true, reason: "All time has no previous period." });
  });
});

describe("out of date", () => {
  const fresh = filesOutcome();
  const length = 24 * HOUR;

  it("is current up to 1% of the window either side of the anchor", () => {
    for (const offset of [0, length / 100, -length / 100]) {
      const view = buildComparisonPresentation(
        input({ state: settledState(fresh), snapshotEpoch: ANCHOR + offset }),
      );
      expect(view.phase).toBe("complete");
    }
  });

  it("withholds the delta, says what each side covers, and offers a re-compare", () => {
    const snapshot = ANCHOR + 3 * HOUR;
    const countCurrent = vi.fn(() => TALLY);
    const view = buildComparisonPresentation(
      input({ state: settledState(fresh), snapshotEpoch: snapshot, countCurrent }),
    );
    expect(view).toMatchObject({
      phase: "stale",
      label: null,
      deltas: null,
      canClear: true,
      action: { label: "Compare again", kind: "recompare", disabled: false },
    });
    expect(view.status).toBe(
      "Out of date. The comparison covers 2026-08-09 12:00:00.000 to 2026-08-10 12:00:00.000 (UTC); " +
        "the tiles now show events from 2026-08-09 15:00:00.000 (UTC). No change is shown.",
    );
    expect(countCurrent).not.toHaveBeenCalled();
  });

  it("asks a live comparison to refresh first, because a re-compare alone keeps its anchor", () => {
    if (fresh.status !== "complete") throw new Error("expected complete");
    const live: ComparisonOutcome = { status: "complete", result: { ...fresh.result, mode: "live" } };
    const view = buildComparisonPresentation(
      input({ state: settledState(live), snapshotEpoch: ANCHOR + 3 * HOUR }),
    );
    expect(view.action).toMatchObject({ label: "Refresh and compare again", kind: "recompare" });
  });

  it("takes precedence over a partial result, and a stale one is never shown as current", () => {
    const outcome = filesOutcome([record({ timestampEpoch: 0 })]);
    const view = buildComparisonPresentation(
      input({ state: settledState(outcome), snapshotEpoch: ANCHOR + 3 * HOUR }),
    );
    expect(view.phase).toBe("stale");
    expect(view.deltas).toBeNull();
  });

  it("is stale when the instant the tiles are measured from is not a date, and says so without printing one", () => {
    const view = buildComparisonPresentation(
      input({ state: settledState(fresh), snapshotEpoch: Number.NaN }),
    );
    expect(view.phase).toBe("stale");
    expect(view.deltas).toBeNull();
    expect(view.status).toBe(
      "Out of date. The comparison covers 2026-08-09 12:00:00.000 to 2026-08-10 12:00:00.000 (UTC); " +
        "the time the tiles are measured from is not known. No change is shown.",
    );
  });
});

describe("every state", () => {
  const complete = filesOutcome();
  const partial = filesOutcome([record({ timestampEpoch: 0 })]);
  const states: Array<[string, Partial<ComparisonPresentationInput>]> = [
    ["off", {}],
    ["off, disabled", { availability: { available: false, detail: "All time has no previous period." } }],
    ["off, cleared", { cleared: true }],
    [
      "running",
      {
        state: {
          phase: "running",
          mode: "live",
          requestId: "event-log-compare-2",
          prior: priorFor(),
          channels: ["System"],
          scanned: 9,
        },
      },
    ],
    ["complete", { state: settledState(complete) }],
    [
      "withheld",
      { state: settledState(complete), countCurrent: () => ({ ...TALLY, unplacedRecords: 2 }) },
    ],
    ["partial", { state: settledState(partial) }],
    ["unavailable", { state: settledState({ status: "unavailable", reason: "queryFailed", detail: "System: the query failed" }) }],
    ["stale", { state: settledState(complete), snapshotEpoch: ANCHOR + 5 * HOUR }],
    ["stale, unusable clock", { state: settledState(complete), snapshotEpoch: Number.NaN }],
  ];

  it.each(states)("%s: no text carries an infinity, a NaN, an undefined or a dash", (_name, overrides) => {
    const view = buildComparisonPresentation(input(overrides));
    const text = [
      view.label,
      view.status,
      view.clearedNotice,
      view.action?.label,
      view.action?.reason,
      ...view.reasons,
      ...view.notes,
    ]
      .filter((part): part is string => typeof part === "string")
      .join("\n");
    expect(text).not.toMatch(/\u221e|Infinity|NaN|undefined|null|\[object|\u2013|\u2014/);
  });

  it.each(states.filter(([name]) => name !== "complete"))(
    "%s: shows no delta, because only a complete comparison that is still current has one",
    (_name, overrides) => {
      expect(buildComparisonPresentation(input(overrides)).deltas).toBeNull();
    },
  );

  it("Clear is offered exactly while a comparison is running or on show", () => {
    const offered = states
      .filter(([, overrides]) => buildComparisonPresentation(input(overrides)).canClear)
      .map(([name]) => name);
    expect(offered).toEqual([
      "running",
      "complete",
      "withheld",
      "partial",
      "unavailable",
      "stale",
      "stale, unusable clock",
    ]);
  });
});

describe("under a time zone that observes daylight saving", () => {
  // The project's TS config has no Node types; Node applies a runtime TZ change to Date.
  const env = (globalThis as unknown as { process: { env: Record<string, string | undefined> } })
    .process.env;
  const previous = env.TZ;
  beforeAll(() => {
    // US Eastern: daylight time ends 2026-11-01T06:00Z, from UTC-04:00 to UTC-05:00.
    env.TZ = "America/New_York";
  });
  afterAll(() => {
    if (previous === undefined) delete env.TZ;
    else env.TZ = previous;
  });

  const at = (iso: string) => Date.parse(iso);
  function priorAt(anchorIso: string): PriorWindow {
    const result = computePriorWindow("7d", at(anchorIso));
    if (result.status !== "available") throw new Error("expected an available prior window");
    return result.prior;
  }
  const running = (prior: PriorWindow): ComparisonState => ({
    phase: "running",
    mode: "live",
    requestId: "event-log-compare-3",
    prior,
    channels: ["System"],
    scanned: 0,
  });
  /** A complete comparison whose previous period is `prior`. */
  function completeAt(prior: PriorWindow): ComparisonState {
    const outcome = filesOutcome();
    if (outcome.status !== "complete") throw new Error("expected complete");
    return settledState({ status: "complete", result: { ...outcome.result, window: "7d", prior } });
  }
  const local = (overrides: Partial<ComparisonPresentationInput>) =>
    buildComparisonPresentation(input({ timeZoneMode: "local", ...overrides }));

  it("names each bound's own offset when the previous period crosses the change", () => {
    // The previous 7 d of an anchor at 2026-11-10T12:00Z runs from 2026-10-27T12:00Z to
    // 2026-11-03T11:59:59.999Z: the first bound is in daylight time, the second after it ended.
    const view = local({ state: running(priorAt("2026-11-10T12:00:00.000Z")) });
    expect(view.label).toBe(
      "Comparing with 2026-10-27 08:00:00.000 (UTC-04:00) to 2026-11-03 06:59:59.999 (UTC-05:00)",
    );
  });

  it("names the offset once when both bounds share it", () => {
    const view = local({ state: running(priorAt("2026-10-20T12:00:00.000Z")) });
    expect(view.label).toBe(
      "Comparing with 2026-10-06 08:00:00.000 to 2026-10-13 07:59:59.999 (UTC-04:00)",
    );
    const after = local({ state: running(priorAt("2026-11-20T12:00:00.000Z")) });
    expect(after.label).toBe(
      "Comparing with 2026-11-06 07:00:00.000 to 2026-11-13 06:59:59.999 (UTC-05:00)",
    );
  });

  it("names the one zone once in UTC, whatever the date", () => {
    const view = buildComparisonPresentation(
      input({ timeZoneMode: "utc", state: running(priorAt("2026-11-10T12:00:00.000Z")) }),
    );
    expect(view.label).toBe(
      "Comparing with 2026-10-27 12:00:00.000 to 2026-11-03 11:59:59.999 (UTC)",
    );
  });

  it("names each bound of the period an out-of-date comparison covers, and the tiles' own start", () => {
    // The anchor is 2026-11-05T12:00Z: the period starts in daylight time and ends after it. The
    // tiles are measured three hours later.
    const prior = priorAt("2026-11-05T12:00:00.000Z");
    const view = local({
      state: completeAt(prior),
      snapshotEpoch: at("2026-11-05T15:00:00.000Z"),
    });
    expect(view.phase).toBe("stale");
    expect(view.status).toBe(
      "Out of date. The comparison covers 2026-10-29 08:00:00.000 (UTC-04:00) to 2026-11-05 07:00:00.000 (UTC-05:00); " +
        "the tiles now show events from 2026-10-29 11:00:00.000 (UTC-04:00). No change is shown.",
    );
  });

  it("gives the tiles' start its own offset even when the covered period has a single one", () => {
    // The period [2026-11-01T07:00Z, 2026-11-08T07:00Z] is wholly in standard time, while the tiles,
    // measured three hours earlier than the anchor, start at 04:00Z, before the change.
    const prior = priorAt("2026-11-08T07:00:00.000Z");
    const view = local({
      state: completeAt(prior),
      snapshotEpoch: at("2026-11-08T04:00:00.000Z"),
    });
    expect(view.status).toBe(
      "Out of date. The comparison covers 2026-11-01 02:00:00.000 to 2026-11-08 02:00:00.000 (UTC-05:00); " +
        "the tiles now show events from 2026-11-01 00:00:00.000 (UTC-04:00). No change is shown.",
    );
  });
});
