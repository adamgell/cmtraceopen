import { describe, expect, it } from "vitest";
import { buildGroupedRows } from "./evtx-filter";
import {
  HISTOGRAM_STACK_ORDER,
  bucketIndexAt,
  buildHistogram,
  rangeOnPlot,
  type WallParts,
  type ZoneClock,
} from "./evtx-histogram";
import {
  HIT_SLOP_PX,
  LEVEL_SLOT,
  MAX_NAMED_LANES,
  MIN_LANE_HEIGHT_PX,
  OTHER_DISCLOSURE_LIMIT,
  OTHER_LANE_ID,
  SWIMLANE_FIELDS,
  buildSwimlanes,
  describeDot,
  describeFoldedLanes,
  describeLaneCell,
  describeLaneCount,
  describeSwimlaneFigure,
  findRecordInScene,
  isCurrentRecord,
  laneCellCounts,
  laneHeightFor,
  laneKeyOf,
  laneLabelLineHeights,
  topEventInCell,
  type SwimlaneField,
} from "./evtx-swimlanes";
import { formatTimeRange } from "./evtx-time";
import type { EvtxLevel, EvtxRecord } from "./types";

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const T0 = Date.UTC(2026, 9, 6, 10, 20, 0);
/** Fixed so no test depends on the run date (the year rule compares with this). */
const NOW = Date.UTC(2026, 9, 16, 12, 0, 0);

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

/** `count` records of one provider, a minute apart from `start`. */
const many = (provider: string, count: number, start = T0, level: EvtxLevel = "Information") =>
  Array.from({ length: count }, (_, i) => rec({ provider, level, timestampEpoch: start + i * MINUTE }));

/** A zone from its offsets, as the histogram tests build one (so DST runs the same on any host). */
function syntheticZone(offsetAt: (epochMs: number) => number, offsets: number[]): ZoneClock {
  const wallAsUtc = (p: WallParts) => Date.UTC(p.year, p.month, p.day, p.hours, p.minutes, p.seconds);
  return {
    wall: (epochMs) => {
      const date = new Date(epochMs + offsetAt(epochMs) * MINUTE);
      return {
        year: date.getUTCFullYear(),
        month: date.getUTCMonth(),
        day: date.getUTCDate(),
        hours: date.getUTCHours(),
        minutes: date.getUTCMinutes(),
        seconds: date.getUTCSeconds(),
      };
    },
    instant: (parts) => {
      const wall = wallAsUtc(parts);
      const valid = offsets
        .map((offset) => ({ offset, epochMs: wall - offset * MINUTE }))
        .filter((candidate) => offsetAt(candidate.epochMs) === candidate.offset)
        .map((candidate) => candidate.epochMs)
        .sort((a, b) => a - b);
      return valid.length > 0 ? valid[0] : wall - Math.min(...offsets) * MINUTE;
    },
  };
}

// America/New_York in 2026: DST starts 2026-03-08 07:00Z and ends 2026-11-01 06:00Z.
const NEW_YORK = syntheticZone(
  (epochMs) => (epochMs >= Date.UTC(2026, 2, 8, 7) && epochMs < Date.UTC(2026, 10, 1, 6) ? -240 : -300),
  [-300, -240],
);

const build = (records: EvtxRecord[], field: SwimlaneField = "provider") =>
  buildSwimlanes(records, field, "utc", undefined, NOW);

describe("lane keys", () => {
  it("name an empty provider or channel, and write the event ID as plain digits", () => {
    expect(laneKeyOf(rec({ provider: "" }), "provider")).toBe("(no provider)");
    expect(laneKeyOf(rec({ channel: "" }), "channel")).toBe("(no channel)");
    expect(laneKeyOf(rec({ eventId: 7036 }), "eventId")).toBe("7036");
  });

  it.each(SWIMLANE_FIELDS.map((field) => [field] as const))(
    "match the Grouped view's group names and counts for %s, so a lane and a group are named alike",
    (field) => {
      const records = [
        rec({ provider: "A", channel: "System", eventId: 1, timestampEpoch: T0 }),
        rec({ provider: "A", channel: "", eventId: 2, timestampEpoch: T0 + MINUTE }),
        rec({ provider: "", channel: "Application", eventId: 2, timestampEpoch: T0 + 2 * MINUTE }),
        rec({ provider: "B", channel: "System", eventId: 10, timestampEpoch: T0 + 3 * MINUTE }),
        rec({ provider: "B", channel: "System", eventId: 10, timestampEpoch: T0 + 4 * MINUTE }),
      ];
      const groups = buildGroupedRows(records, [field], new Set(), "utc").flatMap((row) =>
        row.kind === "group" ? [[row.label, row.count] as const] : [],
      );
      const lanes = build(records, field).lanes.map((lane) => [lane.id, lane.count] as const);
      expect([...lanes].sort()).toEqual([...groups].sort());
    },
  );
});

describe("lane ranking", () => {
  it("ranks lanes by their placed events, most first", () => {
    const scene = build([...many("few", 2), ...many("most", 9), ...many("some", 5)]);
    expect(scene.lanes.map((lane) => [lane.label, lane.count])).toEqual([
      ["most", 9],
      ["some", 5],
      ["few", 2],
    ]);
  });

  it("breaks a tie by name, in code-unit order and not by locale", () => {
    const scene = build([...many("b", 3), ...many("a", 3), ...many("B", 3)]);
    expect(scene.lanes.map((lane) => lane.label)).toEqual(["B", "a", "b"]);
  });

  it("breaks an Event ID tie by the number, so 9 comes before 10", () => {
    const records = [10, 9, 100].flatMap((eventId) =>
      Array.from({ length: 2 }, (_, i) => rec({ eventId, timestampEpoch: T0 + i * MINUTE })),
    );
    expect(build(records, "eventId").lanes.map((lane) => lane.label)).toEqual(["9", "10", "100"]);
  });

  it("ranks on events that can be placed, so a key with only untimed events has no lane", () => {
    const scene = build([
      ...many("charted", 2),
      ...Array.from({ length: 50 }, () => rec({ provider: "ghost", timestampEpoch: 0 })),
    ]);
    expect(scene.lanes.map((lane) => lane.label)).toEqual(["charted"]);
    expect(scene.keyCount).toBe(1);
  });
});

describe("the Other lane", () => {
  const providers = (n: number) =>
    Array.from({ length: n }, (_, i) => many(`provider-${String(i).padStart(2, "0")}`, 100 - i, T0 + i * MINUTE)).flat();

  it("shows the top 12 and folds the rest into 'Other (n lanes)'", () => {
    const scene = build(providers(20));
    expect(scene.lanes).toHaveLength(MAX_NAMED_LANES + 1);
    const other = scene.lanes[MAX_NAMED_LANES];
    expect(other.isOther).toBe(true);
    expect(other.id).toBe(OTHER_LANE_ID);
    expect(other.label).toBe("Other (8 lanes)");
    expect(other.foldedLaneCount).toBe(8);
    expect(scene.lanes.slice(0, MAX_NAMED_LANES).map((lane) => lane.count)).toEqual(
      Array.from({ length: 12 }, (_, i) => 100 - i),
    );
  });

  it("folds exactly the events of the lanes it names, so nothing is dropped or counted twice", () => {
    const scene = build(providers(20));
    const folded = Array.from({ length: 8 }, (_, i) => 100 - (12 + i)).reduce((a, b) => a + b, 0);
    expect(scene.lanes[MAX_NAMED_LANES].count).toBe(folded);
    expect(scene.placed).toBe(providers(20).length);
    expect(scene.lanes.reduce((sum, lane) => sum + lane.count, 0)).toBe(scene.placed);
  });

  it("keeps thirteen keys as thirteen lanes: Other would hide one name for nothing", () => {
    const scene = build(providers(13));
    expect(scene.lanes).toHaveLength(13);
    expect(scene.lanes.some((lane) => lane.isOther)).toBe(false);
    expect(scene.lanes[12].label).toBe("provider-12");
  });

  it("folds from the fourteenth key, as 'Other (2 lanes)'", () => {
    const scene = build(providers(14));
    expect(scene.lanes).toHaveLength(13);
    expect(scene.lanes[12].label).toBe("Other (2 lanes)");
  });

  it("does not make an Other lane for twelve or fewer", () => {
    expect(build(providers(12)).lanes.some((lane) => lane.isOther)).toBe(false);
    expect(build(providers(1)).lanes).toHaveLength(1);
  });

  it("names the folded lanes in rank order, and bounds the list while the count stays whole", () => {
    const scene = build(providers(60));
    const other = scene.lanes[MAX_NAMED_LANES];
    expect(other.foldedLaneCount).toBe(48);
    expect(other.foldedKeys).toHaveLength(OTHER_DISCLOSURE_LIMIT);
    expect(other.foldedKeys[0]).toBe("provider-12");
    const text = describeFoldedLanes(other, "provider");
    expect(text).toContain("48 provider lanes folded into Other");
    expect(text).toContain("provider-12");
    expect(text).not.toContain("provider-40");
    expect(text).toMatch(/and 28 more$/);
    expect(describeFoldedLanes(scene.lanes[0], "provider")).toBe("");
  });

  it("keeps each folded dot's own record, so a dot in Other still says what it is", () => {
    const scene = build(providers(20));
    const other = scene.lanes[MAX_NAMED_LANES];
    const providersInOther = new Set(other.records.map((record) => record.provider));
    expect(providersInOther.size).toBe(8);
    expect(providersInOther.has("provider-00")).toBe(false);
  });
});

describe("the ledger of placed and untimed events", () => {
  it("accounts for every record given: lanes plus untimed", () => {
    const records = [
      ...many("a", 4),
      ...many("b", 3),
      rec({ timestampEpoch: 0 }),
      rec({ timestampEpoch: Number.NaN }),
      rec({ timestampEpoch: -10 }),
    ];
    const scene = build(records);
    expect(scene.placed).toBe(7);
    expect(scene.untimed).toBe(3);
    expect(scene.placed + scene.untimed).toBe(records.length);
    expect(scene.untimed).toBe(scene.axis.untimed);
  });

  it("is no lanes and an unknown span when nothing has a timestamp", () => {
    const scene = build([rec({ timestampEpoch: 0 }), rec({ timestampEpoch: 0 })]);
    expect(scene.lanes).toEqual([]);
    expect(scene.axis.domain).toBeNull();
    expect(scene.untimed).toBe(2);
    expect(scene.placed).toBe(0);
  });

  it("is empty for no records", () => {
    const scene = build([]);
    expect(scene.lanes).toEqual([]);
    expect(scene.untimed).toBe(0);
  });

  it("never places an untimed record on a lane or at the left edge", () => {
    const scene = build([...many("a", 3), rec({ provider: "a", timestampEpoch: 0 })]);
    expect(scene.lanes[0].count).toBe(3);
    expect(scene.lanes[0].epochs.every((epoch) => epoch > 0)).toBe(true);
  });
});

describe("the axis is the histogram's", () => {
  const spread = (clockless = true) => {
    void clockless;
    return Array.from({ length: 72 * 5 }, (_, i) =>
      rec({
        provider: `p${i % 3}`,
        level: HISTOGRAM_STACK_ORDER[i % 5],
        timestampEpoch: T0 + Math.floor(i / 5) * 20 * MINUTE + (i % 5) * 1000,
      }),
    );
  };

  it("has the histogram's domain, edges, interval and year rule for the same records", () => {
    const records = spread();
    const scene = build(records);
    const histogram = buildHistogram(records, "utc", undefined, NOW);
    expect(scene.axis.domain).toEqual(histogram.domain);
    expect(scene.axis.edges).toEqual(histogram.edges);
    expect(scene.axis.intervalMs).toBe(histogram.intervalMs);
    expect(scene.axis.showYear).toBe(histogram.showYear);
  });

  it("is the extent of the timed records rounded out to bucket edges, not the raw first and last", () => {
    const records = [rec({ timestampEpoch: T0 + 7 * MINUTE }), rec({ timestampEpoch: T0 + 13 * HOUR + 4 * MINUTE })];
    const { domain } = build(records).axis;
    expect(domain!.startMs).toBeLessThanOrEqual(T0 + 7 * MINUTE);
    expect(domain!.endMs).toBeGreaterThan(T0 + 13 * HOUR + 4 * MINUTE);
    expect(domain!.startMs % MINUTE).toBe(0);
    expect(domain).not.toEqual({ startMs: T0 + 7 * MINUTE, endMs: T0 + 13 * HOUR + 4 * MINUTE });
  });

  it("builds from the zone it is given, as the histogram does", () => {
    const records = Array.from({ length: 24 * 70 }, (_, i) =>
      rec({ provider: "a", timestampEpoch: Date.UTC(2026, 1, 20) + i * HOUR }),
    );
    const scene = buildSwimlanes(records, "provider", "local", NEW_YORK, NOW);
    expect(scene.axis.edges).toEqual(buildHistogram(records, "local", NEW_YORK, NOW).edges);
    expect(scene.axis.intervalMs).toBe(DAY);
  });

  it("puts every dot inside its own bucket's slice of the plot, across a DST change on a chart of days", () => {
    // 24 h buckets are 23 h long on the day the clocks go forward. A linear time scale would drift
    // against the wash, which is bucket-wise; the dot and the wash over its bucket must agree.
    const records = Array.from({ length: 24 * 70 }, (_, i) =>
      rec({ provider: "a", timestampEpoch: Date.UTC(2026, 1, 20) + i * HOUR }),
    );
    const scene = buildSwimlanes(records, "provider", "local", NEW_YORK, NOW);
    const { axis } = scene;
    const count = axis.buckets.length;
    let checked = 0;
    scene.lanes[0].epochs.forEach((epoch, dot) => {
      const index = bucketIndexAt(axis, epoch);
      const fraction = scene.lanes[0].fractions[dot];
      expect(fraction).toBeGreaterThanOrEqual(index / count);
      expect(fraction).toBeLessThan((index + 1) / count);
      checked += 1;
    });
    expect(checked).toBe(records.length);
  });

  it("puts a dot at the edges of the wash that selects its bucket", () => {
    const scene = build(spread());
    const { axis } = scene;
    const range = { startMs: axis.edges[10], endMs: axis.edges[11] };
    const onPlot = rangeOnPlot(axis, range)!;
    const inside = scene.lanes.flatMap((lane) =>
      Array.from(lane.epochs, (epoch, dot) => ({ epoch, fraction: lane.fractions[dot] })).filter(
        (dotInfo) => dotInfo.epoch >= range.startMs && dotInfo.epoch < range.endMs,
      ),
    );
    expect(inside.length).toBeGreaterThan(0);
    for (const dot of inside) {
      expect(dot.fraction).toBeGreaterThanOrEqual(onPlot.left);
      expect(dot.fraction).toBeLessThan(onPlot.right);
    }
  });

  it("agrees with the histogram's counts in every bucket, summed over the lanes", () => {
    const records = spread();
    const scene = build(records);
    scene.axis.buckets.forEach((bucket) => {
      const total = { Critical: 0, Error: 0, Warning: 0, Information: 0, Verbose: 0 };
      for (const lane of scene.lanes) {
        const cell = laneCellCounts(lane, bucket.startMs, bucket.endMs);
        for (const level of HISTOGRAM_STACK_ORDER) total[level] += cell.counts[level];
      }
      expect(total).toEqual(bucket.counts);
    });
  });
});

describe("a lane's dots", () => {
  it("are in time order, whatever order the records arrive in", () => {
    const records = [3, 1, 4, 1, 5, 9, 2, 6].map((minute, i) =>
      rec({ provider: "a", eventId: i, timestampEpoch: T0 + minute * MINUTE }),
    );
    const lane = build(records).lanes[0];
    expect(Array.from(lane.epochs)).toEqual([...lane.epochs].sort((a, b) => a - b));
    expect(lane.records.map((record) => record.timestampEpoch)).toEqual(Array.from(lane.epochs));
    // The two events at minute 1 keep the order they arrived in.
    expect(lane.records.filter((record) => record.timestampEpoch === T0 + MINUTE).map((r) => r.eventId)).toEqual([1, 3]);
    expect(Array.from(lane.fractions)).toEqual([...lane.fractions].sort((a, b) => a - b));
  });

  it("keep their order and their identity when the records are already in time order", () => {
    const records = many("a", 50);
    const lane = build(records).lanes[0];
    expect(lane.records.every((record, i) => record === records[i])).toBe(true);
  });

  it("hold the record objects, so an id the store rewrites is read as it is now", () => {
    const records = many("a", 3);
    const lane = build(records).lanes[0];
    records[1].id = 99;
    expect(lane.records[1]).toBe(records[1]);
    expect(lane.records[1].id).toBe(99);
  });

  it("carry their level, and the lane's level counts agree", () => {
    const records = [
      ...many("a", 2, T0, "Critical"),
      ...many("a", 3, T0 + HOUR, "Error"),
      ...many("a", 1, T0 + 2 * HOUR, "Verbose"),
    ];
    const lane = build(records).lanes[0];
    expect(lane.levelCounts).toEqual({ Critical: 2, Error: 3, Warning: 0, Information: 0, Verbose: 1 });
    expect(Array.from(lane.levels).filter((slot) => slot === LEVEL_SLOT.Critical)).toHaveLength(2);
    expect(LEVEL_SLOT.Critical).toBeGreaterThan(LEVEL_SLOT.Error);
    expect(LEVEL_SLOT.Verbose).toBe(0);
  });
});

describe("a lane in one cell", () => {
  const lane = () =>
    build([
      rec({ provider: "a", level: "Information", timestampEpoch: T0 }),
      rec({ provider: "a", level: "Error", timestampEpoch: T0 + MINUTE, eventId: 10 }),
      rec({ provider: "a", level: "Error", timestampEpoch: T0 + 2 * MINUTE, eventId: 11 }),
      rec({ provider: "a", level: "Warning", timestampEpoch: T0 + 3 * MINUTE }),
      rec({ provider: "a", level: "Critical", timestampEpoch: T0 + 3 * MINUTE + 1, eventId: 12 }),
      rec({ provider: "a", level: "Critical", timestampEpoch: T0 + 3 * MINUTE + 2, eventId: 13 }),
    ]).lanes[0];

  it("is half open: a dot on the start belongs, a dot on the end does not", () => {
    const cell = laneCellCounts(lane(), T0 + MINUTE, T0 + 3 * MINUTE);
    expect(cell.total).toBe(2);
    expect(cell.counts.Error).toBe(2);
    expect(laneCellCounts(lane(), T0, T0 + MINUTE).total).toBe(1);
  });

  it("selects the most severe event, and the earliest of those", () => {
    expect(topEventInCell(lane(), T0, T0 + 10 * MINUTE)!.eventId).toBe(12);
    expect(topEventInCell(lane(), T0, T0 + 3 * MINUTE)!.level).toBe("Error");
    expect(topEventInCell(lane(), T0, T0 + 3 * MINUTE)!.eventId).toBe(10);
  });

  it("selects nothing in an empty cell", () => {
    expect(topEventInCell(lane(), T0 + HOUR, T0 + 2 * HOUR)).toBeNull();
    expect(laneCellCounts(lane(), T0 + HOUR, T0 + 2 * HOUR).total).toBe(0);
  });
});

describe("finding a record in the scene", () => {
  it("locates a record by its id as it is now, and not by the id it had when the scene was built", () => {
    const records = [...many("a", 3), ...many("b", 2, T0 + HOUR)];
    records.forEach((record, index) => (record.id = index));
    const scene = build(records);
    expect(findRecordInScene(scene, 4)).toEqual({ lane: 1, dot: 1 });
    // The store renumbers records in place on a merge.
    records[4].id = 40;
    expect(findRecordInScene(scene, 4)).toBeNull();
    expect(findRecordInScene(scene, 40)).toEqual({ lane: 1, dot: 1 });
  });

  it("finds nothing in a scene the store no longer holds: a stale record whose id is another event's", () => {
    // After a reload inside the throttle window the scene still has the old objects; the store has
    // new ones, under ids that are the same small numbers.
    const old = [...many("a", 3), ...many("b", 2, T0 + HOUR)];
    old.forEach((record, index) => (record.id = index));
    const scene = build(old);
    const fresh = old.map((record, index) => ({ ...record, id: index }));
    expect(findRecordInScene(scene, 4)).toEqual({ lane: 1, dot: 1 });
    expect(findRecordInScene(scene, 4, old)).toEqual({ lane: 1, dot: 1 });
    expect(findRecordInScene(scene, 4, fresh)).toBeNull();
    expect(findRecordInScene(scene, 4, [])).toBeNull();
    // And the same objects renumbered in place by a merge are still found, at their new ids.
    const merged = [old[4], old[0], old[1], old[2], old[3]];
    merged.forEach((record, index) => (record.id = index));
    expect(findRecordInScene(scene, 0, merged)).toEqual({ lane: 1, dot: 1 });
  });

  it("says a record is current only when it is the store's own under its id", () => {
    const list = many("a", 3);
    list.forEach((record, index) => (record.id = index));
    expect(list.every((record) => isCurrentRecord(record, list))).toBe(true);
    expect(isCurrentRecord(list[1], [])).toBe(false);
    expect(isCurrentRecord(list[1], [list[0], { ...list[1] }, list[2]])).toBe(false);
    expect(isCurrentRecord({ ...list[1], id: 99 }, list)).toBe(false);
  });

  it("is null for no id, an id not charted and an untimed record", () => {
    const scene = build([...many("a", 2), rec({ id: 77, timestampEpoch: 0 })]);
    expect(findRecordInScene(scene, null)).toBeNull();
    expect(findRecordInScene(scene, 999)).toBeNull();
    expect(findRecordInScene(scene, 77)).toBeNull();
  });
});

describe("the words", () => {
  it("count events in the singular and the plural", () => {
    expect(describeLaneCount(1)).toBe("1 event");
    expect(describeLaneCount(0)).toBe("0 events");
    expect(describeLaneCount(1234)).toBe("1,234 events");
  });

  it("name the field, the charted span and its zone in the figure's name", () => {
    const scene = build(many("a", 30));
    const { domain } = scene.axis;
    expect(describeSwimlaneFigure(scene, "utc")).toBe(
      `Events by provider over ${formatTimeRange(domain!.startMs, domain!.endMs, "utc", false)} ` +
        "(UTC), one lane per provider",
    );
    expect(describeSwimlaneFigure(build(many("a", 3), "eventId"), "utc")).toContain("Events by event ID over");
    expect(describeSwimlaneFigure(build([], "channel"), "utc")).toBe("Events by channel, one lane per channel");
  });

  it("word a lane's cell as the histogram words a bucket, led by the lane", () => {
    const scene = build([
      rec({ provider: "a", level: "Error", timestampEpoch: T0 }),
      rec({ provider: "a", level: "Error", timestampEpoch: T0 + 1000 }),
      rec({ provider: "b", level: "Information", timestampEpoch: T0 + 3 * HOUR }),
    ]);
    const [start, end] = [scene.axis.edges[0], scene.axis.edges[1]];
    const text = describeLaneCell(scene.lanes[0], start, end, "utc", false);
    expect(text.startsWith("a, ")).toBe(true);
    expect(text).toContain("2 errors");
    expect(text).toContain("(UTC)");
  });

  it("name a dot's own provider, ID, channel and level, and the others under the pointer", () => {
    const record = rec({ provider: "Prov", eventId: 42, channel: "Chan", level: "Warning", timestampEpoch: T0 });
    const text = describeDot(record, "utc", 0);
    expect(text).toBe("2026-10-06 10:20:00.000 · Warning · Prov 42 · Chan (UTC)");
    expect(describeDot(record, "utc", 3)).toBe(`${text} · +3 more within ${HIT_SLOP_PX} px`);
    expect(describeDot(rec({ provider: "", channel: "" }), "utc", 0)).toContain("(no provider)");
  });
});

describe("lane height", () => {
  it("is 36 px at the default list size", () => {
    expect(laneHeightFor(13)).toBe(MIN_LANE_HEIGHT_PX);
  });

  it.each(Array.from({ length: 10 }, (_, i) => [11 + i] as const))(
    "holds the two label lines at list size %i",
    (fontSize) => {
      const { nameLine, countLine } = laneLabelLineHeights(fontSize);
      expect(laneHeightFor(fontSize)).toBeGreaterThanOrEqual(nameLine + countLine);
      expect(laneHeightFor(fontSize)).toBeGreaterThanOrEqual(MIN_LANE_HEIGHT_PX);
    },
  );

  it("grows with the font and never shrinks below the lane the spec draws", () => {
    const heights = Array.from({ length: 10 }, (_, i) => laneHeightFor(11 + i));
    expect([...heights].sort((a, b) => a - b)).toEqual(heights);
    expect(heights[heights.length - 1]).toBeGreaterThan(MIN_LANE_HEIGHT_PX);
  });
});
