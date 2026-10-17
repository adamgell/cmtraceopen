import { describe, expect, it } from "vitest";
import { isWithinTimeRange } from "./evtx-filter";
import {
  HISTOGRAM_BAR_AREA_PX,
  HISTOGRAM_INTERVALS_MS,
  HISTOGRAM_STACK_ORDER,
  MAX_BUCKETS,
  MIN_SEGMENT_PX,
  UTC_CLOCK,
  bucketEdges,
  bucketIndexAt,
  bucketSegments,
  buildAxisTicks,
  buildHistogram,
  chooseBuckets,
  describeBucket,
  describeCounts,
  describeCoverage,
  describeFigure,
  describeInterval,
  describeUntimed,
  fitScale,
  fractionAt,
  rangeOnPlot,
  zoneClockFor,
  type EvtxHistogram,
  type HistogramBucket,
  type WallParts,
  type ZoneClock,
} from "./evtx-histogram";
import { TIME_RANGE_SEPARATOR } from "./evtx-time";
import type { EvtxLevel, EvtxRecord } from "./types";

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

const utc = (month: number, day: number, hour = 0, minute = 0, second = 0, ms = 0) =>
  Date.UTC(2026, month - 1, day, hour, minute, second, ms);

const rec = (timestampEpoch: number, level: EvtxLevel = "Information", id = 1): EvtxRecord =>
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

/**
 * A zone built from its offsets (minutes east of UTC), so the DST and half-hour paths run the same
 * on any host. `instant` picks the earliest instant whose offset gives that wall time, and a wall
 * time the zone skips resolves forward on the offset in force before the gap, as `Date` does.
 */
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
const KOLKATA = syntheticZone(() => 330, [330]);
const KATHMANDU = syntheticZone(() => 345, [345]);

const deltas = (edges: readonly number[]) => edges.slice(1).map((edge, index) => edge - edges[index]);

describe("the width ladder", () => {
  it("rises, and holds every rung the spec lists", () => {
    expect([...HISTOGRAM_INTERVALS_MS]).toEqual([...HISTOGRAM_INTERVALS_MS].sort((a, b) => a - b));
    for (const spec of [
      MINUTE, 2 * MINUTE, 5 * MINUTE, 10 * MINUTE, 15 * MINUTE, 20 * MINUTE, 30 * MINUTE,
      HOUR, 2 * HOUR, 3 * HOUR, 6 * HOUR, 12 * HOUR, DAY,
    ]) {
      expect(HISTOGRAM_INTERVALS_MS).toContain(spec);
    }
  });

  it("gives 24 hours 72 buckets of 20 minutes (spec 8.5)", () => {
    const min = utc(10, 6, 10, 20);
    const { intervalMs, edges } = chooseBuckets(min, min + DAY - 1, UTC_CLOCK);
    expect(intervalMs).toBe(20 * MINUTE);
    expect(edges.length - 1).toBe(72);
  });

  it("chooses the screenshot fixture's span the same way, from its first record to its last", () => {
    const histogram = buildHistogram(
      [rec(utc(10, 6, 10, 20, 47)), rec(utc(10, 7, 10, 19, 59))],
      "utc",
    );
    expect(histogram.intervalMs).toBe(20 * MINUTE);
    expect(histogram.buckets).toHaveLength(72);
    expect(histogram.edges[0]).toBe(utc(10, 6, 10, 20));
    expect(histogram.edges[72]).toBe(utc(10, 7, 10, 20));
  });

  it("picks the rung nearest 72, not the finest one that stays at or under 96", () => {
    // 15 minutes would give 96 buckets for a day; the rule is nearest 72, which is 20 minutes.
    const min = utc(10, 6, 0, 0);
    expect(chooseBuckets(min, min + DAY - 1, UTC_CLOCK).intervalMs).not.toBe(15 * MINUTE);
  });

  it("keeps every span from a millisecond to two centuries covered, ordered and at most 96 buckets", () => {
    let spans = 0;
    for (let exponent = 0; exponent <= 14; exponent += 0.25) {
      const span = Math.round(10 ** exponent);
      if (span > 200 * 365 * DAY) break;
      for (const offset of [0, 7 * MINUTE + 13, 5 * HOUR + 1, 3 * DAY + 17]) {
        const min = utc(2, 14, 3, 7, 9) + offset;
        const max = min + span;
        const { edges } = chooseBuckets(min, max, UTC_CLOCK);
        const count = edges.length - 1;
        expect(count).toBeGreaterThanOrEqual(1);
        expect(count).toBeLessThanOrEqual(MAX_BUCKETS);
        expect(edges[0]).toBeLessThanOrEqual(min);
        expect(edges[count]).toBeGreaterThan(max);
        for (const width of deltas(edges)) expect(width).toBeGreaterThan(0);
        spans += 1;
      }
    }
    expect(spans).toBeGreaterThan(50);
  });

  it("stays in the 48 to 96 band for spans of two minutes to ten years, bar a rung jump", () => {
    for (const span of [2 * MINUTE, 10 * MINUTE, 45 * MINUTE, HOUR, 3 * HOUR, 6 * HOUR, 2 * DAY, 7 * DAY, 30 * DAY, 90 * DAY, 365 * DAY, 3650 * DAY]) {
      for (const offset of [0, 3 * MINUTE + 11, 4 * HOUR + 7]) {
        const min = utc(5, 20, 1, 1, 1) + offset;
        const count = chooseBuckets(min, min + span, UTC_CLOCK).edges.length - 1;
        expect(count).toBeGreaterThanOrEqual(36);
        expect(count).toBeLessThanOrEqual(MAX_BUCKETS);
      }
    }
  });

  it("gives one record, or records at one instant, a single bucket one second wide", () => {
    const histogram = buildHistogram([rec(utc(10, 6, 10, 20, 47, 250)), rec(utc(10, 6, 10, 20, 47, 250))], "utc");
    expect(histogram.intervalMs).toBe(SECOND);
    expect(histogram.buckets).toHaveLength(1);
    expect(histogram.buckets[0].total).toBe(2);
    expect(histogram.edges).toEqual([utc(10, 6, 10, 20, 47), utc(10, 6, 10, 20, 48)]);
  });
});

describe("buildHistogram", () => {
  it("puts a record on an edge in the later bucket and the one before it in the earlier", () => {
    const first = utc(10, 6, 10, 0);
    const records = [
      rec(first),
      rec(first + 20 * MINUTE - 1),
      rec(first + 20 * MINUTE),
      rec(first + DAY - 1),
    ];
    const histogram = buildHistogram(records, "utc");
    expect(histogram.intervalMs).toBe(20 * MINUTE);
    expect(histogram.buckets[0].total).toBe(2);
    expect(histogram.buckets[1].total).toBe(1);
    expect(histogram.buckets[histogram.buckets.length - 1].total).toBe(1);
  });

  it("counts the records of every level, Verbose included, and places every timed one once", () => {
    const base = utc(10, 6, 12, 0);
    const levels: EvtxLevel[] = ["Critical", "Error", "Warning", "Information", "Verbose"];
    const records = levels.flatMap((level, index) =>
      Array.from({ length: index + 1 }, (_, n) => rec(base + (index * 7 + n) * MINUTE, level, index * 10 + n)),
    );
    const histogram = buildHistogram(records, "utc");
    expect(histogram.placed).toBe(15);
    expect(histogram.untimed).toBe(0);
    const sum = (level: EvtxLevel) => histogram.buckets.reduce((total, bucket) => total + bucket.counts[level], 0);
    expect(levels.map(sum)).toEqual([1, 2, 3, 4, 5]);
    expect(histogram.buckets.reduce((total, bucket) => total + bucket.total, 0)).toBe(15);
  });

  it("counts a record with no usable timestamp as untimed and in no bucket", () => {
    const records = [
      rec(utc(10, 6, 12, 0)),
      rec(utc(10, 6, 13, 0)),
      rec(0),
      rec(-5),
      rec(Number.NaN),
      rec(Number.POSITIVE_INFINITY),
    ];
    const histogram = buildHistogram(records, "utc");
    expect(histogram.untimed).toBe(4);
    expect(histogram.placed).toBe(2);
    expect(histogram.placed + histogram.untimed).toBe(records.length);
    // The extent is the timed records', not stretched to the epoch origin by the untimed ones.
    expect(histogram.domain?.startMs).toBeGreaterThan(utc(10, 6, 11, 0));
  });

  it("has no buckets when nothing is timed, and says how many it could not place", () => {
    const histogram = buildHistogram([rec(0), rec(Number.NaN)], "utc");
    expect(histogram.buckets).toEqual([]);
    expect(histogram.edges).toEqual([]);
    expect(histogram.domain).toBeNull();
    expect(histogram.untimed).toBe(2);
    expect(buildHistogram([], "utc").untimed).toBe(0);
  });

  it("selects exactly the events its bars count when a brush covers whole buckets", () => {
    const base = utc(10, 6, 0, 0);
    const records: EvtxRecord[] = [];
    let seed = 11;
    for (let i = 0; i < 600; i += 1) {
      seed = (seed * 1664525 + 1013904223) >>> 0;
      const at = base + Math.floor((seed / 2 ** 32) * 3 * DAY);
      records.push(rec(i % 7 === 0 ? Math.floor(at / (20 * MINUTE)) * 20 * MINUTE : at, "Warning", i));
    }
    // Events exactly on a bucket edge, which the half-open range must keep with the later bucket.
    const histogram = buildHistogram(records, "utc");
    for (const [a, b] of [[0, 0], [3, 9], [10, 10], [0, histogram.buckets.length - 1], [5, histogram.buckets.length - 1]]) {
      const range = { startMs: histogram.edges[a], endMs: histogram.edges[b + 1] };
      const inRange = records.filter((record) => isWithinTimeRange(record, range)).length;
      const counted = histogram.buckets.slice(a, b + 1).reduce((total, bucket) => total + bucket.total, 0);
      expect(inRange).toBe(counted);
    }
  });

  it("does the same in the host's local zone", () => {
    const base = utc(3, 1, 0, 0);
    const records = Array.from({ length: 400 }, (_, i) => rec(base + i * 37 * MINUTE + (i % 5) * SECOND, "Error", i));
    const histogram = buildHistogram(records, "local");
    expect(histogram.placed).toBe(400);
    expect(histogram.edges.length - 1).toBeLessThanOrEqual(MAX_BUCKETS);
    for (const width of deltas(histogram.edges)) expect(width).toBeGreaterThan(0);
    for (const [a, b] of [[0, 4], [2, 2], [4, histogram.buckets.length - 1]]) {
      const range = { startMs: histogram.edges[a], endMs: histogram.edges[b + 1] };
      expect(records.filter((record) => isWithinTimeRange(record, range)).length).toBe(
        histogram.buckets.slice(a, b + 1).reduce((total, bucket) => total + bucket.total, 0),
      );
    }
    expect(zoneClockFor("local").instant(zoneClockFor("local").wall(base))).toBe(base);
  });

  it("reads each record a fixed number of times, whatever the number of buckets", () => {
    const readsFor = (spanMs: number) => {
      const reads = { time: 0, level: 0 };
      const count = 2000;
      const base = utc(10, 6, 0, 0);
      const records = Array.from({ length: count }, (_, i) => {
        const at = base + Math.floor((i / (count - 1)) * spanMs);
        const record = rec(0, "Information", i);
        Object.defineProperty(record, "timestampEpoch", {
          get: () => {
            reads.time += 1;
            return at;
          },
        });
        Object.defineProperty(record, "level", {
          get: () => {
            reads.level += 1;
            return "Information";
          },
        });
        return record;
      });
      const histogram = buildHistogram(records, "utc");
      return { reads, buckets: histogram.buckets.length, count };
    };
    const few = readsFor(10 * MINUTE);
    const many = readsFor(30 * HOUR);
    expect(many.buckets).toBeGreaterThanOrEqual(48);
    expect(few.reads).toEqual(many.reads);
    // Two passes at most, each reading the time a handful of times, and the level once.
    expect(many.reads.time / many.count).toBeLessThanOrEqual(8);
    expect(many.reads.level / many.count).toBeLessThanOrEqual(1);
  });

  it("rebuckets 100,000 records within a generous ceiling, and prints the figure", () => {
    const count = 100_000;
    const base = utc(10, 1, 0, 0);
    const levels: EvtxLevel[] = ["Critical", "Error", "Warning", "Information", "Verbose"];
    let seed = 7;
    const records = Array.from({ length: count }, (_, i) => {
      seed = (seed * 1664525 + 1013904223) >>> 0;
      return rec(base + Math.floor((seed / 2 ** 32) * 7 * DAY), levels[i % 5], i);
    });
    const timings: number[] = [];
    let histogram: EvtxHistogram | null = null;
    for (let run = 0; run < 5; run += 1) {
      const started = performance.now();
      histogram = buildHistogram(records, "utc");
      timings.push(performance.now() - started);
    }
    timings.sort((a, b) => a - b);
    const median = timings[2];
    // The spec's figure is 50 ms on the Windows dev box (lab item). CI only guards against a gross
    // regression such as Intl formatting per record (about 600 ms here); the one-pass test above is
    // the structural guard.
    console.info(`[evtx-histogram] 100,000 records rebucketed in ${median.toFixed(1)} ms (median of 5)`);
    expect(histogram?.placed).toBe(count);
    expect(median).toBeLessThan(250);
  });
});

describe("zones", () => {
  it("steps whole local days, so a day is 23 hours when the clocks go forward and 25 when they go back", () => {
    const forward = bucketEdges(utc(3, 7, 12), utc(3, 10, 12), DAY, NEW_YORK);
    expect(forward[0]).toBe(Date.UTC(2026, 2, 7, 5));
    expect(deltas(forward).map((delta) => delta / HOUR)).toEqual([24, 23, 24, 24]);
    const back = bucketEdges(utc(10, 31, 12), utc(11, 3, 12), DAY, NEW_YORK);
    expect(deltas(back).map((delta) => delta / HOUR)).toEqual([24, 25, 24, 24]);
  });

  it("keeps every bucket below a day the same real length across a DST change, with the labels shifting", () => {
    const edges = bucketEdges(utc(3, 7, 12), utc(3, 9, 12), 6 * HOUR, NEW_YORK);
    expect(new Set(deltas(edges))).toEqual(new Set([6 * HOUR]));
    // The first edge is on the local 6 hour grid: 12:00Z is 07:00 EST, so the grid mark is 06:00 EST.
    expect(edges[0]).toBe(Date.UTC(2026, 2, 7, 11));
  });

  it("aligns hour buckets to a zone that sits at +5:30 and 20 minute buckets to one at +5:45", () => {
    const hours = bucketEdges(utc(10, 1, 10, 10), utc(10, 1, 14, 0), HOUR, KOLKATA);
    expect(hours[0]).toBe(Date.UTC(2026, 9, 1, 9, 30));
    expect(hours.every((edge) => new Date(edge).getUTCMinutes() === 30)).toBe(true);
    const twenty = bucketEdges(utc(10, 1, 10, 10), utc(10, 1, 12, 0), 20 * MINUTE, KATHMANDU);
    expect(twenty.every((edge) => [15, 35, 55].includes(new Date(edge).getUTCMinutes()))).toBe(true);
    expect(twenty[0]).toBeLessThanOrEqual(utc(10, 1, 10, 10));
  });

  it("builds a whole histogram on a half-hour zone with every record placed once and edges that cover them", () => {
    const base = utc(10, 1, 3, 17);
    const records = Array.from({ length: 300 }, (_, i) => rec(base + i * 11 * MINUTE, "Warning", i));
    const histogram = buildHistogram(records, "utc", KOLKATA);
    expect(histogram.placed).toBe(300);
    expect(histogram.edges[0]).toBeLessThanOrEqual(base);
    expect(histogram.edges[histogram.edges.length - 1]).toBeGreaterThan(records[records.length - 1].timestampEpoch);
    expect(histogram.edges.every((edge) => new Date(edge).getUTCMinutes() % 30 === 0)).toBe(true);
  });
});

describe("positions on the plot", () => {
  const records = Array.from({ length: 48 }, (_, i) => rec(utc(10, 6, 0, 0) + i * 30 * MINUTE));
  const histogram = buildHistogram(records, "utc");
  const count = histogram.buckets.length;

  it("puts bucket edges at their share of the plot and a point inside a bucket part of the way across it", () => {
    expect(fractionAt(histogram, histogram.edges[0])).toBe(0);
    expect(fractionAt(histogram, histogram.edges[count])).toBe(1);
    expect(fractionAt(histogram, histogram.edges[10])).toBeCloseTo(10 / count, 12);
    const half = histogram.edges[10] + (histogram.edges[11] - histogram.edges[10]) / 2;
    expect(fractionAt(histogram, half)).toBeCloseTo(10.5 / count, 12);
    expect(fractionAt(histogram, histogram.edges[0] - histogram.intervalMs)).toBeLessThan(0);
    expect(fractionAt(histogram, histogram.edges[count] + histogram.intervalMs)).toBeGreaterThan(1);
  });

  it("finds the bucket of an instant, and none outside the domain", () => {
    expect(bucketIndexAt(histogram, histogram.edges[3])).toBe(3);
    expect(bucketIndexAt(histogram, histogram.edges[4] - 1)).toBe(3);
    expect(bucketIndexAt(histogram, histogram.edges[0] - 1)).toBe(-1);
    expect(bucketIndexAt(histogram, histogram.edges[count])).toBe(-1);
  });

  it("clips a range that runs past the plot, and reports one wholly outside as none", () => {
    const inside = rangeOnPlot(histogram, { startMs: histogram.edges[2], endMs: histogram.edges[5] });
    expect(inside).toEqual({ left: 2 / count, right: 5 / count, clippedLeft: false, clippedRight: false });
    const partly = rangeOnPlot(histogram, { startMs: histogram.edges[0] - HOUR, endMs: histogram.edges[4] });
    expect(partly).toMatchObject({ left: 0, clippedLeft: true, clippedRight: false });
    const over = rangeOnPlot(histogram, { startMs: histogram.edges[count - 2], endMs: histogram.edges[count] + HOUR });
    expect(over).toMatchObject({ right: 1, clippedRight: true });
    expect(rangeOnPlot(histogram, { startMs: histogram.edges[count], endMs: histogram.edges[count] + HOUR })).toBeNull();
    expect(rangeOnPlot(histogram, { startMs: histogram.edges[0] - HOUR, endMs: histogram.edges[0] })).toBeNull();
    expect(rangeOnPlot(buildHistogram([], "utc"), { startMs: 1, endMs: 2 })).toBeNull();
  });
});

describe("text", () => {
  const bucket = (counts: Partial<Record<EvtxLevel, number>>, startMs = utc(10, 6, 9, 0)): HistogramBucket => {
    const full = { Critical: 0, Error: 0, Warning: 0, Information: 0, Verbose: 0, ...counts };
    return {
      startMs,
      endMs: startMs + 20 * MINUTE,
      counts: full,
      total: Object.values(full).reduce((a, b) => a + b, 0),
    };
  };

  it("reads a bucket as the spec's tooltip does, with the range separator and the zone", () => {
    expect(describeBucket(bucket({ Error: 3, Warning: 5, Information: 40 }), "utc")).toBe(
      `09:00${TIME_RANGE_SEPARATOR}09:20 \u00b7 3 errors, 5 warnings, 40 info (UTC)`,
    );
  });

  it("uses the singular for one, and names Critical and Verbose only when there are some", () => {
    expect(describeCounts(bucket({ Error: 1, Warning: 1, Information: 1 }))).toBe("1 error, 1 warning, 1 info");
    expect(describeCounts(bucket({ Critical: 2, Information: 4 }))).toBe(
      "2 critical, 0 errors, 0 warnings, 4 info",
    );
    expect(describeCounts(bucket({ Verbose: 9, Information: 1 }))).toBe("0 errors, 0 warnings, 1 info, 9 verbose");
  });

  it("says an empty bucket has no events rather than listing zeros", () => {
    expect(describeCounts(bucket({}))).toBe("no events");
  });

  it("writes thousands with separators", () => {
    expect(describeCounts(bucket({ Information: 12345 }))).toContain("12,345 info");
  });

  it("gives a bucket across a DST change its own zone", () => {
    const local = describeBucket(bucket({ Information: 1 }, utc(3, 8, 6, 0)), "local");
    expect(local).toMatch(/\(UTC[+-]\d\d:\d\d\)$/);
  });

  it("names the interval in whole units, singular for one", () => {
    expect(describeInterval(20 * MINUTE)).toBe("20 minutes");
    expect(describeInterval(HOUR)).toBe("1 hour");
    expect(describeInterval(2 * HOUR)).toBe("2 hours");
    expect(describeInterval(DAY)).toBe("1 day");
    expect(describeInterval(30 * SECOND)).toBe("30 seconds");
    expect(describeInterval(730 * DAY)).toBe("730 days");
  });

  it("names the figure by its interval, the span charted and the zone", () => {
    const histogram = buildHistogram([rec(utc(10, 6, 10, 20, 47)), rec(utc(10, 7, 10, 19, 59))], "utc");
    expect(describeFigure(histogram, "utc")).toBe(
      `Events per 20 minutes over Oct 6 10:20${TIME_RANGE_SEPARATOR}Oct 7 10:20 (UTC), stacked by level`,
    );
  });

  it("writes the untimed and coverage notes, singular for one", () => {
    expect(describeUntimed(1)).toBe("1 event without a timestamp is not charted.");
    expect(describeUntimed(2500)).toBe("2,500 events without a timestamp are not charted.");
    expect(describeCoverage(1)).toContain("1 gap in this view");
    expect(describeCoverage(3)).toContain("3 gaps in this view");
  });
});

describe("axis ticks", () => {
  it("makes seven evenly spaced labels, each on a bucket edge", () => {
    const histogram = buildHistogram([rec(utc(10, 6, 9, 0)), rec(utc(10, 6, 14, 59))], "utc");
    const ticks = buildAxisTicks(histogram, "utc");
    expect(ticks).toHaveLength(7);
    expect(ticks[0]).toMatchObject({ edgeIndex: 0, fraction: 0, label: "09:00" });
    expect(ticks[ticks.length - 1]).toMatchObject({ fraction: 1, label: "15:00" });
    const count = histogram.buckets.length;
    for (const tick of ticks) {
      expect(tick.fraction).toBeCloseTo(tick.edgeIndex / count, 12);
      expect(Math.abs(tick.edgeIndex - (ticks.indexOf(tick) * count) / 6)).toBeLessThanOrEqual(0.5);
    }
  });

  it("adds the day when the span crosses one, and seconds when buckets are under a minute", () => {
    const across = buildAxisTicks(
      buildHistogram([rec(utc(10, 6, 22, 0)), rec(utc(10, 7, 3, 0))], "utc"),
      "utc",
    );
    expect(across[0].label).toBe("Oct 6 22:00");
    const quick = buildAxisTicks(buildHistogram([rec(utc(10, 6, 9, 0, 0)), rec(utc(10, 6, 9, 0, 40))], "utc"), "utc");
    expect(quick[0].label).toBe("09:00:00");
  });

  it("makes fewer labels when there are fewer than six buckets, without repeating one", () => {
    const one = buildAxisTicks(buildHistogram([rec(utc(10, 6, 9, 0, 0, 5))], "utc"), "utc");
    expect(one.map((tick) => tick.edgeIndex)).toEqual([0, 1]);
    expect(buildAxisTicks(buildHistogram([], "utc"), "utc")).toEqual([]);
  });
});

describe("bar geometry", () => {
  const buildOf = (rows: Partial<Record<EvtxLevel, number>>[]): EvtxHistogram => {
    const base = utc(10, 6, 0, 0);
    const records: EvtxRecord[] = [];
    rows.forEach((row, index) => {
      for (const [level, count] of Object.entries(row)) {
        for (let n = 0; n < (count as number); n += 1) {
          records.push(rec(base + index * 20 * MINUTE + n, level as EvtxLevel, records.length));
        }
      }
    });
    return buildHistogram(records, "utc");
  };

  it("fits the tallest bucket in the bar area and gives it the room it can", () => {
    const histogram = buildOf([{ Information: 1000, Error: 50 }, { Information: 10 }]);
    const scale = fitScale(histogram);
    const heights = histogram.buckets.map((bucket) =>
      bucketSegments(bucket, scale).reduce((total, segment) => total + segment.heightPx, 0),
    );
    expect(Math.max(...heights)).toBeLessThanOrEqual(HISTOGRAM_BAR_AREA_PX);
    expect(Math.max(...heights)).toBeGreaterThanOrEqual(HISTOGRAM_BAR_AREA_PX - 3);
  });

  it("never draws a non-empty segment under 2 px, even one Critical event in a tall bucket", () => {
    const histogram = buildOf([{ Information: 5000, Critical: 1 }]);
    const segments = bucketSegments(histogram.buckets[0], fitScale(histogram));
    expect(segments.find((segment) => segment.level === "Critical")?.heightPx).toBe(MIN_SEGMENT_PX);
    expect(Math.min(...segments.map((segment) => segment.heightPx))).toBeGreaterThanOrEqual(MIN_SEGMENT_PX);
  });

  it("fits the area even when every level is present and the counts are small", () => {
    const histogram = buildOf([{ Critical: 1, Error: 1, Warning: 1, Information: 1, Verbose: 1 }]);
    const segments = bucketSegments(histogram.buckets[0], fitScale(histogram));
    expect(segments).toHaveLength(5);
    expect(segments.reduce((total, segment) => total + segment.heightPx, 0)).toBeLessThanOrEqual(HISTOGRAM_BAR_AREA_PX);
  });

  it("stacks bottom to top as Verbose, Info, Warning, Error, Critical, and omits an empty level", () => {
    const histogram = buildOf([{ Critical: 3, Information: 4, Verbose: 2 }]);
    const segments = bucketSegments(histogram.buckets[0], 4);
    expect(segments.map((segment) => segment.level)).toEqual(["Verbose", "Information", "Critical"]);
    expect([...HISTOGRAM_STACK_ORDER]).toEqual(["Verbose", "Information", "Warning", "Error", "Critical"]);
  });

  it("scales taller counts taller, in proportion once above the floor", () => {
    const histogram = buildOf([{ Information: 100 }, { Information: 50 }]);
    const scale = fitScale(histogram);
    const [tall, short] = histogram.buckets
      .filter((bucket) => bucket.total > 0)
      .map((bucket) => bucketSegments(bucket, scale)[0].heightPx);
    expect(tall).toBeGreaterThan(short);
    expect(Math.abs(tall - 2 * short)).toBeLessThanOrEqual(1);
  });

  it("has no scale when nothing is placed", () => {
    expect(fitScale(buildHistogram([], "utc"))).toBe(0);
  });
});
