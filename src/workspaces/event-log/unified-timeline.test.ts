import { describe, expect, it } from "vitest";
import {
  isEventOrigin,
  originContext,
  originDetail,
  originLabel,
  timelineCounts,
  unplacedSummary,
  type TimelineOrigin,
  type UnifiedTimeline,
} from "./unified-timeline";

const logOrigin: TimelineOrigin = {
  kind: "log",
  file: "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\IntuneManagementExtension.log",
  component: "IME",
  line: 42,
  source:
    "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\IntuneManagementExtension.log",
  machine: "HOST-A",
  bundle: null,
  recordId: 42,
};

const eventOrigin: TimelineOrigin = {
  kind: "event",
  source: "Live",
  machine: "HOST-A",
  bundle: null,
  channel: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
  provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider",
  processId: 4321,
  activityId: "{activity}",
  eventId: 76,
  recordId: 1234,
};

function timeline(partial: Partial<UnifiedTimeline> = {}): UnifiedTimeline {
  return { items: [], unplaced: [], ...partial };
}

describe("originLabel", () => {
  it("shows the log file name and component, not the whole path", () => {
    expect(originLabel(logOrigin)).toBe("IntuneManagementExtension.log [IME]");
  });

  it("omits the component when the format has none", () => {
    expect(originLabel({ ...logOrigin, component: null })).toBe(
      "IntuneManagementExtension.log"
    );
  });

  it("shows the channel leaf and event id, not the Microsoft-Windows prefix", () => {
    expect(originLabel(eventOrigin)).toBe("Admin (76)");
  });

  it("falls back to the whole value when there is no separator", () => {
    expect(originLabel({ ...eventOrigin, channel: "Security" })).toBe("Security (76)");
    expect(originLabel({ ...logOrigin, file: "app.log", component: null })).toBe("app.log");
  });
});

describe("originContext", () => {
  it("shows machine and source provenance without changing the stable label", () => {
    expect(originContext(eventOrigin)).toBe("HOST-A · Live");
    expect(originContext({ ...logOrigin, machine: null })).toContain("machine unknown");
  });
});

describe("originDetail", () => {
  it("gives the full path and line for a log", () => {
    expect(originDetail(logOrigin)).toContain("IntuneManagementExtension.log:42");
    expect(originDetail(logOrigin)).toContain("(IME)");
  });

  it("gives channel, provider, event and record for an event", () => {
    const detail = originDetail(eventOrigin);
    expect(detail).toContain(eventOrigin.channel);
    expect(detail).toContain(eventOrigin.provider);
    expect(detail).toContain("event 76");
    expect(detail).toContain("record 1234");
  });

  it("includes source machine process and activity provenance for an event", () => {
    const detail = originDetail(eventOrigin);
    expect(detail).toContain("source Live");
    expect(detail).toContain("machine HOST-A");
    expect(detail).toContain("process 4321");
    expect(detail).toContain("activity {activity}");
  });
});

describe("isEventOrigin", () => {
  it("distinguishes the two sources", () => {
    expect(isEventOrigin(eventOrigin)).toBe(true);
    expect(isEventOrigin(logOrigin)).toBe(false);
  });
});

describe("unplacedSummary", () => {
  it("returns null when nothing was dropped", () => {
    // A reassuring "0 items" invites no attention, so the caller hides the notice entirely.
    expect(unplacedSummary(timeline())).toBeNull();
  });

  it("counts both sources and says why", () => {
    const summary = unplacedSummary(
      timeline({
        unplaced: [
          { origin: logOrigin, reason: "missingTimestamp" },
          { origin: logOrigin, reason: "missingTimestamp" },
          { origin: eventOrigin, reason: "missingTimestamp" },
        ],
      })
    );
    expect(summary).toBe("2 log lines and 1 event could not be placed: no timestamp");
  });

  it("uses singular wording for a single item", () => {
    expect(
      unplacedSummary(timeline({ unplaced: [{ origin: logOrigin, reason: "missingTimestamp" }] }))
    ).toBe("1 log line could not be placed: no timestamp");
  });

  it("mentions only the source that actually contributed", () => {
    const summary = unplacedSummary(
      timeline({ unplaced: [{ origin: eventOrigin, reason: "missingTimestamp" }] })
    );
    expect(summary).toBe("1 event could not be placed: no timestamp");
  });
});

describe("timelineCounts", () => {
  it("separates events from log lines", () => {
    const counts = timelineCounts(
      timeline({
        items: [
          { timestampMs: 1, severity: "info", message: "a", origin: logOrigin },
          { timestampMs: 2, severity: "error", message: "b", origin: eventOrigin },
          { timestampMs: 3, severity: "info", message: "c", origin: logOrigin },
        ],
        unplaced: [{ origin: logOrigin, reason: "missingTimestamp" }],
      })
    );
    expect(counts).toEqual({ logs: 2, events: 1, unplaced: 1 });
  });

  it("counts an empty timeline as zero everywhere", () => {
    expect(timelineCounts(timeline())).toEqual({ logs: 0, events: 0, unplaced: 0 });
  });
});
