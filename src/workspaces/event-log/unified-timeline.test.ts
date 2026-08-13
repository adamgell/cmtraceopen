import { describe, expect, it } from "vitest";
import {
  isEventOrigin,
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
};

const eventOrigin: TimelineOrigin = {
  kind: "event",
  channel: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
  provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider",
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
    // That prefix is on nearly every channel and distinguishes nothing in a narrow column.
    expect(originLabel(eventOrigin)).toBe("Admin (76)");
  });

  it("falls back to the whole value when there is no separator", () => {
    expect(originLabel({ ...eventOrigin, channel: "Security" })).toBe("Security (76)");
    expect(originLabel({ ...logOrigin, file: "app.log", component: null })).toBe("app.log");
  });
});

describe("originDetail", () => {
  it("gives the full path and line for a log", () => {
    expect(originDetail(logOrigin)).toContain("IntuneManagementExtension.log:42");
    expect(originDetail(logOrigin)).toContain("(IME)");
  });

  it("gives channel, provider, event and record for an event", () => {
    // All four, as the name promises. Asserting only two let a change that dropped the channel or
    // the provider from the detail line pass.
    const detail = originDetail(eventOrigin);
    expect(detail).toContain(eventOrigin.channel);
    expect(detail).toContain(eventOrigin.provider);
    expect(detail).toContain("event 76");
    expect(detail).toContain("record 1234");
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
