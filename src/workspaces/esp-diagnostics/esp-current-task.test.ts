import { describe, expect, it } from "vitest";
import { deriveEspCurrentTask } from "./esp-current-task";
import { makeEspSession, makeEspWorkload } from "./esp-session-fixtures";
import type { EspNormalizedStatus } from "./types";

function wl(
  normalized: EspNormalizedStatus,
  opts: { id?: string; session?: string; updated?: string } = {},
) {
  return makeEspWorkload({
    workloadId: opts.id ?? `wl-${normalized}`,
    sessionId: opts.session ?? "s1",
    status: { raw: normalized, normalized, display: normalized, detail: null },
    timestamps: {
      firstObserved: {
        rawText: "2026-07-23T20:00:00Z",
        originalOffset: "Z",
        normalizedUtc: "2026-07-23T20:00:00Z",
        kind: "utc",
      },
      started: null,
      ended: null,
      lastUpdated: opts.updated
        ? {
            rawText: opts.updated,
            originalOffset: "Z",
            normalizedUtc: opts.updated,
            kind: "utc",
          }
        : null,
    },
  });
}

const sessions = [makeEspSession({ sessionId: "s1", isLatest: true })];

describe("deriveEspCurrentTask", () => {
  it("reports the actively installing workload as the current task", () => {
    const task = deriveEspCurrentTask(
      [
        wl("succeeded", { id: "a" }),
        wl("installing", { id: "b", updated: "2026-07-23T20:05:00Z" }),
      ],
      sessions,
      "deviceSetup",
    );
    expect(task.state).toBe("running");
    expect(task.workload?.workloadId).toBe("b");
    expect(task.stats).toMatchObject({
      total: 2,
      done: 1,
      running: 1,
      failed: 0,
      queued: 0,
    });
  });

  it("picks the most recently updated when several run at once", () => {
    const task = deriveEspCurrentTask(
      [
        wl("installing", { id: "older", updated: "2026-07-23T20:01:00Z" }),
        wl("downloading", { id: "newer", updated: "2026-07-23T20:09:00Z" }),
      ],
      sessions,
      "deviceSetup",
    );
    expect(task.state).toBe("running");
    expect(task.workload?.workloadId).toBe("newer");
    expect(task.runningCount).toBe(2);
  });

  it("surfaces a failed workload when nothing is running", () => {
    const task = deriveEspCurrentTask(
      [wl("succeeded", { id: "a" }), wl("failed", { id: "bad" })],
      sessions,
      "deviceSetup",
    );
    expect(task.state).toBe("failed");
    expect(task.workload?.workloadId).toBe("bad");
    expect(task.stats.failed).toBe(1);
  });

  it("reports complete when the phase finished", () => {
    const task = deriveEspCurrentTask(
      [wl("succeeded", { id: "a" })],
      sessions,
      "completed",
    );
    expect(task.state).toBe("complete");
  });

  it("shows what is running even while the phase is marked failed", () => {
    const task = deriveEspCurrentTask(
      [
        wl("failed", { id: "bad" }),
        wl("installing", { id: "live", updated: "2026-07-23T20:03:00Z" }),
      ],
      sessions,
      "failed",
    );
    expect(task.state).toBe("running");
    expect(task.workload?.workloadId).toBe("live");
  });

  it("waits when only queued workloads remain", () => {
    const task = deriveEspCurrentTask(
      [wl("pending", { id: "q" })],
      sessions,
      "deviceSetup",
    );
    expect(task.state).toBe("waiting");
    expect(task.stats.queued).toBe(1);
  });

  it("is idle with no workloads", () => {
    const task = deriveEspCurrentTask([], sessions, "deviceSetup");
    expect(task.state).toBe("idle");
    expect(task.stats.total).toBe(0);
  });

  it("scopes counts to the latest session", () => {
    const multi = [
      makeEspSession({ sessionId: "old", isLatest: false }),
      makeEspSession({ sessionId: "s1", isLatest: true }),
    ];
    const task = deriveEspCurrentTask(
      [
        wl("installing", {
          id: "current",
          session: "s1",
          updated: "2026-07-23T20:05:00Z",
        }),
        wl("failed", { id: "stale", session: "old" }),
      ],
      multi,
      "deviceSetup",
    );
    expect(task.state).toBe("running");
    expect(task.stats.total).toBe(1);
    expect(task.stats.failed).toBe(0);
  });
});
