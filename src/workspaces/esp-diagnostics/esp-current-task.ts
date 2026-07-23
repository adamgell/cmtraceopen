import type {
  EspNormalizedStatus,
  EspPhase,
  EspSession,
  EspWorkload,
} from "./types";

// Derives "what is the device doing right now" from the streamed snapshot: which
// workload is actively being processed, plus a live tally of the enrollment's
// progress. Pure so it can be unit-tested and reused; the Action Center re-runs
// it on every session update, which is what makes the readout live.

export type EspTaskState =
  | "running"
  | "failed"
  | "complete"
  | "waiting"
  | "idle";

export interface EspTaskStats {
  total: number;
  done: number;
  failed: number;
  running: number;
  queued: number;
}

export interface EspCurrentTask {
  state: EspTaskState;
  /** The focal workload for the headline (the active one, or the failed one). */
  workload: EspWorkload | null;
  /** How many workloads are running concurrently (>= 1 when state is running). */
  runningCount: number;
  stats: EspTaskStats;
}

const DONE: ReadonlySet<EspNormalizedStatus> = new Set([
  "succeeded",
  "processed",
  "skipped",
  "uninstalled",
  "rebootRequired",
]);
const FAILED: ReadonlySet<EspNormalizedStatus> = new Set(["failed", "cancelled"]);
const RUNNING: ReadonlySet<EspNormalizedStatus> = new Set([
  "downloading",
  "downloaded",
  "installing",
  "inProgress",
]);
// Everything else that is not "unknown" (notStarted, notInstalled, initialized,
// pending) counts as queued -- tracked but not yet acted on.

function instant(value: string | null | undefined): number {
  if (!value) return Number.NEGATIVE_INFINITY;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : Number.NEGATIVE_INFINITY;
}

/** The most recent point at which this workload showed activity. */
function activityInstant(workload: EspWorkload): number {
  return Math.max(
    instant(workload.timestamps.lastUpdated?.normalizedUtc),
    instant(workload.timestamps.started?.normalizedUtc),
    instant(workload.timestamps.firstObserved.normalizedUtc),
  );
}

function mostRecent(workloads: EspWorkload[]): EspWorkload | null {
  if (workloads.length === 0) return null;
  return workloads.reduce((latest, candidate) =>
    activityInstant(candidate) > activityInstant(latest) ? candidate : latest,
  );
}

export function deriveEspCurrentTask(
  workloads: EspWorkload[],
  sessions: EspSession[],
  phase: EspPhase,
): EspCurrentTask {
  // Scope to the session in flight so counts match the phase progress the
  // operator sees; fall back to everything when no session is marked latest.
  const latest =
    sessions.find((session) => session.isLatest) ??
    sessions[sessions.length - 1];
  const relevant = latest
    ? workloads.filter((workload) => workload.sessionId === latest.sessionId)
    : workloads;

  const stats: EspTaskStats = {
    total: relevant.length,
    done: 0,
    failed: 0,
    running: 0,
    queued: 0,
  };
  const running: EspWorkload[] = [];
  const failed: EspWorkload[] = [];
  for (const workload of relevant) {
    const normalized = workload.status.normalized;
    if (DONE.has(normalized)) {
      stats.done += 1;
    } else if (FAILED.has(normalized)) {
      stats.failed += 1;
      failed.push(workload);
    } else if (RUNNING.has(normalized)) {
      stats.running += 1;
      running.push(workload);
    } else if (normalized !== "unknown") {
      stats.queued += 1;
    }
  }

  // An actively-processing workload is always the "now", whatever the phase.
  if (running.length > 0) {
    return {
      state: "running",
      workload: mostRecent(running),
      runningCount: running.length,
      stats,
    };
  }
  if (phase === "completed") {
    return { state: "complete", workload: null, runningCount: 0, stats };
  }
  if (phase === "failed" || failed.length > 0) {
    return { state: "failed", workload: mostRecent(failed), runningCount: 0, stats };
  }
  if (stats.queued > 0) {
    return { state: "waiting", workload: null, runningCount: 0, stats };
  }
  return { state: "idle", workload: null, runningCount: 0, stats };
}
