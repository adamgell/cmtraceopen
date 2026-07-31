import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Button,
  Caption1,
  Subtitle2,
  TabList,
  Tab,
  makeStyles,
  shorthands,
  tokens,
} from "@fluentui/react-components";

import { useJamfStore } from "./jamf-store";
import type { JamfPolicyEvent, JamfPolicyLogResult, JamfPolicyTrigger } from "./types";

type ViewMode = "activity" | "policies" | "installs" | "failures" | "all" | "timeline";

const useStyles = makeStyles({
  root: {
    display: "flex",
    flexDirection: "column",
    height: "100%",
    minHeight: 0,
  },
  header: {
    display: "flex",
    gap: "12px",
    alignItems: "center",
    flexWrap: "wrap",
  },
  statStrip: {
    display: "flex",
    flexWrap: "wrap",
    gap: "20px",
    marginTop: "10px",
    marginBottom: "4px",
    ...shorthands.padding("10px", "12px"),
    backgroundColor: tokens.colorNeutralBackground3,
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
  },
  stat: {
    display: "flex",
    flexDirection: "column",
    minWidth: "96px",
  },
  statLabel: {
    fontSize: "10px",
    fontWeight: 600,
    letterSpacing: "0.3px",
    textTransform: "uppercase" as const,
    color: tokens.colorNeutralForeground3,
  },
  statValue: {
    fontSize: "15px",
    fontVariantNumeric: "tabular-nums",
    color: tokens.colorNeutralForeground1,
  },
  statValueBad: {
    fontSize: "15px",
    fontVariantNumeric: "tabular-nums",
    color: tokens.colorPaletteRedForeground1,
    fontWeight: 600,
  },
  scroll: {
    flex: 1,
    minHeight: 0,
    overflowY: "auto" as const,
    marginTop: "8px",
    ...shorthands.border("1px", "solid", tokens.colorNeutralStroke2),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
  },
  table: {
    width: "100%",
    borderCollapse: "collapse",
    fontVariantNumeric: "tabular-nums",
    fontSize: "12px",
  },
  th: {
    position: "sticky" as const,
    top: 0,
    zIndex: 1,
    textAlign: "left" as const,
    ...shorthands.padding("6px", "10px"),
    backgroundColor: tokens.colorNeutralBackground3,
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
    fontSize: "10.5px",
    fontWeight: 600,
    textTransform: "uppercase" as const,
    letterSpacing: "0.3px",
    color: tokens.colorNeutralForeground3,
    whiteSpace: "nowrap" as const,
  },
  td: {
    ...shorthands.padding("4px", "10px"),
    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
    verticalAlign: "top" as const,
  },
  tdTime: {
    ...shorthands.padding("4px", "10px"),
    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
    whiteSpace: "nowrap" as const,
    color: tokens.colorNeutralForeground2,
  },
  policyName: {
    fontWeight: 600,
  },
  failure: {
    color: tokens.colorPaletteRedForeground1,
  },
  empty: {
    ...shorthands.padding("24px"),
    textAlign: "center" as const,
    color: tokens.colorNeutralForeground3,
  },
  dayRow: {
    display: "grid",
    gridTemplateColumns: "112px 1fr",
    gap: "12px",
    ...shorthands.padding("8px", "12px"),
    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
  },
  dayDate: {
    fontWeight: 600,
    whiteSpace: "nowrap" as const,
  },
  dayDetail: {
    color: tokens.colorNeutralForeground2,
    fontSize: "12px",
  },
});

function describeTrigger(t: JamfPolicyTrigger): string {
  switch (t.type) {
    case "recurringCheckIn": return "Recurring check-in";
    case "event":            return `Event: ${t.value}`;
    case "manual":           return "Manual";
    case "startup":          return "Startup";
    case "login":            return "Login";
    case "logout":           return "Logout";
    case "policyId":         return `Policy ID ${t.value}`;
    case "other":            return t.value;
  }
}

// Backend timestamps are UTC instants; render them in the reader's zone.
function formatTimestamp(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

function formatDayKey(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString();
}

// Only policy executions carry an elapsed time — see compute_durations in
// src-tauri/src/jamf/policy_log.rs for what it measures.
function formatDuration(ms: number | null): string {
  if (ms == null) return "-";
  if (ms < 1000) return `${ms} ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${Math.round(seconds % 60)}s`;
}

function describeResult(e: JamfPolicyEvent): string {
  switch (e.result.type) {
    case "success":    return "Success";
    case "failure":    return `Failure - ${e.result.value}`;
    case "inProgress": return "In progress";
    case "unknown":    return "-";
  }
}

const isPolicyRun = (e: JamfPolicyEvent) =>
  e.trigger.type === "other" && e.trigger.value === "execute";
// "Installing <pkg>..." / "Successfully installed <pkg>." — what a policy
// actually delivered, as opposed to the policy starting.
const isInstall = (e: JamfPolicyEvent) =>
  e.trigger.type === "other" && e.trigger.value === "install";
const isInstallSuccess = (e: JamfPolicyEvent) => isInstall(e) && e.result.type === "success";
const isFailure = (e: JamfPolicyEvent) => e.result.type === "failure";
const isCheckIn = (e: JamfPolicyEvent) =>
  e.trigger.type === "recurringCheckIn" ||
  e.trigger.type === "startup" ||
  e.trigger.type === "login" ||
  e.trigger.type === "logout" ||
  e.trigger.type === "manual" ||
  e.trigger.type === "event";

/// jamf.log is dominated by routine bookkeeping — launchd task cleanup, "no
/// patch policies were found" — that the parser classifies as other/info. Those
/// lines are still available under All, but they bury the handful of events that
/// actually describe what the Mac did.
const isNoise = (e: JamfPolicyEvent) =>
  e.trigger.type === "other" && (e.trigger.value === "info" || e.trigger.value === "patch-check");

export function MacosJamfPoliciesTab() {
  const styles = useStyles();
  const slice = useJamfStore((s) => s.policies);
  const begin = useJamfStore((s) => s.beginLoad);
  const finish = useJamfStore((s) => s.finishLoad);
  const fail = useJamfStore((s) => s.failLoad);
  const [view, setView] = useState<ViewMode>("activity");

  const reload = async () => {
    begin("policies");
    try {
      const result = await invoke<JamfPolicyLogResult>("jamf_parse_policy_log", { path: null });
      finish("policies", result);
    } catch (e) {
      fail("policies", e instanceof Error ? e.message : String(e));
    }
  };

  useEffect(() => {
    if (slice.status === "idle") void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const events = useMemo<JamfPolicyEvent[]>(() => slice.data?.events ?? [], [slice.data]);

  const stats = useMemo(() => {
    const runs = events.filter(isPolicyRun);
    const installs = events.filter(isInstallSuccess);
    const failures = events.filter(isFailure);
    const checkIns = events.filter((e) => e.trigger.type === "recurringCheckIn");
    const first = events[0]?.timestamp;
    const last = events[events.length - 1]?.timestamp;
    const slowest = runs.reduce<JamfPolicyEvent | null>(
      (acc, e) => (e.durationMs != null && (acc?.durationMs ?? -1) < e.durationMs ? e : acc),
      null
    );
    const lastCheckIn = checkIns[checkIns.length - 1]?.timestamp ?? null;
    return { runs, installs, failures, checkIns, first, last, slowest, lastCheckIn };
  }, [events]);

  const visible = useMemo(() => {
    switch (view) {
      case "policies": return events.filter(isPolicyRun);
      case "installs": return events.filter(isInstall);
      case "failures": return events.filter(isFailure);
      case "all":      return events;
      case "timeline": return events;
      case "activity":
      default:         return events.filter((e) => !isNoise(e) || isFailure(e));
    }
  }, [events, view]);

  if (slice.status === "loading") return <div>Parsing jamf.log...</div>;
  if (slice.status === "error")
    return (
      <div>
        <div>Failed to parse jamf.log: {slice.error}</div>
        <Button onClick={reload}>Retry</Button>
      </div>
    );

  return (
    <div className={styles.root}>
      <div className={styles.header}>
        <Subtitle2>Policy events</Subtitle2>
        <Caption1>
          {events.length} event(s) · {slice.data?.unparsedLines ?? 0} unparsed · {slice.data?.sourcePath}
        </Caption1>
        <Button size="small" onClick={reload}>Re-parse</Button>
      </div>

      <div className={styles.statStrip}>
        <Stat label="Span" value={
          stats.first && stats.last
            ? `${formatDayKey(stats.first)} – ${formatDayKey(stats.last)}`
            : "-"
        } />
        <Stat label="Check-ins" value={String(stats.checkIns.length)} />
        <Stat label="Policy runs" value={String(stats.runs.length)} />
        <Stat label="Installs" value={String(stats.installs.length)} />
        <Stat label="Failures" value={String(stats.failures.length)} bad={stats.failures.length > 0} />
        <Stat
          label="Last check-in"
          value={stats.lastCheckIn ? formatTimestamp(stats.lastCheckIn) : "-"}
        />
        <Stat
          label="Slowest run"
          value={
            stats.slowest
              ? `${formatDuration(stats.slowest.durationMs)} · ${stats.slowest.policyName}`
              : "-"
          }
        />
      </div>

      <TabList selectedValue={view} onTabSelect={(_, d) => setView(d.value as ViewMode)}>
        <Tab value="activity">Activity ({events.filter((e) => !isNoise(e) || isFailure(e)).length})</Tab>
        <Tab value="policies">Policies ({stats.runs.length})</Tab>
        <Tab value="installs">Installs ({stats.installs.length})</Tab>
        <Tab value="failures">Failures ({stats.failures.length})</Tab>
        <Tab value="timeline">By day</Tab>
        <Tab value="all">All ({events.length})</Tab>
      </TabList>

      <div className={styles.scroll}>
        {view === "timeline" ? (
          <DaySummary events={events} styles={styles} />
        ) : (
          <EventTable events={visible} styles={styles} />
        )}
      </div>
    </div>
  );
}

function Stat({ label, value, bad }: { label: string; value: string; bad?: boolean }) {
  const styles = useStyles();
  return (
    <div className={styles.stat}>
      <span className={styles.statLabel}>{label}</span>
      <span className={bad ? styles.statValueBad : styles.statValue}>{value}</span>
    </div>
  );
}

type Styles = ReturnType<typeof useStyles>;

function EventTable({ events, styles }: { events: JamfPolicyEvent[]; styles: Styles }) {
  if (events.length === 0) {
    return <div className={styles.empty}>Nothing matches this filter.</div>;
  }
  return (
    <table className={styles.table}>
      <thead>
        <tr>
          <th className={styles.th}>Time</th>
          <th className={styles.th}>Trigger</th>
          <th className={styles.th}>Policy / package</th>
          <th className={styles.th}>Result</th>
          <th className={styles.th} style={{ textAlign: "right" }}>Elapsed</th>
        </tr>
      </thead>
      <tbody>
        {events.map((e, i) => (
          <tr key={`${e.rawLineOffset}-${i}`}>
            <td className={styles.tdTime}>{formatTimestamp(e.timestamp)}</td>
            <td className={styles.td}>{describeTrigger(e.trigger)}</td>
            <td className={`${styles.td} ${e.policyName ? styles.policyName : ""}`}>
              {e.policyName ?? e.policyId ?? "-"}
            </td>
            <td className={`${styles.td} ${isFailure(e) ? styles.failure : ""}`}>
              {describeResult(e)}
            </td>
            <td className={styles.td} style={{ textAlign: "right" }}>
              {formatDuration(e.durationMs)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/// One line per day: how often the Mac checked in, what actually ran, and what
/// failed. The raw table answers "what happened at 09:33"; this answers "has
/// this Mac been behaving".
function DaySummary({ events, styles }: { events: JamfPolicyEvent[]; styles: Styles }) {
  const days = useMemo(() => {
    const byDay = new Map<string, JamfPolicyEvent[]>();
    for (const e of events) {
      const key = formatDayKey(e.timestamp);
      const bucket = byDay.get(key);
      if (bucket) bucket.push(e);
      else byDay.set(key, [e]);
    }
    return [...byDay.entries()].reverse();
  }, [events]);

  if (days.length === 0) {
    return <div className={styles.empty}>No events.</div>;
  }

  return (
    <div>
      {days.map(([day, dayEvents]) => {
        const checkIns = dayEvents.filter(isCheckIn).length;
        const runs = dayEvents.filter(isPolicyRun);
        const installs = dayEvents.filter(isInstallSuccess);
        const failures = dayEvents.filter(isFailure);
        return (
          <div key={day} className={styles.dayRow}>
            <span className={styles.dayDate}>{day}</span>
            <span className={styles.dayDetail}>
              {checkIns} check-in{checkIns === 1 ? "" : "s"}
              {runs.length > 0 && (
                <>
                  {" · "}
                  {runs
                    .map((r) => `${r.policyName} (${formatDuration(r.durationMs)})`)
                    .join(", ")}
                </>
              )}
              {installs.length > 0 && (
                <>
                  {" · installed "}
                  {installs.map((i) => i.policyName).join(", ")}
                </>
              )}
              {failures.length > 0 && (
                <span className={styles.failure}>
                  {" · "}
                  {failures.length} failure{failures.length === 1 ? "" : "s"}
                </span>
              )}
            </span>
          </div>
        );
      })}
    </div>
  );
}
