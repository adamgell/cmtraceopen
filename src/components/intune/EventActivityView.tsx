import { useMemo, useState, useCallback, useRef, useEffect } from "react";
import { tokens } from "@fluentui/react-components";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  LOG_UI_FONT_FAMILY,
  LOG_MONOSPACE_FONT_FAMILY,
  getLogListMetrics,
} from "../../lib/log-accessibility";
import { formatDisplayDateTime } from "../../lib/date-time-format";
import { useUiStore } from "../../stores/ui-store";
import { useIntuneStore } from "../../stores/intune-store";
import type { IntuneEvent, IntuneStatus, IntuneEventType, GuidRegistryEntry } from "../../types/intune";
import { STATUS_COLORS, EVENT_TYPE_LABELS, formatDuration } from "./EventTimelineRow";

/** A group of events sharing the same app identity. */
interface ActivityGroup {
  key: string;
  label: string;
  events: IntuneEvent[];
  worstStatus: IntuneStatus;
  eventTypes: Set<IntuneEventType>;
  startEpoch: number;
  endEpoch: number;
  totalDurationSecs: number | null;
  successCount: number;
  failedCount: number;
}

// ── Grouping logic ────────────────────────────────────────────────────

const STATUS_SEVERITY: Record<IntuneStatus, number> = {
  Failed: 0,
  Timeout: 1,
  InProgress: 2,
  Pending: 3,
  Unknown: 4,
  Success: 5,
};

function extractAppName(name: string): string | null {
  const idx = name.indexOf(" — ");
  return idx > 0 ? name.slice(idx + 3) : null;
}

/**
 * Extract an app name from the detail text.
 * Matches "application Windows App" or "ApplicationName":"Foo".
 */
const GUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function extractAppNameFromDetail(
  detail: string,
  registry?: Record<string, GuidRegistryEntry>
): string | null {
  // Match "application <name>", "for app <name>", "app with id: <name>"
  const patterns = [
    /\bapplication\s+([^.,:]+)/i,
    /\bfor\s+app\s+([^.,:]+)/i,
    /\bapp\s+with\s+id\s*:\s*([^.,:]+)/i,
  ];
  for (const re of patterns) {
    const m = re.exec(detail);
    if (m) {
      let name = m[1].trim();
      // Trim trailing "and ..." clauses
      name = name.replace(/\s+and\s+.*$/i, "").trim();
      if (name.length === 0) continue;
      // If it's a GUID, try to resolve it via the registry
      if (GUID_PATTERN.test(name)) {
        const entry = registry?.[name.toLowerCase()] ?? registry?.[name];
        if (entry) return entry.name;
        continue;
      }
      return name;
    }
  }
  const jsonMatch = /"(?:ApplicationName|Name)"\s*:\s*"([^"]+)"/i.exec(detail);
  if (jsonMatch) return jsonMatch[1];
  return null;
}

function groupKey(
  event: IntuneEvent,
  registry?: Record<string, GuidRegistryEntry>
): string {
  const guidSuffix = event.guid ? `:${event.guid.toLowerCase()}` : "";
  // 1. Resolved app name from event name (after " — "), with GUID tiebreaker
  const appFromName = extractAppName(event.name);
  if (appFromName) return `name:${appFromName.toLowerCase()}${guidSuffix}`;
  // 2. App name from detail text (resolves GUIDs via registry)
  const appFromDetail = extractAppNameFromDetail(event.detail, registry);
  if (appFromDetail) return `name:${appFromDetail.toLowerCase()}${guidSuffix}`;
  // 3. GUID (only if no name found)
  if (event.guid) return `guid:${event.guid.toLowerCase()}`;
  // 4. Solo fallback
  return `solo:${event.id}`;
}

function groupLabel(
  events: IntuneEvent[],
  registry?: Record<string, GuidRegistryEntry>
): string {
  // 1. Check event name for resolved app name (after " — ")
  for (const e of events) {
    const app = extractAppName(e.name);
    if (app) return app;
  }
  // 2. Check detail text for app name patterns (resolves GUIDs)
  for (const e of events) {
    const appName = extractAppNameFromDetail(e.detail, registry);
    if (appName) return appName;
  }
  // 3. Full GUID fallback
  if (events[0]?.guid) return events[0].guid;
  return events[0]?.name ?? "Unknown";
}

function worstStatus(events: IntuneEvent[]): IntuneStatus {
  let worst: IntuneStatus = "Success";
  for (const e of events) {
    if (STATUS_SEVERITY[e.status] < STATUS_SEVERITY[worst]) {
      worst = e.status;
    }
  }
  return worst;
}

export function buildActivityGroups(
  events: IntuneEvent[],
  registry?: Record<string, GuidRegistryEntry>
): ActivityGroup[] {
  const map = new Map<string, IntuneEvent[]>();

  for (const event of events) {
    const key = groupKey(event, registry);
    const existing = map.get(key);
    if (existing) {
      existing.push(event);
    } else {
      map.set(key, [event]);
    }
  }

  // Collapse solo events into "Other Activity"
  const soloEvents: IntuneEvent[] = [];
  const realGroups: ActivityGroup[] = [];

  for (const [key, groupEvents] of map) {
    if (key.startsWith("solo:")) {
      soloEvents.push(...groupEvents);
      continue;
    }

    groupEvents.sort((a, b) => (a.startTimeEpoch ?? 0) - (b.startTimeEpoch ?? 0));
    const types = new Set<IntuneEventType>();
    let successCount = 0;
    let failedCount = 0;
    let totalDur: number | null = null;

    for (const e of groupEvents) {
      types.add(e.eventType);
      if (e.status === "Success") successCount++;
      if (e.status === "Failed") failedCount++;
      if (e.durationSecs != null) {
        totalDur = (totalDur ?? 0) + e.durationSecs;
      }
    }

    const startEpoch = groupEvents[0]?.startTimeEpoch ?? 0;
    const lastEvent = groupEvents[groupEvents.length - 1];
    const endEpoch = lastEvent?.endTimeEpoch ?? lastEvent?.startTimeEpoch ?? 0;

    realGroups.push({
      key,
      label: groupLabel(groupEvents, registry),
      events: groupEvents,
      worstStatus: worstStatus(groupEvents),
      eventTypes: types,
      startEpoch,
      endEpoch,
      totalDurationSecs: totalDur,
      successCount,
      failedCount,
    });
  }

  // Add "Other Activity" group for solo events
  if (soloEvents.length > 0) {
    soloEvents.sort((a, b) => (a.startTimeEpoch ?? 0) - (b.startTimeEpoch ?? 0));
    const types = new Set<IntuneEventType>();
    let successCount = 0;
    let failedCount = 0;
    for (const e of soloEvents) {
      types.add(e.eventType);
      if (e.status === "Success") successCount++;
      if (e.status === "Failed") failedCount++;
    }

    realGroups.push({
      key: "other",
      label: "Other Activity",
      events: soloEvents,
      worstStatus: worstStatus(soloEvents),
      eventTypes: types,
      startEpoch: soloEvents[0]?.startTimeEpoch ?? 0,
      endEpoch: soloEvents[soloEvents.length - 1]?.startTimeEpoch ?? 0,
      totalDurationSecs: null,
      successCount,
      failedCount,
    });
  }

  // Sort by earliest event time
  realGroups.sort((a, b) => a.startEpoch - b.startEpoch);
  return realGroups;
}

// ── Components ────────────────────────────────────────────────────────

interface EventActivityViewProps {
  events: IntuneEvent[];
}

export function EventActivityView({ events }: EventActivityViewProps) {
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const guidRegistry = useIntuneStore((s) => s.guidRegistry);
  const metrics = useMemo(() => getLogListMetrics(logListFontSize), [logListFontSize]);
  const groups = useMemo(() => buildActivityGroups(events, guidRegistry), [events, guidRegistry]);
  const [expandedKeys, setExpandedKeys] = useState<Set<string>>(new Set());

  const toggleGroup = useCallback((key: string) => {
    setExpandedKeys((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  // Build flat list for virtualizer: group headers + expanded event rows
  const flatItems = useMemo(() => {
    const items: Array<
      | { type: "header"; group: ActivityGroup }
      | { type: "event"; event: IntuneEvent; group: ActivityGroup }
    > = [];
    for (const group of groups) {
      items.push({ type: "header", group });
      if (expandedKeys.has(group.key)) {
        for (const event of group.events) {
          items.push({ type: "event", event, group });
        }
      }
    }
    return items;
  }, [groups, expandedKeys]);

  const parentRef = useRef<HTMLDivElement>(null);
  const headerHeight = 52;
  const eventRowEstimate = 60;

  const virtualizer = useVirtualizer({
    count: flatItems.length,
    getScrollElement: () => parentRef.current,
    estimateSize: (index) =>
      flatItems[index]?.type === "header" ? headerHeight : eventRowEstimate,
    getItemKey: (index) => {
      const item = flatItems[index];
      return item?.type === "header" ? `h:${item.group.key}` : `e:${item?.event.id}`;
    },
    overscan: 10,
  });

  // Scroll to newly expanded group
  const prevExpandedRef = useRef(expandedKeys);
  useEffect(() => {
    const prev = prevExpandedRef.current;
    prevExpandedRef.current = expandedKeys;
    // Find newly added key
    for (const key of expandedKeys) {
      if (!prev.has(key)) {
        const idx = flatItems.findIndex(
          (item) => item.type === "header" && item.group.key === key
        );
        if (idx >= 0) virtualizer.scrollToIndex(idx, { align: "start" });
        break;
      }
    }
  }, [expandedKeys, flatItems, virtualizer]);

  const fontSize = metrics.fontSize;

  if (groups.length === 0) {
    return (
      <div
        style={{
          padding: "20px",
          color: tokens.colorNeutralForeground3,
          textAlign: "center",
          fontSize: `${fontSize}px`,
          fontFamily: LOG_UI_FONT_FAMILY,
        }}
      >
        No events to group.
      </div>
    );
  }

  return (
    <div
      ref={parentRef}
      role="tree"
      aria-label={`Activity groups — ${groups.length} apps`}
      style={{
        overflowY: "auto",
        height: "100%",
        backgroundColor: tokens.colorNeutralBackground1,
        fontFamily: LOG_UI_FONT_FAMILY,
      }}
    >
      <div
        style={{
          height: `${virtualizer.getTotalSize()}px`,
          width: "100%",
          position: "relative",
        }}
      >
        {virtualizer.getVirtualItems().map((virtualRow) => {
          const item = flatItems[virtualRow.index];
          if (!item) return null;

          return (
            <div
              key={virtualRow.key}
              data-index={virtualRow.index}
              ref={virtualizer.measureElement}
              style={{
                position: "absolute",
                top: 0,
                left: 0,
                width: "100%",
                transform: `translateY(${virtualRow.start}px)`,
              }}
            >
              {item.type === "header" ? (
                <ActivityGroupHeader
                  group={item.group}
                  isExpanded={expandedKeys.has(item.group.key)}
                  onToggle={toggleGroup}
                  fontSize={fontSize}
                />
              ) : (
                <ActivityEventRow
                  event={item.event}
                  fontSize={fontSize}
                  guidRegistry={guidRegistry}
                />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Group header ──────────────────────────────────────────────────────

function ActivityGroupHeader({
  group,
  isExpanded,
  onToggle,
  fontSize,
}: {
  group: ActivityGroup;
  isExpanded: boolean;
  onToggle: (key: string) => void;
  fontSize: number;
}) {
  const statusColor = STATUS_COLORS[group.worstStatus];
  const typeLabels = Array.from(group.eventTypes)
    .map((t) => EVENT_TYPE_LABELS[t])
    .join(", ");

  return (
    <div
      role="treeitem"
      aria-expanded={isExpanded}
      tabIndex={0}
      onClick={() => onToggle(group.key)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onToggle(group.key);
        }
      }}
      style={{
        display: "flex",
        alignItems: "center",
        gap: "10px",
        padding: "8px 12px",
        cursor: "pointer",
        backgroundColor: tokens.colorNeutralBackground3,
        borderLeft: `4px solid ${statusColor}`,
        borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
        fontSize: `${fontSize}px`,
        userSelect: "none",
      }}
    >
      {/* Expand/collapse indicator */}
      <span
        style={{
          fontSize: `${fontSize + 2}px`,
          color: tokens.colorNeutralForeground3,
          width: "16px",
          textAlign: "center",
          flexShrink: 0,
          transition: "transform 0.15s ease",
          transform: isExpanded ? "rotate(90deg)" : "rotate(0deg)",
        }}
      >
        ▶
      </span>

      {/* App name */}
      <span
        style={{
          fontWeight: 600,
          color: tokens.colorNeutralForeground1,
          flex: 1,
          minWidth: 0,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
        title={group.label}
      >
        {group.label}
      </span>

      {/* Event type badges */}
      <span
        style={{
          fontSize: `${Math.max(fontSize - 2, 9)}px`,
          padding: "2px 6px",
          borderRadius: "3px",
          backgroundColor: tokens.colorNeutralBackground4,
          color: tokens.colorNeutralForeground2,
          fontWeight: 700,
          flexShrink: 0,
        }}
      >
        {typeLabels}
      </span>

      {/* Event count */}
      <span
        style={{
          fontSize: `${Math.max(fontSize - 1, 10)}px`,
          color: tokens.colorNeutralForeground3,
          flexShrink: 0,
        }}
      >
        {group.events.length} event{group.events.length !== 1 ? "s" : ""}
      </span>

      {/* Status counts */}
      {group.successCount > 0 && (
        <StatusPill
          count={group.successCount}
          color={STATUS_COLORS.Success}
          fontSize={fontSize}
        />
      )}
      {group.failedCount > 0 && (
        <StatusPill
          count={group.failedCount}
          color={STATUS_COLORS.Failed}
          fontSize={fontSize}
        />
      )}

      {/* Duration */}
      {group.totalDurationSecs != null && (
        <span
          style={{
            fontSize: `${Math.max(fontSize - 1, 10)}px`,
            color: tokens.colorNeutralForeground3,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            flexShrink: 0,
          }}
        >
          {formatDuration(group.totalDurationSecs)}
        </span>
      )}

      {/* Time range */}
      {group.events[0]?.startTime && (
        <span
          style={{
            fontSize: `${Math.max(fontSize - 2, 9)}px`,
            color: tokens.colorNeutralForeground4,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            flexShrink: 0,
          }}
        >
          {formatDisplayDateTime(group.events[0].startTime) ?? ""}
        </span>
      )}

      {/* Overall status */}
      <span
        style={{
          fontSize: `${Math.max(fontSize - 1, 10)}px`,
          fontWeight: 700,
          color: statusColor,
          flexShrink: 0,
          minWidth: "70px",
          textAlign: "right",
        }}
      >
        {group.worstStatus.toUpperCase()}
      </span>
    </div>
  );
}

// ── Event row inside expanded group ───────────────────────────────────

// ── Detail parsing ────────────────────────────────────────────────────

const INTENT_MAP: Record<string, string> = {
  "0": "Available", "1": "Available (no enrollment)", "3": "Required", "4": "Uninstall",
  requiredinstall: "Required Install", requireduninstall: "Required Uninstall",
  availableinstall: "Available Install", availableuninstall: "Available Uninstall",
};

const TARGET_TYPE_MAP: Record<string, string> = {
  "1": "User", "2": "Device", "3": "Both",
};

interface ParsedTag {
  label: string;
  value: string;
  color: "green" | "red" | "yellow" | "blue" | "neutral";
}

function parseStructuredTags(detail: string): ParsedTag[] {
  const tags: ParsedTag[] = [];

  // Intent (numeric or named)
  const intentNum = /intent\s*[=:]\s*(\d+)/i.exec(detail);
  if (intentNum) {
    const val = INTENT_MAP[intentNum[1]] ?? `Intent ${intentNum[1]}`;
    tags.push({ label: "Intent", value: val, color: val.includes("Required") ? "red" : "neutral" });
  }
  const intentNamed = /targeted\s+intent\s*[=:]\s*(\w+)/i.exec(detail);
  if (intentNamed && !intentNum) {
    const val = INTENT_MAP[intentNamed[1].toLowerCase()] ?? intentNamed[1];
    tags.push({ label: "Intent", value: val, color: val.includes("Required") ? "red" : "neutral" });
  }

  // Target type
  const targetMatch = /targetType\s*[=:]\s*(\d+)/i.exec(detail);
  if (targetMatch) {
    tags.push({ label: "Target", value: TARGET_TYPE_MAP[targetMatch[1]] ?? `Type ${targetMatch[1]}`, color: "neutral" });
  }

  // Detection
  const detectionMatch = /Detection\s*=\s*(Detected|Not\s*Detected|NotDetected)/i.exec(detail);
  if (detectionMatch) {
    const detected = detectionMatch[1].toLowerCase().includes("not") ? false : true;
    tags.push({ label: "Detection", value: detected ? "Detected" : "Not Detected", color: detected ? "green" : "yellow" });
  }

  // Applicability
  const applicabilityMatch = /Applicability\s*=\s*(Applicable|Not\s*Applicable|NotApplicable)/i.exec(detail);
  if (applicabilityMatch) {
    const applicable = !applicabilityMatch[1].toLowerCase().includes("not");
    tags.push({ label: "Applicability", value: applicable ? "Applicable" : "Not Applicable", color: applicable ? "green" : "yellow" });
  }

  // Reboot
  const rebootMatch = /Reboot\s*=\s*(\w+)/i.exec(detail);
  if (rebootMatch) {
    const val = rebootMatch[1];
    tags.push({ label: "Reboot", value: val, color: val.toLowerCase() === "clean" ? "green" : "red" });
  }

  // GRS expired
  const grsMatch = /GRS\s+expired\s*=\s*(True|False)/i.exec(detail);
  if (grsMatch) {
    tags.push({ label: "GRS", value: grsMatch[1] === "True" ? "Expired" : "Active", color: grsMatch[1] === "True" ? "yellow" : "green" });
  }

  // Enforcement classification
  const enforcementMatch = /enforcement\s+classification\s*[=:]\s*(\w+)/i.exec(detail);
  if (enforcementMatch) {
    tags.push({ label: "Enforcement", value: enforcementMatch[1], color: "blue" });
  }

  // Desired state
  const desiredMatch = /desired\s+state\s*[=:]\s*(\w+)/i.exec(detail);
  if (desiredMatch) {
    tags.push({ label: "Desired", value: desiredMatch[1], color: "neutral" });
  }

  // Exit code
  const exitMatch = /exit\s*code\s*[=:]\s*(-?\d+)/i.exec(detail);
  if (exitMatch) {
    const code = exitMatch[1];
    tags.push({ label: "Exit", value: code, color: code === "0" ? "green" : "red" });
  }

  return tags;
}

const GUID_RE = /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g;

/**
 * Replace GUIDs in text with resolved app names from the registry.
 */
function resolveGuidsInText(
  text: string,
  registry: Record<string, GuidRegistryEntry>
): string {
  if (Object.keys(registry).length === 0) return text;
  return text.replace(GUID_RE, (guid) => {
    const entry = registry[guid.toLowerCase()] ?? registry[guid];
    return entry ? `${entry.name}` : guid;
  });
}

// ── Event row component ──────────────────────────────────────────────

function ActivityEventRow({
  event,
  fontSize,
  guidRegistry,
}: {
  event: IntuneEvent;
  fontSize: number;
  guidRegistry: Record<string, GuidRegistryEntry>;
}) {
  const smallFont = Math.max(fontSize - 2, 9);
  const monoFont = Math.max(fontSize - 1, 10);
  const statusColor = STATUS_COLORS[event.status];
  const tags = parseStructuredTags(event.detail);
  const resolvedDetail = resolveGuidsInText(event.detail, guidRegistry);

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: "4px",
        padding: "6px 12px 8px 42px",
        backgroundColor: tokens.colorNeutralBackground1,
        borderLeft: `4px solid ${statusColor}`,
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        fontSize: `${fontSize}px`,
      }}
    >
      {/* Top row: status, timestamp, duration, error code */}
      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
        <span
          style={{
            fontSize: `${smallFont}px`,
            fontWeight: 700,
            color: statusColor,
            flexShrink: 0,
            width: "72px",
          }}
        >
          {event.status.toUpperCase()}
        </span>
        <span
          style={{
            fontSize: `${monoFont}px`,
            color: tokens.colorNeutralForeground3,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            flexShrink: 0,
          }}
        >
          {formatDisplayDateTime(event.startTime) ?? "—"}
        </span>
        {event.durationSecs != null && (
          <span
            style={{
              fontSize: `${monoFont}px`,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              color: tokens.colorNeutralForeground3,
            }}
          >
            {formatDuration(event.durationSecs)}
          </span>
        )}
        {event.errorCode && (
          <span
            style={{
              fontSize: `${smallFont}px`,
              fontWeight: 700,
              padding: "1px 6px",
              borderRadius: "3px",
              backgroundColor: tokens.colorPaletteRedBackground2,
              color: tokens.colorPaletteRedForeground1,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            }}
          >
            {event.errorCode}
          </span>
        )}
      </div>

      {/* Parsed tags row */}
      {tags.length > 0 && (
        <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", paddingLeft: "72px" }}>
          {tags.map((tag, i) => {
            const colors = tag.color === "neutral"
              ? { bg: tokens.colorNeutralBackground4, fg: tokens.colorNeutralForeground2 }
              : tag.color === "green"
                ? { bg: tokens.colorPaletteGreenBackground1, fg: tokens.colorPaletteGreenForeground1 }
                : tag.color === "red"
                  ? { bg: tokens.colorPaletteRedBackground2, fg: tokens.colorPaletteRedForeground1 }
                  : tag.color === "yellow"
                    ? { bg: tokens.colorPaletteYellowBackground1, fg: tokens.colorPaletteMarigoldForeground1 }
                    : { bg: tokens.colorPaletteBlueBackground2, fg: tokens.colorPaletteBlueForeground2 };

            return (
              <span
                key={i}
                style={{
                  fontSize: `${smallFont}px`,
                  fontWeight: 600,
                  padding: "1px 6px",
                  borderRadius: "3px",
                  backgroundColor: colors.bg,
                  color: colors.fg,
                }}
              >
                {tag.label}: {tag.value}
              </span>
            );
          })}
        </div>
      )}

      {/* Detail message — word-wrapped, GUIDs resolved */}
      <div
        style={{
          color: tokens.colorNeutralForeground2,
          fontFamily: LOG_MONOSPACE_FONT_FAMILY,
          fontSize: `${monoFont}px`,
          whiteSpace: "pre-wrap",
          wordBreak: "break-word",
          lineHeight: "1.4",
          paddingLeft: "72px",
        }}
      >
        {resolvedDetail}
      </div>
    </div>
  );
}

// ── Helpers ───────────────────────────────────────────────────────────

function StatusPill({
  count,
  color,
  fontSize,
}: {
  count: number;
  color: string;
  fontSize: number;
}) {
  return (
    <span
      style={{
        fontSize: `${Math.max(fontSize - 2, 9)}px`,
        fontWeight: 700,
        color,
        flexShrink: 0,
      }}
    >
      {count}
    </span>
  );
}
