import { useMemo, useRef, useState, useEffect } from "react";
import { Button, Checkbox, Input, tokens } from "@fluentui/react-components";
import { useEvtxStore } from "../../stores/evtx-store";
import type { EvtxChannelInfo } from "../../types/event-log-workspace";

const WINDOWS_LOGS = new Set(["Application", "Security", "Setup", "System", "ForwardedEvents"]);
const WINDOWS_LOGS_ORDER = ["Application", "Security", "System", "Setup", "ForwardedEvents"];

interface ChannelGroup {
  key: string;
  label: string;
  channels: EvtxChannelInfo[];
}

interface ChannelSection {
  label: string;
  groups: ChannelGroup[];
  defaultExpanded: boolean;
}

function buildSections(channels: EvtxChannelInfo[]): ChannelSection[] {
  const windowsLogs: EvtxChannelInfo[] = [];
  const serviceChannels: EvtxChannelInfo[] = [];

  for (const ch of channels) {
    if (WINDOWS_LOGS.has(ch.name)) {
      windowsLogs.push(ch);
    } else {
      serviceChannels.push(ch);
    }
  }

  windowsLogs.sort(
    (a, b) => WINDOWS_LOGS_ORDER.indexOf(a.name) - WINDOWS_LOGS_ORDER.indexOf(b.name)
  );

  // Group service channels by provider prefix (before the "/")
  const groupMap = new Map<string, EvtxChannelInfo[]>();
  const standalone: EvtxChannelInfo[] = [];

  for (const ch of serviceChannels) {
    const slashIdx = ch.name.indexOf("/");
    if (slashIdx > 0) {
      const prefix = ch.name.slice(0, slashIdx);
      const existing = groupMap.get(prefix) ?? [];
      existing.push(ch);
      groupMap.set(prefix, existing);
    } else {
      standalone.push(ch);
    }
  }

  // Build groups: standalone channels become single-item groups
  const serviceGroups: ChannelGroup[] = [];

  for (const ch of standalone) {
    serviceGroups.push({ key: ch.name, label: ch.name, channels: [ch] });
  }

  for (const [prefix, chs] of groupMap) {
    chs.sort((a, b) => a.name.localeCompare(b.name));
    serviceGroups.push({ key: prefix, label: prefix, channels: chs });
  }

  serviceGroups.sort((a, b) => a.label.localeCompare(b.label));

  const sections: ChannelSection[] = [];

  if (windowsLogs.length > 0) {
    sections.push({
      label: "Windows Logs",
      groups: windowsLogs.map((ch) => ({
        key: ch.name,
        label: ch.name,
        channels: [ch],
      })),
      defaultExpanded: true,
    });
  }

  if (serviceGroups.length > 0) {
    sections.push({
      label: "Applications and Services Logs",
      groups: serviceGroups,
      defaultExpanded: false,
    });
  }

  return sections;
}

const MIN_SIDEBAR_WIDTH = 180;
const MAX_SIDEBAR_WIDTH = 500;
const DEFAULT_SIDEBAR_WIDTH = 280;

export function ChannelPicker() {
  const channels = useEvtxStore((s) => s.channels);
  const selectedChannels = useEvtxStore((s) => s.selectedChannels);
  const toggleChannel = useEvtxStore((s) => s.toggleChannel);
  const selectAllChannels = useEvtxStore((s) => s.selectAllChannels);
  const deselectAllChannels = useEvtxStore((s) => s.deselectAllChannels);
  const sourceMode = useEvtxStore((s) => s.sourceMode);
  const loadedChannels = useEvtxStore((s) => s.loadedChannels);
  const loadSelectedChannels = useEvtxStore((s) => s.loadSelectedChannels);
  const isLoading = useEvtxStore((s) => s.isLoading);

  const [search, setSearch] = useState("");
  const [collapsedSections, setCollapsedSections] = useState<Set<string>>(new Set());
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  const [sidebarWidth, setSidebarWidth] = useState(DEFAULT_SIDEBAR_WIDTH);
  const resizeRef = useRef<{ startX: number; startWidth: number } | null>(null);

  useEffect(() => {
    const onMouseMove = (e: MouseEvent) => {
      if (!resizeRef.current) return;
      const delta = e.clientX - resizeRef.current.startX;
      setSidebarWidth(
        Math.max(MIN_SIDEBAR_WIDTH, Math.min(resizeRef.current.startWidth + delta, MAX_SIDEBAR_WIDTH))
      );
    };
    const onMouseUp = () => {
      if (resizeRef.current) {
        resizeRef.current = null;
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
      }
    };
    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
    return () => {
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
    };
  }, []);

  const filteredChannels = useMemo(() => {
    if (!search.trim()) return channels;
    const lower = search.toLowerCase();
    return channels.filter((c) => c.name.toLowerCase().includes(lower));
  }, [channels, search]);

  const sections = useMemo(() => buildSections(filteredChannels), [filteredChannels]);

  // Compute inline — Set objects in useMemo deps don't trigger reliably
  const unloadedSelectedCount =
    sourceMode !== "live"
      ? 0
      : [...selectedChannels].filter((ch) => !loadedChannels.has(ch)).length;

  const toggleSection = (label: string) => {
    setCollapsedSections((prev) => {
      const next = new Set(prev);
      if (next.has(label)) next.delete(label);
      else next.add(label);
      return next;
    });
  };

  const toggleGroup = (key: string) => {
    setCollapsedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const isSectionExpanded = (section: ChannelSection) =>
    section.defaultExpanded ? !collapsedSections.has(section.label) : collapsedSections.has(section.label);

  return (
    <div style={{ display: "flex", flexShrink: 0 }}>
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          height: "100%",
          width: `${sidebarWidth}px`,
          minWidth: `${MIN_SIDEBAR_WIDTH}px`,
          backgroundColor: tokens.colorNeutralBackground2,
          overflow: "hidden",
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: "8px",
            borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
            display: "flex",
            flexDirection: "column",
            gap: "6px",
            flexShrink: 0,
          }}
        >
          <div
            style={{
              fontSize: "11px",
              fontWeight: 600,
              color: tokens.colorNeutralForeground3,
              textTransform: "uppercase",
              letterSpacing: "0.5px",
            }}
          >
            Channels ({selectedChannels.size}/{channels.length})
          </div>
          <Input
            value={search}
            onChange={(_, data) => setSearch(data.value)}
            placeholder="Filter channels..."
            size="small"
            style={{ width: "100%" }}
          />
          <div style={{ display: "flex", gap: "4px" }}>
            <Button size="small" appearance="subtle" onClick={selectAllChannels}>
              Select All
            </Button>
            <Button size="small" appearance="subtle" onClick={deselectAllChannels}>
              Deselect All
            </Button>
          </div>
          {sourceMode === "live" && unloadedSelectedCount > 0 && (
            <Button
              size="small"
              appearance="primary"
              disabled={isLoading}
              onClick={loadSelectedChannels}
              style={{ width: "100%" }}
            >
              {isLoading
                ? "Loading..."
                : `Load ${unloadedSelectedCount} channel${unloadedSelectedCount !== 1 ? "s" : ""}`}
            </Button>
          )}
        </div>

        {/* Tree */}
        <div style={{ flex: 1, overflowY: "auto", padding: "4px 0" }}>
          {search.trim() ? (
            // Flat list when searching
            <div style={{ padding: "0 8px" }}>
              {filteredChannels.map((ch) => (
                <ChannelLeaf
                  key={ch.name}
                  channel={ch}
                  selected={selectedChannels.has(ch.name)}
                  loaded={loadedChannels.has(ch.name)}
                  onToggle={() => toggleChannel(ch.name)}
                  indent={0}
                />
              ))}
            </div>
          ) : (
            sections.map((section) => {
              const expanded = isSectionExpanded(section);
              return (
                <div key={section.label}>
                  <TreeToggle
                    label={section.label}
                    expanded={expanded}
                    onToggle={() => toggleSection(section.label)}
                    indent={0}
                    count={section.groups.reduce((n, g) => n + g.channels.length, 0)}
                    bold
                  />
                  {expanded &&
                    section.groups.map((group) => {
                      if (group.channels.length === 1) {
                        // Single channel — render inline, no subfolder
                        const ch = group.channels[0];
                        const displayName =
                          ch.name.includes("/") ? ch.name.split("/").pop()! : ch.name;
                        return (
                          <ChannelLeaf
                            key={ch.name}
                            channel={ch}
                            displayName={displayName}
                            selected={selectedChannels.has(ch.name)}
                            loaded={loadedChannels.has(ch.name)}
                            onToggle={() => toggleChannel(ch.name)}
                            indent={1}
                          />
                        );
                      }

                      // Multi-channel group — render as subfolder
                      const groupExpanded = !collapsedGroups.has(group.key);
                      return (
                        <div key={group.key}>
                          <TreeToggle
                            label={group.label}
                            expanded={groupExpanded}
                            onToggle={() => toggleGroup(group.key)}
                            indent={1}
                            count={group.channels.length}
                          />
                          {groupExpanded &&
                            group.channels.map((ch) => {
                              const subName = ch.name.split("/").pop() ?? ch.name;
                              return (
                                <ChannelLeaf
                                  key={ch.name}
                                  channel={ch}
                                  displayName={subName}
                                  selected={selectedChannels.has(ch.name)}
                                  loaded={loadedChannels.has(ch.name)}
                                  onToggle={() => toggleChannel(ch.name)}
                                  indent={2}
                                />
                              );
                            })}
                        </div>
                      );
                    })}
                </div>
              );
            })
          )}
          {filteredChannels.length === 0 && (
            <div
              style={{
                fontSize: "12px",
                color: tokens.colorNeutralForeground4,
                padding: "8px",
                textAlign: "center",
              }}
            >
              No channels match filter
            </div>
          )}
        </div>
      </div>

      {/* Resize handle */}
      <div
        style={{
          width: "4px",
          cursor: "col-resize",
          backgroundColor: tokens.colorNeutralStroke2,
          flexShrink: 0,
        }}
        onMouseDown={(e) => {
          e.preventDefault();
          resizeRef.current = { startX: e.clientX, startWidth: sidebarWidth };
          document.body.style.cursor = "col-resize";
          document.body.style.userSelect = "none";
        }}
      />
    </div>
  );
}

// ── Subcomponents ─────────────────────────────────────────────────────────

function TreeToggle({
  label,
  expanded,
  onToggle,
  indent,
  count,
  bold,
}: {
  label: string;
  expanded: boolean;
  onToggle: () => void;
  indent: number;
  count: number;
  bold?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onToggle}
      style={{
        display: "flex",
        alignItems: "center",
        gap: "4px",
        width: "100%",
        padding: `3px 8px 3px ${8 + indent * 12}px`,
        border: "none",
        background: "transparent",
        cursor: "pointer",
        fontSize: "11px",
        fontWeight: bold ? 600 : 500,
        color: tokens.colorNeutralForeground2,
        textAlign: "left",
        overflow: "hidden",
      }}
      title={label}
    >
      <span style={{ fontSize: "8px", width: "10px", flexShrink: 0 }}>
        {expanded ? "\u25BC" : "\u25B6"}
      </span>
      <span
        style={{
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          flex: 1,
        }}
      >
        {label}
      </span>
      <span
        style={{
          fontSize: "10px",
          color: tokens.colorNeutralForeground4,
          flexShrink: 0,
        }}
      >
        {count}
      </span>
    </button>
  );
}

function ChannelLeaf({
  channel,
  displayName,
  selected,
  loaded,
  onToggle,
  indent,
}: {
  channel: EvtxChannelInfo;
  displayName?: string;
  selected: boolean;
  loaded: boolean;
  onToggle: () => void;
  indent: number;
}) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "4px",
        paddingLeft: `${8 + indent * 12}px`,
        paddingRight: "4px",
      }}
    >
      <Checkbox
        checked={selected}
        onChange={onToggle}
        label={
          <span
            style={{
              fontSize: "11px",
              color: tokens.colorNeutralForeground1,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
            title={channel.name}
          >
            {displayName ?? channel.name}
            {loaded && channel.eventCount > 0 && (
              <span
                style={{
                  marginLeft: "4px",
                  fontSize: "10px",
                  color: tokens.colorNeutralForeground4,
                }}
              >
                ({channel.eventCount})
              </span>
            )}
          </span>
        }
      />
    </div>
  );
}
