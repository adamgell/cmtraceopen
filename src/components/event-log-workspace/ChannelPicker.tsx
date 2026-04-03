import { memo, useMemo, useRef, useState, useEffect, useCallback } from "react";
import { Button, Input, tokens } from "@fluentui/react-components";
import { useEvtxStore } from "../../stores/evtx-store";
import type { EvtxChannelInfo } from "../../types/event-log-workspace";

// ── Tree data structure ─────────────────────────────────────────────────────

interface TreeNode {
  name: string;
  fullPath: string;
  channel: EvtxChannelInfo | null; // leaf node if present
  children: Map<string, TreeNode>;
}

const WINDOWS_LOGS = new Set(["Application", "Security", "Setup", "System", "ForwardedEvents"]);
const WINDOWS_LOGS_ORDER = ["Application", "Security", "System", "Setup", "ForwardedEvents"];

function buildTree(channels: EvtxChannelInfo[]): { windowsLogs: EvtxChannelInfo[]; serviceTree: TreeNode } {
  const windowsLogs: EvtxChannelInfo[] = [];
  const root: TreeNode = { name: "", fullPath: "", channel: null, children: new Map() };

  for (const ch of channels) {
    if (WINDOWS_LOGS.has(ch.name)) {
      windowsLogs.push(ch);
      continue;
    }

    // Split channel path: "Microsoft-Windows-AAD/Operational"
    // → split on "/" first, then split the provider part on "-"
    const slashParts = ch.name.split("/");
    const providerParts = slashParts[0].split("-");
    const allParts = [...providerParts, ...slashParts.slice(1)];

    let node = root;
    for (const part of allParts) {
      if (!node.children.has(part)) {
        node.children.set(part, {
          name: part,
          fullPath: "",
          channel: null,
          children: new Map(),
        });
      }
      node = node.children.get(part)!;
    }
    node.channel = ch;
    node.fullPath = ch.name;
  }

  // Collapse single-child chains: if a node has exactly one child and no channel,
  // merge it with its child (e.g., "Microsoft" → "Windows" becomes "Microsoft-Windows" if Windows only has children)
  collapseChains(root);

  windowsLogs.sort(
    (a, b) => WINDOWS_LOGS_ORDER.indexOf(a.name) - WINDOWS_LOGS_ORDER.indexOf(b.name)
  );

  return { windowsLogs, serviceTree: root };
}

function collapseChains(node: TreeNode) {
  // Process children first (bottom-up)
  for (const child of node.children.values()) {
    collapseChains(child);
  }

  // If this node has exactly one child, no channel, and child also has no channel,
  // merge child's name into this node
  if (node.children.size === 1 && !node.channel) {
    const [childName, child] = [...node.children.entries()][0];
    if (!child.channel || child.children.size > 0) {
      // Merge: combine names with "-"
      const mergedName = node.name ? `${node.name}-${childName}` : childName;
      node.name = mergedName;
      node.channel = child.channel;
      node.fullPath = child.fullPath;
      node.children = child.children;
    }
  }
}

function countLeaves(node: TreeNode): number {
  if (node.children.size === 0) return node.channel ? 1 : 0;
  let count = node.channel ? 1 : 0;
  for (const child of node.children.values()) {
    count += countLeaves(child);
  }
  return count;
}

function getSortedChildren(node: TreeNode): TreeNode[] {
  return [...node.children.values()].sort((a, b) => a.name.localeCompare(b.name));
}

// ── Constants ───────────────────────────────────────────────────────────────

const MIN_SIDEBAR_WIDTH = 200;
const MAX_SIDEBAR_WIDTH = 500;
const DEFAULT_SIDEBAR_WIDTH = 300;

// ── Component ───────────────────────────────────────────────────────────────

export function ChannelPicker() {
  const channels = useEvtxStore((s) => s.channels);
  const selectedChannels = useEvtxStore((s) => s.selectedChannels);
  const toggleChannel = useEvtxStore((s) => s.toggleChannel);
  const selectAllChannels = useEvtxStore((s) => s.selectAllChannels);
  const deselectAllChannels = useEvtxStore((s) => s.deselectAllChannels);
  const sourceMode = useEvtxStore((s) => s.sourceMode);
  const loadedChannels = useEvtxStore((s) => s.loadedChannels);
  const loadSelectedChannels = useEvtxStore((s) => s.loadSelectedChannels);
  const refreshLoadedChannels = useEvtxStore((s) => s.refreshLoadedChannels);
  const isLoading = useEvtxStore((s) => s.isLoading);

  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set(["Windows Logs"]));
  const [sidebarWidth, setSidebarWidth] = useState(DEFAULT_SIDEBAR_WIDTH);
  const resizeRef = useRef<{ startX: number; startWidth: number } | null>(null);

  useEffect(() => {
    const onMouseMove = (e: MouseEvent) => {
      if (!resizeRef.current) return;
      setSidebarWidth(
        Math.max(MIN_SIDEBAR_WIDTH, Math.min(resizeRef.current.startWidth + (e.clientX - resizeRef.current.startX), MAX_SIDEBAR_WIDTH))
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

  const { windowsLogs, serviceTree } = useMemo(() => buildTree(channels), [channels]);

  const filteredChannels = useMemo(() => {
    if (!search.trim()) return null;
    const lower = search.toLowerCase();
    return channels.filter((c) => c.name.toLowerCase().includes(lower));
  }, [channels, search]);

  const unloadedSelectedCount =
    sourceMode !== "live"
      ? 0
      : [...selectedChannels].filter((ch) => !loadedChannels.has(ch)).length;

  const toggleExpand = useCallback((key: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

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
            gap: "5px",
            flexShrink: 0,
          }}
        >
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
          {sourceMode === "live" && (
            <div style={{ display: "flex", gap: "4px" }}>
              {unloadedSelectedCount > 0 && (
                <Button
                  size="small"
                  appearance="primary"
                  disabled={isLoading}
                  onClick={loadSelectedChannels}
                  style={{ flex: 1 }}
                >
                  {isLoading ? "Loading..." : `Load ${unloadedSelectedCount}`}
                </Button>
              )}
              <Button
                size="small"
                appearance="subtle"
                disabled={isLoading}
                onClick={refreshLoadedChannels}
                title="Reload all loaded channels"
              >
                Refresh
              </Button>
            </div>
          )}
        </div>

        {/* Tree */}
        <div style={{ flex: 1, overflowY: "auto", padding: "2px 0", fontSize: "12px" }}>
          {filteredChannels ? (
            // Flat search results
            filteredChannels.map((ch) => (
              <ChannelLeaf
                key={ch.name}
                name={ch.name}
                channel={ch}
                selected={selectedChannels.has(ch.name)}
                loaded={loadedChannels.has(ch.name)}
                onToggle={() => toggleChannel(ch.name)}
                depth={0}
              />
            ))
          ) : (
            <>
              {/* Windows Logs */}
              <FolderRow
                label="Windows Logs"
                expanded={expanded.has("Windows Logs")}
                onToggle={() => toggleExpand("Windows Logs")}
                depth={0}
              />
              {expanded.has("Windows Logs") &&
                windowsLogs.map((ch) => (
                  <ChannelLeaf
                    key={ch.name}
                    name={ch.name}
                    channel={ch}
                    selected={selectedChannels.has(ch.name)}
                    loaded={loadedChannels.has(ch.name)}
                    onToggle={() => toggleChannel(ch.name)}
                    depth={1}
                  />
                ))}

              {/* Applications and Services Logs */}
              <FolderRow
                label="Applications and Services Logs"
                expanded={expanded.has("AppServices")}
                onToggle={() => toggleExpand("AppServices")}
                depth={0}
                count={countLeaves(serviceTree)}
              />
              {expanded.has("AppServices") && (
                <TreeNodeView
                  node={serviceTree}
                  depth={1}
                  expanded={expanded}
                  toggleExpand={toggleExpand}
                  selectedChannels={selectedChannels}
                  loadedChannels={loadedChannels}
                  toggleChannel={toggleChannel}
                />
              )}
            </>
          )}
          {filteredChannels && filteredChannels.length === 0 && (
            <div
              style={{
                fontSize: "12px",
                color: tokens.colorNeutralForeground4,
                padding: "12px 8px",
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

// ── Tree rendering ──────────────────────────────────────────────────────────

function TreeNodeView({
  node,
  depth,
  expanded,
  toggleExpand,
  selectedChannels,
  loadedChannels,
  toggleChannel,
}: {
  node: TreeNode;
  depth: number;
  expanded: Set<string>;
  toggleExpand: (key: string) => void;
  selectedChannels: Set<string>;
  loadedChannels: Set<string>;
  toggleChannel: (name: string) => void;
}) {
  const children = getSortedChildren(node);

  return (
    <>
      {children.map((child) => {
        const key = child.fullPath || child.name;
        const hasChildren = child.children.size > 0;
        const isExpanded = expanded.has(key);

        if (!hasChildren && child.channel) {
          // Pure leaf — just a channel
          return (
            <ChannelLeaf
              key={key}
              name={child.name}
              channel={child.channel}
              selected={selectedChannels.has(child.channel.name)}
              loaded={loadedChannels.has(child.channel.name)}
              onToggle={() => toggleChannel(child.channel!.name)}
              depth={depth}
            />
          );
        }

        // Folder node (may also have a channel)
        return (
          <div key={key}>
            <FolderRow
              label={child.name}
              expanded={isExpanded}
              onToggle={() => toggleExpand(key)}
              depth={depth}
              count={countLeaves(child)}
              channel={child.channel ?? undefined}
              selected={child.channel ? selectedChannels.has(child.channel.name) : undefined}
              loaded={child.channel ? loadedChannels.has(child.channel.name) : undefined}
              onChannelToggle={child.channel ? () => toggleChannel(child.channel!.name) : undefined}
            />
            {isExpanded && (
              <TreeNodeView
                node={child}
                depth={depth + 1}
                expanded={expanded}
                toggleExpand={toggleExpand}
                selectedChannels={selectedChannels}
                loadedChannels={loadedChannels}
                toggleChannel={toggleChannel}
              />
            )}
          </div>
        );
      })}
    </>
  );
}

// ── Leaf & folder rows ──────────────────────────────────────────────────────

const ChannelLeaf = memo(function ChannelLeaf({
  name,
  channel,
  selected,
  loaded,
  onToggle,
  depth,
}: {
  name: string;
  channel: EvtxChannelInfo;
  selected: boolean;
  loaded: boolean;
  onToggle: () => void;
  depth: number;
}) {
  return (
    <label
      style={{
        display: "flex",
        alignItems: "center",
        gap: "4px",
        paddingLeft: `${4 + depth * 16}px`,
        paddingRight: "4px",
        height: "22px",
        cursor: "pointer",
        color: tokens.colorNeutralForeground1,
        whiteSpace: "nowrap",
      }}
      title={channel.name}
    >
      <span style={{ width: "14px", flexShrink: 0 }} />
      <input
        type="checkbox"
        checked={selected}
        onChange={onToggle}
        style={{ cursor: "pointer", margin: 0, flexShrink: 0 }}
      />
      <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{name}</span>
      {loaded && channel.eventCount > 0 && (
        <span style={{ fontSize: "10px", color: tokens.colorNeutralForeground4, flexShrink: 0 }}>
          ({channel.eventCount})
        </span>
      )}
    </label>
  );
});

const FolderRow = memo(function FolderRow({
  label,
  expanded,
  onToggle,
  depth,
  count,
  channel,
  selected,
  loaded,
  onChannelToggle,
}: {
  label: string;
  expanded: boolean;
  onToggle: () => void;
  depth: number;
  count?: number;
  channel?: EvtxChannelInfo;
  selected?: boolean;
  loaded?: boolean;
  onChannelToggle?: () => void;
}) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "4px",
        paddingLeft: `${4 + depth * 16}px`,
        paddingRight: "4px",
        height: "22px",
        whiteSpace: "nowrap",
      }}
    >
      <button
        type="button"
        onClick={onToggle}
        style={{
          width: "14px",
          flexShrink: 0,
          background: "none",
          border: "none",
          cursor: "pointer",
          padding: 0,
          fontSize: "8px",
          color: tokens.colorNeutralForeground3,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        {expanded ? "\u25BC" : "\u25B6"}
      </button>
      {onChannelToggle != null && (
        <input
          type="checkbox"
          checked={selected ?? false}
          onChange={onChannelToggle}
          style={{ cursor: "pointer", margin: 0, flexShrink: 0 }}
        />
      )}
      <span
        onClick={onToggle}
        style={{
          cursor: "pointer",
          fontWeight: 500,
          color: tokens.colorNeutralForeground1,
          overflow: "hidden",
          textOverflow: "ellipsis",
          flex: 1,
        }}
      >
        {label}
      </span>
      {count != null && count > 0 && (
        <span style={{ fontSize: "10px", color: tokens.colorNeutralForeground4, flexShrink: 0 }}>
          {count}
        </span>
      )}
      {loaded && channel && channel.eventCount > 0 && (
        <span style={{ fontSize: "10px", color: tokens.colorNeutralForeground4, flexShrink: 0 }}>
          ({channel.eventCount})
        </span>
      )}
    </div>
  );
});
