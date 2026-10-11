/**
 * The order the Event Logs channel pane lists its channels in, and the tree it lists them as
 * (spec 8.6), kept apart from any component so every figure that colors by channel can use it.
 * Pure: no React, no store.
 */

/** Anything with a channel name; the tree and the order never read more than that. */
export interface NamedChannel {
  name: string;
}

export interface ChannelTreeNode<T extends NamedChannel = NamedChannel> {
  name: string;
  fullPath: string;
  channel: T | null; // leaf node if present
  children: Map<string, ChannelTreeNode<T>>;
}

export interface ChannelTree<T extends NamedChannel = NamedChannel> {
  windowsLogs: T[];
  serviceTree: ChannelTreeNode<T>;
}

const WINDOWS_LOGS = new Set(["Application", "Security", "Setup", "System", "ForwardedEvents"]);
const WINDOWS_LOGS_ORDER = ["Application", "Security", "System", "Setup", "ForwardedEvents"];

export function buildChannelTree<T extends NamedChannel>(channels: readonly T[]): ChannelTree<T> {
  const windowsLogs: T[] = [];
  const root: ChannelTreeNode<T> = { name: "", fullPath: "", channel: null, children: new Map() };

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

function collapseChains<T extends NamedChannel>(node: ChannelTreeNode<T>) {
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

export function countChannelLeaves<T extends NamedChannel>(node: ChannelTreeNode<T>): number {
  if (node.children.size === 0) return node.channel ? 1 : 0;
  let count = node.channel ? 1 : 0;
  for (const child of node.children.values()) {
    count += countChannelLeaves(child);
  }
  return count;
}

export function sortedChannelChildren<T extends NamedChannel>(
  node: ChannelTreeNode<T>
): ChannelTreeNode<T>[] {
  return [...node.children.values()].sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * Channel names in the order the channel pane lists them (spec 6.3 "channel display order"):
 * Windows Logs in Event Viewer order, then the Applications and Services tree depth first with
 * each level sorted by name and a node's own channel ahead of the channels beneath it.
 *
 * A channel's index in the result is the `i` every placement passes to `channelColor(i)`, so the
 * pane, the Table and the charts all draw one channel in one color. The result is a function of the
 * set of names alone: it does not change with the filter text, with which groups are collapsed, or
 * with the order the names arrived in. Pass every channel the workbench lists (the store's
 * `channels`), not only the ones with loaded events, or the indices will not agree with the pane.
 */
export function orderChannelNames(names: readonly string[]): string[] {
  const ordered = new Set<string>();
  const tree = buildChannelTree([...new Set(names)].map((name) => ({ name })));
  for (const channel of tree.windowsLogs) ordered.add(channel.name);
  const walk = (node: ChannelTreeNode) => {
    for (const child of sortedChannelChildren(node)) {
      if (child.channel) ordered.add(child.channel.name);
      walk(child);
    }
  };
  walk(tree.serviceTree);
  return [...ordered];
}
