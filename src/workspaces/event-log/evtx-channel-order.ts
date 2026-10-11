/**
 * The order the Event Logs channel pane lists its channels in, and the tree it lists them as
 * (spec 8.6), kept apart from any component so every figure that colors by channel can use it.
 * Pure: no React, no store.
 *
 * This file is also on Phase 14 (#846). If the two branches add it independently, resolve the
 * add/add conflict to this version: it is a superset (the tree helpers the pane renders from, name
 * dedupe, and the text-log helpers below).
 */
import type { EvtxArchiveMember, EvtxRecord } from "./types";

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

/**
 * True for the file name an EVTX archive member carries: `.evtx`, or a rotation `.evtx.N`
 * (`is_evtx_name` in archive.rs, which looks at the part after the last "/").
 */
export function isEvtxMemberName(name: string): boolean {
  const file = name.slice(name.lastIndexOf("/") + 1).toLowerCase();
  if (file.endsWith(".evtx")) return true;
  const at = file.lastIndexOf(".evtx.");
  return at > 0 && /^\d+$/.test(file.slice(at + ".evtx.".length));
}

/** `{archive}::{member}` where the member is not an EVTX file: how an archive labels a text member. */
function isTextMemberLabel(name: string): boolean {
  const at = name.lastIndexOf("::");
  if (at <= 0) return false;
  const member = name.slice(at + 2);
  return member.length > 0 && !isEvtxMemberName(member);
}

/** What the open reported, beyond the records, about which channels are text logs. */
export interface TextLogContext {
  /** The channels the workbench lists (the store's `channels`, by name). */
  channels?: readonly string[];
  /** The archive members the open reported (the store's `archiveMembers`). */
  archiveMembers?: readonly Pick<EvtxArchiveMember, "path" | "kind">[];
}

/**
 * The channels that are really text logs. An archive reader labels a text member (a .log inside a
 * .zip) `{archive}::{member}`, lists it like a channel, and labels its records with that name and
 * `originKind: "log"`. A text log is not an event channel: it has no color index, no level
 * semantics and no place in `orderChannelNames`, so a caller that colors or orders by channel
 * excludes these names before it asks for an order.
 *
 * A channel is a text log when any of these holds, and none of its records is an event:
 * - it has records and every one is `originKind: "log"`;
 * - it is a listed channel named like an archive member the open reported as text;
 * - it is a listed channel named `{archive}::{member}` with a member that is not an EVTX name.
 *
 * The last two catch a member that kept no records (empty, wholly unparseable, or cut to zero
 * lines), which the records alone cannot recognize. Returns the set for all records in one pass;
 * use it in a loop, and `isTextLogChannel` for a single name.
 */
export function textLogChannelNames(
  records: readonly Pick<EvtxRecord, "channel" | "originKind">[],
  context: TextLogContext = {}
): Set<string> {
  const eventChannels = new Set<string>();
  const logChannels = new Set<string>();
  for (const record of records) {
    if (record.originKind === "log") logChannels.add(record.channel);
    else eventChannels.add(record.channel);
  }
  const textMembers = new Set(
    (context.archiveMembers ?? [])
      .filter((member) => member.kind === "text")
      .map((member) => member.path)
  );
  for (const name of context.channels ?? []) {
    if (textMembers.has(name) || isTextMemberLabel(name)) logChannels.add(name);
  }
  for (const name of eventChannels) logChannels.delete(name);
  return logChannels;
}

export function isTextLogChannel(
  name: string,
  records: readonly Pick<EvtxRecord, "channel" | "originKind">[],
  context: Pick<TextLogContext, "archiveMembers"> = {}
): boolean {
  let sawLog = false;
  for (const record of records) {
    if (record.channel !== name) continue;
    if (record.originKind !== "log") return false;
    sawLog = true;
  }
  return (
    sawLog ||
    isTextMemberLabel(name) ||
    (context.archiveMembers ?? []).some((member) => member.kind === "text" && member.path === name)
  );
}
