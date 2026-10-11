/**
 * Channel names in the order the channel pane displays them (spec 8.6), so a
 * channel's index, and therefore its `channelColor(i)`, is the same in the pane
 * and in the Charts view (spec 6.3: every placement passes the same index).
 *
 * Windows Logs come first in the pane's fixed order, then the Applications and
 * Services tree, depth first, each folder's own channel before its children and
 * siblings sorted by name. The tree is built exactly as `ChannelPicker.tsx`
 * builds it (name split on "/" then "-", single-child chains collapsed).
 *
 * This is a copy of that logic, not an import, because the pane is being
 * rewritten (Phase 8) and adopts this helper then. The test renders the real
 * pane and compares, so a drift in either shows up.
 */

const WINDOWS_LOGS_ORDER = ["Application", "Security", "System", "Setup", "ForwardedEvents"];

interface TreeNode {
  name: string;
  channel: string | null;
  children: Map<string, TreeNode>;
}

function collapseChains(node: TreeNode): void {
  for (const child of node.children.values()) collapseChains(child);
  if (node.children.size === 1 && node.channel === null) {
    const [childName, child] = [...node.children.entries()][0];
    if (child.channel === null || child.children.size > 0) {
      node.name = node.name ? `${node.name}-${childName}` : childName;
      node.channel = child.channel;
      node.children = child.children;
    }
  }
}

function visit(node: TreeNode, out: string[]): void {
  const children = [...node.children.values()].sort((a, b) =>
    a.name.localeCompare(b.name),
  );
  for (const child of children) {
    if (child.channel !== null) out.push(child.channel);
    visit(child, out);
  }
}

export function orderChannelNames(names: readonly string[]): string[] {
  const windowsLogs: string[] = [];
  const root: TreeNode = { name: "", channel: null, children: new Map() };

  for (const name of names) {
    if (WINDOWS_LOGS_ORDER.includes(name)) {
      windowsLogs.push(name);
      continue;
    }
    const slashParts = name.split("/");
    const allParts = [...slashParts[0].split("-"), ...slashParts.slice(1)];
    let node = root;
    for (const part of allParts) {
      let next = node.children.get(part);
      if (!next) {
        next = { name: part, channel: null, children: new Map() };
        node.children.set(part, next);
      }
      node = next;
    }
    node.channel = name;
  }
  collapseChains(root);
  windowsLogs.sort(
    (a, b) => WINDOWS_LOGS_ORDER.indexOf(a) - WINDOWS_LOGS_ORDER.indexOf(b),
  );

  const ordered = [...windowsLogs];
  visit(root, ordered);
  return ordered;
}
