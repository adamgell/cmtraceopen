import type {
  RegistryKey,
  RegistryTreeNode,
  RegistryValueKind,
} from "../types/registry";

/**
 * Build a tree structure from flat registry key paths.
 */
export function buildRegistryTree(keys: RegistryKey[]): RegistryTreeNode[] {
  const roots: RegistryTreeNode[] = [];
  const nodeMap = new Map<string, RegistryTreeNode>();

  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    const parts = key.path.split("\\");
    let currentPath = "";

    for (let j = 0; j < parts.length; j++) {
      const parentPath = currentPath;
      currentPath = j === 0 ? parts[j] : currentPath + "\\" + parts[j];

      if (nodeMap.has(currentPath)) {
        // Node already exists — update keyIndex if this is the exact key
        if (j === parts.length - 1) {
          nodeMap.get(currentPath)!.keyIndex = i;
        }
        continue;
      }

      const node: RegistryTreeNode = {
        name: parts[j],
        fullPath: currentPath,
        children: [],
        keyIndex: j === parts.length - 1 ? i : null,
      };
      nodeMap.set(currentPath, node);

      if (j === 0) {
        roots.push(node);
      } else {
        const parent = nodeMap.get(parentPath);
        if (parent) {
          parent.children.push(node);
        }
      }
    }
  }

  return roots;
}

export interface FlatTreeRow {
  node: RegistryTreeNode;
  depth: number;
}

/**
 * Flatten the tree into a list of visible rows based on expanded state.
 */
export function flattenVisibleTree(
  roots: RegistryTreeNode[],
  expandedPaths: Set<string>
): FlatTreeRow[] {
  const rows: FlatTreeRow[] = [];

  function walk(nodes: RegistryTreeNode[], depth: number) {
    for (const node of nodes) {
      rows.push({ node, depth });
      if (node.children.length > 0 && expandedPaths.has(node.fullPath)) {
        walk(node.children, depth + 1);
      }
    }
  }

  walk(roots, 0);
  return rows;
}

const VALUE_TYPE_LABELS: Record<RegistryValueKind, string> = {
  string: "REG_SZ",
  dword: "REG_DWORD",
  qword: "REG_QWORD",
  binary: "REG_BINARY",
  expandString: "REG_EXPAND_SZ",
  multiString: "REG_MULTI_SZ",
  none: "REG_NONE",
  deleteMarker: "(deleted)",
};

export function getValueTypeLabel(kind: RegistryValueKind): string {
  return VALUE_TYPE_LABELS[kind] ?? kind;
}

/**
 * Search registry keys and values for a query string.
 * Returns indices into the keys array that match.
 */
export function searchRegistryKeys(
  keys: RegistryKey[],
  query: string
): number[] {
  if (!query) return [];
  const lower = query.toLowerCase();
  const matches: number[] = [];

  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    if (key.path.toLowerCase().includes(lower)) {
      matches.push(i);
      continue;
    }
    const valueMatch = key.values.some(
      (v) =>
        v.name.toLowerCase().includes(lower) ||
        v.data.toLowerCase().includes(lower)
    );
    if (valueMatch) {
      matches.push(i);
    }
  }

  return matches;
}
