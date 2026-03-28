import { create } from "zustand";
import type { RegistryParseResult, RegistryTreeNode } from "../types/registry";
import {
  buildRegistryTree,
  searchRegistryKeys,
} from "../lib/registry-utils";

export interface RegistryState {
  registryData: RegistryParseResult | null;
  tree: RegistryTreeNode[];
  selectedKeyPath: string | null;
  expandedPaths: Set<string>;
  searchQuery: string;
  searchMatches: number[];
  searchCurrentIndex: number;

  setRegistryData: (data: RegistryParseResult | null) => void;
  setSelectedKeyPath: (path: string | null) => void;
  toggleExpanded: (path: string) => void;
  expandToPath: (path: string) => void;
  setSearchQuery: (query: string) => void;
  searchNext: () => void;
  searchPrevious: () => void;
  clear: () => void;
}

export const useRegistryStore = create<RegistryState>((set, get) => ({
  registryData: null,
  tree: [],
  selectedKeyPath: null,
  expandedPaths: new Set<string>(),
  searchQuery: "",
  searchMatches: [],
  searchCurrentIndex: -1,

  setRegistryData: (data) => {
    if (!data) {
      set({ registryData: null, tree: [], selectedKeyPath: null, expandedPaths: new Set(), searchQuery: "", searchMatches: [], searchCurrentIndex: -1 });
      return;
    }
    const tree = buildRegistryTree(data.keys);
    // Auto-expand all nodes
    const expanded = new Set<string>();
    function expandAll(nodes: RegistryTreeNode[]) {
      for (const node of nodes) {
        expanded.add(node.fullPath);
        if (node.children.length > 0) {
          expandAll(node.children);
        }
      }
    }
    expandAll(tree);
    set({ registryData: data, tree, expandedPaths: expanded, selectedKeyPath: null, searchQuery: "", searchMatches: [], searchCurrentIndex: -1 });
  },

  setSelectedKeyPath: (path) => set({ selectedKeyPath: path }),

  toggleExpanded: (path) => {
    const expanded = new Set(get().expandedPaths);
    if (expanded.has(path)) {
      expanded.delete(path);
    } else {
      expanded.add(path);
    }
    set({ expandedPaths: expanded });
  },

  expandToPath: (path) => {
    const expanded = new Set(get().expandedPaths);
    const parts = path.split("\\");
    let current = "";
    for (let i = 0; i < parts.length; i++) {
      current = i === 0 ? parts[i] : current + "\\" + parts[i];
      expanded.add(current);
    }
    set({ expandedPaths: expanded, selectedKeyPath: path });
  },

  setSearchQuery: (query) => {
    const { registryData } = get();
    if (!registryData || !query) {
      set({ searchQuery: query, searchMatches: [], searchCurrentIndex: -1 });
      return;
    }
    const matches = searchRegistryKeys(registryData.keys, query);
    set({ searchQuery: query, searchMatches: matches, searchCurrentIndex: matches.length > 0 ? 0 : -1 });
  },

  searchNext: () => {
    const { searchMatches, searchCurrentIndex } = get();
    if (searchMatches.length === 0) return;
    const next = (searchCurrentIndex + 1) % searchMatches.length;
    set({ searchCurrentIndex: next });
    navigateToMatch(get(), next);
  },

  searchPrevious: () => {
    const { searchMatches, searchCurrentIndex } = get();
    if (searchMatches.length === 0) return;
    const prev = searchCurrentIndex <= 0 ? searchMatches.length - 1 : searchCurrentIndex - 1;
    set({ searchCurrentIndex: prev });
    navigateToMatch(get(), prev);
  },

  clear: () => {
    set({
      registryData: null,
      tree: [],
      selectedKeyPath: null,
      expandedPaths: new Set(),
      searchQuery: "",
      searchMatches: [],
      searchCurrentIndex: -1,
    });
  },
}));

function navigateToMatch(state: RegistryState, matchIndex: number) {
  const keyIdx = state.searchMatches[matchIndex];
  if (keyIdx == null || !state.registryData) return;
  const key = state.registryData.keys[keyIdx];
  if (key) {
    useRegistryStore.getState().expandToPath(key.path);
  }
}

// ---- Module-level cache for tab switching ----

const registryCache = new Map<string, RegistryParseResult>();

export function getCachedRegistry(filePath: string): RegistryParseResult | undefined {
  return registryCache.get(filePath);
}

export function setCachedRegistry(filePath: string, data: RegistryParseResult): void {
  registryCache.set(filePath, data);
  // Cap cache size
  if (registryCache.size > 30) {
    const first = registryCache.keys().next().value;
    if (first !== undefined) registryCache.delete(first);
  }
}

export function clearCachedRegistry(filePath: string): void {
  registryCache.delete(filePath);
}
