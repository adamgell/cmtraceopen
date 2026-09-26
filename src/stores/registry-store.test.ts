import { beforeEach, describe, expect, it } from "vitest";
import type { RegistryParseResult } from "../types/registry";
import { useRegistryStore } from "./registry-store";

function data(paths: string[]): RegistryParseResult {
  return {
    keys: paths.map((path, index) => ({
      path,
      values: [],
      lineNumber: index + 1,
      isDelete: false,
    })),
    filePath: "HKLM.reg",
    fileSize: 1024,
    totalKeys: paths.length,
    totalValues: 0,
    parseErrors: 0,
  };
}

describe("registry store case-insensitive subtrees", () => {
  beforeEach(() => {
    useRegistryStore.getState().clear();
  });

  it("takes the selection with a collapsing subtree that came in mixed case", () => {
    // Registry keys are case-insensitive, so the second key's node hangs from the
    // first key's subtree. Collapsing that subtree has to move the selection back
    // to it rather than leave the selection on a row it just hid.
    useRegistryStore
      .getState()
      .setRegistryData(data(["HKLM\\Software\\A", "hklm\\software\\B"]));

    const parent = useRegistryStore.getState().tree[0].children[0];
    const child = parent.children.find((node) => node.name === "B")!;

    // Loading a file expands every branch, so this toggle is the collapse.
    expect(useRegistryStore.getState().expandedPaths.has(parent.fullPath)).toBe(
      true,
    );
    useRegistryStore.getState().setSelectedKeyPath(child.fullPath);
    useRegistryStore.getState().toggleExpanded(parent.fullPath);

    expect(useRegistryStore.getState().selectedKeyPath).toBe(parent.fullPath);
  });

  it("reveals a search match whose key arrived in another casing", () => {
    useRegistryStore
      .getState()
      .setRegistryData(data(["HKLM\\Software\\A", "hklm\\software\\B"]));

    const parent = useRegistryStore.getState().tree[0].children[0];
    const child = parent.children.find((node) => node.name === "B")!;

    // Loading expands every branch, so collapse first: the reveal has to do
    // the work for the assertion to mean anything.
    useRegistryStore.getState().toggleExpanded(parent.fullPath);
    expect(useRegistryStore.getState().expandedPaths.has(parent.fullPath)).toBe(
      false,
    );

    useRegistryStore.getState().setSearchQuery("B");
    useRegistryStore.getState().searchNext();

    // The file says hklm, the tree says HKLM: the match must still be shown.
    expect(useRegistryStore.getState().selectedKeyPath).toBe(child.fullPath);
    expect(useRegistryStore.getState().expandedPaths.has(parent.fullPath)).toBe(
      true,
    );
  });
});
