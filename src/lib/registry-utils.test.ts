import { describe, expect, it } from "vitest";
import { buildRegistryTree } from "./registry-utils";

const K = (path: string) => ({ path, name: "v", kind: "String", value: "x" }) as never;

function allPaths(nodes: ReturnType<typeof buildRegistryTree>): string[] {
  return nodes.flatMap((n) => [n.fullPath, ...allPaths(n.children)]);
}

describe("buildRegistryTree", () => {
  it("builds nested nodes with synthetic intermediates", () => {
    const tree = buildRegistryTree([K("HKLM\\SOFTWARE\\A"), K("HKLM\\SOFTWARE\\B")]);
    const paths = allPaths(tree);
    expect(paths).toContain("HKLM\\SOFTWARE\\A");
    expect(paths).toContain("HKLM\\SOFTWARE\\B");
    expect(paths).toContain("HKLM\\SOFTWARE");
    expect(tree[0].children.find((c) => c.name === "SOFTWARE")?.keyIndex).toBeNull();
  });

  it("keeps one node when a key is listed twice", () => {
    const tree = buildRegistryTree([K("HKLM\\A"), K("HKLM\\A")]);
    expect(allPaths(tree).filter((p) => p === "HKLM\\A").length).toBe(1);
  });

  it("records the flat key index on real keys", () => {
    const tree = buildRegistryTree([K("HKLM\\A"), K("HKLM\\B")]);
    expect(tree[0].children.find((c) => c.name === "B")?.keyIndex).toBe(1);
  });

  it("merges keys that differ only in case, since registry keys are case-insensitive", () => {
    // Before this, HKLM\SOFTWARE and hklm\SOFTWARE produced two independent trees.
    const tree = buildRegistryTree([K("HKLM\\SOFTWARE\\A"), K("hklm\\SOFTWARE\\a")]);
    const paths = allPaths(tree);

    expect(tree.length).toBe(1);
    expect(paths.filter((p) => p.toLowerCase() === "hklm\\software\\a").length).toBe(1);
    expect(paths.filter((p) => p.toLowerCase() === "hklm").length).toBe(1);
  });

  it("adopts the displayed casing of the parent a key attaches to", () => {
    // The second key arrives with different casing, so it merges into the first
    // key's subtree. A node that keeps its own raw casing does not prefix-match
    // the parent it hangs from, which strands whatever checks that.
    const tree = buildRegistryTree([K("HKLM\\Software\\A"), K("hklm\\software\\B")]);
    const paths = allPaths(tree);

    expect(paths).toContain("HKLM\\Software\\B");
    expect(paths).not.toContain("hklm\\software\\B");

    const parent = tree[0].children[0];
    const child = parent.children.find((c) => c.name === "B")!;
    const parentPrefix = parent.fullPath + "\\";
    expect(child.fullPath.startsWith(parentPrefix)).toBe(true);
  });

  it("displays the first-seen casing rather than imposing lowercase", () => {
    const tree = buildRegistryTree([K("HKLM\\Software\\A"), K("hklm\\software\\a")]);
    expect(allPaths(tree)).toContain("HKLM\\Software\\A");
  });
});
