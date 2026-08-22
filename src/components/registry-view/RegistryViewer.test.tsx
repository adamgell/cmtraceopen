import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RegistryViewer } from "./RegistryViewer";
import { useRegistryStore } from "../../stores/registry-store";
import { useLogStore } from "../../stores/log-store";
import type { RegistryParseResult } from "../../types/registry";

type VirtualRange = {
  startIndex: number;
  endIndex: number;
  overscan: number;
};
let capturedRangeExtractor:
  | ((range: VirtualRange) => number[])
  | undefined;

vi.mock("@tanstack/react-virtual", () => ({
  defaultRangeExtractor: ({
    startIndex,
    endIndex,
    overscan,
  }: VirtualRange) =>
    Array.from(
      { length: endIndex - startIndex + 1 + overscan * 2 },
      (_, index) => Math.max(0, startIndex - overscan) + index,
    ),
  useVirtualizer: ({
    count,
    rangeExtractor,
  }: {
    count: number;
    rangeExtractor?: (range: VirtualRange) => number[];
  }) => {
    capturedRangeExtractor = rangeExtractor;
    return {
      getVirtualItems: () =>
        Array.from({ length: count }, (_, index) => ({
          index,
          key: index,
          start: index * 26,
          size: 26,
        })),
      getTotalSize: () => count * 26,
      scrollToIndex: vi.fn(),
    };
  },
}));

const fixture: RegistryParseResult = {
  filePath: "C:/Windows/Temp/secureboot.reg",
  fileSize: 2048,
  totalKeys: 2,
  totalValues: 2,
  parseErrors: 0,
  keys: [
    {
      path: "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot",
      lineNumber: 3,
      isDelete: false,
      values: [
        { name: "AvailableUpdates", kind: "dword", data: "0x2", lineNumber: 4 },
      ],
    },
    {
      path: "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
      lineNumber: 6,
      isDelete: false,
      values: [
        { name: "UEFISecureBootEnabled", kind: "dword", data: "0x1", lineNumber: 7 },
      ],
    },
  ],
};

describe("RegistryViewer", () => {
  beforeEach(() => {
    capturedRangeExtractor = undefined;
    useRegistryStore.getState().clear();
    useLogStore.getState().clear();
    useLogStore.setState({ openFilePath: fixture.filePath });
    useRegistryStore.getState().setRegistryData(fixture);
  });
  afterEach(() => {
    cleanup();
  });

  it("shows key/value counts, tree selection, and Name/Type/Data values", () => {
    render(<RegistryViewer />);
    expect(screen.getByText("Registry Keys")).toBeInTheDocument();
    expect(screen.getByText("2 keys, 2 values")).toBeInTheDocument();
    fireEvent.click(screen.getByText("SecureBoot"));
    expect(screen.getByText("Name")).toBeInTheDocument();
    expect(screen.getByText("Type")).toBeInTheDocument();
    expect(screen.getByText("Data")).toBeInTheDocument();
    expect(screen.getByText("AvailableUpdates")).toBeInTheDocument();
    expect(screen.getByText("0x2")).toBeInTheDocument();
  });

  it("exposes registry keys as a navigable tree", () => {
    render(<RegistryViewer />);

    const tree = screen.getByRole("tree", { name: "Registry keys" });
    const treeItems = screen.getAllByRole("treeitem");
    expect(tree).toBeInTheDocument();
    expect(treeItems.length).toBeGreaterThan(0);
    expect(treeItems[0]).toHaveAttribute("aria-level", "1");

    fireEvent.click(treeItems[0]);
    expect(tree).toHaveAttribute("aria-activedescendant", treeItems[0].id);
  });

  it("selects a primary-pointer row before tree focus initializes a different row", () => {
    render(<RegistryViewer />);

    const tree = screen.getByRole("tree", { name: "Registry keys" });
    const target = screen
      .getByTitle(fixture.keys[1].path)
      .closest('[role="treeitem"]');
    if (!target) throw new Error("Expected the target registry row");

    fireEvent.pointerDown(target, { button: 0 });
    fireEvent.focus(tree);

    expect(target).toHaveAttribute("aria-selected", "true");
    expect(tree).toHaveAttribute("aria-activedescendant", target.id);
  });

  it("does not select a row from a secondary pointer press", () => {
    render(<RegistryViewer />);

    const tree = screen.getByRole("tree", { name: "Registry keys" });
    const rows = screen.getAllByRole("treeitem");
    const target = screen
      .getByTitle(fixture.keys[1].path)
      .closest('[role="treeitem"]');
    if (!target) throw new Error("Expected the target registry row");

    fireEvent.pointerDown(target, { button: 2 });
    fireEvent.focus(tree);

    expect(rows[0]).toHaveAttribute("aria-selected", "true");
    expect(target).toHaveAttribute("aria-selected", "false");
  });

  it("toggles a disclosure without changing the selected row", () => {
    render(<RegistryViewer />);

    const tree = screen.getByRole("tree", { name: "Registry keys" });
    fireEvent.focus(tree);
    const selected = screen.getAllByRole("treeitem")[0];
    const target = screen
      .getByTitle(fixture.keys[0].path)
      .closest('[role="treeitem"]');
    const disclosure = target?.firstElementChild;
    if (!target || !disclosure) {
      throw new Error("Expected the target registry row disclosure");
    }

    fireEvent.pointerDown(disclosure, { button: 0 });
    fireEvent.click(disclosure);

    expect(selected).toHaveAttribute("aria-selected", "true");
    expect(target).toHaveAttribute("aria-selected", "false");
    expect(target).toHaveAttribute("aria-expanded", "false");
  });

  it("cancels disclosure focus before toggling an unselected lower row", () => {
    useLogStore.setState({ openFilePath: null });
    render(<RegistryViewer />);

    const tree = screen.getByRole("tree", { name: "Registry keys" });
    const target = screen
      .getByTitle(fixture.keys[0].path)
      .closest('[role="treeitem"]');
    const disclosure = target?.firstElementChild;
    if (!target || !disclosure) {
      throw new Error("Expected the lower registry row disclosure");
    }

    const pointerDown = new MouseEvent("pointerdown", {
      button: 0,
      bubbles: true,
      cancelable: true,
    });
    fireEvent(disclosure, pointerDown);
    if (!pointerDown.defaultPrevented) {
      fireEvent.focus(tree);
    }
    fireEvent.click(disclosure);

    expect(pointerDown.defaultPrevented).toBe(true);
    expect(useRegistryStore.getState().selectedKeyPath).toBeNull();
    expect(target).toHaveAttribute("aria-expanded", "false");
  });

  it("initializes tree focus and navigates vertically", () => {
    render(<RegistryViewer />);

    const tree = screen.getByRole("tree", { name: "Registry keys" });
    const treeItems = screen.getAllByRole("treeitem");

    fireEvent.focus(tree);
    expect(tree).toHaveAttribute("aria-activedescendant", treeItems[0].id);
    expect(treeItems[0]).toHaveAttribute("aria-selected", "true");

    fireEvent.keyDown(tree, { key: "ArrowDown" });
    expect(tree).toHaveAttribute("aria-activedescendant", treeItems[1].id);

    fireEvent.keyDown(tree, { key: "ArrowUp" });
    expect(tree).toHaveAttribute("aria-activedescendant", treeItems[0].id);
  });

  it("initializes from an arrow key when no row is selected", () => {
    render(<RegistryViewer />);

    const tree = screen.getByRole("tree", { name: "Registry keys" });
    const treeItems = screen.getAllByRole("treeitem");
    fireEvent.keyDown(tree, { key: "ArrowDown" });

    expect(tree).toHaveAttribute("aria-activedescendant", treeItems[0].id);
    expect(treeItems[0]).toHaveAttribute("aria-selected", "true");
  });

  it("moves into the first child with ArrowRight from an expanded parent", () => {
    render(<RegistryViewer />);

    const tree = screen.getByRole("tree", { name: "Registry keys" });
    const treeItems = screen.getAllByRole("treeitem");

    fireEvent.focus(tree);
    fireEvent.keyDown(tree, { key: "ArrowRight" });

    expect(tree).toHaveAttribute("aria-activedescendant", treeItems[1].id);
  });

  it("moves from a collapsed child to its parent with ArrowLeft", () => {
    render(<RegistryViewer />);

    const tree = screen.getByRole("tree", { name: "Registry keys" });

    fireEvent.focus(tree);
    fireEvent.keyDown(tree, { key: "ArrowDown" });
    act(() => {
      useRegistryStore
        .getState()
        .toggleExpanded("HKEY_LOCAL_MACHINE\\SYSTEM");
    });

    const collapsedItems = screen.getAllByRole("treeitem");
    fireEvent.keyDown(tree, { key: "ArrowLeft" });

    expect(tree).toHaveAttribute(
      "aria-activedescendant",
      collapsedItems[0].id,
    );
  });

  it("moves from an expanded-state leaf to its parent with one ArrowLeft press", () => {
    const leafPath = fixture.keys[1].path;
    useRegistryStore.setState((state) => ({
      expandedPaths: new Set([...state.expandedPaths, leafPath]),
      selectedKeyPath: leafPath,
    }));
    expect(useRegistryStore.getState().expandedPaths).toContain(leafPath);
    render(<RegistryViewer />);

    const tree = screen.getByRole("tree", { name: "Registry keys" });
    fireEvent.keyDown(tree, { key: "ArrowLeft" });

    expect(useRegistryStore.getState().selectedKeyPath).toBe(
      "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot",
    );
  });

  it("never expands leaves when registry data loads or search navigation reveals a key", () => {
    const parentPath =
      "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot";
    const leafPath = fixture.keys[1].path;

    expect(useRegistryStore.getState().expandedPaths).toContain(parentPath);
    expect(useRegistryStore.getState().expandedPaths).not.toContain(leafPath);

    act(() => useRegistryStore.getState().expandToPath(leafPath));

    expect(useRegistryStore.getState().expandedPaths).toContain(parentPath);
    expect(useRegistryStore.getState().expandedPaths).not.toContain(leafPath);
    expect(useRegistryStore.getState().selectedKeyPath).toBe(leafPath);
  });

  it("handles Home and End as cancellable first/last-row navigation", () => {
    render(<RegistryViewer />);

    const tree = screen.getByRole("tree", { name: "Registry keys" });
    const rows = screen.getAllByRole("treeitem");
    fireEvent.focus(tree);

    const endEvent = new KeyboardEvent("keydown", {
      key: "End",
      bubbles: true,
      cancelable: true,
    });
    fireEvent(tree, endEvent);
    expect(endEvent.defaultPrevented).toBe(true);
    expect(tree).toHaveAttribute(
      "aria-activedescendant",
      rows[rows.length - 1].id,
    );

    const homeEvent = new KeyboardEvent("keydown", {
      key: "Home",
      bubbles: true,
      cancelable: true,
    });
    fireEvent(tree, homeEvent);
    expect(homeEvent.defaultPrevented).toBe(true);
    expect(tree).toHaveAttribute("aria-activedescendant", rows[0].id);
  });

  it("selects a collapsed ancestor when its selected descendant becomes hidden", () => {
    const ancestorPath = "HKEY_LOCAL_MACHINE\\SYSTEM";
    useRegistryStore.getState().setSelectedKeyPath(fixture.keys[1].path);
    render(<RegistryViewer />);

    act(() => useRegistryStore.getState().toggleExpanded(ancestorPath));

    const ancestor = screen
      .getByTitle(ancestorPath)
      .closest('[role="treeitem"]');
    if (!ancestor) throw new Error("Expected the collapsed ancestor row");
    expect(useRegistryStore.getState().selectedKeyPath).toBe(ancestorPath);
    expect(ancestor).toHaveAttribute("aria-selected", "true");
  });

  it("exposes each visible row's position within its sibling set", () => {
    useRegistryStore.getState().setRegistryData({
      ...fixture,
      totalKeys: 4,
      keys: [
        ...fixture.keys,
        {
          ...fixture.keys[0],
          path: "HKEY_LOCAL_MACHINE\\SOFTWARE",
          values: [],
        },
        {
          ...fixture.keys[0],
          path: "HKEY_CURRENT_USER\\Software",
          values: [],
        },
      ],
    });
    render(<RegistryViewer />);

    const hklm = screen
      .getByTitle("HKEY_LOCAL_MACHINE")
      .closest('[role="treeitem"]');
    const hkcu = screen
      .getByTitle("HKEY_CURRENT_USER")
      .closest('[role="treeitem"]');
    const system = screen
      .getByTitle("HKEY_LOCAL_MACHINE\\SYSTEM")
      .closest('[role="treeitem"]');
    const software = screen
      .getByTitle("HKEY_LOCAL_MACHINE\\SOFTWARE")
      .closest('[role="treeitem"]');

    expect(hklm).toHaveAttribute("aria-posinset", "1");
    expect(hklm).toHaveAttribute("aria-setsize", "2");
    expect(hkcu).toHaveAttribute("aria-posinset", "2");
    expect(hkcu).toHaveAttribute("aria-setsize", "2");
    expect(system).toHaveAttribute("aria-posinset", "1");
    expect(system).toHaveAttribute("aria-setsize", "2");
    expect(software).toHaveAttribute("aria-posinset", "2");
    expect(software).toHaveAttribute("aria-setsize", "2");
  });

  it("keeps a selected registry row in the virtualized range", () => {
    const selectedPath = fixture.keys[1].path;
    useRegistryStore.getState().setSelectedKeyPath(selectedPath);

    render(<RegistryViewer />);

    const rangeExtractor = capturedRangeExtractor;
    if (!rangeExtractor) {
      throw new Error("RegistryViewer test mock did not capture a range extractor");
    }
    expect(rangeExtractor({ startIndex: 0, endIndex: 0, overscan: 0 })).toEqual(
      expect.arrayContaining([0, 5]),
    );
  });
});
