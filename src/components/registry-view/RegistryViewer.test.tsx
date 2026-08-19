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
