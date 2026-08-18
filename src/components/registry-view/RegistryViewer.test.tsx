import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RegistryViewer } from "./RegistryViewer";
import { useRegistryStore } from "../../stores/registry-store";
import { useLogStore } from "../../stores/log-store";
import type { RegistryParseResult } from "../../types/registry";

vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: ({ count }: { count: number }) => ({
    getVirtualItems: () =>
      Array.from({ length: count }, (_, index) => ({
        index,
        key: index,
        start: index * 26,
        size: 26,
      })),
    getTotalSize: () => count * 26,
    scrollToIndex: vi.fn(),
  }),
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
});
