import { describe, expect, it, vi, beforeEach } from "vitest";
import type { LogEntry } from "../types/log";

const menuItemNew = vi.hoisted(
  () => vi.fn(async (opts: { id: string; text: string; action?: () => void }) => opts),
);
const predefinedNew = vi.hoisted(() => vi.fn(async (opts: { item: string }) => opts));
const menuNew = vi.hoisted(() =>
  vi.fn(async ({ items }: { items: unknown[] }) => ({
    items,
    popup: vi.fn(async () => undefined),
  })),
);

vi.mock("@tauri-apps/api/menu", () => ({
  MenuItem: { new: menuItemNew },
  PredefinedMenuItem: { new: predefinedNew },
  Menu: { new: menuNew },
}));

const writeText = vi.hoisted(() => vi.fn(async (_text: string) => undefined));

vi.mock("@tauri-apps/plugin-clipboard-manager", () => ({
  writeText,
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

import { useContextMenu } from "./use-context-menu";
import { renderHook } from "@testing-library/react";
import { useFilterStore } from "../stores/filter-store";
import { useMarkerStore } from "../stores/marker-store";

function entry(overrides: Partial<LogEntry> = {}): LogEntry {
  return {
    id: 4,
    lineNumber: 40,
    message: "Install failed 0x80070005 for app Contoso VPN",
    component: "AppEnforce",
    timestamp: Date.parse("2026-07-26T12:00:03Z"),
    timestampDisplay: "2026-07-26 12:00:03.000",
    severity: "Error",
    thread: 1004,
    threadDisplay: "1004",
    sourceFile: "appexecmgr.cpp",
    format: "Ccm",
    filePath: "C:/Windows/CCM/Logs/AppEnforce.log",
    timezoneOffset: null,
    errorCodeSpans: [
      {
        start: 15,
        end: 25,
        codeHex: "0x80070005",
        codeDecimal: "2147942405",
        description: "Access is denied.",
        category: "Win32",
      },
    ],
    ...overrides,
  };
}

describe("useContextMenu", () => {
  beforeEach(() => {
    menuItemNew.mockClear();
    predefinedNew.mockClear();
    menuNew.mockClear();
    writeText.mockClear();
    useFilterStore.getState().clearFilter();
    useMarkerStore.setState({
      markersByFile: new Map(),
      categories: [
        { id: "bug", label: "Bug", color: "#ef4444" },
        { id: "investigate", label: "Investigate", color: "#60a5fa" },
        { id: "confirmed", label: "Confirmed", color: "#4ade80" },
      ],
    });
  });

  it("builds copy, filter, jump, marker, error lookup, and reveal items", async () => {
    const { result } = renderHook(() => useContextMenu());
    await result.current.showContextMenu(entry(), {
      preventDefault: vi.fn(),
    } as unknown as React.MouseEvent);

    const labels = menuItemNew.mock.calls.map((call) => call[0].text);
    expect(labels).toEqual(
      expect.arrayContaining([
        "Copy Line",
        "Copy Message",
        "Copy Timestamp",
        "Jump to Line…",
        "Mark as Bug",
        "Mark as Investigate",
        "Mark as Confirmed",
        "Error Lookup: 0x80070005",
        "Open Source File",
      ]),
    );
    expect(labels.some((label) => label.startsWith("Include:"))).toBe(true);
    expect(labels.some((label) => label.startsWith("Exclude:"))).toBe(true);
    expect(menuNew).toHaveBeenCalled();
  });

  it("runs copy and include-filter actions for the selected entry", async () => {
    const selectedEntry = entry();
    const { result } = renderHook(() => useContextMenu());
    await result.current.showContextMenu(selectedEntry, {
      preventDefault: vi.fn(),
    } as unknown as React.MouseEvent);

    const copyMessage = menuItemNew.mock.calls.find(
      ([opts]) => opts.id === "copy-message",
    )?.[0];
    const includeFilter = menuItemNew.mock.calls.find(
      ([opts]) => opts.id === "include-filter",
    )?.[0];

    expect(copyMessage?.action).toBeTypeOf("function");
    expect(includeFilter?.action).toBeTypeOf("function");

    copyMessage?.action?.();
    expect(writeText).toHaveBeenCalledWith(selectedEntry.message);

    includeFilter?.action?.();
    expect(useFilterStore.getState().clauses).toEqual([
      { field: "Message", value: selectedEntry.message, op: "Contains" },
    ]);
  });
});
