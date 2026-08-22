import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());
const listeners = vi.hoisted(() => new Map<string, unknown>());

vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn((name: string, handler: unknown) => {
    listeners.set(name, handler);
    return Promise.resolve(() => {});
  }),
}));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

const { SourcePicker } = await import("./SourcePicker");
const { useEvtxStore } = await import("./evtx-store");
const { useUiStore } = await import("../../stores/ui-store");

describe("SourcePicker remote source", () => {
  beforeEach(() => {
    invoke.mockReset();
    useEvtxStore.setState({
      sourceMode: null,
      remoteMachine: null,
      channels: [],
      records: [],
      coverageGaps: [],
      isLoading: false,
      loadError: null,
      loadedChannels: new Set<string>(),
      selectedChannels: new Set<string>(),
    });
    useUiStore.setState({ currentPlatform: "windows" });
    invoke.mockImplementation(async (name: string) => {
      if (name === "evtx_enumerate_remote_channels") {
        return [{ name: "Application", eventCount: 0, sourceType: { remote: { machine: "lab-host" } } }];
      }
      return {
        records: [],
        channels: [{ name: "Application", eventCount: 0, sourceType: { remote: { machine: "lab-host" } } }],
        totalRecords: 0,
        parseErrors: 0,
        errorMessages: [],
      };
    });
  });

  it("offers remote computer selection without username or password inputs", async () => {
    render(<SourcePicker />);

    const input = document.querySelector('input[aria-label="Remote computer name"]');
    expect(input).not.toBeNull();
    expect(document.querySelector('input[type="password"]')).toBeNull();
    expect(document.querySelector('input[aria-label*="username" i]')).toBeNull();

    fireEvent.change(input!, { target: { value: "lab-host" } });
    const remoteButton = Array.from(document.querySelectorAll("button")).find((button) =>
      button.textContent?.includes("Remote computer")
    );
    expect(remoteButton).not.toBeUndefined();
    fireEvent.click(remoteButton!);

    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("evtx_enumerate_remote_channels", { machine: "lab-host" })
    );
    expect(invoke).toHaveBeenCalledWith(
      "evtx_query_remote_channels",
      expect.objectContaining({ machine: "lab-host", channels: ["Application"] })
    );
  });

  it("restores the remote target from the store after remount", () => {
    useEvtxStore.setState({ remoteMachine: "lab-host" });

    render(<SourcePicker />);

    expect(document.querySelector<HTMLInputElement>('input[aria-label="Remote computer name"]')?.value).toBe(
      "lab-host"
    );
  });

  it("keeps an edited target when persisted remote state changes after failure", async () => {
    useEvtxStore.setState({ remoteMachine: "old-host" });
    render(<SourcePicker />);

    const input = document.querySelector<HTMLInputElement>('input[aria-label="Remote computer name"]');
    fireEvent.change(input!, { target: { value: "new-host" } });
    useEvtxStore.setState({ remoteMachine: "failed-host" });
    await waitFor(() => expect(input?.value).toBe("new-host"));
  });

  it("shows channel coverage gaps alongside the source error", () => {
    useEvtxStore.setState({
      loadError: "lab-host: remote source access denied",
      coverageGaps: ["lab-host/Security: not read (access denied)"],
    });

    render(<SourcePicker />);

    expect(document.body.textContent).toContain("remote source access denied");
    expect(document.body.textContent).toContain("Security: not read (access denied)");
  });

  it("announces a source error while the empty picker remains visible", () => {
    const message =
      "No .evtx files were found. Source diagnostics: C:/protected/Security.evtx: Access is denied";
    useEvtxStore.setState({ loadError: message });

    render(<SourcePicker />);

    expect(screen.getByText(message)).toHaveAttribute("role", "alert");
    expect(screen.getByText("Open .evtx files...")).toBeInTheDocument();
  });

  it("keeps classified coverage visible when a remote query also fails", async () => {
    invoke.mockImplementation(async (name: string) => {
      if (name === "evtx_enumerate_remote_channels") {
        return [
          { name: "Application", eventCount: 1, sourceType: { remote: { machine: "lab-host" } } },
        ];
      }
      throw new Error("access denied");
    });

    render(<SourcePicker />);
    const input = document.querySelector('input[aria-label="Remote computer name"]');
    fireEvent.change(input!, { target: { value: "lab-host" } });
    const remoteButton = Array.from(document.querySelectorAll("button")).find((button) =>
      button.textContent?.includes("Remote computer")
    );
    fireEvent.click(remoteButton!);

    await waitFor(() => {
      expect(document.body.textContent).toContain("lab-host/Application: access denied");
      expect(document.body.textContent).toContain("lab-host/Application: not read (access denied)");
    });
  });
});
