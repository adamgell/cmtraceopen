import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
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
    invoke.mockImplementation(async (name: string, args?: Record<string, unknown>) => {
      if (name === "evtx_enumerate_remote_channels") {
        return [{ name: "Application", eventCount: 0, sourceType: { remote: { machine: "lab-host" } } }];
      }
      if (name === "evtx_query_remote_channels") {
        const { channels, requestId } = args as {
          channels: string[];
          requestId: string;
        };
        queueMicrotask(() => {
          const complete = listeners.get("evtx-record-stream-complete") as
            | ((event: { payload: Record<string, unknown> }) => void)
            | undefined;
          for (const channel of channels) {
            complete?.({
              payload: { channel, requestId, sequenceCount: 0, totalRecords: 0 },
            });
          }
        });
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

  it("resumes persisted remote-target synchronization after a successful enumeration", async () => {
    render(<SourcePicker />);

    const input = document.querySelector<HTMLInputElement>(
      'input[aria-label="Remote computer name"]',
    )!;
    fireEvent.change(input, { target: { value: "lab-host" } });
    const remoteButton = Array.from(document.querySelectorAll("button")).find(
      (button) => button.textContent?.includes("Remote computer"),
    )!;
    fireEvent.click(remoteButton);

    await waitFor(
      () => {
        expect(
          document.querySelector('input[aria-label="Remote computer name"]'),
        ).not.toBeNull();
      },
      { timeout: 3_000 },
    );
    const synchronizedInput = document.querySelector<HTMLInputElement>(
      'input[aria-label="Remote computer name"]',
    )!;
    act(() => {
      useEvtxStore.setState({ remoteMachine: "replacement-host" });
    });

    await waitFor(() => expect(synchronizedInput.value).toBe("replacement-host"));
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

  it("announces asynchronously added coverage gaps as a bounded list", async () => {
    render(<SourcePicker />);

    const status = document.querySelector<HTMLElement>(
      '[role="status"][aria-label="Coverage gaps"]',
    );
    expect(status).not.toBeNull();
    if (!status) return;
    expect(status).toHaveAttribute("aria-live", "polite");
    expect(status.querySelectorAll("li")).toHaveLength(0);

    act(() => {
      useEvtxStore.setState({
        coverageGaps: Array.from(
          { length: 258 },
          (_, index) => `source-${index}: coverage gap ${index}`,
        ),
      });
    });

    await waitFor(() => {
      expect(status.querySelectorAll("li")).toHaveLength(256);
    });
    expect(status).toHaveTextContent("3 additional coverage gaps omitted by display limit.");
    expect(status).not.toHaveTextContent("source-257: coverage gap 257");
  });

  it("renders every coverage gap when the list exactly reaches the display limit", () => {
    useEvtxStore.setState({
      coverageGaps: Array.from(
        { length: 256 },
        (_, index) => `source-${index}: coverage gap ${index}`,
      ),
    });

    render(<SourcePicker />);

    const status = document.querySelector<HTMLElement>(
      '[role="status"][aria-label="Coverage gaps"]',
    );
    expect(status).not.toBeNull();
    expect(status?.querySelectorAll("li")).toHaveLength(256);
    expect(status).toHaveTextContent("source-255: coverage gap 255");
    expect(status).not.toHaveTextContent("omitted by display limit");
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
