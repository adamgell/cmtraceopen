import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { tokens } from "@fluentui/react-components";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(() => Promise.resolve(() => {})),
}));

import {
  EvtxCoverageBanner,
  MAX_COVERAGE_NOTES,
  accessDeniedChannels,
  pickCoverageNoteColors,
} from "./EvtxCoverageBanner";
import { useEvtxStore } from "./evtx-store";
import { useEvtxLayoutStore } from "./evtx-layout-store";
import { resolveToken } from "./evtx-visual-tokens";
import { RestartAsAdministratorDialog } from "../../components/dialogs/RestartAsAdministratorDialog";
import { contrastRatio } from "../../lib/color-contrast";
import { resetElevationCoordinatorForTests } from "../../lib/elevation";
import { getAllThemes } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
import type { AppElevationState } from "../../types/elevation";
import type { EventLogSourceManifest, EvtxCoverageGap } from "./types";

/**
 * Gaps in the backend's real shapes. A live channel the Event Log service refuses arrives as
 * `absorb_scan` builds it (src-tauri/src/event_log/commands.rs): source = the channel, the reason
 * with the "{channel}: " prefix stripped. Its kind is `accessDenied` once #931 lands; the reason
 * text is `describe_query_status` in live.rs.
 */
const LIVE_REFUSAL_5 =
  "the Event Log service refused the channel query (Windows error 5: Access is denied)";
const LIVE_REFUSAL_1314 =
  "the Event Log service refused the channel query (Windows error 1314: A required privilege is not held by the client)";

function liveDenied(channel: string, reason = LIVE_REFUSAL_5): EvtxCoverageGap {
  return { source: channel, kind: "accessDenied", reason };
}

/** Files mode: `SourceCoverage::AccessDenied` from manifest expansion (parser.rs), mirrored twice. */
const FILE_PATH = "C:\\Fixture\\EventLogs\\Security.evtx";
const FILE_REASON = "source metadata access was denied";
const FILE_MANIFEST: EventLogSourceManifest = {
  entries: [],
  coverage: [{ kind: "accessDenied", path: FILE_PATH, reason: FILE_REASON }],
};

const OFFERABLE: AppElevationState = { platformSupported: true, isElevated: false };
const ELEVATED: AppElevationState = { platformSupported: true, isElevated: true };
const NOT_WINDOWS: AppElevationState = {
  platformSupported: false,
  isElevated: false,
  detail: "Restarting as administrator is only supported on Windows",
};

function answerElevation(state: AppElevationState | Error): void {
  invoke.mockImplementation((command: string) => {
    if (command !== "get_app_elevation_state") {
      return Promise.reject(new Error(`unexpected command ${command}`));
    }
    return state instanceof Error ? Promise.reject(state) : Promise.resolve(state);
  });
}

function elevationProbes(): number {
  return invoke.mock.calls.filter(([command]) => command === "get_app_elevation_state").length;
}

/** Renders and lets the elevation probe answer. */
async function renderRail(): Promise<void> {
  render(<EvtxCoverageBanner variant="rail" />);
  await act(async () => {
    await Promise.resolve();
  });
}

function notes(): HTMLElement[] {
  return Array.from(document.querySelectorAll<HTMLElement>("[data-coverage-note]"));
}

beforeEach(() => {
  invoke.mockReset();
  resetElevationCoordinatorForTests();
  useEvtxStore.setState({
    coverageGaps: [],
    coverageDetails: [],
    tailCoverageGaps: [],
    archiveMembers: [],
    sourceManifest: null,
  });
  useUiStore.getState().setElevationPrompt(null);
  useUiStore.setState({ themeId: "light", logListFontSize: 13 });
});

afterEach(cleanup);

describe("EvtxCoverageBanner grid variant", () => {
  beforeEach(() => {
    useEvtxLayoutStore.setState({ panels: { channels: true, insights: false, dock: false } });
  });

  it("renders every archive member decision, including duplicate paths", () => {
    const member = {
      path: "bundle.zip::logs/Application.evtx",
      kind: "evtx" as const,
      sha256: "abc123",
      outcome: "duplicate" as const,
    };
    useEvtxStore.setState({ archiveMembers: [member, { ...member }] });

    render(<EvtxCoverageBanner />);

    expect(screen.getByText("2 archive members in this view")).toBeInTheDocument();
    expect(screen.getByText("Archive member provenance (2)")).toBeInTheDocument();
    expect(
      screen.getAllByText(
        "bundle.zip::logs/Application.evtx: evtx duplicate (sha256:abc123)"
      )
    ).toHaveLength(2);
  });

  it("reports the full archive count when member messages reach the display limit", () => {
    useEvtxStore.setState({
      archiveMembers: Array.from({ length: 4_098 }, (_, index) => ({
        path: `bundle.zip::logs/member-${index}.evtx`,
        kind: "evtx" as const,
        outcome: "parsed" as const,
      })),
    });

    render(<EvtxCoverageBanner />);

    expect(screen.getByText("4098 archive members in this view")).toBeInTheDocument();
    expect(screen.getByText("Archive member provenance (4098)")).toBeInTheDocument();
    expect(
      screen.getByText("<archive member metadata: 2 omitted by display limit>"),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("bundle.zip::logs/member-4096.evtx: evtx parsed"),
    ).not.toBeInTheDocument();
  });

  it("bounds rendered coverage gaps and reports the omitted count", () => {
    useEvtxStore.setState({
      coverageGaps: Array.from(
        { length: 258 },
        (_, index) => `source-${index}: coverage gap ${index}`,
      ),
    });

    render(<EvtxCoverageBanner />);

    expect(screen.getByText("258 gaps in this view")).toBeInTheDocument();
    expect(screen.getAllByRole("listitem")).toHaveLength(100);
    expect(screen.getByText("source-99: coverage gap 99")).toBeInTheDocument();
    expect(
      screen.getByText("<coverage gaps: 158 omitted by display limit>"),
    ).toBeInTheDocument();
    expect(screen.queryByText("source-257: coverage gap 257")).not.toBeInTheDocument();
  });
});

describe("EvtxCoverageBanner grid variant follows the Insights rail", () => {
  // Nothing else in this stack discloses a gap with the rail off (the channel pane and the status
  // bar carry no coverage state yet), so the grid banner is what keeps a partial load from reading
  // as whole there.
  beforeEach(() => {
    useEvtxStore.setState({ coverageDetails: [liveDenied("Security")] });
  });

  it("lists every gap above the grid while the rail is hidden", () => {
    useEvtxLayoutStore.setState({ panels: { channels: true, insights: false, dock: false } });
    render(<EvtxCoverageBanner />);
    expect(screen.getByText("1 gap in this view")).toBeInTheDocument();
    expect(screen.getByText(`Security: ${LIVE_REFUSAL_5}`)).toBeInTheDocument();
  });

  it("leaves the gaps to the rail while it is shown", () => {
    useEvtxLayoutStore.setState({ panels: { channels: true, insights: true, dock: false } });
    const { container } = render(<EvtxCoverageBanner />);
    expect(container).toBeEmptyDOMElement();
  });

  it("comes back when the rail is hidden again", () => {
    useEvtxLayoutStore.setState({ panels: { channels: true, insights: true, dock: false } });
    render(<EvtxCoverageBanner />);
    expect(screen.queryByText("1 gap in this view")).toBeNull();
    act(() => useEvtxLayoutStore.getState().togglePanel("insights"));
    expect(screen.getByText("1 gap in this view")).toBeInTheDocument();
  });

  it("stays while the rail is shown when the diagnosis that feeds its disclosure failed", () => {
    useEvtxLayoutStore.setState({ panels: { channels: true, insights: true, dock: false } });
    render(<EvtxCoverageBanner diagnosisFailed />);
    expect(screen.getByText("1 gap in this view")).toBeInTheDocument();
  });
});

describe("accessDeniedChannels", () => {
  it("keys on the accessDenied kind only, in first-reported order, each source once", () => {
    expect(
      accessDeniedChannels(
        [
          liveDenied("Security"),
          { source: "Application", kind: "missing", reason: "channel not found" },
          liveDenied("System", LIVE_REFUSAL_1314),
          liveDenied("Security", LIVE_REFUSAL_1314),
        ],
        [],
      ),
    ).toEqual(["Security", "System"]);
  });

  it("merges the parser's gap and the manifest's coverage row for the same file into one", () => {
    expect(
      accessDeniedChannels(
        [{ source: FILE_PATH, kind: "accessDenied", reason: FILE_REASON }],
        FILE_MANIFEST.coverage,
      ),
    ).toEqual([FILE_PATH]);
  });

  it("does not read the refusal wording: a record gap carrying it is not a note (#931)", () => {
    // Today's live shape for an unelevated Security read. The note waits for #931 to file it as
    // accessDenied; no phrase matching stands in.
    expect(
      accessDeniedChannels(
        [
          { source: "Security", kind: "record", reason: LIVE_REFUSAL_5 },
          { source: "System", kind: "record", reason: LIVE_REFUSAL_1314 },
        ],
        [],
      ),
    ).toEqual([]);
  });
});

describe("EvtxCoverageBanner rail variant (coverage note)", () => {
  it("shows the spec sentence, a decorative lock icon and an Elevate action named for the channel", async () => {
    answerElevation(OFFERABLE);
    useEvtxStore.setState({ coverageDetails: [liveDenied("Security")] });

    await renderRail();

    const [note] = notes();
    expect(note).toBeDefined();
    expect(note).toHaveTextContent(
      "Security channel not read. Findings may be incomplete.Elevate",
    );
    const icon = note.querySelector("svg");
    expect(icon).toHaveAttribute("aria-hidden", "true");
    const action = within(note).getByRole("button", { name: "Elevate to read Security" });
    expect(action.tagName).toBe("BUTTON");
    expect(action).toHaveTextContent(/^Elevate$/);
  });

  it("is not a live region", async () => {
    answerElevation(OFFERABLE);
    useEvtxStore.setState({ coverageDetails: [liveDenied("Security")] });

    await renderRail();

    const [note] = notes();
    expect(
      note.closest('[aria-live], [role="status"], [role="alert"], [role="log"]'),
    ).toBeNull();
    expect(note.querySelector('[aria-live], [role="status"], [role="alert"]')).toBeNull();
  });

  it("opens the shared RestartAsAdministratorDialog with a workspace-only coverage request", async () => {
    answerElevation(OFFERABLE);
    useEvtxStore.setState({ coverageDetails: [liveDenied("Security")] });
    render(<RestartAsAdministratorDialog />);

    await renderRail();
    expect(screen.queryByRole("dialog")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Elevate to read Security" }));

    expect(useUiStore.getState().elevationPrompt).toEqual({
      request: { reason: "coverageRecommended", workspace: "event-log", target: { kind: "workspace" } },
    });
    const dialog = screen.getByRole("dialog", { name: "Restart as administrator?" });
    expect(dialog).toHaveTextContent("returning to the current workspace");
    // Only the confirmation opens; the relaunch command waits for its second click.
    expect(invoke.mock.calls.map(([command]) => command)).toEqual(["get_app_elevation_state"]);
  });

  it("never replaces a confirmation already on screen", async () => {
    answerElevation(OFFERABLE);
    useEvtxStore.setState({ coverageDetails: [liveDenied("Security")] });
    const existing = {
      request: {
        reason: "accessDenied" as const,
        workspace: "log" as const,
        target: { kind: "file" as const, path: "C:\\Logs\\app.log" },
      },
    };
    useUiStore.getState().setElevationPrompt(existing);

    await renderRail();
    fireEvent.click(screen.getByRole("button", { name: "Elevate to read Security" }));

    expect(useUiStore.getState().elevationPrompt).toBe(existing);
  });

  it("is hidden when the app is already elevated", async () => {
    answerElevation(ELEVATED);
    useEvtxStore.setState({ coverageDetails: [liveDenied("Security")] });

    await renderRail();

    expect(elevationProbes()).toBe(1);
    expect(notes()).toHaveLength(0);
    expect(screen.queryByText(/channel not read/)).toBeNull();
  });

  it("is hidden when not on Windows", async () => {
    answerElevation(NOT_WINDOWS);
    useEvtxStore.setState({ coverageDetails: [liveDenied("Security")] });

    await renderRail();

    expect(elevationProbes()).toBe(1);
    expect(notes()).toHaveLength(0);
  });

  it("is hidden when the elevation state cannot be read", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    answerElevation(new Error("ipc unavailable"));
    useEvtxStore.setState({ coverageDetails: [liveDenied("Security")] });

    await renderRail();

    expect(notes()).toHaveLength(0);
    warn.mockRestore();
  });

  it("leaves every other gap kind to the coverage disclosure, without probing elevation", async () => {
    answerElevation(OFFERABLE);
    useEvtxStore.setState({
      coverageDetails: [
        { source: "Security", kind: "record", reason: LIVE_REFUSAL_5 },
        { source: "Application", kind: "missing", reason: "channel not found" },
        { source: "System", kind: "limitReached", reason: "reader stopped at 10000 events" },
        { source: "Setup", kind: "cancelled", reason: "operator stopped the load" },
        { source: "C:\\x.evtx", kind: "chunk", reason: "chunk 3 rejected", chunkId: 3 },
      ],
      sourceManifest: {
        entries: [],
        coverage: [
          { kind: "empty", path: "C:\\empty.evtx", reason: "no records" },
          { kind: "unsupported", path: "C:\\y.bin", reason: "not an event log" },
        ],
      },
      coverageGaps: [`Security: ${LIVE_REFUSAL_5}`],
      tailCoverageGaps: ["Security: live tail access denied"],
    });

    const { container } = render(<EvtxCoverageBanner variant="rail" />);
    await act(async () => {
      await Promise.resolve();
    });

    expect(container).toBeEmptyDOMElement();
    expect(elevationProbes()).toBe(0);
  });

  it("shows one note per channel, each with its own exact sentence and action", async () => {
    answerElevation(OFFERABLE);
    useEvtxStore.setState({
      coverageDetails: [
        liveDenied("Security"),
        liveDenied("CONTOSO-PC01/Microsoft-Windows-Sysmon/Operational", LIVE_REFUSAL_1314),
      ],
    });

    await renderRail();

    expect(notes().map((note) => note.dataset.coverageNote)).toEqual([
      "Security",
      "CONTOSO-PC01/Microsoft-Windows-Sysmon/Operational",
    ]);
    expect(
      screen.getByText("Security channel not read. Findings may be incomplete."),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "CONTOSO-PC01/Microsoft-Windows-Sysmon/Operational channel not read. Findings may be incomplete.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", {
        name: "Elevate to read CONTOSO-PC01/Microsoft-Windows-Sysmon/Operational",
      }),
    ).toBeInTheDocument();
  });

  it("names a files-mode source by its path, once, though the parser and the manifest both report it", async () => {
    answerElevation(OFFERABLE);
    useEvtxStore.setState({
      coverageDetails: [{ source: FILE_PATH, kind: "accessDenied", reason: FILE_REASON }],
      sourceManifest: FILE_MANIFEST,
    });

    await renderRail();

    expect(notes()).toHaveLength(1);
    expect(
      screen.getByText(`${FILE_PATH} channel not read. Findings may be incomplete.`),
    ).toBeInTheDocument();
  });

  it(`bounds the notes at ${MAX_COVERAGE_NOTES} and counts the rest`, async () => {
    answerElevation(OFFERABLE);
    useEvtxStore.setState({
      coverageDetails: ["Security", "System", "Setup", "Sysmon", "LAPS"].map((channel) =>
        liveDenied(channel),
      ),
    });

    await renderRail();

    expect(notes().map((note) => note.dataset.coverageNote)).toEqual([
      "Security",
      "System",
      "Setup",
    ]);
    expect(screen.getByText("+2 more channels not read")).toBeInTheDocument();

    act(() =>
      useEvtxStore.setState({
        coverageDetails: ["Security", "System", "Setup", "Sysmon"].map((channel) =>
          liveDenied(channel),
        ),
      }),
    );
    expect(screen.getByText("+1 more channel not read")).toBeInTheDocument();
  });

  it("sizes its text from logListFontSize", async () => {
    answerElevation(OFFERABLE);
    useEvtxStore.setState({ coverageDetails: [liveDenied("Security")] });
    useUiStore.setState({ logListFontSize: 18 });

    await renderRail();

    // f - 2, the rail body size (spec 7.1).
    const wrapper = notes()[0].parentElement?.parentElement;
    expect(wrapper).toHaveStyle({ fontSize: "16px" });
  });

  it("keeps the archive member provenance reachable, collapsed, beside the notes", async () => {
    useEvtxStore.setState({
      archiveMembers: [
        { path: "bundle.zip::logs/Application.evtx", kind: "evtx", outcome: "parsed" },
      ],
    });

    await renderRail();

    const summary = screen.getByText("Archive member provenance (1)");
    expect(summary.closest("details")).not.toHaveAttribute("open");
    expect(screen.getByText("bundle.zip::logs/Application.evtx: evtx parsed")).toBeInTheDocument();
    expect(elevationProbes()).toBe(0);
  });
});

describe("coverage note contrast on colorNeutralBackground4", () => {
  const FLOOR = 4.5;

  it("covers all seven themes", () => {
    expect(getAllThemes()).toHaveLength(7);
  });

  it.each(getAllThemes().map((theme) => [theme.id, theme] as const))(
    "%s: the sentence, the lock icon and the Elevate action reach 4.5:1 on the note",
    (_id, theme) => {
      const colors = pickCoverageNoteColors(theme);
      expect(colors.background).toBe(tokens.colorNeutralBackground4);
      const surface = resolveToken(colors.background, theme);
      for (const [name, color] of Object.entries({ text: colors.text, action: colors.action })) {
        expect(
          contrastRatio(resolveToken(color, theme), surface),
          `${theme.id} ${name} on ${surface}`,
        ).toBeGreaterThanOrEqual(FLOOR);
      }
    },
  );

  it("keeps the designed tokens wherever they pass and falls back to black or white only where they miss", () => {
    const byId = (id: string) =>
      pickCoverageNoteColors(getAllThemes().find((theme) => theme.id === id)!);
    // Measured on Background4. Foreground2: solarized-dark 4.36 (white instead: 11.66).
    // colorBrandForegroundLink: nord 4.12 (white instead: 7.38), dracula 4.35 (white: 9.15).
    expect(byId("solarized-dark")).toEqual({
      background: tokens.colorNeutralBackground4,
      text: "#ffffff",
      action: tokens.colorBrandForegroundLink,
    });
    expect(byId("nord")).toEqual({
      background: tokens.colorNeutralBackground4,
      text: tokens.colorNeutralForeground2,
      action: "#ffffff",
    });
    expect(byId("dracula")).toEqual({
      background: tokens.colorNeutralBackground4,
      text: tokens.colorNeutralForeground2,
      action: "#ffffff",
    });
    for (const id of ["light", "dark", "high-contrast", "classic-cmtrace"]) {
      expect(byId(id)).toEqual({
        background: tokens.colorNeutralBackground4,
        text: tokens.colorNeutralForeground2,
        action: tokens.colorBrandForegroundLink,
      });
    }
  });

  it("draws the note with the picked colors", async () => {
    answerElevation(OFFERABLE);
    useEvtxStore.setState({ coverageDetails: [liveDenied("Security")] });
    useUiStore.setState({ themeId: "solarized-dark" });

    await renderRail();

    const [note] = notes();
    expect(note).toHaveStyle({ color: "#ffffff" });
    expect(note.style.backgroundColor).toBe(tokens.colorNeutralBackground4);
    expect(within(note).getByRole("button").style.color).toBe(tokens.colorBrandForegroundLink);
  });
});
