import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { useState, type ReactNode } from "react";
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
  accessDeniedSources,
  coverageNoteSubject,
  pickCoverageNoteColors,
} from "./EvtxCoverageBanner";
import { CoverageClaimsProvider, useCoverageClaim } from "./evtx-coverage-claims";
import { formatCoverageGap } from "./evtx-coverage";
import { useEvtxStore } from "./evtx-store";
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
 * `absorb_scan` builds it (src-tauri/src/event_log/commands.rs): source = the channel, or
 * `machine/channel` for a remote read, with the reason's "{source}: " prefix stripped. Its kind is
 * `accessDenied` once #931 lands; the reason text is `describe_query_status` in live.rs.
 */
const LIVE_REFUSAL_5 =
  "the Event Log service refused the channel query (Windows error 5: Access is denied)";
const LIVE_REFUSAL_1314 =
  "the Event Log service refused the channel query (Windows error 1314: A required privilege is not held by the client)";
const REMOTE_MACHINE = "CONTOSO-PC01";

function liveDenied(source: string, reason = LIVE_REFUSAL_5): EvtxCoverageGap {
  return { source, kind: "accessDenied", reason };
}

/** Files mode: `SourceCoverage::AccessDenied` from manifest expansion (parser.rs), mirrored twice. */
const FILE_PATH = "C:\\Fixture\\EventLogs\\Security.evtx";
const FILE_REASON = "source metadata access was denied";
const FILE_GAP: EvtxCoverageGap = { source: FILE_PATH, kind: "accessDenied", reason: FILE_REASON };
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

async function settle(): Promise<void> {
  await act(async () => {
    await Promise.resolve();
  });
}

/** Renders the rail variant (on screen unless told otherwise) and lets the probe answer. */
async function renderRail(visible = true): Promise<void> {
  render(<EvtxCoverageBanner variant="rail" visible={visible} />);
  await settle();
}

function notes(): HTMLElement[] {
  return Array.from(document.querySelectorAll<HTMLElement>("[data-coverage-note]"));
}

function gridBanner(): HTMLElement | null {
  return document.querySelector<HTMLElement>("[data-coverage-banner]");
}

/** A stand-in surface that claims the given gap keys while mounted. */
function ClaimingSurface({ keys, archiveProvenance = false }: { keys: string[]; archiveProvenance?: boolean }) {
  const [claim] = useState(() => ({ keys: new Set(keys), archiveProvenance }));
  useCoverageClaim(claim);
  return null;
}

/** The lines the banner lists, as shown. */
function bannerLines(): string[] {
  const banner = gridBanner();
  return banner
    ? Array.from(banner.querySelectorAll("li"))
        .filter((item) => !item.closest("[data-archive-provenance]"))
        .map((item) => item.textContent ?? "")
    : [];
}

function withClaims(children: ReactNode) {
  return <CoverageClaimsProvider>{children}</CoverageClaimsProvider>;
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
    sourceMode: "live",
    remoteMachine: null,
  });
  useUiStore.getState().setElevationPrompt(null);
  useUiStore.setState({ themeId: "light", logListFontSize: 13 });
});

afterEach(cleanup);

describe("EvtxCoverageBanner grid variant", () => {
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

  it("is not a live region (the announcer speaks for every surface)", () => {
    useEvtxStore.setState({ coverageDetails: [liveDenied("Security")] });
    render(<EvtxCoverageBanner />);
    const banner = gridBanner();
    expect(banner).not.toBeNull();
    expect(banner).not.toHaveAttribute("aria-live");
    expect(banner).not.toHaveAttribute("role");
    expect(banner?.querySelector("[aria-live]")).toBeNull();
  });
});

describe("the grid banner lists only what no surface claims", () => {
  const SYSTEM_LIMIT: EvtxCoverageGap = {
    source: "System",
    kind: "limitReached",
    reason: "reader stopped at 10000 events; the source may contain more",
  };

  beforeEach(() => {
    useEvtxStore.setState({ coverageDetails: [liveDenied("Security"), SYSTEM_LIMIT] });
  });

  it("lists every gap when nothing claims one", () => {
    render(withClaims(<EvtxCoverageBanner />));
    expect(bannerLines()).toEqual([
      `Security: ${LIVE_REFUSAL_5}`,
      formatCoverageGap(SYSTEM_LIMIT),
    ]);
    expect(screen.getByText("2 gaps in this view")).toBeInTheDocument();
  });

  it("leaves out a claimed gap and counts only what it lists", () => {
    render(
      withClaims(
        <>
          <EvtxCoverageBanner />
          <ClaimingSurface keys={[`Security: ${LIVE_REFUSAL_5}`]} />
        </>,
      ),
    );
    expect(bannerLines()).toEqual([formatCoverageGap(SYSTEM_LIMIT)]);
    expect(screen.getByText("1 gap in this view")).toBeInTheDocument();
  });

  it("is not drawn when every gap is claimed, and comes back when the claim is released", () => {
    function Toggle() {
      const [claimed, setClaimed] = useState(true);
      return (
        <>
          <EvtxCoverageBanner />
          {claimed && (
            <ClaimingSurface keys={[`Security: ${LIVE_REFUSAL_5}`, formatCoverageGap(SYSTEM_LIMIT)]} />
          )}
          <button type="button" onClick={() => setClaimed(false)}>
            release
          </button>
        </>
      );
    }
    render(withClaims(<Toggle />));
    expect(gridBanner()).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "release" }));
    expect(bannerLines()).toHaveLength(2);
  });

  it("keys a legacy line and its structured gap as one", () => {
    useEvtxStore.setState({
      coverageGaps: [`Security: ${LIVE_REFUSAL_5}`, `  ${formatCoverageGap(SYSTEM_LIMIT)}  `],
    });
    render(
      withClaims(
        <>
          <EvtxCoverageBanner />
          <ClaimingSurface keys={[`Security: ${LIVE_REFUSAL_5}`]} />
        </>,
      ),
    );
    // The legacy copies dedupe against the structured gaps; the claimed one is gone from both.
    expect(bannerLines()).toEqual([`  ${formatCoverageGap(SYSTEM_LIMIT)}  `]);
  });

  it("hands the archive provenance to the surface that claims it", () => {
    useEvtxStore.setState({
      coverageDetails: [],
      archiveMembers: [
        { path: "bundle.zip::logs/Application.evtx", kind: "evtx", outcome: "parsed" },
      ],
    });
    const { rerender } = render(withClaims(<EvtxCoverageBanner />));
    expect(screen.getByText("Archive member provenance (1)")).toBeInTheDocument();
    rerender(
      withClaims(
        <>
          <EvtxCoverageBanner />
          <ClaimingSurface keys={[]} archiveProvenance />
        </>,
      ),
    );
    expect(gridBanner()).toBeNull();
  });
});

describe("a gap and the archive provenance appear in exactly one place", () => {
  const SYSTEM_LIMIT: EvtxCoverageGap = {
    source: "System",
    kind: "limitReached",
    reason: "reader stopped at 10000 events; the source may contain more",
  };

  function renderBoth(visible: boolean) {
    render(
      withClaims(
        <>
          <EvtxCoverageBanner />
          {/* The rail panel is hidden, not unmounted, when it is off screen. */}
          <div hidden={!visible}>
            <EvtxCoverageBanner variant="rail" visible={visible} />
          </div>
        </>,
      ),
    );
  }

  beforeEach(() => {
    answerElevation(OFFERABLE);
    useEvtxStore.setState({
      coverageDetails: [liveDenied("Security"), SYSTEM_LIMIT],
      archiveMembers: [
        { path: "bundle.zip::logs/Application.evtx", kind: "evtx", outcome: "parsed" },
      ],
    });
  });

  it("rail on screen: the note and the provenance there, the rest in the banner", async () => {
    renderBoth(true);
    await settle();

    expect(notes()).toHaveLength(1);
    expect(bannerLines()).toEqual([formatCoverageGap(SYSTEM_LIMIT)]);
    const provenance = Array.from(document.querySelectorAll("[data-archive-provenance]"));
    expect(provenance).toHaveLength(1);
    expect(gridBanner()?.contains(provenance[0])).toBe(false);
  });

  it("rail off screen: everything in the banner, the note claiming nothing", async () => {
    renderBoth(false);
    await settle();

    expect(bannerLines()).toEqual([`Security: ${LIVE_REFUSAL_5}`, formatCoverageGap(SYSTEM_LIMIT)]);
    const banner = gridBanner();
    expect(banner?.querySelectorAll("[data-archive-provenance]")).toHaveLength(1);
  });
});

describe("accessDeniedSources", () => {
  it("keys on the accessDenied kind only, in first-reported order, each source once", () => {
    expect(
      accessDeniedSources(
        [
          liveDenied("Security"),
          { source: "Application", kind: "missing", reason: "channel not found" },
          liveDenied("System", LIVE_REFUSAL_1314),
          liveDenied("Security", LIVE_REFUSAL_1314),
        ],
        [],
      ),
    ).toEqual([
      {
        source: "Security",
        manifest: false,
        keys: [`Security: ${LIVE_REFUSAL_5}`, `Security: ${LIVE_REFUSAL_1314}`],
      },
      { source: "System", manifest: false, keys: [`System: ${LIVE_REFUSAL_1314}`] },
    ]);
  });

  it("merges the parser's gap and the manifest's coverage row for the same file into one", () => {
    // Both rows carry the same line, so they share one key: the banner's own line for the file.
    expect(accessDeniedSources([FILE_GAP], FILE_MANIFEST.coverage)).toEqual([
      { source: FILE_PATH, manifest: true, keys: [`${FILE_PATH}: ${FILE_REASON}`] },
    ]);
    expect(accessDeniedSources([FILE_GAP], [])).toEqual([
      { source: FILE_PATH, manifest: false, keys: [`${FILE_PATH}: ${FILE_REASON}`] },
    ]);
  });

  it("does not read the refusal wording: a record gap carrying it is not a note (#931)", () => {
    // Today's live shape for an unelevated Security read. The note waits for #931 to file it as
    // accessDenied; no phrase matching stands in.
    expect(
      accessDeniedSources(
        [
          { source: "Security", kind: "record", reason: LIVE_REFUSAL_5 },
          { source: "System", kind: "record", reason: LIVE_REFUSAL_1314 },
        ],
        [],
      ),
    ).toEqual([]);
  });
});

describe("coverageNoteSubject", () => {
  const local = { sourceMode: "live" as const, remoteMachine: null };
  const remote = { sourceMode: "live" as const, remoteMachine: REMOTE_MACHINE };
  const files = { sourceMode: "files" as const, remoteMachine: null };
  const entry = (source: string, manifest = false) => ({ source, manifest });

  it("names a local live channel exactly, slashes included", () => {
    expect(coverageNoteSubject(entry("Security"), local)).toEqual({
      kind: "channel",
      source: "Security",
      channel: "Security",
    });
    expect(coverageNoteSubject(entry("Microsoft-Windows-AAD/Operational"), local)).toEqual({
      kind: "channel",
      source: "Microsoft-Windows-AAD/Operational",
      channel: "Microsoft-Windows-AAD/Operational",
    });
    // Without a remote session, a machine-like prefix is just part of the name.
    expect(coverageNoteSubject(entry(`${REMOTE_MACHINE}/Security`), local)).toMatchObject({
      kind: "channel",
      channel: `${REMOTE_MACHINE}/Security`,
    });
  });

  it("splits a remote read into machine and channel, keeping the channel's own slashes", () => {
    expect(coverageNoteSubject(entry(`${REMOTE_MACHINE}/Security`), remote)).toEqual({
      kind: "remote",
      source: `${REMOTE_MACHINE}/Security`,
      machine: REMOTE_MACHINE,
      channel: "Security",
    });
    expect(
      coverageNoteSubject(entry(`${REMOTE_MACHINE}/Microsoft-Windows-AAD/Operational`), remote),
    ).toMatchObject({
      kind: "remote",
      machine: REMOTE_MACHINE,
      channel: "Microsoft-Windows-AAD/Operational",
    });
  });

  it("names a file by its base name: drive, UNC and POSIX paths, and any manifest row", () => {
    expect(coverageNoteSubject(entry(FILE_PATH), files)).toEqual({
      kind: "file",
      source: FILE_PATH,
      fileName: "Security.evtx",
    });
    expect(coverageNoteSubject(entry("\\\\server\\share\\System.evtx"), files)).toMatchObject({
      kind: "file",
      fileName: "System.evtx",
    });
    expect(coverageNoteSubject(entry("/var/log/Setup.evtx"), files)).toMatchObject({
      kind: "file",
      fileName: "Setup.evtx",
    });
    expect(coverageNoteSubject(entry("Archive-Security.evtx", true), files)).toMatchObject({
      kind: "file",
      fileName: "Archive-Security.evtx",
    });
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
    expect(screen.queryByText(/not read/)).toBeNull();
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

    const { container } = render(<EvtxCoverageBanner variant="rail" visible />);
    await settle();

    expect(container).toBeEmptyDOMElement();
    expect(elevationProbes()).toBe(0);
  });

  it("claims what it draws only while on screen, and keeps its probe answer meanwhile", async () => {
    answerElevation(OFFERABLE);
    useEvtxStore.setState({ coverageDetails: [liveDenied("Security")] });
    function Harness() {
      const [visible, setVisible] = useState(false);
      return (
        <>
          <EvtxCoverageBanner />
          <div hidden={!visible}>
            <EvtxCoverageBanner variant="rail" visible={visible} />
          </div>
          <button type="button" onClick={() => setVisible((value) => !value)}>
            toggle
          </button>
        </>
      );
    }
    render(withClaims(<Harness />));
    await settle();
    expect(bannerLines()).toEqual([`Security: ${LIVE_REFUSAL_5}`]);

    fireEvent.click(screen.getByRole("button", { name: "toggle" }));
    expect(gridBanner()).toBeNull();
    expect(notes()).toHaveLength(1);

    fireEvent.click(screen.getByRole("button", { name: "toggle" }));
    expect(bannerLines()).toEqual([`Security: ${LIVE_REFUSAL_5}`]);
    // The note stayed mounted while hidden: one probe for the whole sequence.
    expect(elevationProbes()).toBe(1);
  });

  it("shows one note per local channel, each with its own exact sentence and action", async () => {
    answerElevation(OFFERABLE);
    useEvtxStore.setState({
      coverageDetails: [
        liveDenied("Security"),
        liveDenied("Microsoft-Windows-Sysmon/Operational", LIVE_REFUSAL_1314),
      ],
    });

    await renderRail();

    expect(notes().map((note) => note.dataset.coverageNote)).toEqual([
      "Security",
      "Microsoft-Windows-Sysmon/Operational",
    ]);
    expect(
      screen.getByText("Security channel not read. Findings may be incomplete."),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "Microsoft-Windows-Sysmon/Operational channel not read. Findings may be incomplete.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Elevate to read Microsoft-Windows-Sysmon/Operational" }),
    ).toBeInTheDocument();
  });

  it("names an unreadable file by its base name, once, with the full path as the action's tooltip", async () => {
    answerElevation(OFFERABLE);
    useEvtxStore.setState({
      sourceMode: "files",
      coverageDetails: [FILE_GAP],
      sourceManifest: FILE_MANIFEST,
    });

    await renderRail();

    expect(notes()).toHaveLength(1);
    expect(
      screen.getByText("Security.evtx not read. Findings may be incomplete."),
    ).toBeInTheDocument();
    expect(screen.queryByText(/channel not read/)).toBeNull();
    const action = screen.getByRole("button", { name: "Elevate to read Security.evtx" });
    expect(action).toHaveAccessibleDescription(FILE_PATH);
  });

  it("keeps a remote channel's note without an Elevate action, whatever the local elevation", async () => {
    answerElevation(ELEVATED);
    useEvtxStore.setState({
      remoteMachine: REMOTE_MACHINE,
      coverageDetails: [liveDenied(`${REMOTE_MACHINE}/Security`)],
    });

    await renderRail();

    expect(
      screen.getByText(`Security channel on ${REMOTE_MACHINE} not read. Findings may be incomplete.`),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button")).toBeNull();
    // Elevating here would not change the remote credentials, so nothing is probed.
    expect(elevationProbes()).toBe(0);
  });

  it("offers Elevate for a local channel and not for a remote one", async () => {
    answerElevation(OFFERABLE);
    useEvtxStore.setState({ coverageDetails: [liveDenied("Security")] });
    await renderRail();
    expect(screen.getByRole("button", { name: "Elevate to read Security" })).toBeInTheDocument();
    cleanup();

    useEvtxStore.setState({
      remoteMachine: REMOTE_MACHINE,
      coverageDetails: [liveDenied(`${REMOTE_MACHINE}/Security`)],
    });
    await renderRail();
    expect(notes()).toHaveLength(1);
    expect(screen.queryByRole("button", { name: /Elevate/ })).toBeNull();
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

  it("claims only the notes it names: the counted ones are named in the banner, once", async () => {
    answerElevation(OFFERABLE);
    useEvtxStore.setState({
      coverageDetails: ["Security", "System", "Setup", "Sysmon", "LAPS"].map((channel) =>
        liveDenied(channel),
      ),
    });
    render(
      withClaims(
        <>
          <EvtxCoverageBanner />
          <EvtxCoverageBanner variant="rail" visible />
        </>,
      ),
    );
    await settle();

    expect(screen.getByText("+2 more channels not read")).toBeInTheDocument();
    expect(bannerLines()).toEqual([`Sysmon: ${LIVE_REFUSAL_5}`, `LAPS: ${LIVE_REFUSAL_5}`]);
    expect(screen.getByText("2 gaps in this view")).toBeInTheDocument();
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

describe("coverage announcer", () => {
  function liveTexts(): string[] {
    return Array.from(document.querySelectorAll("[aria-live]")).map(
      (region) => region.textContent ?? "",
    );
  }

  function announcer(): HTMLElement {
    const region = document.querySelector<HTMLElement>("[data-coverage-announcer]");
    expect(region).not.toBeNull();
    return region as HTMLElement;
  }

  /** The announcer's lines, one element each, as a screen reader reads them. */
  function lines(): string[] {
    return Array.from(announcer().children).map((line) => line.textContent ?? "");
  }

  const SECURITY_LINE = `Security: ${LIVE_REFUSAL_5}`;
  const SYSTEM_LINE = `System: ${LIVE_REFUSAL_1314}`;

  it("is a visually hidden polite status region that starts empty", () => {
    render(<EvtxCoverageBanner variant="announcer" />);
    const region = announcer();
    expect(region).toHaveAttribute("role", "status");
    expect(region).toHaveAttribute("aria-live", "polite");
    expect(region).toHaveStyle({ position: "absolute", width: "1px", height: "1px" });
    expect(region).toBeEmptyDOMElement();
  });

  it("announces a gap that arrives after the first load once, with the rail on and the banner hidden", async () => {
    answerElevation(OFFERABLE);
    useEvtxStore.setState({ coverageDetails: [liveDenied("Security")] });
    render(
      withClaims(
        <>
          <EvtxCoverageBanner variant="announcer" />
          <EvtxCoverageBanner />
          <EvtxCoverageBanner variant="rail" visible />
          {/* The rail's disclosure, covering both gaps once a summary has them. */}
          <ClaimingSurface keys={[SECURITY_LINE, SYSTEM_LINE]} />
        </>,
      ),
    );
    await settle();

    expect(gridBanner()).toBeNull();
    // Only the new lines: no count line, which would make the whole status region re-read.
    expect(lines()).toEqual([SECURITY_LINE]);

    act(() =>
      useEvtxStore.setState({
        coverageDetails: [liveDenied("Security"), liveDenied("System", LIVE_REFUSAL_1314)],
      }),
    );

    expect(gridBanner()).toBeNull();
    expect(lines()).toEqual([SYSTEM_LINE]);
    // Once across every live region in the document, not only the announcer.
    const texts = liveTexts();
    expect(texts).toHaveLength(1);
    expect(texts[0].split(SYSTEM_LINE)).toHaveLength(2);
  });

  it("leaves nothing stale when the gaps shrink", async () => {
    useEvtxStore.setState({
      coverageDetails: [liveDenied("Security"), liveDenied("System", LIVE_REFUSAL_1314)],
    });
    render(<EvtxCoverageBanner variant="announcer" />);
    await settle();
    expect(lines()).toEqual([SECURITY_LINE, SYSTEM_LINE]);

    // System is cleared: nothing is added, so the region empties rather than keep its line.
    act(() => useEvtxStore.setState({ coverageDetails: [liveDenied("Security")] }));
    expect(announcer()).toBeEmptyDOMElement();
    expect(liveTexts().join("")).not.toContain(SYSTEM_LINE);
  });

  it("announces a gap again when it is reported again after going away", async () => {
    useEvtxStore.setState({
      coverageDetails: [liveDenied("Security"), liveDenied("System", LIVE_REFUSAL_1314)],
    });
    render(<EvtxCoverageBanner variant="announcer" />);
    await settle();

    act(() => useEvtxStore.setState({ coverageDetails: [liveDenied("Security")] }));
    act(() =>
      useEvtxStore.setState({
        coverageDetails: [liveDenied("Security"), liveDenied("System", LIVE_REFUSAL_1314)],
      }),
    );
    expect(lines()).toEqual([SYSTEM_LINE]);
  });

  it("announces nothing for an update that adds no gap", async () => {
    useEvtxStore.setState({ coverageDetails: [liveDenied("Security")] });
    render(<EvtxCoverageBanner variant="announcer" />);
    await settle();
    expect(lines()).toEqual([SECURITY_LINE]);

    act(() => useEvtxStore.setState({ coverageDetails: [liveDenied("Security")] }));
    expect(announcer()).toBeEmptyDOMElement();
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
