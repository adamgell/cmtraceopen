import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { tokens } from "@fluentui/react-components";
import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes } from "../../lib/themes";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { DiagnosisFinding, EvtxRecord } from "./types";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";

const invoke = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

const { EvtxDetailPane } = await import("./EvtxDetailPane");
const { useEvtxStore } = await import("./evtx-store");
const { sanitizeLayout, useEvtxLayoutStore } = await import("./evtx-layout-store");
const { useMarkerStore } = await import("../../stores/marker-store");
const { useUiStore } = await import("../../stores/ui-store");

const RECORD: EvtxRecord = {
  id: 1,
  eventRecordId: 42,
  timestamp: "2026-08-22T12:00:00Z",
  timestampEpoch: 1,
  provider: "Example Provider",
  channel: "Application",
  eventId: 100,
  level: "Information",
  computer: "TEST-PC",
  message: "Example event",
  eventData: [],
  rawXml: "<Event />",
  sourceLabel: "Application.evtx",
  activityId: "activity-1",
  userId: "user-42",
  userSid: "S-1-5-21-1000",
};

describe("EvtxDetailPane correlation identity", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue(null);
    useEvtxStore.getState().reset();
    useEvtxStore.setState({
      records: [RECORD],
      selectedRecordId: RECORD.id,
    });
    useMarkerStore.setState({
      markersByFile: new Map(),
      loadingFiles: new Set(["event-log:Application.evtx"]),
    });
  });

  it("renders the event user identifier separately from the security identifier", () => {
    render(<EvtxDetailPane />);

    expect(screen.getByText("Correlation identity")).toBeInTheDocument();
    expect(screen.getByText("User ID")).toBeInTheDocument();
    expect(screen.getByText("user-42")).toBeInTheDocument();
    expect(screen.getAllByText(/User SID/)).toHaveLength(1);
    expect(screen.getByText("S-1-5-21-1000")).toBeInTheDocument();
  });

  it("keeps a SID-only value in metadata instead of presenting it as correlation identity", () => {
    useEvtxStore.setState({
      records: [{ ...RECORD, activityId: undefined, userId: undefined }],
    });

    render(<EvtxDetailPane />);

    expect(screen.queryByText("Correlation identity")).not.toBeInTheDocument();
    expect(screen.getAllByText(/User SID/)).toHaveLength(1);
    expect(screen.getByText("S-1-5-21-1000")).toBeInTheDocument();
  });
});

describe("EvtxDetailPane error codes", () => {
  const mention = (overrides: Record<string, unknown>) => ({
    start: 0,
    end: 10,
    codeHex: "0x80070005",
    codeDecimal: "-2147024891",
    description: "",
    category: "",
    outcome: null,
    known: false,
    ...overrides,
  });

  beforeEach(() => {
    invoke.mockReset();
    useUiStore.setState({ logDetailsFontSize: 14 });
    useEvtxStore.getState().reset();
    useEvtxStore.setState({
      records: [{ ...RECORD, message: "Update failed with 0x80070005" }],
      selectedRecordId: RECORD.id,
    });
    useMarkerStore.setState({
      markersByFile: new Map(),
      loadingFiles: new Set(["event-log:Application.evtx"]),
    });
  });

  it("shows a code the database knows with its meaning", async () => {
    invoke.mockImplementation((command: string) =>
      command === "resolve_error_codes_in_text"
        ? Promise.resolve([
            mention({
              known: true,
              description: "Access is denied.",
              category: "Win32",
              outcome: "failure",
            }),
          ])
        : Promise.resolve(null),
    );

    render(<EvtxDetailPane />);

    expect(
      await screen.findByText("Error codes in this event"),
    ).toBeInTheDocument();
    expect(screen.getByText(/Access is denied\./)).toBeInTheDocument();
    expect(screen.getByText(/Win32/)).toBeInTheDocument();
  });

  it("uses pixel line height for the error code list", async () => {
    invoke.mockImplementation((command: string) =>
      command === "resolve_error_codes_in_text"
        ? Promise.resolve([mention({})])
        : Promise.resolve(null),
    );

    render(<EvtxDetailPane />);

    await screen.findByText("Error codes in this event");
    expect(screen.getByRole("list")).toHaveStyle({ lineHeight: "22px" });
  });

  it("shows Win32 and HRESULT forms separately while deduplicating repeated literals", async () => {
    const message = "Update failed with 0x00000005 and 0x80070005";
    useEvtxStore.setState({
      records: [{ ...RECORD, message, eventData: [{ name: "Error", value: "0x00000005" }] }],
    });
    const win32 = mention({
      start: 19,
      end: 29,
      codeHex: "0x00000005",
      codeDecimal: "5",
      known: true,
      description: "Access is denied.",
      category: "Windows",
      outcome: "failure",
    });
    invoke.mockImplementation((command: string) =>
      command === "resolve_error_codes_in_text"
        ? Promise.resolve([
            win32,
            { ...win32, start: 34, end: 44, codeHex: "0x80070005", codeDecimal: "-2147024891" },
            { ...win32, start: 45, end: 55 },
          ])
        : Promise.resolve(null),
    );

    render(<EvtxDetailPane />);

    await screen.findByText("Error codes in this event");
    const codes = within(screen.getByRole("list"));
    expect(codes.getAllByText("0x00000005")).toHaveLength(1);
    expect(codes.getAllByText("0x80070005")).toHaveLength(1);
    expect(codes.getAllByRole("listitem")).toHaveLength(2);
  });

  it("labels a code the database cannot explain instead of staying silent", async () => {
    invoke.mockImplementation((command: string) =>
      command === "resolve_error_codes_in_text"
        ? Promise.resolve([mention({ codeHex: "0xDEADBEEF", known: false })])
        : Promise.resolve(null),
    );

    render(<EvtxDetailPane />);

    expect(
      await screen.findByText("Error codes in this event"),
    ).toBeInTheDocument();
    expect(screen.getByText("0xDEADBEEF")).toBeInTheDocument();
    expect(screen.getByText("Not in the error database")).toBeInTheDocument();
  });

  it("shows nothing extra when the command reports no codes", async () => {
    invoke.mockResolvedValue([]);

    render(<EvtxDetailPane />);

    expect(screen.getByText("Update failed with 0x80070005")).toBeInTheDocument();
    expect(screen.queryByText("Error codes in this event")).not.toBeInTheDocument();
  });

  it.each(["success", "failure"] as const)("hides the previous event's codes while awaiting lookup %s", async (outcome) => {
    let settleLookup: ((result: ReturnType<typeof mention>[] | Error) => void) | undefined;
    const nextLookup = new Promise<ReturnType<typeof mention>[]>((resolve, reject) => {
      settleLookup = (result) => result instanceof Error ? reject(result) : resolve(result);
    });
    invoke.mockImplementation((command: string, args: { text?: string }) => {
      if (command !== "resolve_error_codes_in_text") return Promise.resolve(null);
      return args.text?.includes("0xDEADBEEF")
        ? nextLookup
        : Promise.resolve([mention({ description: "Previous event failure", known: true })]);
    });
    const second = { ...RECORD, id: 2, message: "Next event 0xDEADBEEF" };
    useEvtxStore.setState({ records: [
      { ...RECORD, message: "Update failed with 0x80070005" }, second,
    ] });
    render(<EvtxDetailPane />);
    expect(await screen.findByText("Previous event failure")).toBeInTheDocument();

    act(() => useEvtxStore.setState({ selectedRecordId: second.id }));
    expect(screen.getByText(second.message)).toBeInTheDocument();
    expect(screen.queryByText("Previous event failure")).not.toBeInTheDocument();
    expect(screen.queryByText("Error codes in this event")).not.toBeInTheDocument();

    if (!settleLookup) throw new Error("lookup promise was not initialized");
    const settle = settleLookup;
    if (outcome === "success") {
      await act(async () => settle([mention({ codeHex: "0xDEADBEEF" })]));
      expect(screen.getByText("0xDEADBEEF")).toBeInTheDocument();
    } else {
      await act(async () => settle(new Error("lookup unavailable")));
      expect(screen.queryByText("Error codes in this event")).not.toBeInTheDocument();
    }
    expect(screen.queryByText("Previous event failure")).not.toBeInTheDocument();
  });
});

describe("EvtxDetailPane rail layout", () => {
  const fields = Array.from({ length: 8 }, (_, index) => ({
    name: `Field${index + 1}`,
    value: `value-${index + 1}`,
  }));
  const FULL: EvtxRecord = {
    ...RECORD,
    level: "Error",
    message: "Installation failed.",
    eventData: fields,
    rawXml: "<Event><System /></Event>",
    processId: 4321,
    threadId: 99,
    task: 7,
    opcode: 2,
    keywords: "0x8000000000000000",
    mapped: [{ property: "PayloadData1", text: "mapped text", complete: true }],
    eventRecordIdText: "88456",
    timestampEpoch: Date.parse("2026-08-22T12:00:00Z"),
  };

  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue([]);
    useEvtxStore.getState().reset();
    useEvtxStore.setState({ records: [FULL], selectedRecordId: FULL.id, timeZoneMode: "utc" });
    useEvtxLayoutStore.setState(sanitizeLayout({ railTab: "details" }));
    useMarkerStore.setState({
      markersByFile: new Map(),
      loadingFiles: new Set(["event-log:Application.evtx"]),
    });
  });

  it("shows the summary header, the message and the time with the computer", () => {
    render(<EvtxDetailPane />);

    const region = screen.getByRole("region", { name: "Event log details" });
    expect(within(region).getByText("Event 100")).toBeInTheDocument();
    expect(within(region).getByText("Error")).toBeInTheDocument();
    expect(within(region).getByText("Installation failed.")).toBeInTheDocument();
    expect(within(region).getByText("2026-08-22 12:00:00.000")).toBeInTheDocument();
    expect(region).toHaveTextContent("\u00b7 TEST-PC");
  });

  it("lays out the definition grid with each field once", () => {
    render(<EvtxDetailPane />);

    for (const term of ["Channel", "Provider", "Record ID", "Process", "User SID"]) {
      expect(screen.getAllByText(term)).toHaveLength(1);
    }
    expect(screen.getByText("88456")).toBeInTheDocument();
    expect(screen.getByText("PID 4321 \u00b7 TID 99")).toBeInTheDocument();
    expect(screen.getByText("S-1-5-21-1000")).toBeInTheDocument();
  });

  it("previews six EventData fields and reveals the rest on request", () => {
    render(<EvtxDetailPane />);

    expect(screen.getByText("Field6")).toBeInTheDocument();
    expect(screen.queryByText("Field7")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Show all 8" }));
    expect(screen.getByText("Field8")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Show fewer" }));
    expect(screen.queryByText("Field7")).not.toBeInTheDocument();
  });

  it("offers no Show all when everything already fits the preview", () => {
    useEvtxStore.setState({ records: [{ ...FULL, eventData: fields.slice(0, 3) }] });
    render(<EvtxDetailPane />);

    expect(screen.queryByRole("button", { name: /Show all/ })).not.toBeInTheDocument();
  });

  it("keeps every earlier section reachable: identity, mapped fields, metadata and markers", () => {
    useEvtxStore.setState({ records: [{ ...FULL, sessionId: "session-9" }] });
    render(<EvtxDetailPane />);

    expect(screen.getByText("Correlation identity")).toBeInTheDocument();
    expect(screen.getByText("session-9")).toBeInTheDocument();
    expect(screen.getByText("Mapped fields")).toBeInTheDocument();
    expect(screen.getByText("mapped text")).toBeInTheDocument();
    for (const label of ["Source:", "Task:", "Opcode:", "Keywords:"]) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
    expect(document.querySelector("[data-evtx-marker-key]")).not.toBeNull();
  });

  it("switches between the Details and XML sub-tabs and resets on another record", () => {
    render(<EvtxDetailPane />);

    const tabs = screen.getByRole("tablist", { name: "Event detail view" });
    expect(within(tabs).getAllByRole("tab")).toHaveLength(2);
    expect(within(tabs).getByRole("tab", { name: "Details" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(screen.queryByLabelText("Raw event XML")).not.toBeInTheDocument();

    fireEvent.click(within(tabs).getByRole("tab", { name: "XML" }));
    expect(screen.getByLabelText("Raw event XML")).toHaveTextContent(FULL.rawXml);
    expect(screen.queryByText("Installation failed.")).not.toBeInTheDocument();

    act(() =>
      useEvtxStore.setState({
        records: [FULL, { ...FULL, id: 2 }],
        selectedRecordId: 2,
      }),
    );
    expect(screen.queryByLabelText("Raw event XML")).not.toBeInTheDocument();
    expect(screen.getByText("Installation failed.")).toBeInTheDocument();
  });

  it("closes: clears the selection and returns the rail to Insights", () => {
    render(<EvtxDetailPane />);

    fireEvent.click(screen.getByRole("button", { name: "Close details" }));

    expect(useEvtxStore.getState().selectedRecordId).toBeNull();
    expect(useEvtxLayoutStore.getState().railTab).toBe("insights");
  });
});

describe("EvtxDetailPane rail extras", () => {
  const rec = (id: number, overrides: Partial<EvtxRecord> = {}): EvtxRecord => ({
    ...RECORD,
    id,
    sourceLabel: "C:\\Users\\examiner\\Downloads\\Application.evtx",
    eventRecordId: 500 + id,
    timestampEpoch: Date.parse("2026-08-22T12:00:00Z") + id * 60_000,
    ...overrides,
  });
  const records = [rec(0), rec(1), rec(2)];

  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue(null);
    useEvtxStore.getState().reset();
    useEvtxStore.setState({
      records,
      selectedRecordId: 1,
      timeZoneMode: "utc",
      timeWindow: "all",
      sortField: "time",
      sortDirection: "asc",
    });
    useEvtxLayoutStore.setState(sanitizeLayout({ railTab: "details" }));
    useMarkerStore.setState({
      markersByFile: new Map(),
      loadingFiles: new Set(["event-log:Application.evtx"]),
    });
  });

  it("moves through the visible records in grid order with Previous and Next", () => {
    render(<EvtxDetailPane visibleRecords={records} />);

    fireEvent.click(screen.getByRole("button", { name: "Next event" }));
    expect(useEvtxStore.getState().selectedRecordId).toBe(2);
    expect(screen.getByRole("button", { name: "Next event" })).toHaveAttribute("aria-disabled", "true");

    fireEvent.click(screen.getByRole("button", { name: "Previous event" }));
    fireEvent.click(screen.getByRole("button", { name: "Previous event" }));
    expect(useEvtxStore.getState().selectedRecordId).toBe(0);
    expect(screen.getByRole("button", { name: "Previous event" })).toHaveAttribute(
      "aria-disabled",
      "true",
    );
  });

  it("follows the grid's sort direction", () => {
    useEvtxStore.setState({ sortDirection: "desc" });
    render(<EvtxDetailPane visibleRecords={records} />);

    fireEvent.click(screen.getByRole("button", { name: "Next event" }));
    expect(useEvtxStore.getState().selectedRecordId).toBe(0);
  });

  it("disables both when the selection is not among the visible records", () => {
    render(<EvtxDetailPane visibleRecords={[records[0]]} />);
    expect(screen.getByRole("button", { name: "Next event" })).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByRole("button", { name: "Previous event" })).toHaveAttribute(
      "aria-disabled",
      "true",
    );
  });

  it("keeps focus on the button that disables itself at the end of the list", () => {
    render(<EvtxDetailPane visibleRecords={records} />);
    const next = screen.getByRole("button", { name: "Next event" });
    next.focus();

    fireEvent.click(next);

    expect(useEvtxStore.getState().selectedRecordId).toBe(2);
    expect(next).toHaveAttribute("aria-disabled", "true");
    expect(next).toHaveFocus();
    // A disabled-but-focusable button does nothing when activated again.
    fireEvent.click(next);
    expect(useEvtxStore.getState().selectedRecordId).toBe(2);
  });

  it("walks the rendered rows: grouped, with the records of a collapsed group skipped", () => {
    // Providers by time: P0 (0), Q (1), P0 (2), Q (3). Grouped by provider: P0 [0, 2], Q [1, 3].
    const mixed = [
      rec(0, { provider: "P0" }),
      rec(1, { provider: "Q" }),
      rec(2, { provider: "P0" }),
      rec(3, { provider: "Q" }),
    ];
    useEvtxStore.setState({ records: mixed, selectedRecordId: 0, groupBy: ["provider"] });
    const { rerender } = render(<EvtxDetailPane visibleRecords={mixed} />);

    fireEvent.click(screen.getByRole("button", { name: "Next event" }));
    expect(useEvtxStore.getState().selectedRecordId).toBe(2);
    fireEvent.click(screen.getByRole("button", { name: "Next event" }));
    // Time order would say record 3; the grid renders Q's group after P0's, so this is record 1.
    expect(useEvtxStore.getState().selectedRecordId).toBe(1);

    // Collapse Q: its records have no rows, so Next stops after P0's.
    act(() =>
      useEvtxStore.setState({
        collapsedGroups: new Set(["/provider=Q"]),
        selectedRecordId: 2,
      }),
    );
    rerender(<EvtxDetailPane visibleRecords={mixed} />);
    expect(screen.getByRole("button", { name: "Next event" })).toHaveAttribute(
      "aria-disabled",
      "true",
    );
    // Expanded again, Next continues into the second group.
    act(() => useEvtxStore.setState({ collapsedGroups: new Set() }));
    rerender(<EvtxDetailPane visibleRecords={mixed} />);
    expect(screen.getByRole("button", { name: "Next event" })).not.toHaveAttribute("aria-disabled");
  });

  it("sizes the header buttons at 24 px", () => {
    render(<EvtxDetailPane visibleRecords={records} />);
    expect(screen.getByRole("button", { name: "Next event" })).toHaveStyle({
      width: "24px",
      height: "24px",
    });
  });

  it("counts same ID and provider occurrences, never binning a record without a timestamp", () => {
    const withBad = [...records, rec(3, { timestampEpoch: 0 }), rec(4, { provider: "Other" })];
    useEvtxStore.setState({ records: withBad });
    render(<EvtxDetailPane visibleRecords={withBad} />);

    const card = screen.getByRole("group", { name: "Same ID" });
    expect(card).toHaveTextContent("Same ID in visible events");
    expect(card).not.toHaveTextContent(/visible events,/);
    expect(card).toHaveTextContent("4 occurrences");
    expect(card).toHaveTextContent("first 2026-08-22 12:00:00.000");
    const svg = card.querySelector("svg") as SVGElement;
    expect(svg).toHaveAttribute("aria-hidden", "true");
    expect(svg).toHaveStyle({ height: "22px" });
    // 24 bins, and only the three timestamped matches are drawn.
    expect(svg.getAttribute("viewBox")).toBe("0 0 24 22");
    expect(svg.querySelectorAll("rect")).toHaveLength(3);
  });

  it("counts only the visible records: a filter that hides same-ID records lowers the count", () => {
    const all = [rec(0), rec(1, { level: "Error" }), rec(2, { level: "Error" })];
    useEvtxStore.setState({ records: all });
    const { rerender } = render(<EvtxDetailPane visibleRecords={all} />);
    expect(screen.getByRole("group", { name: "Same ID" })).toHaveTextContent("3 occurrences");

    // The level filter hides the first record, so the pane receives the narrower visible set.
    rerender(<EvtxDetailPane visibleRecords={all.slice(1)} />);
    expect(screen.getByRole("group", { name: "Same ID" })).toHaveTextContent("2 occurrences");
    expect(screen.getByRole("group", { name: "Same ID" })).toHaveTextContent(
      "Same ID in visible events",
    );
  });

  it("names the time window the card covers", () => {
    useEvtxStore.setState({ timeWindow: "24h" });
    render(<EvtxDetailPane visibleRecords={records} />);
    expect(screen.getByRole("group", { name: "Same ID" })).toHaveTextContent(
      "Same ID in visible events, last 24 hours",
    );
  });

  it("draws the sparkline with a color that reaches 3:1 on the card surface in every theme", () => {
    for (const theme of getAllThemes()) {
      const visuals = buildEvtxVisualTokens(theme);
      const surface = resolveToken(tokens.colorNeutralBackground1, theme);
      expect(
        contrastRatio(resolveToken(visuals.singleSeries, theme), surface),
        theme.id,
      ).toBeGreaterThanOrEqual(3);
    }
    expect(getAllThemes()).toHaveLength(7);
  });

  const finding: DiagnosisFinding = {
    findingId: "f-9",
    class: "confirmedFailure",
    severity: "error",
    confidence: "high",
    title: "Enrollment failed",
    summary: "s",
    // The shape the UI receives over IPC: the display projection redacts the machine and source.
    evidence: [
      {
        kind: "event",
        value: {
          source: "C:\\Users\\[user:00112233445566ff]\\Downloads\\Application.evtx",
          provider: "Example Provider",
          eventId: 100,
          recordId: 501,
          channel: "Application",
          machine: "[host:0123456789abcdef]",
        },
      },
    ],
    coverageGaps: [],
    recommendedChecks: [],
  };

  it("shows the finding callout only for a record that is event evidence of a finding", () => {
    const { rerender } = render(<EvtxDetailPane visibleRecords={records} findings={[finding]} />);
    expect(screen.getByRole("button", { name: /Part of finding: Enrollment failed/ })).toBeInTheDocument();

    act(() => useEvtxStore.setState({ selectedRecordId: 2 }));
    rerender(<EvtxDetailPane visibleRecords={records} findings={[finding]} />);
    expect(screen.queryByRole("button", { name: /Part of finding/ })).toBeNull();
  });

  it("shows no callout when two loaded records from different machines match the evidence", () => {
    const twin = rec(1, { id: 9, computer: "OTHER-PC", sourceLabel: "C:\\Users\\other.user\\Downloads\\Application.evtx", eventRecordId: 501 });
    const both = [...records, twin];
    useEvtxStore.setState({ records: both, selectedRecordId: 1 });
    render(<EvtxDetailPane visibleRecords={both} findings={[finding]} />);
    expect(screen.queryByRole("button", { name: /Part of finding/ })).toBeNull();
  });

  it("switches to Insights and focuses the finding's card when the callout is activated", async () => {
    render(
      <>
        <article data-finding-id="f-9" tabIndex={-1} aria-label="card" />
        <EvtxDetailPane visibleRecords={records} findings={[finding]} />
      </>,
    );
    fireEvent.click(screen.getByRole("button", { name: /Part of finding/ }));

    expect(useEvtxLayoutStore.getState().railTab).toBe("insights");
    await waitFor(() => expect(screen.getByLabelText("card")).toHaveFocus());
  });

  it("links the Details and XML sub-tabs to their panel", () => {
    render(<EvtxDetailPane visibleRecords={records} />);

    const detailsTab = screen.getByRole("tab", { name: "Details" });
    const panel = document.getElementById(detailsTab.getAttribute("aria-controls") as string)!;
    expect(panel).toHaveAttribute("role", "tabpanel");
    expect(panel).toHaveAttribute("aria-labelledby", detailsTab.id);

    fireEvent.click(screen.getByRole("tab", { name: "XML" }));
    const xmlTab = screen.getByRole("tab", { name: "XML" });
    const xmlPanel = document.getElementById(xmlTab.getAttribute("aria-controls") as string)!;
    expect(xmlPanel).toHaveAttribute("aria-labelledby", xmlTab.id);
    expect(xmlPanel).toContainElement(screen.getByLabelText("Raw event XML"));
  });

  it("sizes the XML view from the details font size", () => {
    useUiStore.setState({ logDetailsFontSize: 15 });
    render(<EvtxDetailPane visibleRecords={records} />);
    fireEvent.click(screen.getByRole("tab", { name: "XML" }));

    const xml = screen.getByLabelText("Raw event XML");
    // The XML text is one step under the details mono size (details size minus 1, minus 1 more).
    expect(xml.style.fontSize).toBe("13px");
    expect(screen.getByRole("region", { name: "Event log details" })).toHaveStyle({
      fontSize: "15px",
    });
  });

  it("renders Channel and Provider in the UI font and the record ID in the numeric font", () => {
    render(<EvtxDetailPane visibleRecords={records} />);
    const valueOf = (term: string) =>
      screen.getByText(term).nextElementSibling as HTMLElement;
    expect(valueOf("Channel").style.fontFamily).toBe("");
    expect(valueOf("Provider").style.fontFamily).toBe("");
    expect(valueOf("Record ID").style.fontFamily).toContain("fontFamilyNumeric");
  });
});
