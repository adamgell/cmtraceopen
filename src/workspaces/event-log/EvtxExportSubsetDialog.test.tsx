import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes } from "../../lib/themes";
import { deferred } from "../../test-utils/deferred";
import { tokens } from "@fluentui/react-components";
import { useUiStore } from "../../stores/ui-store";
import { EVTX_SUBSET_UNREDACTED_NOTICE, EvtxExportSubsetDialog } from "./EvtxExportSubsetDialog";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";
import type { EvtxRecord } from "./types";

const record = (partial: Partial<EvtxRecord> = {}): EvtxRecord => ({
  id: 1,
  eventRecordId: 1,
  timestamp: "2026-08-09T12:00:00Z",
  timestampEpoch: 0,
  provider: "Provider",
  channel: "System",
  eventId: 1,
  level: "Error",
  computer: "HOST",
  message: "event",
  eventData: [],
  rawXml: "<Event />",
  sourceLabel: "Live",
  ...partial,
});

const LIVE_RECORDS = [
  record({ channel: "System", eventRecordId: 10 }),
  record({ channel: "System", eventRecordId: 11 }),
  record({ channel: "Application", eventRecordId: 3 }),
];

const exportedFile = (partial: Record<string, unknown> = {}) => ({
  kind: "channel",
  sourcePath: "Application",
  fileName: "Application-subset.evtx",
  outputPath: "C:\\out\\Application-subset.evtx",
  requestedRecords: 1,
  status: "exported",
  exportedRecords: 1,
  missing: { count: 0, sample: [] },
  unrequested: { count: 0, sample: [] },
  messagesArchived: true,
  error: null,
  warnings: [],
  ...partial,
});

const SUCCESS = {
  folder: "C:\\out",
  files: [
    exportedFile(),
    exportedFile({
      sourcePath: "System",
      fileName: "System-subset.evtx",
      outputPath: "C:\\out\\System-subset.evtx",
      requestedRecords: 2,
      exportedRecords: 2,
    }),
  ],
};

/** jsdom reports an inline hex color as `rgb(r, g, b)`. */
function cssColorToHex(color: string): string {
  const match = /^rgb\((\d+), (\d+), (\d+)\)$/.exec(color);
  if (!match) return color;
  return `#${[match[1], match[2], match[3]]
    .map((channel) => Number(channel).toString(16).padStart(2, "0"))
    .join("")}`;
}

const button = (name: string) => screen.getByRole("button", { name });
const exportButton = () => button("Export unredacted");

function renderDialog(
  records: readonly EvtxRecord[] = LIVE_RECORDS,
  props: { onClose?: () => void; onFinished?: (summary: string) => void } = {},
) {
  const onClose = props.onClose ?? vi.fn();
  render(
    <EvtxExportSubsetDialog records={records} onClose={onClose} onFinished={props.onFinished} />,
  );
  return { onClose };
}

async function chooseFolder(folder = "C:\\out") {
  vi.mocked(open).mockResolvedValueOnce(folder);
  await act(async () => {
    fireEvent.click(button("Choose folder\u2026"));
  });
  await waitFor(() => expect(exportButton()).not.toHaveAttribute("aria-disabled", "true"));
}

describe("EvtxExportSubsetDialog", () => {
  beforeEach(() => {
    useUiStore.setState(useUiStore.getInitialState(), true);
    vi.mocked(invoke).mockReset();
    vi.mocked(open).mockReset();
  });
  afterEach(cleanup);

  it("shows the spec's unredacted warning verbatim beside Export unredacted and Cancel", async () => {
    renderDialog();
    const dialog = await screen.findByRole("alertdialog");
    expect(EVTX_SUBSET_UNREDACTED_NOTICE).toBe(
      "These .evtx files are not redacted. They contain the original machine names, user SIDs, and other identifiers.",
    );
    expect(within(dialog).getByRole("note")).toHaveTextContent(EVTX_SUBSET_UNREDACTED_NOTICE);
    expect(exportButton()).toBeInTheDocument();
    expect(button("Cancel")).toBeInTheDocument();
  });

  it("describes the alert dialog by the unredacted warning, so it is read before any button", async () => {
    renderDialog();
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveAccessibleName("Export EVTX subset");
    expect(dialog).toHaveAccessibleDescription(EVTX_SUBSET_UNREDACTED_NOTICE);
    // The same element the visible notice is, not a copy of its text.
    expect(dialog.getAttribute("aria-describedby")).toBe(
      within(dialog).getByRole("note").getAttribute("id"),
    );
  });

  it("drops the description once the form, and its warning, is replaced by the result", async () => {
    vi.mocked(invoke).mockResolvedValueOnce(SUCCESS);
    renderDialog();
    await chooseFolder();
    await act(async () => {
      fireEvent.click(exportButton());
    });
    await screen.findByRole("list", { name: "Exported files" });
    expect(screen.getByRole("alertdialog")).not.toHaveAttribute("aria-describedby");
  });

  it("puts initial focus on Cancel, not on the export button", async () => {
    renderDialog();
    await screen.findByRole("alertdialog");
    await waitFor(() => expect(button("Cancel")).toHaveFocus());
    expect(exportButton()).not.toHaveFocus();
  });

  it("lists each source with its event count, one file per source", async () => {
    renderDialog();
    const list = await screen.findByRole("list", { name: "Sources" });
    const items = within(list).getAllByRole("listitem");
    expect(items.map((item) => item.textContent)).toEqual([
      "Application1 event",
      "System2 events",
    ]);
  });

  it("keeps Export unredacted unavailable until a folder is chosen, and invokes nothing", async () => {
    renderDialog();
    await screen.findByRole("alertdialog");
    expect(exportButton()).toHaveAttribute("aria-disabled", "true");
    expect(exportButton()).toHaveAttribute("title", "Choose a folder first");
    fireEvent.click(exportButton());
    expect(invoke).not.toHaveBeenCalled();
  });

  it("makes no call and keeps the export unavailable when the folder picker is cancelled", async () => {
    vi.mocked(open).mockResolvedValueOnce(null);
    renderDialog();
    await screen.findByRole("alertdialog");
    await act(async () => {
      fireEvent.click(button("Choose folder\u2026"));
    });
    expect(open).toHaveBeenCalledWith(
      expect.objectContaining({ directory: true, multiple: false }),
    );
    expect(screen.getByText("No folder chosen")).toBeInTheDocument();
    expect(exportButton()).toHaveAttribute("aria-disabled", "true");
    expect(invoke).not.toHaveBeenCalled();
  });

  it("sends the chosen folder and the lossless record ids, then shows each file with its count", async () => {
    vi.mocked(invoke).mockResolvedValueOnce(SUCCESS);
    const onFinished = vi.fn();
    renderDialog(
      [
        record({ channel: "System", eventRecordId: 2 ** 53, eventRecordIdText: "9007199254740991" }),
        record({ channel: "Application", eventRecordId: 3 }),
      ],
      { onFinished },
    );
    await chooseFolder("C:\\out");
    await act(async () => {
      fireEvent.click(exportButton());
    });

    expect(invoke).toHaveBeenCalledTimes(1);
    expect(invoke).toHaveBeenCalledWith("evtx_export_subset", {
      folder: "C:\\out",
      sources: [
        {
          kind: "channel",
          path: "Application",
          recordGroups: [{ computer: "HOST", recordIds: ["3"] }],
        },
        {
          kind: "channel",
          path: "System",
          recordGroups: [{ computer: "HOST", recordIds: ["9007199254740991"] }],
        },
      ],
    });
    const files = await screen.findByRole("list", { name: "Exported files" });
    expect(screen.getByRole("status")).toHaveTextContent("Exported 2 EVTX subset files (3 events).");
    expect(files).toHaveTextContent("Application-subset.evtx: 1 event");
    expect(files).toHaveTextContent("System-subset.evtx: 2 events");
    expect(onFinished).toHaveBeenCalledWith("Exported 2 EVTX subset files (3 events).");
    expect(button("Close")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Export unredacted" })).toBeNull();
  });

  it("closes through Cancel without exporting", async () => {
    const { onClose } = renderDialog();
    await screen.findByRole("alertdialog");
    fireEvent.click(button("Cancel"));
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(invoke).not.toHaveBeenCalled();
  });

  it("closes on Escape before an export starts", async () => {
    const { onClose } = renderDialog();
    const dialog = await screen.findByRole("alertdialog");
    fireEvent.keyDown(dialog, { key: "Escape" });
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(invoke).not.toHaveBeenCalled();
  });

  it("starts one export however many times the button is activated, and cannot be closed meanwhile", async () => {
    const pending = deferred<typeof SUCCESS>();
    vi.mocked(invoke).mockReturnValueOnce(pending.promise);
    const { onClose } = renderDialog();
    await chooseFolder();
    await act(async () => {
      fireEvent.click(exportButton());
      fireEvent.click(exportButton());
    });
    expect(invoke).toHaveBeenCalledTimes(1);

    // The files are being written and cannot be recalled: Cancel and Escape do nothing.
    expect(button("Cancel")).toHaveAttribute("aria-disabled", "true");
    fireEvent.click(button("Cancel"));
    fireEvent.keyDown(screen.getByRole("alertdialog"), { key: "Escape" });
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Exporting\u2026" })).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Exporting EVTX subset files");

    await act(async () => {
      pending.resolve(SUCCESS);
    });
    await waitFor(() =>
      expect(screen.getByRole("status")).toHaveTextContent("Exported 2 EVTX subset files"),
    );
  });

  it("shows a refused request as an alert and lets the operator choose another folder and retry", async () => {
    vi.mocked(invoke)
      .mockRejectedValueOnce(
        "These files already exist in C:\\out and are never overwritten: System-subset.evtx.",
      )
      .mockResolvedValueOnce(SUCCESS);
    renderDialog();
    await chooseFolder("C:\\out");
    await act(async () => {
      fireEvent.click(exportButton());
    });
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("never overwritten: System-subset.evtx");
    // Back to a state where the export can be retried, with the dialog still open.
    expect(exportButton()).not.toHaveAttribute("aria-disabled", "true");

    await chooseFolder("D:\\elsewhere");
    await act(async () => {
      fireEvent.click(exportButton());
    });
    expect(vi.mocked(invoke).mock.calls[1][1]).toMatchObject({ folder: "D:\\elsewhere" });
    await waitFor(() =>
      expect(screen.getByRole("status")).toHaveTextContent("Exported 2 EVTX subset files"),
    );
  });

  it("reports a failed file and an unverified count instead of presenting the request as fact", async () => {
    vi.mocked(invoke).mockResolvedValueOnce({
      folder: "C:\\out",
      files: [
        exportedFile({
          exportedRecords: null,
          missing: null,
          unrequested: null,
          warnings: ["which events the file holds could not be verified (cannot open the exported file)"],
        }),
        exportedFile({
          sourcePath: "System",
          fileName: "System-subset.evtx",
          outputPath: "C:\\out\\System-subset.evtx",
          requestedRecords: 2,
          status: "failed",
          exportedRecords: null,
          missing: null,
          unrequested: null,
          messagesArchived: false,
          error: "EvtExportLog: access denied (needs elevation)",
        }),
      ],
    });
    renderDialog();
    await chooseFolder();
    await act(async () => {
      fireEvent.click(exportButton());
    });
    const files = await screen.findByRole("list", { name: "Exported files" });
    expect(screen.getByRole("status")).toHaveTextContent(
      "Exported 1 of 2 EVTX subset files (1 event, counts not verified); 1 failed.",
    );
    expect(files).toHaveTextContent("Application-subset.evtx: 1 requested, count not verified");
    expect(files).toHaveTextContent("Warning: which events the file holds could not be verified");
    expect(files).toHaveTextContent("System-subset.evtx Failed");
    expect(files).toHaveTextContent("access denied (needs elevation)");
  });

  it("says which events are missing and which are extra, never a bare 'N of M'", async () => {
    vi.mocked(invoke).mockResolvedValueOnce({
      folder: "C:\\out",
      files: [
        exportedFile({
          sourcePath: "Application",
          requestedRecords: 3,
          exportedRecords: 2,
          missing: { count: 1, sample: ["2"] },
          warnings: ["1 requested event not in the file (EventRecordID 2); the log may have wrapped"],
        }),
        exportedFile({
          sourcePath: "System",
          fileName: "System-subset.evtx",
          outputPath: "C:\\out\\System-subset.evtx",
          requestedRecords: 1,
          exportedRecords: 2,
          unrequested: { count: 1, sample: ["HOST-B: 100"] },
          warnings: ["the file also holds 1 event that was not requested (EventRecordID HOST-B: 100)"],
        }),
      ],
    });
    renderDialog();
    await chooseFolder();
    await act(async () => {
      fireEvent.click(exportButton());
    });
    const files = await screen.findByRole("list", { name: "Exported files" });
    expect(files).toHaveTextContent("Application-subset.evtx: 2 events in the file (3 requested; 1 missing)");
    expect(files).toHaveTextContent("System-subset.evtx: 2 events in the file (1 requested; 1 not requested)");
    expect(files).not.toHaveTextContent("2 of 1");
    expect(screen.getByRole("status")).toHaveTextContent(
      "Exported 2 EVTX subset files (4 events); 2 files differ from the request.",
    );
  });

  it("keeps saying what was left out after the export, in the heading, the live region and the list", async () => {
    vi.mocked(invoke).mockResolvedValueOnce({ folder: "C:\\out", files: [SUCCESS.files[0]] });
    const onFinished = vi.fn();
    renderDialog(
      [
        record({ channel: "Application", eventRecordId: 3 }),
        record({ originKind: "log", sourceLabel: "C:\\logs\\a.log" }),
        record({ sourceLabel: "bundle.zip::System.evtx", eventRecordId: 4 }),
        record({ sourceLabel: "bundle.zip::System.evtx", eventRecordId: 5 }),
      ],
      { onFinished },
    );
    await chooseFolder();
    await act(async () => {
      fireEvent.click(exportButton());
    });
    await screen.findByRole("list", { name: "Exported files" });
    const summary = "Exported 1 EVTX subset file (1 event); 3 not included.";
    expect(screen.getByRole("status")).toHaveTextContent(summary);
    // Once in the live region and once, visibly, as the heading of the result.
    expect(screen.getAllByText(summary)).toHaveLength(2);
    // The view bar's status line outlives the dialog, so it carries the same words.
    expect(onFinished).toHaveBeenCalledWith(summary);
    expect(screen.getByText("Not included")).toBeInTheDocument();
    expect(screen.getByText("1 text log line (not Windows events)")).toBeInTheDocument();
  });

  it("sends the same id from two machines as two events, one group each", async () => {
    vi.mocked(invoke).mockResolvedValueOnce({ folder: "C:\\out", files: [] });
    renderDialog([
      record({ channel: "ForwardedEvents", computer: "HOST-A", eventRecordId: 100 }),
      record({ channel: "ForwardedEvents", computer: "HOST-B", eventRecordId: 100 }),
    ]);
    const list = await screen.findByRole("list", { name: "Sources" });
    expect(list).toHaveTextContent("ForwardedEvents2 events");
    await chooseFolder();
    await act(async () => {
      fireEvent.click(exportButton());
    });
    expect(vi.mocked(invoke).mock.calls[0][1]).toMatchObject({
      sources: [
        {
          path: "ForwardedEvents",
          recordGroups: [
            { computer: "HOST-A", recordIds: ["100"] },
            { computer: "HOST-B", recordIds: ["100"] },
          ],
        },
      ],
    });
  });

  it("names what cannot be exported instead of leaving it out silently", async () => {
    renderDialog([
      record({ channel: "System", eventRecordId: 1 }),
      record({ originKind: "log", sourceLabel: "C:\\logs\\a.log" }),
      record({ sourceLabel: "bundle.zip::System.evtx", eventRecordId: 4 }),
      record({ sourceLabel: "bundle.zip::System.evtx", eventRecordId: 5 }),
    ]);
    await screen.findByRole("alertdialog");
    expect(screen.getByText("Not included")).toBeInTheDocument();
    expect(screen.getByText("1 text log line (not Windows events)")).toBeInTheDocument();
    expect(
      screen.getByText(
        "2 events read from inside an archive (an archive member has no .evtx file of its own)",
      ),
    ).toBeInTheDocument();
  });

  it("says so, and cannot export, when nothing in the list can go into a subset", async () => {
    renderDialog([record({ originKind: "log", sourceLabel: "C:\\logs\\a.log" })]);
    await screen.findByRole("alertdialog");
    expect(screen.getByText("Nothing in the list can be exported as an .evtx subset.")).toBeInTheDocument();
    expect(exportButton()).toHaveAttribute("aria-disabled", "true");
    expect(screen.queryByRole("list", { name: "Sources" })).toBeNull();
  });

  it("takes its turn in the modal queue and releases it on close", async () => {
    useUiStore.getState().requestModal("about");
    const { onClose } = renderDialog();
    // Another modal owns the screen, so this one waits rather than stacking on it.
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(useUiStore.getState().modalQueue).toEqual(["eventLogSubsetExport"]);
    act(() => useUiStore.getState().releaseModal("about"));
    expect(await screen.findByRole("alertdialog")).toBeInTheDocument();
    expect(useUiStore.getState().modalOwner).toBe("eventLogSubsetExport");
    fireEvent.click(button("Cancel"));
    expect(onClose).toHaveBeenCalled();
    cleanup();
    expect(useUiStore.getState().modalOwner).toBeNull();
  });
});

describe("EvtxExportSubsetDialog colors", () => {
  beforeEach(() => {
    vi.mocked(invoke).mockReset();
    vi.mocked(open).mockReset();
  });
  afterEach(cleanup);

  // The dialog draws on the dialog surface (colorNeutralBackground1). Each text color it uses has
  // to reach 4.5:1 there in every theme: body text, the muted secondary text, the unredacted
  // warning (levels.Warning.textColor) and a failure (levels.Error.textColor).
  it.each(getAllThemes().map((theme) => [theme.id, theme] as const))(
    "keeps every text color at 4.5:1 or better on the dialog surface in %s",
    async (_id, theme) => {
      useUiStore.setState({ ...useUiStore.getInitialState(), themeId: theme.id }, true);
      const visual = buildEvtxVisualTokens(theme);
      const surface = resolveToken(tokens.colorNeutralBackground1, theme);
      const pairs: Array<[string, string]> = [
        ["body text", tokens.colorNeutralForeground1],
        ["secondary text", tokens.colorNeutralForeground2],
        ["unredacted warning", visual.levels.Warning.textColor],
        ["failure text", visual.levels.Error.textColor],
      ];
      const failures = pairs
        .map(([role, color]) => [role, contrastRatio(resolveToken(color, theme), surface)] as const)
        .filter(([, ratio]) => ratio < 4.5)
        .map(([role, ratio]) => `${theme.id}: ${role} ${ratio.toFixed(2)}:1`);
      expect(failures, failures.join("; ")).toEqual([]);

      // And the dialog really draws its warning with the token measured above.
      render(<EvtxExportSubsetDialog records={LIVE_RECORDS} onClose={() => undefined} />);
      const notice = (await screen.findByRole("note")) as HTMLElement;
      expect(cssColorToHex(notice.style.color)).toBe(visual.levels.Warning.textColor.toLowerCase());
    },
  );
});
