/**
 * "EVTX subset..." (spec 8.17): copies the events on screen into new `.evtx` files, one per
 * source log, with `EvtExportLog`.
 *
 * Deviation from spec 8.17, to be confirmed by the maintainer: it asks for "a summary toast" that
 * lists the files and the record count for each. The app has no toast host, so the list is the
 * dialog's done view and the one-line outcome stays in the view bar's status line after the dialog
 * is closed. Two readings of the same section are made in the backend: `{source-label}` is the
 * file stem for an `.evtx` source, and names that collide are numbered `{label}-N-subset.evtx`.
 *
 * The files are raw copies, so the shared redaction module cannot apply. The dialog therefore
 * puts the unredacted warning next to the one button that starts the export, and starts with
 * focus on Cancel so that Enter or Space on opening can never export by accident.
 *
 * Mounted only while the operator wants it: the view bar renders it with a snapshot of the
 * records at the moment of the click, so what is exported is what the list showed then, and each
 * open starts from a clean state.
 */
import {
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type ReactElement,
} from "react";
import {
  Button,
  Dialog,
  DialogActions,
  DialogBody,
  DialogContent,
  DialogSurface,
  DialogTitle,
  Spinner,
  tokens,
} from "@fluentui/react-components";
import {
  CheckmarkCircle16Regular,
  DismissCircle16Regular,
  FolderOpen16Regular,
  Warning16Regular,
} from "@fluentui/react-icons";
import { open } from "@tauri-apps/plugin-dialog";
import { useModalOwnership } from "../../hooks/use-modal-ownership";
import {
  exportEventLogSubset,
  type EvtxSubsetFileResult,
  type EvtxSubsetResult,
} from "../../lib/commands";
import {
  LOG_MONOSPACE_FONT_FAMILY,
  LOG_UI_FONT_FAMILY,
  getLogListMetrics,
} from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { useEvtxVisualTokens } from "./evtx-visual-tokens";
import {
  describeSkippedRecords,
  planEvtxSubsetSources,
  summarizeEvtxSubsetResult,
  type EvtxSubsetSkipped,
} from "./evtx-subset-sources";
import type { EvtxRecord } from "./types";

/** The wording is the spec's (8.17) and is asserted by the dialog's test. */
export const EVTX_SUBSET_UNREDACTED_NOTICE =
  "These .evtx files are not redacted. They contain the original machine names, user SIDs, and other identifiers.";

const FOLDER_DIALOG_TITLE = "Choose a folder for the EVTX subset files";

const VISUALLY_HIDDEN: CSSProperties = {
  position: "absolute",
  width: "1px",
  height: "1px",
  overflow: "hidden",
  clipPath: "inset(50%)",
  whiteSpace: "nowrap",
};

interface EvtxExportSubsetDialogProps {
  /** The records the list showed when the dialog was opened. */
  records: readonly EvtxRecord[];
  onClose: () => void;
  /** Called once with a one-line summary when an export finishes, for the view bar's status line. */
  onFinished?: (summary: string) => void;
}

type Phase = "ready" | "exporting" | "done";

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function EvtxExportSubsetDialog({
  records,
  onClose,
  onFinished,
}: EvtxExportSubsetDialogProps): ReactElement {
  const ownsModal = useModalOwnership("eventLogSubsetExport", true);
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(logListFontSize), [logListFontSize]);
  const visualTokens = useEvtxVisualTokens();
  const smallFontSize = `${Math.max(10, metrics.fontSize - 1)}px`;

  const plan = useMemo(() => planEvtxSubsetSources(records), [records]);
  // Fluent labels the surface by its title only, so the gate's wording is wired as its description:
  // a screen-reader user hears the warning when the dialog opens, before reaching any button.
  const noticeId = useId();
  const [folder, setFolder] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>("ready");
  const [result, setResult] = useState<EvtxSubsetResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Set before the first await, so a second activation made while the first is still in flight
  // cannot start a second export of the same files.
  const startedRef = useRef(false);

  // Fluent moves focus to the first focusable element when a dialog opens, which here would be
  // "Choose folder\u2026". The spec wants Cancel, so it is focused explicitly. This runs after
  // Fluent's own effect: Dialog is a child of this component, and children's effects run first.
  const cancelRef = useRef<HTMLButtonElement | null>(null);
  const closeRef = useRef<HTMLButtonElement | null>(null);
  useEffect(() => {
    if (ownsModal) cancelRef.current?.focus();
  }, [ownsModal]);
  // The Export button the operator just pressed is replaced by Close; keep focus inside the dialog.
  useEffect(() => {
    if (phase === "done") closeRef.current?.focus();
  }, [phase]);

  const exporting = phase === "exporting";
  const announcement =
    phase === "done" && result
      ? summarizeEvtxSubsetResult(result, plan.skippedRecords)
      : exporting
        ? "Exporting EVTX subset files"
        : "";
  const canExport = folder !== null && plan.sources.length > 0 && phase === "ready";

  const chooseFolder = async () => {
    try {
      const selected = await open({
        directory: true,
        multiple: false,
        title: FOLDER_DIALOG_TITLE,
      });
      // Cancelling the picker returns null: the previous choice stands and nothing is invoked.
      if (typeof selected === "string") {
        setFolder(selected);
        setError(null);
      }
    } catch (pickError) {
      setError(`Could not open the folder picker: ${errorMessage(pickError)}`);
    }
  };

  const runExport = async () => {
    if (startedRef.current || folder === null || plan.sources.length === 0) return;
    startedRef.current = true;
    setPhase("exporting");
    setError(null);
    try {
      const response = await exportEventLogSubset(
        folder,
        plan.sources.map(({ kind, path, recordGroups }) => ({ kind, path, recordGroups })),
      );
      setResult(response);
      setPhase("done");
      onFinished?.(summarizeEvtxSubsetResult(response, plan.skippedRecords));
    } catch (exportError) {
      // Nothing was exported when the whole request is refused (an existing file, a bad folder),
      // so the operator can fix the cause here and try again.
      setError(errorMessage(exportError));
      setPhase("ready");
    } finally {
      startedRef.current = false;
    }
  };

  const textColor = tokens.colorNeutralForeground1;
  const mutedColor = tokens.colorNeutralForeground2;
  const warningColor = visualTokens.levels.Warning.textColor;
  const errorColor = visualTokens.levels.Error.textColor;

  return (
    <Dialog
      open={ownsModal}
      // "alert" keeps a click outside the surface from dismissing it; Escape and the close
      // button are handled below so that nothing can close the dialog while files are written.
      modalType="alert"
      onOpenChange={(_, data) => {
        if (!data.open && !exporting) onClose();
      }}
    >
      <DialogSurface
        style={{ maxWidth: "640px", fontFamily: LOG_UI_FONT_FAMILY }}
        // The warning is only on screen until the result replaces the form.
        aria-describedby={phase === "done" ? undefined : noticeId}
      >
        <DialogBody>
          <DialogTitle>Export EVTX subset</DialogTitle>
          <DialogContent>
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                gap: "12px",
                fontSize: `${metrics.fontSize}px`,
                color: textColor,
              }}
            >
              {/*
                Always mounted, so a change to it is announced. A live region that appears together
                with its text is often missed, and the result replaces the controls that had focus.
              */}
              <span role="status" aria-live="polite" style={VISUALLY_HIDDEN}>
                {announcement}
              </span>
              {phase === "done" && result ? (
                <SubsetResult
                  result={result}
                  skipped={plan.skipped}
                  notIncluded={plan.skippedRecords}
                  smallFontSize={smallFontSize}
                  warningColor={warningColor}
                  errorColor={errorColor}
                />
              ) : (
                <>
                  <p style={{ margin: 0, color: mutedColor }}>
                    Copy the events currently shown into new .evtx files, one for each source
                    log.
                  </p>

                  {plan.sources.length > 0 ? (
                    <ul
                      aria-label="Sources"
                      style={{
                        margin: 0,
                        padding: 0,
                        listStyle: "none",
                        display: "flex",
                        flexDirection: "column",
                        gap: "4px",
                      }}
                    >
                      {plan.sources.map((source) => (
                        <li
                          key={`${source.kind}:${source.path}`}
                          style={{ display: "flex", gap: "12px", justifyContent: "space-between" }}
                        >
                          <span
                            title={source.path}
                            style={{
                              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                              overflowWrap: "anywhere",
                            }}
                          >
                            {source.path}
                          </span>
                          <span
                            style={{
                              flexShrink: 0,
                              fontFamily: tokens.fontFamilyNumeric,
                              fontVariantNumeric: "tabular-nums",
                              color: mutedColor,
                            }}
                          >
                            {`${source.recordCount.toLocaleString()} ${
                              source.recordCount === 1 ? "event" : "events"
                            }`}
                          </span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p style={{ margin: 0 }}>
                      Nothing in the list can be exported as an .evtx subset.
                    </p>
                  )}

                  <NotIncluded skipped={plan.skipped} fontSize={smallFontSize} color={mutedColor} />

                  <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                    <Button
                      appearance="outline"
                      size="small"
                      icon={<FolderOpen16Regular />}
                      disabledFocusable={exporting}
                      onClick={() => {
                        if (!exporting) void chooseFolder();
                      }}
                    >
                      {"Choose folder\u2026"}
                    </Button>
                    <span
                      data-evtx-subset-folder
                      title={folder ?? undefined}
                      style={{
                        fontFamily: folder ? LOG_MONOSPACE_FONT_FAMILY : undefined,
                        color: folder ? textColor : mutedColor,
                        overflowWrap: "anywhere",
                      }}
                    >
                      {folder ?? "No folder chosen"}
                    </span>
                  </div>

                  <div style={{ fontSize: smallFontSize, color: mutedColor }}>
                    Files are named{" "}
                    <span style={{ fontFamily: LOG_MONOSPACE_FONT_FAMILY }}>
                      {"{source}-subset.evtx"}
                    </span>
                    . Message text is saved in a LocaleMetaData folder beside them, so keep that
                    folder with the files. Existing files are never overwritten.
                  </div>

                  <div
                    id={noticeId}
                    role="note"
                    style={{
                      display: "flex",
                      alignItems: "flex-start",
                      gap: "8px",
                      fontWeight: 600,
                      color: warningColor,
                    }}
                  >
                    <Warning16Regular aria-hidden style={{ flexShrink: 0, marginTop: "2px" }} />
                    <span>{EVTX_SUBSET_UNREDACTED_NOTICE}</span>
                  </div>

                  {error && (
                    <div
                      role="alert"
                      style={{ display: "flex", gap: "8px", color: errorColor }}
                    >
                      <DismissCircle16Regular aria-hidden style={{ flexShrink: 0, marginTop: "2px" }} />
                      <span style={{ overflowWrap: "anywhere" }}>{error}</span>
                    </div>
                  )}
                </>
              )}
            </div>
          </DialogContent>
          <DialogActions>
            {phase === "done" ? (
              <Button ref={closeRef} appearance="primary" onClick={onClose}>
                Close
              </Button>
            ) : (
              <>
                <Button
                  ref={cancelRef}
                  appearance="secondary"
                  disabledFocusable={exporting}
                  onClick={() => {
                    if (!exporting) onClose();
                  }}
                >
                  Cancel
                </Button>
                <Button
                  appearance="primary"
                  disabledFocusable={!canExport}
                  icon={exporting ? <Spinner size="tiny" /> : undefined}
                  title={
                    folder === null && plan.sources.length > 0
                      ? "Choose a folder first"
                      : undefined
                  }
                  onClick={() => {
                    if (canExport) void runExport();
                  }}
                >
                  {exporting ? "Exporting\u2026" : "Export unredacted"}
                </Button>
              </>
            )}
          </DialogActions>
        </DialogBody>
      </DialogSurface>
    </Dialog>
  );
}

/** The events the plan left out and why, shown before and after the export. */
function NotIncluded({
  skipped,
  fontSize,
  color,
}: {
  skipped: EvtxSubsetSkipped[];
  fontSize: string;
  color: string;
}): ReactElement | null {
  if (skipped.length === 0) return null;
  return (
    <div style={{ fontSize, color }}>
      <div style={{ fontWeight: 600 }}>Not included</div>
      <ul style={{ margin: "2px 0 0", paddingLeft: "18px" }}>
        {skipped.map((entry) => (
          <li key={entry.reason}>{describeSkippedRecords(entry)}</li>
        ))}
      </ul>
    </div>
  );
}

function SubsetResult({
  result,
  skipped,
  notIncluded,
  smallFontSize,
  warningColor,
  errorColor,
}: {
  result: EvtxSubsetResult;
  skipped: EvtxSubsetSkipped[];
  notIncluded: number;
  smallFontSize: string;
  warningColor: string;
  errorColor: string;
}): ReactElement {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
      <div style={{ fontWeight: 600 }}>{summarizeEvtxSubsetResult(result, notIncluded)}</div>
      <div style={{ fontSize: smallFontSize, color: tokens.colorNeutralForeground2, overflowWrap: "anywhere" }}>
        Saved to <span style={{ fontFamily: LOG_MONOSPACE_FONT_FAMILY }}>{result.folder}</span>
      </div>
      <NotIncluded
        skipped={skipped}
        fontSize={smallFontSize}
        color={tokens.colorNeutralForeground2}
      />
      <ul
        aria-label="Exported files"
        style={{ margin: 0, padding: 0, listStyle: "none", display: "flex", flexDirection: "column", gap: "8px" }}
      >
        {result.files.map((file) => (
          <SubsetResultRow
            key={file.outputPath}
            file={file}
            smallFontSize={smallFontSize}
            warningColor={warningColor}
            errorColor={errorColor}
          />
        ))}
      </ul>
    </div>
  );
}

/**
 * What the written file holds, by what was found in it. Never a bare "N of M": a file can be short
 * of what was asked for, hold events nobody asked for, or both, and each is said on its own.
 */
function recordCountText(file: EvtxSubsetFileResult): string {
  const requested = file.requestedRecords.toLocaleString();
  const noun = (count: number) => (count === 1 ? "event" : "events");
  if (file.exportedRecords === null) return `${requested} requested, count not verified`;
  const missing = file.missing?.count ?? 0;
  const unrequested = file.unrequested?.count ?? 0;
  const held = `${file.exportedRecords.toLocaleString()} ${noun(file.exportedRecords)}`;
  if (missing === 0 && unrequested === 0) return held;
  const parts = [`${requested} requested`];
  if (missing > 0) parts.push(`${missing.toLocaleString()} missing`);
  if (unrequested > 0) parts.push(`${unrequested.toLocaleString()} not requested`);
  return `${held} in the file (${parts.join("; ")})`;
}

function SubsetResultRow({
  file,
  smallFontSize,
  warningColor,
  errorColor,
}: {
  file: EvtxSubsetFileResult;
  smallFontSize: string;
  warningColor: string;
  errorColor: string;
}): ReactElement {
  const failed = file.status === "failed";
  return (
    <li style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
      <div style={{ display: "flex", gap: "8px", alignItems: "flex-start" }}>
        {failed ? (
          <DismissCircle16Regular aria-hidden style={{ flexShrink: 0, marginTop: "2px", color: errorColor }} />
        ) : (
          <CheckmarkCircle16Regular aria-hidden style={{ flexShrink: 0, marginTop: "2px" }} />
        )}
        <div style={{ minWidth: 0 }}>
          <div>
            <span style={{ fontFamily: LOG_MONOSPACE_FONT_FAMILY, overflowWrap: "anywhere" }} title={file.outputPath}>
              {file.fileName}
            </span>
            {failed ? (
              <span style={{ color: errorColor, fontWeight: 600 }}>{" Failed"}</span>
            ) : (
              <span style={{ fontFamily: tokens.fontFamilyNumeric, fontVariantNumeric: "tabular-nums" }}>
                {`: ${recordCountText(file)}`}
              </span>
            )}
          </div>
          {file.error && (
            <div style={{ fontSize: smallFontSize, color: errorColor, overflowWrap: "anywhere" }}>
              {file.error}
            </div>
          )}
          {file.warnings.map((warning) => (
            <div key={warning} style={{ fontSize: smallFontSize, color: warningColor, overflowWrap: "anywhere" }}>
              {`Warning: ${warning}`}
            </div>
          ))}
        </div>
      </div>
    </li>
  );
}
