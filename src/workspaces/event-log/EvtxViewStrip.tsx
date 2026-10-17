/**
 * The view strip (spec 8.15, Q-5): one card per saved set of filters, the built-in "Enrollment
 * triage" first, a dashed "New view" button, and the source line on the right.
 *
 * A card applies its view. Which card is active is DERIVED, never remembered: a view is active
 * while the criteria on screen equal its own (`viewMatchesCriteria`), so editing a filter, a Stop
 * that restores the time window, a source change or a cleared channel turns it off with no code of
 * its own. Layout is not part of that test (filters persist across layout switches, spec 9) and the
 * transient criteria are not on the criteria shape.
 *
 * What a view cannot show is said, not left as an empty grid: an active view whose channels are not
 * loaded (live) or not in the files says how many.
 */
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent,
} from "react";
import {
  createFocusOutlineStyle,
  makeStyles,
  Menu,
  MenuItem,
  MenuList,
  MenuPopover,
  MenuTrigger,
  mergeClasses,
  shorthands,
  tokens,
} from "@fluentui/react-components";
import { Add16Regular } from "@fluentui/react-icons";
import { open, save } from "@tauri-apps/plugin-dialog";
import { readTextFile, writeTextFile } from "@tauri-apps/plugin-fs";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { applyView } from "./evtx-criteria-actions";
import {
  EvtxDeleteViewDialog,
  EvtxViewNameDialog,
  viewFailureMessage,
  viewImportFailureMessage,
  viewImportSummary,
  type EvtxViewImportOutcome,
} from "./EvtxViewDialogs";
import { useFilterChips } from "./EvtxFilterChips";
import { useEvtxLayoutStore } from "./evtx-layout-store";
import { captureCriteria } from "./evtx-saved-filters";
import { eventLogSourceLabel } from "./evtx-source-label";
import { useEvtxStore } from "./evtx-store";
import {
  buildViewExport,
  captureLayout,
  listViews,
  missingViewChannels,
  parseViewExport,
  viewDescription,
  viewMatchesCriteria,
  viewSubtitle,
  type EvtxView,
} from "./evtx-views";
import { useEvtxViewStore, type EvtxViewFailure } from "./evtx-views-store";
import { useRailTextColors } from "./evtx-rail-text";
import { useEvtxVisualTokens } from "./evtx-visual-tokens";

const NEW_VIEW_ID = "__new-view__";

const useStyles = makeStyles({
  card: {
    display: "inline-flex",
    alignItems: "center",
    columnGap: "6px",
    boxSizing: "border-box",
    // Spec 8.15: radius 6, padding 4px 10px, a 1 px border.
    ...shorthands.padding("4px", "10px"),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    ...shorthands.border("1px", "solid", "transparent"),
    fontFamily: "inherit",
    fontSize: "inherit",
    lineHeight: "inherit",
    whiteSpace: "nowrap",
    cursor: "pointer",
    ...createFocusOutlineStyle({ style: { outlineRadius: tokens.borderRadiusLarge } }),
  },
  // The inactive look is classes; the active card is inline, in the selection colors. Hover shows
  // in the border, not the fill: the text colors are guaranteed against the strip surface, and a
  // hover fill is a second surface they would have to clear in every theme (it does not in
  // high contrast, solarized-dark or dracula).
  idle: {
    backgroundColor: "transparent",
    color: tokens.colorNeutralForeground1,
    ...shorthands.borderColor(tokens.colorNeutralStroke1),
    ":hover": { ...shorthands.borderColor(tokens.colorNeutralStroke1Hover) },
  },
  newView: {
    columnGap: "4px",
    backgroundColor: "transparent",
    color: tokens.colorNeutralForeground2,
    ...shorthands.borderStyle("dashed"),
    ...shorthands.borderColor(tokens.colorNeutralStroke1),
    ":hover": { ...shorthands.borderColor(tokens.colorNeutralStroke1Hover) },
  },
  visuallyHidden: {
    position: "absolute",
    width: "1px",
    height: "1px",
    overflow: "hidden",
    clipPath: "inset(50%)",
    whiteSpace: "nowrap",
  },
});

/** A file name for an export: the view's name reduced to letters, digits, spaces, dashes and underscores. */
export function exportFileStem(name: string): string {
  const stem = name
    .replace(/[^A-Za-z0-9 _-]+/g, "")
    .trim()
    .replace(/\s+/g, "-")
    .slice(0, 40)
    .toLowerCase();
  return stem || "view";
}

export function EvtxViewStrip() {
  const styles = useStyles();
  const { selection, levels } = useEvtxVisualTokens();
  // Secondary text (spec 8.15 names fg3) by the rule the rail already uses on this surface: fg3 where
  // it reaches 4.5:1 on colorNeutralBackground1, else fg2 (fg3 measures 3.37:1 in solarized-dark and
  // 3.03:1 in dracula). The strip does not keep a rule of its own.
  const { cardSecondary: mutedText } = useRailTextColors();
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(logListFontSize), [logListFontSize]);
  // Spec 8.15: f - 2 for the cards, on one line (about 24 px a card, 30 px with the strip's padding);
  // the eyebrow is the 7.1 treatment, max(10, f - 3).
  const fontPx = Math.max(10, metrics.fontSize - 2);
  const fontSize = `${fontPx}px`;
  const lineHeight = `${Math.round(fontPx * 1.3)}px`;
  const eyebrowSize = `${Math.max(10, metrics.fontSize - 3)}px`;
  const dialogFontSize = `${Math.max(11, metrics.fontSize - 1)}px`;

  const custom = useEvtxViewStore((s) => s.views);
  const views = useMemo(() => listViews(custom), [custom]);

  // The criteria on screen, as a saved filter would capture them.
  const filterLevels = useEvtxStore((s) => s.filterLevels);
  const filterEventIds = useEvtxStore((s) => s.filterEventIds);
  const timeWindow = useEvtxStore((s) => s.timeWindow);
  const selectedChannels = useEvtxStore((s) => s.selectedChannels);
  const filterSearch = useEvtxStore((s) => s.filterSearch);
  const filterSearchDraft = useEvtxStore((s) => s.filterSearchDraft);
  const quickFilter = useEvtxStore((s) => s.quickFilter);
  const quickFilterDraft = useEvtxStore((s) => s.quickFilterDraft);
  const groupBy = useEvtxStore((s) => s.groupBy);
  const current = useMemo(
    () =>
      captureCriteria({
        filterLevels,
        filterEventIds,
        timeWindow,
        selectedChannels,
        filterSearch,
        filterSearchDraft,
        quickFilter,
        quickFilterDraft,
        groupBy,
      }),
    [
      filterLevels,
      filterEventIds,
      timeWindow,
      selectedChannels,
      filterSearch,
      filterSearchDraft,
      quickFilter,
      quickFilterDraft,
      groupBy,
    ],
  );
  const activeIds = useMemo(
    () => new Set(views.filter((view) => viewMatchesCriteria(view, current)).map((view) => view.id)),
    [views, current],
  );

  // Which channels the source holds: the loaded ones live, every channel in the files otherwise.
  // The chip row's own answer, so the two cannot disagree (and it holds still through a refetch).
  const { heldChannels } = useFilterChips();
  const sourceMode = useEvtxStore((s) => s.sourceMode);
  const remoteMachine = useEvtxStore((s) => s.remoteMachine);
  const records = useEvtxStore((s) => s.records);
  const sourceLabel = useMemo(
    () => eventLogSourceLabel({ sourceMode, remoteMachine, records }),
    [sourceMode, remoteMachine, records],
  );
  const absence = sourceMode === "live" ? "not loaded" : "not in these files";

  // Polite, one node per message, so a repeated message is announced again.
  const [announcement, setAnnouncement] = useState({ id: 0, text: "" });
  const announce = useCallback(
    (text: string) => setAnnouncement((previous) => ({ id: previous.id + 1, text })),
    [],
  );

  // A failure is shown in full under the strip until the next thing is done; so is what an import did.
  const [problem, setProblem] = useState<string | null>(null);
  const [importNotice, setImportNotice] = useState<string | null>(null);
  const clearMessages = () => {
    setProblem(null);
    setImportNotice(null);
  };

  const applyAndAnnounce = (view: EvtxView) => {
    clearMessages();
    const missing = missingViewChannels(view, heldChannels).length;
    applyView(view);
    announce(
      missing > 0
        ? `Applied ${view.name}. ${missing} of its channels ${missing === 1 ? "is" : "are"} ${absence}.`
        : `Applied ${view.name}.`,
    );
  };

  // One tab stop for the whole toolbar, and arrows between its items (the layout tablist's pattern).
  const itemIds = useMemo(() => [...views.map((view) => view.id), NEW_VIEW_ID], [views]);
  const [tabStop, setTabStop] = useState<string | null>(null);
  const firstActive = views.find((view) => activeIds.has(view.id))?.id;
  const stop = tabStop !== null && itemIds.includes(tabStop) ? tabStop : (firstActive ?? itemIds[0]);
  const itemRefs = useRef<Record<string, HTMLButtonElement | null>>({});
  const focusItem = (id: string) => itemRefs.current[id]?.focus();
  const onToolbarKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const target = event.target as HTMLElement;
    const id = target.closest<HTMLElement>("[data-evtx-view-item]")?.dataset.evtxViewItem;
    if (id === undefined) return;
    const index = itemIds.indexOf(id);
    let next: number;
    switch (event.key) {
      case "ArrowRight":
        next = (index + 1) % itemIds.length;
        break;
      case "ArrowLeft":
        next = (index - 1 + itemIds.length) % itemIds.length;
        break;
      case "Home":
        next = 0;
        break;
      case "End":
        next = itemIds.length - 1;
        break;
      default:
        return;
    }
    event.preventDefault();
    focusItem(itemIds[next]);
  };

  // At most one dialog is open, and the view it concerns is named by id. After it closes, focus goes
  // back to the control that opened it (or to what is left of it).
  type Dialog = { kind: "new" } | { kind: "rename" | "delete"; id: string } | null;
  const [dialog, setDialog] = useState<Dialog>(null);
  const [menuFor, setMenuFor] = useState<string | null>(null);
  // The menu is opened by state, so Fluent does not know a key opened it and leaves focus on the
  // card, out of reach of the arrow keys. Whenever a menu opens, focus its first item.
  useEffect(() => {
    if (menuFor === null) return;
    const timer = setTimeout(() => {
      document.querySelector<HTMLElement>('[role="menu"] [role="menuitem"]')?.focus();
    }, 0);
    return () => clearTimeout(timer);
  }, [menuFor]);
  const focusSoon = (id: string) => setTimeout(() => focusItem(id), 0);
  const closeDialog = (returnTo: string) => {
    setDialog(null);
    focusSoon(returnTo);
  };
  const dialogView =
    dialog !== null && dialog.kind !== "new" ? custom.find((view) => view.id === dialog.id) : undefined;

  const saveNew = (name: string, includeLayout: boolean): EvtxViewFailure | null => {
    const result = useEvtxViewStore
      .getState()
      .create(
        name,
        captureCriteria(useEvtxStore.getState()),
        includeLayout ? captureLayout(useEvtxLayoutStore.getState()) : null,
      );
    if (!result.ok) return result.reason;
    clearMessages();
    announce(`Saved view ${result.view.name}.`);
    return null;
  };
  const renameView = (id: string, name: string): EvtxViewFailure | null => {
    const result = useEvtxViewStore.getState().rename(id, name);
    if (!result.ok) return result.reason;
    clearMessages();
    announce(`Renamed to ${result.view.name}.`);
    return null;
  };
  const updateFromCurrent = (view: EvtxView) => {
    const result = useEvtxViewStore
      .getState()
      .update(view.id, captureCriteria(useEvtxStore.getState()), captureLayout(useEvtxLayoutStore.getState()));
    if (result.ok) {
      clearMessages();
      announce(`Updated ${view.name} from the current filters.`);
    } else {
      setProblem(`${view.name} was not updated. ${viewFailureMessage(result.reason, view.name)}`);
    }
  };
  const duplicateView = (view: EvtxView) => {
    const result = useEvtxViewStore.getState().duplicate(view);
    if (result.ok) {
      clearMessages();
      announce(`Duplicated ${view.name} as ${result.view.name}.`);
      focusSoon(result.view.id);
    } else {
      setProblem(`${view.name} was not duplicated. ${viewFailureMessage(result.reason, view.name)}`);
    }
  };
  const deleteView = (id: string) => {
    // The next item takes the focus the card had. New view follows every custom card, so there is
    // always one: the card after it, or New view when it was the last.
    const next = itemIds[itemIds.indexOf(id) + 1];
    const name = custom.find((view) => view.id === id)?.name ?? "view";
    useEvtxViewStore.getState().remove(id);
    clearMessages();
    announce(`Deleted ${name}.`);
    closeDialog(next);
  };
  // One export at a time: the save dialog is awaited before anything else is in flight.
  const exporting = useRef(false);
  const exportView = async (view: EvtxView) => {
    if (exporting.current) return;
    exporting.current = true;
    clearMessages();
    try {
      const destination = await save({
        defaultPath: `${exportFileStem(view.name)}.json`,
        filters: [{ name: "CMTrace Open view", extensions: ["json"] }],
      });
      if (!destination) return;
      await writeTextFile(destination, buildViewExport([view]));
      announce(`Exported ${view.name}.`);
    } catch (error) {
      setProblem(`${view.name} was not exported. ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      exporting.current = false;
    }
  };

  // Picks a file, reads it as strictly as the library reads anything, and says what it did. The
  // dialog guards against a second pick while one is open.
  const importFromFile = async (): Promise<EvtxViewImportOutcome> => {
    try {
      const chosen = await open({
        multiple: false,
        filters: [{ name: "CMTrace Open view", extensions: ["json"] }],
      });
      if (typeof chosen !== "string") return { kind: "cancelled" };
      const parsed = parseViewExport(await readTextFile(chosen));
      if (!parsed.ok) return { kind: "failed", message: viewImportFailureMessage(parsed.reason) };
      const merged = useEvtxViewStore.getState().importViews(parsed.views);
      const summary = viewImportSummary({ ...merged, skipped: merged.skipped + parsed.skipped });
      setProblem(null);
      // Announced through the persistent region, as every other action is: a live region that mounts
      // already holding its text is not reliably spoken. The notice below is for the eye.
      setImportNotice(summary);
      announce(summary);
      return { kind: "imported" };
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      return { kind: "failed", message: `That file could not be read. ${reason}` };
    }
  };

  const activeStyle: CSSProperties = {
    backgroundColor: selection.background,
    borderColor: selection.border,
    color: selection.foreground,
  };

  return (
    <div
      data-evtx-region="view-strip"
      style={{
        display: "flex",
        alignItems: "center",
        flexWrap: "wrap",
        columnGap: "6px",
        rowGap: "4px",
        padding: "6px 12px 0",
        flexShrink: 0,
        backgroundColor: tokens.colorNeutralBackground1,
        fontSize,
        lineHeight,
      }}
    >
      <span
        aria-hidden
        style={{
          fontSize: eyebrowSize,
          fontWeight: 600,
          letterSpacing: ".08em",
          textTransform: "uppercase",
          color: mutedText,
        }}
      >
        Views
      </span>
      <div
        role="toolbar"
        aria-label="Views"
        onKeyDown={onToolbarKeyDown}
        style={{ display: "flex", flexWrap: "wrap", alignItems: "center", columnGap: "6px", rowGap: "4px" }}
      >
        {views.map((view) => {
          const active = activeIds.has(view.id);
          const missing = active ? missingViewChannels(view, heldChannels).length : 0;
          const subtitle =
            missing > 0
              ? `${viewSubtitle(view)} · ${missing} ${missing === 1 ? "channel" : "channels"} ${absence}`
              : viewSubtitle(view);
          const subtitleId = `evtx-view-subtitle-${view.id}`;
          const menuOpen = menuFor === view.id;
          return (
            <Menu
              key={view.id}
              openOnContext
              open={menuOpen}
              onOpenChange={(_, data) => setMenuFor(data.open ? view.id : null)}
            >
              <MenuTrigger disableButtonEnhancement>
                <button
                  ref={(element) => {
                    itemRefs.current[view.id] = element;
                  }}
                  type="button"
                  className={mergeClasses(styles.card, !active && styles.idle)}
                  style={active ? activeStyle : undefined}
                  aria-pressed={active}
                  aria-label={view.name}
                  aria-describedby={subtitleId}
                  aria-haspopup="menu"
                  title={viewDescription(view)}
                  tabIndex={stop === view.id ? 0 : -1}
                  data-evtx-view-item={view.id}
                  data-evtx-view-card={view.builtIn ? "built-in" : "custom"}
                  onFocus={() => setTabStop(view.id)}
                  onClick={() => applyAndAnnounce(view)}
                  onKeyDown={(event) => {
                    // The context menu from the keyboard, without relying on the webview to turn
                    // these keys into a contextmenu event (WKWebView has no menu key).
                    if (event.key === "ContextMenu" || (event.key === "F10" && event.shiftKey)) {
                      event.preventDefault();
                      setMenuFor(view.id);
                    } else if (event.key === "Escape" && menuOpen) {
                      // The workspace clears a brushed range on Escape unless something used the
                      // key. Closing this menu is that use. Fluent's trigger does not close on a
                      // key that is already prevented, so this closes it.
                      event.preventDefault();
                      setMenuFor(null);
                    }
                  }}
                >
                  <span style={{ fontWeight: 600 }}>{view.name}</span>
                  <span id={subtitleId} style={{ color: active ? selection.foreground : mutedText }}>
                    {subtitle}
                  </span>
                </button>
              </MenuTrigger>
              <MenuPopover>
                <MenuList>
                  {!view.builtIn && (
                    <MenuItem onClick={() => setDialog({ kind: "rename", id: view.id })}>Rename...</MenuItem>
                  )}
                  {!view.builtIn && (
                    <MenuItem onClick={() => updateFromCurrent(view)}>Update from current</MenuItem>
                  )}
                  <MenuItem onClick={() => duplicateView(view)}>Duplicate</MenuItem>
                  {!view.builtIn && (
                    <MenuItem onClick={() => setDialog({ kind: "delete", id: view.id })}>Delete...</MenuItem>
                  )}
                  <MenuItem onClick={() => void exportView(view)}>Export...</MenuItem>
                </MenuList>
              </MenuPopover>
            </Menu>
          );
        })}
        <button
          ref={(element) => {
            itemRefs.current[NEW_VIEW_ID] = element;
          }}
          type="button"
          className={mergeClasses(styles.card, styles.newView)}
          tabIndex={stop === NEW_VIEW_ID ? 0 : -1}
          data-evtx-view-item={NEW_VIEW_ID}
          onFocus={() => setTabStop(NEW_VIEW_ID)}
          onClick={() => setDialog({ kind: "new" })}
        >
          {/* The icon is 16 px by default and the line is 14 at the default size, which would make
              this button 2 px taller than the cards: it takes the line height. */}
          <Add16Regular
            aria-hidden
            data-evtx-new-view-icon
            style={{ width: lineHeight, height: lineHeight, flexShrink: 0 }}
          />
          New view
        </button>
      </div>
      {sourceLabel && (
        <span
          data-evtx-view-source
          style={{ marginLeft: "auto", whiteSpace: "nowrap", color: mutedText }}
        >
          {sourceLabel}
        </span>
      )}
      <span role="status" aria-live="polite" className={styles.visuallyHidden}>
        {announcement.text && <span key={announcement.id}>{announcement.text}</span>}
      </span>
      {importNotice && (
        <div data-evtx-import-notice style={{ flexBasis: "100%", color: mutedText }}>
          {importNotice}
        </div>
      )}
      {problem && (
        <div role="alert" style={{ flexBasis: "100%", color: levels.Error.textColor, overflowWrap: "anywhere" }}>
          {problem}
        </div>
      )}
      <EvtxViewNameDialog
        open={dialog?.kind === "new"}
        title="New view"
        saveLabel="Save"
        initialName=""
        offerLayout
        fontSize={dialogFontSize}
        onClose={() => closeDialog(NEW_VIEW_ID)}
        onSave={saveNew}
        onImport={importFromFile}
      />
      <EvtxViewNameDialog
        open={dialog?.kind === "rename" && dialogView !== undefined}
        title="Rename view"
        saveLabel="Rename"
        initialName={dialogView?.name ?? ""}
        offerLayout={false}
        fontSize={dialogFontSize}
        onClose={() => closeDialog(dialog && dialog.kind !== "new" ? dialog.id : NEW_VIEW_ID)}
        onSave={(name) => (dialog && dialog.kind === "rename" ? renameView(dialog.id, name) : "not-found")}
      />
      <EvtxDeleteViewDialog
        open={dialog?.kind === "delete" && dialogView !== undefined}
        name={dialogView?.name ?? ""}
        fontSize={dialogFontSize}
        onClose={() => closeDialog(dialog && dialog.kind !== "new" ? dialog.id : NEW_VIEW_ID)}
        onConfirm={() => dialog && dialog.kind === "delete" && deleteView(dialog.id)}
      />
    </div>
  );
}
