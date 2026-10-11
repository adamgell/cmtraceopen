/**
 * The "More filters" popover (spec section 8.3): event IDs, the quick filter, saved filters.
 *
 * It also holds sort and the time zone. The spec gives those two no home on the filter row, the
 * view bar or the table header, and the issue requires every capability of the old filter bar to
 * stay reachable, so they sit in a "Display" section here. They are not criteria and do not count
 * toward the button's number.
 */
import { useEffect, useMemo, useState } from "react";
import {
  Button,
  Checkbox,
  Dropdown,
  Input,
  Option,
  Popover,
  PopoverSurface,
  PopoverTrigger,
  tokens,
} from "@fluentui/react-components";
import { ArrowDown16Regular, ArrowUp16Regular } from "@fluentui/react-icons";
import {
  EVTX_QUICK_FILTER_ACTIONS,
  EVTX_QUICK_FILTER_MODES,
  EVTX_QUICK_FILTER_SCOPES,
  parseEventIdSelectors,
  type EvtxQuickFilterAction,
  type EvtxQuickFilterMode,
  type EvtxQuickFilterScope,
} from "./evtx-filter";
import { useFilterChips, type EvtxFilterChip } from "./EvtxFilterChips";
import { useSavedFilterStore } from "./evtx-filter-store";
import { orderFilters, sanitizeCriteria } from "./evtx-saved-filters";
import { timeZoneLabel } from "./evtx-time";
import { useEvtxStore, type EvtxSortField } from "./evtx-store";
import type { EvtxVisualTokens } from "./evtx-visual-tokens";

const EVENT_ID_VALIDATION_HELP = "Use decimal Event IDs or ranges from 0 to 4294967295.";

const SORT_FIELD_LABELS: Record<EvtxSortField, string> = {
  time: "Time",
  eventId: "Event ID",
  level: "Level",
  provider: "Provider",
  channel: "Channel",
};

const SORT_FIELDS: EvtxSortField[] = ["time", "eventId", "level", "provider", "channel"];

// Records, so a mode added later (the field grammar in Phase 5b, #833) fails to compile until it
// has a label here.
const QUICK_FILTER_MODE_LABELS: Record<EvtxQuickFilterMode, string> = {
  oneString: "One string",
  multipleWords: "Any words",
  multipleStrings: "Any strings",
  allWords: "All words",
  allStrings: "All strings",
  eventIds: "Event IDs",
};
const QUICK_FILTER_SCOPE_LABELS: Record<EvtxQuickFilterScope, string> = {
  allColumns: "All columns",
  visibleColumns: "Visible columns",
};
const QUICK_FILTER_ACTION_LABELS: Record<EvtxQuickFilterAction, string> = {
  show: "Show matches",
  hide: "Hide matches",
};

/**
 * The number on the button: every active criterion that is not visible on the filter row as a level
 * toggle, the search box or the time window (spec 8.3). Those are the chips other than the search
 * text: a channel subset, Event IDs and the quick filter, and later the transient time range and
 * record scope. Case, highlight, mode, scope and action tune the quick filter and are not criteria
 * of their own, and sort and the time zone are not criteria at all.
 */
export function moreFiltersActiveCount(chips: readonly EvtxFilterChip[]): number {
  return chips.filter((chip) => chip.id !== "search").length;
}

interface EvtxMoreFiltersProps {
  controlFontSize: string;
  visual: EvtxVisualTokens;
}

export function EvtxMoreFilters({ controlFontSize, visual }: EvtxMoreFiltersProps) {
  const filterEventIds = useEvtxStore((s) => s.filterEventIds);
  const setFilterEventIds = useEvtxStore((s) => s.setFilterEventIds);
  const quickFilter = useEvtxStore((s) => s.quickFilter);
  const setQuickFilter = useEvtxStore((s) => s.setQuickFilter);
  const sortField = useEvtxStore((s) => s.sortField);
  const setSortField = useEvtxStore((s) => s.setSortField);
  const sortDirection = useEvtxStore((s) => s.sortDirection);
  const setSortDirection = useEvtxStore((s) => s.setSortDirection);
  const timeZoneMode = useEvtxStore((s) => s.timeZoneMode);
  const setTimeZoneMode = useEvtxStore((s) => s.setTimeZoneMode);
  const setGroupBy = useEvtxStore((s) => s.setGroupBy);
  const setBeforeLoadCriteria = useEvtxStore((s) => s.setBeforeLoadCriteria);
  const setFilterSearch = useEvtxStore((s) => s.setFilterSearch);

  // Event IDs are a before-load criterion: committing a list refetches the loaded channels in live
  // mode. So the field edits a draft, and the list is committed on Enter or blur, never per
  // keystroke, and never while it is invalid ("4624,abc" would otherwise be sent on the way to a
  // valid list). The draft follows the store when something else changes it: a chip, Clear all or
  // a saved filter.
  const [eventIdsDraft, setEventIdsDraft] = useState(filterEventIds);
  useEffect(() => setEventIdsDraft(filterEventIds), [filterEventIds]);
  const eventIdInputInvalid = useMemo(
    () => parseEventIdSelectors(eventIdsDraft).invalid,
    [eventIdsDraft],
  );
  const commitEventIds = () => {
    if (eventIdInputInvalid || eventIdsDraft === filterEventIds) return;
    setFilterEventIds(eventIdsDraft);
  };
  const quickEventIdInputInvalid = useMemo(
    () => quickFilter.mode === "eventIds" && parseEventIdSelectors(quickFilter.query).invalid,
    [quickFilter.mode, quickFilter.query],
  );
  const activeCount = moreFiltersActiveCount(useFilterChips().chips);

  const savedFilters = useSavedFilterStore((s) => s.savedFilters);
  const saveFilter = useSavedFilterStore((s) => s.save);
  const markFilterUsed = useSavedFilterStore((s) => s.markUsed);
  // The one ordering, not a second one. A re-implementation here once dropped the lastUsed
  // tiebreak, so marking a filter used changed the stored order and never changed what the
  // operator saw.
  const orderedFilters = useMemo(() => orderFilters(savedFilters), [savedFilters]);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  // An in-app field rather than window.prompt. Tauri's macOS webview is WKWebView, which does not
  // implement prompt, so the save-filter action silently did nothing on macOS.
  const [pendingName, setPendingName] = useState<string | null>(null);

  const commitFilterName = (name: string) => {
    const trimmed = name.trim();
    if (!trimmed) return;
    const state = useEvtxStore.getState();
    const saved = saveFilter(
      trimmed,
      sanitizeCriteria({
        beforeLoad: {
          levels: [...state.filterLevels],
          eventIds: state.filterEventIds,
          timeWindow: state.timeWindow,
          selectedChannels: [...state.selectedChannels],
        },
        onLoad: {
          search: state.filterSearch,
          quickFilter: state.quickFilter,
        },
        afterLoad: { groupBy: state.groupBy },
      }),
    );
    setPendingName(null);
    setStatusMessage(saved ? `Saved "${trimmed}"` : "That name cannot be used");
  };

  const applySavedFilter = (id: string) => {
    const filter = savedFilters.find((candidate) => candidate.id === id);
    if (!filter) return;
    const { criteria } = filter;
    setBeforeLoadCriteria(criteria.beforeLoad);
    setFilterSearch(criteria.onLoad.search);
    setQuickFilter(criteria.onLoad.quickFilter);
    setGroupBy(criteria.afterLoad.groupBy);
    markFilterUsed(id);
  };

  const nextSortDirectionLabel = sortDirection === "asc" ? "descending" : "ascending";
  // Grammar errors read in the Warning text color (spec 8.3), which clears 4.5:1 on the popover
  // surface in all seven themes. It replaces the red palette tokens the old bar used.
  const invalidColor = visual.levels.Warning.textColor;
  const invalidStyle = { color: invalidColor, fontSize: controlFontSize };
  const sectionLabelStyle = {
    fontSize: controlFontSize,
    fontWeight: 600,
    color: tokens.colorNeutralForeground2,
  } as const;
  const sectionStyle = { display: "flex", flexDirection: "column", gap: "6px" } as const;
  const rowStyle = { display: "flex", flexWrap: "wrap", alignItems: "center", gap: "8px" } as const;

  return (
    <Popover positioning="below-end" trapFocus>
      <PopoverTrigger disableButtonEnhancement>
        <Button
          size="small"
          title="Event IDs, the quick filter, saved filters, sort and time zone"
          style={{
            minWidth: "auto",
            minHeight: "28px",
            padding: "2px 10px",
            fontSize: controlFontSize,
          }}
        >
          {`More filters · ${activeCount}`}
        </Button>
      </PopoverTrigger>
      <PopoverSurface
        aria-label="More filters"
        style={{
          boxShadow: tokens.shadow8,
          width: "440px",
          maxWidth: "calc(100vw - 24px)",
          display: "flex",
          flexDirection: "column",
          gap: "14px",
        }}
      >
        <div style={sectionStyle}>
          <span style={sectionLabelStyle}>Event IDs</span>
          <span style={{ display: "inline-flex", alignItems: "center", gap: "8px" }}>
            <Input
              input={{ style: { fontSize: controlFontSize } }}
              aria-label="Event IDs"
              aria-invalid={eventIdInputInvalid}
              aria-describedby={eventIdInputInvalid ? "event-id-filter-error" : undefined}
              title={eventIdInputInvalid ? EVENT_ID_VALIDATION_HELP : undefined}
              value={eventIdsDraft}
              onChange={(_, data) => setEventIdsDraft(data.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") commitEventIds();
              }}
              onBlur={commitEventIds}
              placeholder="Event IDs (comma sep.)"
              size="small"
              style={{
                width: "200px",
                borderColor: eventIdInputInvalid ? invalidColor : undefined,
              }}
            />
            {eventIdInputInvalid && (
              <span
                id="event-id-filter-error"
                role="alert"
                aria-label="Invalid Event IDs"
                title={EVENT_ID_VALIDATION_HELP}
                style={invalidStyle}
              >
                Invalid Event IDs
              </span>
            )}
          </span>
        </div>

        <div style={sectionStyle}>
          <span style={sectionLabelStyle}>Quick filter</span>
          <span style={{ display: "inline-flex", alignItems: "center", gap: "8px" }}>
            <Input
              input={{ style: { fontSize: controlFontSize } }}
              value={quickFilter.query}
              onChange={(_, data) => setQuickFilter({ ...quickFilter, query: data.value })}
              placeholder={
                quickFilter.mode === "eventIds" ? "Quick IDs (e.g. 4624-4626)" : "Quick filter..."
              }
              aria-label="Quick filter query"
              aria-invalid={quickEventIdInputInvalid}
              aria-describedby={quickEventIdInputInvalid ? "quick-event-id-filter-error" : undefined}
              title={quickEventIdInputInvalid ? EVENT_ID_VALIDATION_HELP : undefined}
              size="small"
              style={{
                width: "200px",
                borderColor: quickEventIdInputInvalid ? invalidColor : undefined,
              }}
            />
            {quickEventIdInputInvalid && (
              <span
                id="quick-event-id-filter-error"
                role="alert"
                aria-label="Invalid quick Event IDs"
                title={EVENT_ID_VALIDATION_HELP}
                style={invalidStyle}
              >
                Invalid quick Event IDs
              </span>
            )}
          </span>
          <div style={rowStyle}>
            {/* inlinePopup keeps each listbox inside the surface, so choosing an option is not an outside click. */}
            <Dropdown
              button={{ style: { fontSize: controlFontSize } }}
              inlinePopup
              size="small"
              aria-label="Quick filter matching grammar"
              value={QUICK_FILTER_MODE_LABELS[quickFilter.mode]}
              selectedOptions={[quickFilter.mode]}
              title="Quick filter matching grammar"
              style={{ minWidth: "120px" }}
              onOptionSelect={(_, data) => {
                if (data.optionValue) {
                  setQuickFilter({
                    ...quickFilter,
                    mode: data.optionValue as EvtxQuickFilterMode,
                  });
                }
              }}
            >
              {EVTX_QUICK_FILTER_MODES.map((mode) => (
                <Option key={mode} value={mode} style={{ fontSize: controlFontSize }}>
                  {QUICK_FILTER_MODE_LABELS[mode]}
                </Option>
              ))}
            </Dropdown>
            <Dropdown
              button={{ style: { fontSize: controlFontSize } }}
              inlinePopup
              size="small"
              aria-label="Quick filter column scope"
              value={QUICK_FILTER_SCOPE_LABELS[quickFilter.scope]}
              selectedOptions={[quickFilter.scope]}
              title="Quick filter column scope"
              style={{ minWidth: "120px" }}
              onOptionSelect={(_, data) => {
                if (data.optionValue) {
                  setQuickFilter({
                    ...quickFilter,
                    scope: data.optionValue as EvtxQuickFilterScope,
                  });
                }
              }}
            >
              {EVTX_QUICK_FILTER_SCOPES.map((scope) => (
                <Option key={scope} value={scope} style={{ fontSize: controlFontSize }}>
                  {QUICK_FILTER_SCOPE_LABELS[scope]}
                </Option>
              ))}
            </Dropdown>
            <Dropdown
              button={{ style: { fontSize: controlFontSize } }}
              inlinePopup
              size="small"
              aria-label="Quick filter show or hide behavior"
              value={QUICK_FILTER_ACTION_LABELS[quickFilter.action]}
              selectedOptions={[quickFilter.action]}
              title="Quick filter show or hide behavior"
              style={{ minWidth: "120px" }}
              onOptionSelect={(_, data) => {
                if (data.optionValue) {
                  setQuickFilter({
                    ...quickFilter,
                    action: data.optionValue as EvtxQuickFilterAction,
                  });
                }
              }}
            >
              {EVTX_QUICK_FILTER_ACTIONS.map((action) => (
                <Option key={action} value={action} style={{ fontSize: controlFontSize }}>
                  {QUICK_FILTER_ACTION_LABELS[action]}
                </Option>
              ))}
            </Dropdown>
          </div>
          <div style={rowStyle}>
            <Checkbox
              checked={quickFilter.caseSensitive}
              label={<span style={{ fontSize: controlFontSize }}>Case</span>}
              title="Case-sensitive quick filter"
              onChange={(_, data) =>
                setQuickFilter({ ...quickFilter, caseSensitive: data.checked === true })
              }
            />
            <Checkbox
              checked={quickFilter.highlight}
              label={<span style={{ fontSize: controlFontSize }}>Highlight</span>}
              title="Highlight quick-filter matches"
              onChange={(_, data) =>
                setQuickFilter({ ...quickFilter, highlight: data.checked === true })
              }
            />
          </div>
        </div>

        <div style={sectionStyle}>
          <span style={sectionLabelStyle}>Saved filters</span>
          <div style={rowStyle}>
            <Dropdown
              button={{ style: { fontSize: controlFontSize } }}
              inlinePopup
              size="small"
              aria-label="Saved filters"
              placeholder="Saved"
              value=""
              selectedOptions={[]}
              style={{ minWidth: "160px" }}
              title="Apply a saved filter"
              onOptionSelect={(_, data) => {
                if (data.optionValue === "__save__") setPendingName("");
                else if (data.optionValue) applySavedFilter(data.optionValue);
              }}
            >
              <Option value="__save__" style={{ fontSize: controlFontSize }}>
                Save current...
              </Option>
              {orderedFilters.map((filter) => (
                <Option key={filter.id} value={filter.id} style={{ fontSize: controlFontSize }}>
                  {filter.favorite ? `★ ${filter.name}` : filter.name}
                </Option>
              ))}
            </Dropdown>
            {pendingName !== null && (
              <Input
                input={{ style: { fontSize: controlFontSize } }}
                autoFocus
                size="small"
                value={pendingName}
                placeholder="Name this filter"
                aria-label="Name this filter"
                style={{ width: "180px" }}
                onChange={(_, data) => setPendingName(data.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") commitFilterName(pendingName);
                  if (event.key === "Escape") setPendingName(null);
                }}
                onBlur={() => setPendingName(null)}
              />
            )}
          </div>
          {statusMessage && (
            <span style={{ fontSize: controlFontSize, color: tokens.colorNeutralForeground2 }}>
              {statusMessage}
            </span>
          )}
        </div>

        <div style={sectionStyle}>
          <span style={sectionLabelStyle}>Display</span>
          <div style={rowStyle}>
            <span style={{ fontSize: controlFontSize, color: tokens.colorNeutralForeground2 }}>
              Sort:
            </span>
            <Dropdown
              button={{ style: { fontSize: controlFontSize } }}
              inlinePopup
              aria-label="Sort by"
              value={SORT_FIELD_LABELS[sortField]}
              selectedOptions={[sortField]}
              onOptionSelect={(_, data) => {
                if (data.optionValue) setSortField(data.optionValue as EvtxSortField);
              }}
              size="small"
              style={{ minWidth: "100px" }}
            >
              {SORT_FIELDS.map((field) => (
                <Option key={field} value={field} style={{ fontSize: controlFontSize }}>
                  {SORT_FIELD_LABELS[field]}
                </Option>
              ))}
            </Dropdown>
            <Button
              size="small"
              appearance="outline"
              aria-label={`Change sort direction to ${nextSortDirectionLabel}`}
              onClick={() => setSortDirection(sortDirection === "asc" ? "desc" : "asc")}
              title={`Change sort direction to ${nextSortDirectionLabel}`}
              style={{ minWidth: "auto", padding: "2px 6px", fontSize: controlFontSize }}
            >
              {sortDirection === "asc" ? <ArrowUp16Regular /> : <ArrowDown16Regular />}
            </Button>
            <Button
              size="small"
              appearance="outline"
              onClick={() => setTimeZoneMode(timeZoneMode === "local" ? "utc" : "local")}
              style={{ minWidth: "auto", padding: "2px 8px", fontSize: controlFontSize }}
              title={
                timeZoneMode === "utc"
                  ? "Event times are shown in UTC, as Windows recorded them. Click for local time."
                  : "Event times are shown in this machine's local time. Click for UTC, which is what most other logs use."
              }
            >
              {timeZoneLabel(timeZoneMode)}
            </Button>
          </div>
        </div>
      </PopoverSurface>
    </Popover>
  );
}
