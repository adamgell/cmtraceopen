import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { tokens } from "@fluentui/react-components";
import { afterEach, describe, expect, it, vi } from "vitest";
import { contrastRatio, parseHex } from "../../lib/color-contrast";
import {
  getLogListMetrics,
  LOG_MONOSPACE_FONT_FAMILY,
  MAX_LOG_LIST_FONT_SIZE,
  MIN_LOG_LIST_FONT_SIZE,
} from "../../lib/log-accessibility";
import { getAllThemes } from "../../lib/themes";
import type { CMTraceTheme } from "../../lib/themes/types";
import { useUiStore } from "../../stores/ui-store";
import type { Marker } from "../../types/markers";
import {
  defaultColumnConfig,
  sanitizeColumnConfig,
  visibleColumns,
  type EvtxColumnConfig,
} from "./evtx-columns";
import {
  buildEvtxRowPalette,
  evtxRowMinWidth,
  EvtxMarkerControls,
  EvtxTimelineHeader,
  EvtxTimelineRow,
  resolveEvtxRowVisualState,
  shortChannelName,
} from "./EvtxTimelineRow";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";
import type { EvtxLevel, EvtxRecord } from "./types";

function record(): EvtxRecord {
  return {
    id: 4,
    eventRecordId: 42,
    timestamp: "2026-08-18 12:00:00",
    timestampEpoch: 1_000,
    provider: "Provider",
    channel: "Application",
    eventId: 100,
    level: "Error",
    computer: "PC01",
    message: "setup failure happened",
    eventData: [],
    rawXml: "<Event />",
    sourceLabel: "Application.evtx",
  };
}

function renderRow(overrides: Partial<React.ComponentProps<typeof EvtxTimelineRow>> = {}) {
  return render(
    <EvtxTimelineRow
      record={record()}
      dataIndex={0}
      isSelected={false}
      fontSize={13}
      monoFontSize={12}
      lineHeight="20px"
      rowHeight={23}
      columnConfig={defaultColumnConfig()}
      columns={visibleColumns(defaultColumnConfig())}
      timeZoneMode="local"
      onSelect={vi.fn()}
      {...overrides}
    />
  );
}

const tagged: Marker = {
  lineId: 5,
  category: "investigate",
  color: "#60a5fa",
  added: "2026-08-18T12:00:00Z",
};

describe("EvtxTimelineRow triage state", () => {
  it("applies selected, marker, severity, match, and default precedence deterministically", () => {
    expect(resolveEvtxRowVisualState({
      isSelected: true,
      marker: tagged,
      level: "Error",
      quickFilterMatch: true,
    })).toBe("selected");
    expect(resolveEvtxRowVisualState({
      isSelected: false,
      marker: tagged,
      level: "Error",
      quickFilterMatch: true,
    })).toBe("marker");
    expect(resolveEvtxRowVisualState({
      isSelected: false,
      marker: null,
      level: "Error",
      quickFilterMatch: true,
    })).toBe("severity");
    expect(resolveEvtxRowVisualState({
      isSelected: false,
      marker: null,
      level: null,
      quickFilterMatch: true,
    })).toBe("match");
    expect(resolveEvtxRowVisualState({
      isSelected: false,
      marker: null,
      level: null,
      quickFilterMatch: false,
    })).toBe("default");
  });
  it("renders text and ARIA metadata when the quick-filter match is enabled", () => {
    renderRow({
      quickFilter: {
        mode: "oneString",
        query: "failure",
        scope: "allColumns",
        action: "show",
        caseSensitive: false,
        highlight: true,
      },
      quickFilterMatch: true,
    });

    expect(screen.getAllByLabelText("Quick-filter match").length).toBeGreaterThan(0);
    expect(screen.getByRole("row")).toHaveAttribute("data-quick-filter-match", "true");
    expect(screen.getByRole("row")).toHaveAttribute(
      "aria-description",
      expect.stringContaining("Quick-filter match"),
    );
  });

  it("keeps selected state ahead of marker state and exposes tag and bookmark by key", () => {
    const onTag = vi.fn();
    const onBookmark = vi.fn();
    renderRow({ marker: tagged, isSelected: true, onTag, onBookmark });

    const row = screen.getByRole("row");
    expect(row).toHaveAttribute("aria-selected", "true");
    expect(row).toHaveAttribute("aria-rowindex", "1");
    expect(row).toHaveAttribute("data-marker-category", "investigate");
    expect(row).toHaveAttribute("data-evtx-visual-state", "selected");
    expect(row).toHaveAttribute(
      "aria-description",
      expect.stringContaining("Tagged investigate"),
    );
    const cells = screen.getAllByRole("gridcell");
    const columns = visibleColumns(defaultColumnConfig());
    // One cell per column and no marker cell: the first cell is the first column.
    expect(cells).toHaveLength(columns.length);
    cells.forEach((cell, index) => {
      expect(cell).toHaveAttribute("aria-colindex", String(index + 1));
    });
    columns.forEach((column, index) => {
      expect(cells[index]).toHaveAccessibleName(new RegExp(`^${column.label}: `));
    });
    fireEvent.keyDown(row, { key: "t" });
    expect(onTag).toHaveBeenCalledWith(expect.objectContaining({ eventRecordId: 42 }));
    fireEvent.keyDown(row, { key: "b" });
    expect(onBookmark).toHaveBeenCalledWith(expect.objectContaining({ eventRecordId: 42 }));
  });

  it("carries no tag or bookmark button and no marker cell (spec 8.7)", () => {
    renderRow({ marker: tagged, quickFilterMatch: true });
    expect(screen.queryAllByRole("button")).toHaveLength(0);
    expect(screen.queryByRole("gridcell", { name: "Event markers" })).toBeNull();
    expect(screen.queryByRole("group", { name: "Event markers" })).toBeNull();
  });

  it("ignores the marker shortcuts when EventRecordID is unavailable", () => {
    const onTag = vi.fn();
    const onBookmark = vi.fn();
    renderRow({
      record: {
        ...record(),
        eventRecordId: 0,
        eventRecordIdText: "0",
      },
      onTag,
      onBookmark,
    });

    const row = screen.getByRole("row");
    expect(row).toHaveAttribute(
      "aria-description",
      expect.stringContaining("Markers unavailable: EventRecordID is missing")
    );
    fireEvent.keyDown(row, { key: "t" });
    fireEvent.keyDown(row, { key: "b" });
    expect(onTag).not.toHaveBeenCalled();
    expect(onBookmark).not.toHaveBeenCalled();
  });

  it("keeps marker shortcuts on the roving row when grouped", () => {
    const onTag = vi.fn();
    const onBookmark = vi.fn();
    renderRow({ grouped: true, onTag, onBookmark, tabIndex: 0 });

    const row = screen.getByRole("row");
    expect(row).toHaveAttribute("aria-level", "1");
    row.focus();
    fireEvent.keyDown(row, { key: "t" });
    fireEvent.keyDown(row, { key: "b" });

    expect(onTag).toHaveBeenCalledWith(expect.objectContaining({ eventRecordId: 42 }));
    expect(onBookmark).toHaveBeenCalledWith(expect.objectContaining({ eventRecordId: 42 }));
    expect(row).toHaveFocus();
  });

  it.each([
    ["Control", { ctrlKey: true }],
    ["Alt", { altKey: true }],
    ["Shift", { shiftKey: true }],
    ["Meta", { metaKey: true }],
  ])("does not run marker shortcuts when the %s modifier is held", (_label, modifier) => {
    const onTag = vi.fn();
    const onBookmark = vi.fn();
    renderRow({ onTag, onBookmark });

    const row = screen.getByRole("row");
    fireEvent.keyDown(row, { key: "t", ...modifier });
    fireEvent.keyDown(row, { key: "b", ...modifier });

    expect(onTag).not.toHaveBeenCalled();
    expect(onBookmark).not.toHaveBeenCalled();
  });

  it("has no nested tab stop, so the row is the only focus target", () => {
    const onTag = vi.fn();
    const onBookmark = vi.fn();
    renderRow({ onTag, onBookmark, tabIndex: 0 });

    const row = screen.getByRole("row");
    expect(row).toHaveAttribute("tabindex", "0");
    expect(row).not.toHaveAttribute("aria-level");
    expect(row.querySelectorAll("button, [tabindex]")).toHaveLength(0);

    row.focus();
    expect(row).toHaveFocus();
    fireEvent.keyDown(row, { key: "t" });
    fireEvent.keyDown(row, { key: "b" });
    expect(onTag).toHaveBeenCalledWith(expect.objectContaining({ eventRecordId: 42 }));
    expect(onBookmark).toHaveBeenCalledWith(expect.objectContaining({ eventRecordId: 42 }));
  });

  it("does not render highlight markup when the control is off", () => {
    renderRow({
      quickFilter: {
        mode: "oneString",
        query: "failure",
        scope: "allColumns",
        action: "show",
        caseSensitive: false,
        highlight: false,
      },
      quickFilterMatch: true,
    });

    expect(screen.queryByLabelText("Quick-filter match")).not.toBeInTheDocument();
    expect(screen.getByRole("row")).toHaveAttribute("data-quick-filter-match", "false");
    expect(screen.getByRole("row")).toHaveAttribute("data-evtx-filter-match", "true");
  });

  it("highlights only substrings matched by the quick-filter regular expression", () => {
    renderRow({
      record: {
        ...record(),
        provider: "é",
        channel: "Å",
        message: "é",
      },
      quickFilter: {
        mode: "oneString",
        query: "e",
        scope: "allColumns",
        action: "show",
        caseSensitive: false,
        highlight: true,
      },
      quickFilterMatch: true,
    });

    expect(screen.queryByLabelText("Quick-filter match")).not.toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------------------------
// Table restyle (#836, spec 8.7, D1, D3, D4, D13, Q-1) and Adam's contrast criterion.
// ---------------------------------------------------------------------------------------------

const LEVELS: readonly EvtxLevel[] = ["Critical", "Error", "Warning", "Information", "Verbose"];
const TINTED_LEVELS: readonly EvtxLevel[] = ["Critical", "Error", "Warning"];
const PLAIN_LEVELS: readonly EvtxLevel[] = ["Information", "Verbose"];
const THEMES = getAllThemes().map((theme) => [theme.id, theme] as const);
const CLASSIC = THEMES.filter(([id]) => id === "classic-cmtrace");

function levelRecord(level: EvtxLevel, partial: Partial<EvtxRecord> = {}): EvtxRecord {
  return { ...record(), level, ...partial };
}

/** The DOM's normalized `rgb(r, g, b)` form of a hex color, as jsdom reports inline styles. */
function rgb(hex: string): string {
  const [r, g, b] = parseHex(hex);
  return `rgb(${r}, ${g}, ${b})`;
}

/** The inline-style form of a CSS color string from the token module: `var(...)` or hex. */
function asStyle(css: string): string {
  return css.startsWith("#") ? rgb(css) : css;
}

/** Resolves an inline style color (`rgb(...)` from jsdom, or `var(--token)`) to hex in `theme`. */
function toHex(css: string, theme: CMTraceTheme): string {
  const match = /^rgb\((\d+), (\d+), (\d+)\)$/.exec(css);
  if (match) {
    return `#${[match[1], match[2], match[3]]
      .map((channel) => Number(channel).toString(16).padStart(2, "0"))
      .join("")}`;
  }
  return resolveToken(css, theme);
}

function setTheme(themeId: CMTraceTheme["id"]) {
  useUiStore.setState({ themeId });
}

afterEach(() => {
  cleanup();
  setTheme("light");
});

const cell = (label: RegExp) => screen.getByRole("gridcell", { name: label });
const styleOf = (element: Element) => (element as HTMLElement).style;

/** Every element of a rendered row that draws text, keyed by role. */
function textElements() {
  return {
    time: cell(/^Event Time:/),
    eventId: cell(/^Event ID:/),
    channel: cell(/^Channel:/),
    provider: cell(/^Provider:/),
    message: cell(/^Description:/),
    links: cell(/^Links:/),
  };
}

type TextRole = keyof ReturnType<typeof textElements>;

/**
 * A highlighting quick filter whose terms occur in every visible text cell of `highlightRecord`:
 * "x" in the provider, channel and message, "0" and "1" in the time and the event ID.
 */
const HIGHLIGHT_FILTER = {
  mode: "multipleWords" as const,
  query: "x 0 1",
  scope: "visibleColumns" as const,
  action: "show" as const,
  caseSensitive: false,
  highlight: true,
};

function highlightRecord(level: EvtxLevel): EvtxRecord {
  return levelRecord(level, {
    provider: "Provider-x",
    channel: "Application x",
    message: "x failure x",
  });
}

function renderFullRow(level: EvtxLevel, isSelected: boolean) {
  return renderRow({
    record: highlightRecord(level),
    isSelected,
    linkCount: 3,
    channelIndex: 2,
    quickFilter: HIGHLIGHT_FILTER,
    quickFilterMatch: true,
  });
}

/** The color of a `1px solid <color>` outline, as the DOM reports it. */
function outlineColor(element: HTMLElement): string {
  const match = /^1px solid (.+)$/.exec(element.style.outline);
  if (!match) throw new Error(`Expected a 1px solid outline, got "${element.style.outline}"`);
  return match[1];
}

describe("EvtxTimelineRow palette (spec D3, 6.2, 8.7)", () => {
  it.each(TINTED_LEVELS)("tints a %s row with its row background and row text, row-wide", (level) => {
    for (const [, theme] of THEMES) {
      const visual = buildEvtxVisualTokens(theme);
      const palette = buildEvtxRowPalette(visual, level, false);
      expect(palette.background).toBe(visual.levels[level].rowBackground);
      expect(palette.ink).toBe(visual.levels[level].rowText);
    }
  });

  it.each([
    ["Critical", "error"],
    ["Error", "error"],
    ["Warning", "warning"],
  ] as const)("takes the %s tint from severityPalette.%s", (level, kind) => {
    for (const [, theme] of THEMES) {
      const palette = buildEvtxRowPalette(buildEvtxVisualTokens(theme), level, false);
      expect(palette.background).toBe(theme.severityPalette[kind].background);
      expect(palette.ink).toBe(theme.severityPalette[kind].text);
    }
  });

  it.each(PLAIN_LEVELS)("leaves a %s row on the default surface", (level) => {
    for (const [, theme] of THEMES) {
      const palette = buildEvtxRowPalette(buildEvtxVisualTokens(theme), level, false);
      expect(palette.background).toBe(tokens.colorNeutralBackground1);
      expect(palette.selectionInset).toBeNull();
    }
  });

  it("uses the light-blue selection triplet on a selected row, whatever its level", () => {
    for (const [, theme] of THEMES) {
      for (const level of LEVELS) {
        const palette = buildEvtxRowPalette(buildEvtxVisualTokens(theme), level, true);
        expect(palette.background).toBe(tokens.colorPaletteBlueBackground2);
        expect(palette.ink).toBe(tokens.colorPaletteBlueForeground2);
        expect(palette.selectionInset).toBe(tokens.colorPaletteBlueBorderActive);
      }
    }
  });
});

describe.each(THEMES)("row text contrast in the %s theme (issue #836)", (_id, theme) => {
  const visual = buildEvtxVisualTokens(theme);
  const FLOOR = 4.5;

  /** Every text role of a row at the resolved colors the palette gives it. */
  function measured(level: EvtxLevel, isSelected: boolean) {
    const palette = buildEvtxRowPalette(visual, level, isSelected);
    const background = resolveToken(palette.background, theme);
    const pairs: [string, string][] = [
      ["time (secondary)", palette.secondary],
      ["provider (secondary)", palette.secondary],
      ["event ID, channel and message (ink)", palette.ink],
      ["links cell", palette.link],
    ];
    return { palette, background, pairs };
  }

  it.each(TINTED_LEVELS)("keeps every text role at 4.5:1 on a %s row", (level) => {
    const { background, pairs } = measured(level, false);
    const failures = pairs
      .map(([name, color]) => [name, resolveToken(color, theme)] as const)
      .map(([name, hex]) => [name, hex, contrastRatio(hex, background)] as const)
      .filter(([, , ratio]) => ratio < FLOOR)
      .map(([name, hex, ratio]) => `${theme.id} ${level} row ${name} ${hex} on ${background} = ${ratio.toFixed(2)}`);
    expect(failures, failures.join("; ")).toEqual([]);
  });

  it.each(LEVELS)("keeps every text role at 4.5:1 on a selected %s row", (level) => {
    const { background, pairs } = measured(level, true);
    const failures = pairs
      .map(([name, color]) => [name, resolveToken(color, theme)] as const)
      .map(([name, hex]) => [name, hex, contrastRatio(hex, background)] as const)
      .filter(([, , ratio]) => ratio < FLOOR)
      .map(([name, hex, ratio]) => `${theme.id} selected ${level} row ${name} ${hex} on ${background} = ${ratio.toFixed(2)}`);
    expect(failures, failures.join("; ")).toEqual([]);
  });

  it.each(PLAIN_LEVELS)("keeps every text role at 4.5:1 on a plain %s row", (level) => {
    const { background, pairs } = measured(level, false);
    const failures = pairs
      .map(([name, color]) => [name, resolveToken(color, theme)] as const)
      .map(([name, hex]) => [name, hex, contrastRatio(hex, background)] as const)
      .filter(([, , ratio]) => ratio < FLOOR)
      .map(([name, hex, ratio]) => `${theme.id} ${level} row ${name} ${hex} on ${background} = ${ratio.toFixed(2)}`);
    expect(failures, failures.join("; ")).toEqual([]);
  });

  it("keeps the level icon at 3:1 on a tinted or plain row and 4.5:1 on a selected one", () => {
    const failures: string[] = [];
    for (const level of LEVELS) {
      for (const isSelected of [false, true]) {
        const palette = buildEvtxRowPalette(visual, level, isSelected);
        const icon = resolveToken(palette.icon, theme);
        const background = resolveToken(palette.background, theme);
        const floor = isSelected ? 4.5 : 3;
        const ratio = contrastRatio(icon, background);
        if (ratio < floor) {
          failures.push(`${theme.id} ${isSelected ? "selected " : ""}${level} icon ${icon} on ${background} = ${ratio.toFixed(2)} (< ${floor})`);
        }
      }
    }
    expect(failures, failures.join("; ")).toEqual([]);
  });

  it("keeps the channel swatch outline at 3:1 on every row that draws one", () => {
    const failures: string[] = [];
    for (const level of LEVELS) {
      for (const isSelected of [false, true]) {
        const palette = buildEvtxRowPalette(visual, level, isSelected);
        if (!palette.swatchOutline) continue;
        const outline = resolveToken(palette.swatchOutline, theme);
        const background = resolveToken(palette.background, theme);
        const ratio = contrastRatio(outline, background);
        if (ratio < 3) {
          failures.push(`${theme.id} ${isSelected ? "selected " : ""}${level} outline ${outline} on ${background} = ${ratio.toFixed(2)}`);
        }
      }
    }
    expect(failures, failures.join("; ")).toEqual([]);
  });

  it("outlines the swatch on every tinted or selected row and on no plain one", () => {
    for (const level of LEVELS) {
      const tinted = TINTED_LEVELS.includes(level);
      expect(buildEvtxRowPalette(visual, level, true).swatchOutline).not.toBeNull();
      expect(buildEvtxRowPalette(visual, level, false).swatchOutline !== null).toBe(tinted);
    }
  });
});

describe("the pairs Adam named in issue #836, measured in the classic theme", () => {
  it.each(CLASSIC)("holds Time, Provider and Links to 4.5:1 on the %s Error row and selection", (_id, theme) => {
    const visual = buildEvtxVisualTokens(theme);
    const report: string[] = [];
    for (const isSelected of [false, true]) {
      const palette = buildEvtxRowPalette(visual, "Error", isSelected);
      const background = resolveToken(palette.background, theme);
      for (const [name, color] of [
        ["Time", palette.secondary],
        ["Provider", palette.secondary],
        ["Links", palette.link],
      ] as const) {
        const ratio = contrastRatio(resolveToken(color, theme), background);
        report.push(`${isSelected ? "selected" : "Error row"} ${name} ${ratio.toFixed(2)}`);
        expect(ratio, report.join("; ")).toBeGreaterThanOrEqual(4.5);
      }
    }
  });

  it.each(THEMES.filter(([id]) => id === "dark"))("holds Links to 4.5:1 on the %s Warning and Error rows", (_id, theme) => {
    const visual = buildEvtxVisualTokens(theme);
    for (const level of ["Warning", "Error"] as const) {
      const palette = buildEvtxRowPalette(visual, level, false);
      const ratio = contrastRatio(
        resolveToken(palette.link, theme),
        resolveToken(palette.background, theme),
      );
      expect(ratio, `${theme.id} ${level} links ${ratio.toFixed(2)}`).toBeGreaterThanOrEqual(4.5);
    }
  });
});

describe.each(THEMES)("EvtxTimelineRow rendering in the %s theme", (_id, theme) => {
  const visual = buildEvtxVisualTokens(theme);

  it.each(LEVELS.flatMap((level) => [[level, false] as const, [level, true] as const]))(
    "draws every text role of a %s row (selected: %s) in the palette color, and each pair measures 4.5:1",
    (level, isSelected) => {
      setTheme(theme.id);
      renderFullRow(level, isSelected);
      const palette = buildEvtxRowPalette(visual, level, isSelected);
      const row = screen.getByRole("row");
      const els = textElements();
      const expected: Record<TextRole, string> = {
        time: palette.secondary,
        eventId: palette.ink,
        channel: palette.ink,
        provider: palette.secondary,
        message: palette.ink,
        links: palette.link,
      };

      expect(styleOf(row).backgroundColor).toBe(asStyle(palette.background));
      expect(styleOf(row).color).toBe(asStyle(palette.ink));

      // Measured from what the DOM actually carries, not from the palette: if rendering drifts
      // to another color, this fails even when the palette itself is fine.
      const background = toHex(styleOf(row).backgroundColor, theme);
      const failures: string[] = [];
      for (const role of Object.keys(expected) as TextRole[]) {
        expect(styleOf(els[role]).color, `${role} color`).toBe(asStyle(expected[role]));
        const hex = toHex(styleOf(els[role]).color, theme);
        const ratio = contrastRatio(hex, background);
        if (ratio < 4.5) {
          failures.push(`${theme.id} ${isSelected ? "selected " : ""}${level} ${role} ${hex} on ${background} = ${ratio.toFixed(2)}`);
        }
      }

      // The quick-filter highlight, in every cell that carries a term. It keeps the cell's text
      // color, draws no fill (so it cannot be taken for a row tint or the selection), and is
      // outlined in the row's primary text color, which is at 4.5:1 or better on the row.
      for (const role of ["time", "eventId", "channel", "provider", "message"] as const) {
        const marks = [...els[role].querySelectorAll<HTMLElement>("mark")];
        expect(marks.length, `${role} highlight`).toBeGreaterThan(0);
        for (const mark of marks) {
          expect(mark.style.backgroundColor, `${role} highlight fill`).toBe("transparent");
          expect(mark.style.color, `${role} highlight text`).toBe("inherit");
          // Inside the mark's box, so a cell's clipping cannot cut off the left edge of a match
          // that starts the cell. An outline takes no layout space.
          expect(mark.style.outlineOffset, `${role} highlight outline offset`).toBe("-1px");
          // The outline shorthand is reported as written, not normalized to rgb().
          expect(outlineColor(mark), `${role} highlight outline`).toBe(palette.highlight);
          expect(mark.getAttribute("style"), `${role} highlight underline`).toMatch(
            /text-decoration-line:\s*underline/,
          );
          const outline = toHex(outlineColor(mark), theme);
          const ratio = contrastRatio(outline, background);
          if (ratio < 4.5) {
            failures.push(`${theme.id} ${isSelected ? "selected " : ""}${level} ${role} highlight outline ${outline} on ${background} = ${ratio.toFixed(2)}`);
          }
        }
      }
      expect(failures, failures.join("; ")).toEqual([]);
    },
  );
});

describe("the quick-filter highlight on rows its tint would swallow", () => {
  it.each(CLASSIC)("stays visible on a %s Warning row, where the browser default is #FFFF00 on #FFFF00", (_id, theme) => {
    setTheme(theme.id);
    renderRow({
      record: highlightRecord("Warning"),
      quickFilter: HIGHLIGHT_FILTER,
      quickFilterMatch: true,
    });
    const row = styleOf(screen.getByRole("row"));
    const mark = cell(/^Description:/).querySelector<HTMLElement>("mark")!;
    const background = toHex(row.backgroundColor, theme);
    // The classic Warning tint is the browser's own highlight yellow, so a default mark vanishes.
    expect(background).toBe("#ffff00");
    expect(mark.style.backgroundColor).toBe("transparent");
    const ratio = contrastRatio(toHex(outlineColor(mark), theme), background);
    expect(ratio).toBeGreaterThanOrEqual(4.5);
  });

  it("takes no box space: no padding, margin or border, so no cell's layout changes", () => {
    renderRow({ record: highlightRecord("Information"), quickFilter: HIGHLIGHT_FILTER, quickFilterMatch: true });
    const marks = [...document.querySelectorAll<HTMLElement>("mark")];
    expect(marks.length).toBeGreaterThan(0);
    for (const mark of marks) {
      const attribute = mark.getAttribute("style") ?? "";
      expect(attribute).not.toMatch(/(^|;\s*)(padding|margin|border)(-[a-z]+)?:/);
      expect(mark.style.outlineOffset).toBe("-1px");
    }
  });

  it("is a visible highlight, not the browser default, on every row of the light theme", () => {
    setTheme("light");
    for (const level of LEVELS) {
      renderRow({ record: highlightRecord(level), quickFilter: HIGHLIGHT_FILTER, quickFilterMatch: true });
      const mark = cell(/^Description:/).querySelector<HTMLElement>("mark")!;
      expect(mark.style.backgroundColor, `${level} fill`).toBe("transparent");
      expect(mark.style.outline, `${level} outline`).not.toBe("");
      cleanup();
    }
  });
});

describe("EvtxTimelineRow layout and typography (spec D1, D4, 8.7)", () => {
  it.each([MIN_LOG_LIST_FONT_SIZE, 13, MAX_LOG_LIST_FONT_SIZE])(
    "is exactly the metrics row height at list font size %i, with room for its line",
    (fontSize) => {
      const metrics = getLogListMetrics(fontSize);
      renderRow({
        rowHeight: metrics.rowHeight,
        fontSize: metrics.fontSize,
        lineHeight: `${metrics.rowLineHeight}px`,
      });
      const row = styleOf(screen.getByRole("row"));
      expect(row.height).toBe(`${metrics.rowHeight}px`);
      expect(row.boxSizing).toBe("border-box");
      // No vertical padding, and a 1 px bottom border, so the line must fit in what is left.
      expect(row.paddingTop).toBe("");
      expect(row.paddingBottom).toBe("");
      expect(row.borderBottom).toBe(`1px solid ${tokens.colorNeutralStroke3}`);
      expect(metrics.rowLineHeight).toBeLessThanOrEqual(metrics.rowHeight - 1);
    },
  );

  it("draws no zebra stripe: neighbouring plain rows share one background", () => {
    const first = renderRow({ record: levelRecord("Information"), dataIndex: 0 });
    const even = styleOf(screen.getByRole("row")).backgroundColor;
    first.unmount();
    renderRow({ record: levelRecord("Information"), dataIndex: 1 });
    expect(styleOf(screen.getByRole("row")).backgroundColor).toBe(even);
    expect(even).toBe(tokens.colorNeutralBackground1);
  });

  it("sets time and ID in the numeric face with tabular figures, the ID at 700 weight", () => {
    renderRow();
    const time = styleOf(cell(/^Event Time:/));
    const id = styleOf(cell(/^Event ID:/));
    for (const style of [time, id]) {
      expect(style.fontFamily).toBe(tokens.fontFamilyNumeric);
      expect(style.fontVariantNumeric).toBe("tabular-nums");
    }
    expect(time.fontSize).toBe("12px");
    expect(time.whiteSpace).toBe("nowrap");
    expect(id.fontWeight).toBe("700");
    expect(id.fontSize).toBe("13px");
  });

  it("keeps the monospace face for the message only", () => {
    renderRow();
    expect(styleOf(cell(/^Description:/)).fontFamily).toBe(LOG_MONOSPACE_FONT_FAMILY);
    for (const label of [/^Event Time:/, /^Event ID:/, /^Provider:/, /^Channel:/, /^Links:/]) {
      expect(styleOf(cell(label)).fontFamily).not.toBe(LOG_MONOSPACE_FONT_FAMILY);
    }
  });

  it("gives the optional numeric columns the numeric face too", () => {
    const config = sanitizeColumnConfig({
      order: ["level", "recordId", "processId", "keywords", "computer", "message"],
      widths: {},
    });
    renderRow({
      columnConfig: config,
      columns: visibleColumns(config),
      record: levelRecord("Information", { processId: 4242 }),
    });
    for (const label of [/^Record ID:/, /^PID:/]) {
      expect(styleOf(cell(label)).fontFamily).toBe(tokens.fontFamilyNumeric);
      expect(styleOf(cell(label)).fontVariantNumeric).toBe("tabular-nums");
    }
    expect(styleOf(cell(/^Keywords:/)).fontFamily).toBe(LOG_MONOSPACE_FONT_FAMILY);
    expect(styleOf(cell(/^Computer:/)).fontFamily).not.toBe(LOG_MONOSPACE_FONT_FAMILY);
  });

  it.each([MIN_LOG_LIST_FONT_SIZE, 13, MAX_LOG_LIST_FONT_SIZE])(
    "sets the optional columns and map columns at the grid font size, %ipx, not below it",
    (listFont) => {
      const metrics = getLogListMetrics(listFont);
      const config = sanitizeColumnConfig({
        order: [
          "level",
          "recordId",
          "computer",
          "task",
          "opcode",
          "processId",
          "threadId",
          "keywords",
          "mapped:RemoteHost",
          "provider",
          "message",
        ],
        widths: {},
      });
      renderRow({
        columnConfig: config,
        columns: visibleColumns(config),
        fontSize: metrics.fontSize,
        monoFontSize: Math.max(10, metrics.fontSize - 1),
        record: levelRecord("Information", {
          task: 7,
          opcode: 1,
          processId: 4242,
          threadId: 99,
          keywords: "0x8000000000000000",
          mapped: [{ property: "RemoteHost", text: "host-1", complete: true }],
        }),
      });
      const expected = `${metrics.fontSize}px`;
      for (const label of [
        /^Record ID:/,
        /^Computer:/,
        /^Task:/,
        /^Opcode:/,
        /^PID:/,
        /^TID:/,
        /^Keywords:/,
        /^RemoteHost:/,
        /^Provider:/,
      ]) {
        expect(styleOf(cell(label)).fontSize, String(label)).toBe(expected);
      }
      // Keywords keeps the monospace face; the time is the one cell at f - 1.
      expect(styleOf(cell(/^Keywords:/)).fontFamily).toBe(LOG_MONOSPACE_FONT_FAMILY);
      // The numeric columns keep the numeric face at that size.
      for (const label of [/^Record ID:/, /^Task:/, /^Opcode:/, /^PID:/, /^TID:/]) {
        expect(styleOf(cell(label)).fontFamily, String(label)).toBe(tokens.fontFamilyNumeric);
      }
      expect(styleOf(cell(/^Computer:/)).fontFamily).not.toBe(tokens.fontFamilyNumeric);
      expect(styleOf(cell(/^RemoteHost:/)).fontFamily).not.toBe(tokens.fontFamilyNumeric);
    },
  );

  it("sizes each cell from the shared column widths", () => {
    renderRow();
    const config = defaultColumnConfig();
    const widths: Record<string, string> = {
      Level: "32px",
      "Event Time": "154px",
      "Event ID": "52px",
      Channel: "120px",
      Provider: "162px",
      Links: "44px",
    };
    for (const column of visibleColumns(config)) {
      const element = styleOf(cell(new RegExp(`^${column.label}:`)));
      if (column.label === "Description") {
        expect(element.flexGrow).toBe("1");
      } else {
        expect(element.width).toBe(widths[column.label]);
        expect(element.flexShrink).toBe("0");
      }
    }
  });
});

describe("EvtxTimelineRow minimum width", () => {
  it("is the insets, every column with a width, and the gaps", () => {
    const config = defaultColumnConfig();
    // 4 + 12 + 12 insets, 32 + 154 + 52 + 120 + 162 + 44 widths (the description has none), and 6
    // gaps of 10 between the 7 cells. There is no marker cell.
    expect(evtxRowMinWidth(config, visibleColumns(config))).toBe(28 + 564 + 60);
  });

  it("follows the widths a configuration sets and the columns it shows", () => {
    const config = sanitizeColumnConfig({
      order: ["level", "timestamp", "message"],
      widths: { timestamp: 165, message: 300 },
    });
    expect(evtxRowMinWidth(config, visibleColumns(config))).toBe(28 + (32 + 165 + 300) + 20);
  });

  it("is applied to the row, so its background spans the columns when the grid scrolls sideways", () => {
    const config = defaultColumnConfig();
    renderRow({ columnConfig: config, columns: visibleColumns(config) });
    expect(styleOf(screen.getByRole("row")).minWidth).toBe(
      `${evtxRowMinWidth(config, visibleColumns(config))}px`,
    );
  });
});

describe("EvtxTimelineRow level cell (spec D13, 7.3)", () => {
  it.each(LEVELS)("shows %s as an icon with an accessible name, not as colored text", (level) => {
    renderRow({ record: levelRecord(level) });
    const levelCell = cell(/^Level:/);
    expect(levelCell).toHaveAccessibleName(`Level: ${level}`);
    expect(screen.getByRole("img", { name: level })).toBeInTheDocument();
    expect(levelCell).toContainElement(screen.getByRole("img", { name: level }));
    // The old ERR / WARN badge text is gone.
    expect(levelCell).toHaveTextContent("");
    expect(screen.getByRole("row")).toHaveAccessibleName(new RegExp(`Level: ${level}`));
  });

  it("draws a different icon shape for every level, so severity is not carried by color alone", () => {
    const shapes = new Set<string>();
    for (const level of LEVELS) {
      const view = renderRow({ record: levelRecord(level) });
      shapes.add(screen.getByRole("img", { name: level }).innerHTML);
      view.unmount();
    }
    expect(shapes.size).toBe(LEVELS.length);
  });

  it("has no left severity border: only a marker color may occupy the left slot", () => {
    renderRow({ record: levelRecord("Critical") });
    expect(styleOf(screen.getByRole("row")).borderLeft).toBe("");
  });

  it("centers the icon in the level column, in the level's icon color", () => {
    setTheme("light");
    renderRow({ record: levelRecord("Warning") });
    const levelCell = styleOf(cell(/^Level:/));
    expect(levelCell.justifyContent).toBe("center");
    expect(levelCell.color).toBe(
      asStyle(buildEvtxRowPalette(buildEvtxVisualTokens(THEMES[0][1]), "Warning", false).icon),
    );
  });
});

describe("EvtxTimelineRow selection (spec 6.2, Q-1)", () => {
  it("draws the blue triplet: background, 3 px inset and text", () => {
    renderRow({ record: levelRecord("Error"), isSelected: true });
    const row = styleOf(screen.getByRole("row"));
    expect(row.backgroundColor).toBe(tokens.colorPaletteBlueBackground2);
    expect(row.color).toBe(tokens.colorPaletteBlueForeground2);
    expect(row.boxShadow).toBe(`inset 3px 0 0 ${tokens.colorPaletteBlueBorderActive}`);
  });

  it("draws no inset on a row that is not selected", () => {
    renderRow({ record: levelRecord("Error") });
    expect(styleOf(screen.getByRole("row")).boxShadow).toBe("");
  });

  it("adds a cue that forced colors keeps, as its own element so the row's focus ring survives", () => {
    renderRow({ record: levelRecord("Error"), isSelected: true });
    const row = screen.getByRole("row");
    const cue = row.querySelector<HTMLElement>("[data-evtx-selected-cue]")!;
    expect(cue).not.toBeNull();
    // Forced colors replaces the background and drops the inset box-shadow; a transparent
    // outline is drawn in the system color there and is invisible everywhere else.
    expect(cue.style.outline).toBe("2px solid transparent");
    expect(cue.style.outlineOffset).toBe("-2px");
    expect(cue.style.position).toBe("absolute");
    expect(cue.style.pointerEvents).toBe("none");
    expect(cue).toHaveAttribute("aria-hidden", "true");
    // On its own element, not the row: an inline outline on the row would replace the browser's
    // focus ring on the row that keyboard navigation selects.
    expect(styleOf(row).outline).toBe("");
    expect(row.querySelectorAll("[role=gridcell]")).toHaveLength(
      visibleColumns(defaultColumnConfig()).length,
    );
  });

  it("adds no cue to a row that is not selected", () => {
    renderRow({ record: levelRecord("Error") });
    expect(screen.getByRole("row").querySelector("[data-evtx-selected-cue]")).toBeNull();
  });

  it("does not bold the selected message or recolor it brand", () => {
    renderRow({ isSelected: true });
    const message = styleOf(cell(/^Description:/));
    expect(message.fontWeight).toBe("");
    expect(message.color).toBe(tokens.colorPaletteBlueForeground2);
  });
});

describe("EvtxTimelineRow marker slot (spec 8.7)", () => {
  it("puts the marker color in a 4 px left slot", () => {
    renderRow({ marker: tagged, record: levelRecord("Information") });
    expect(styleOf(screen.getByRole("row")).borderLeft).toBe(`4px solid ${rgb(tagged.color)}`);
  });

  it("does not tint the row with the marker color", () => {
    renderRow({ marker: tagged, record: levelRecord("Information") });
    expect(styleOf(screen.getByRole("row")).backgroundColor).toBe(tokens.colorNeutralBackground1);
    cleanup();
    renderRow({ marker: tagged, record: levelRecord("Error") });
    expect(styleOf(screen.getByRole("row")).backgroundColor).toBe(
      asStyle(buildEvtxVisualTokens(THEMES[0][1]).levels.Error.rowBackground),
    );
  });

  it("keeps the marker and the selection inset side by side on a selected, marked row", () => {
    renderRow({ marker: tagged, isSelected: true });
    const row = styleOf(screen.getByRole("row"));
    expect(row.borderLeft).toBe(`4px solid ${rgb(tagged.color)}`);
    expect(row.boxShadow).toBe(`inset 3px 0 0 ${tokens.colorPaletteBlueBorderActive}`);
    expect(row.backgroundColor).toBe(tokens.colorPaletteBlueBackground2);
  });

  it("keeps content at the same x whether or not a marker is present", () => {
    renderRow();
    const unmarked = styleOf(screen.getByRole("row"));
    const unmarkedX = parseFloat(unmarked.paddingLeft) + parseFloat(unmarked.borderLeftWidth || "0");
    cleanup();
    renderRow({ marker: tagged });
    const marked = styleOf(screen.getByRole("row"));
    const markedX = parseFloat(marked.paddingLeft) + parseFloat(marked.borderLeftWidth || "0");
    expect(unmarkedX).toBe(16);
    expect(markedX).toBe(16);
  });

  it("lays the columns out the same in every marker state, since no cell changes width", () => {
    const layouts = new Set<string>();
    for (const props of [
      {},
      { marker: tagged },
      { marker: { ...tagged, category: "bookmark" } as Marker },
      { quickFilterMatch: true },
      { record: { ...record(), eventRecordId: 0, eventRecordIdText: "0" } },
    ] as Partial<React.ComponentProps<typeof EvtxTimelineRow>>[]) {
      const view = renderRow(props);
      const cells = screen.getAllByRole("gridcell");
      expect(cells[0]).toHaveAccessibleName(/^Level:/);
      layouts.add(cells.map((cell) => styleOf(cell).width || styleOf(cell).flexGrow).join(","));
      view.unmount();
    }
    expect(layouts.size).toBe(1);
  });
});

describe("EvtxTimelineRow quick-filter match state", () => {
  it("is carried by data attributes and the row's description, with no extra element", () => {
    renderRow({ quickFilterMatch: true });
    const row = screen.getByRole("row");
    expect(row).toHaveAttribute("data-evtx-filter-match", "true");
    expect(row).toHaveAttribute("aria-description", expect.stringContaining("Quick-filter match"));
    // No icon, label or other element is added for a match: with a show-mode filter every row
    // shown matched and with hide mode none did, so it would tell nothing per row.
    expect(row.querySelector("[data-evtx-filter-match-label]")).toBeNull();
    // The level icon is the only icon in the row (the links cell is empty).
    expect(row.querySelectorAll("svg")).toHaveLength(1);
    expect(screen.getAllByRole("gridcell")).toHaveLength(visibleColumns(defaultColumnConfig()).length);
  });

  it("is absent when the row is not a match", () => {
    renderRow();
    const row = screen.getByRole("row");
    expect(row).toHaveAttribute("data-evtx-filter-match", "false");
    expect(row).not.toHaveAttribute("aria-description", expect.stringContaining("Quick-filter match"));
  });
});

describe("EvtxMarkerControls in the Details pane", () => {
  it("offers tag and bookmark buttons that call back and reflect the marker", () => {
    const onTag = vi.fn();
    const onBookmark = vi.fn();
    render(
      <EvtxMarkerControls
        record={record()}
        marker={tagged}
        markerAddressable
        fontSize={13}
        variant="detail"
        onTag={onTag}
        onBookmark={onBookmark}
      />,
    );
    expect(screen.getByRole("group", { name: "Selected event markers" })).toBeInTheDocument();
    const tag = screen.getByRole("button", { name: "Remove event tag" });
    const bookmark = screen.getByRole("button", { name: "Bookmark event" });
    expect(tag).toHaveTextContent("Tagged: investigate");
    expect(tag).toHaveAttribute("aria-pressed", "true");
    expect(bookmark).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(tag);
    fireEvent.click(bookmark);
    expect(onTag).toHaveBeenCalledWith(expect.objectContaining({ eventRecordId: 42 }));
    expect(onBookmark).toHaveBeenCalledWith(expect.objectContaining({ eventRecordId: 42 }));
  });

  it("disables both buttons when EventRecordID is unavailable", () => {
    const onTag = vi.fn();
    render(
      <EvtxMarkerControls
        record={record()}
        marker={null}
        markerAddressable={false}
        fontSize={13}
        variant="detail"
        onTag={onTag}
      />,
    );
    const tag = screen.getByRole("button", { name: "EventRecordID unavailable; tagging is disabled" });
    expect(tag).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "EventRecordID unavailable; bookmarking is disabled" }),
    ).toBeDisabled();
    fireEvent.click(tag);
    expect(onTag).not.toHaveBeenCalled();
  });
});

describe("EvtxTimelineRow channel cell (spec 8.7)", () => {
  it.each([
    ["Microsoft-Windows-AAD/Operational", "AAD/Operational"],
    ["System", "System"],
    ["Application", "Application"],
    ["Microsoft-Windows-", "Microsoft-Windows-"],
    ["Microsoft-Windows-Kernel-Power", "Kernel-Power"],
  ])("shortens %s to %s", (channel, short) => {
    expect(shortChannelName(channel)).toBe(short);
  });

  it("shows the short name, with the full name in the tooltip and the accessible name", () => {
    renderRow({ record: levelRecord("Information", { channel: "Microsoft-Windows-AAD/Operational" }) });
    const channel = cell(/^Channel:/);
    expect(channel).toHaveTextContent("AAD/Operational");
    expect(channel).toHaveAttribute("title", "Microsoft-Windows-AAD/Operational");
    expect(channel).toHaveAccessibleName("Channel: Microsoft-Windows-AAD/Operational");
  });

  it("draws no swatch when the channel's display position is unknown", () => {
    renderRow();
    expect(document.querySelector("[data-evtx-channel-swatch]")).toBeNull();
  });

  it("draws a 7 px swatch in the channel color, outlined on a tinted row and not on a plain one", () => {
    setTheme("light");
    const light = buildEvtxVisualTokens(THEMES[0][1]);
    renderRow({ record: levelRecord("Error"), channelIndex: 8 });
    const tinted = styleOf(document.querySelector("[data-evtx-channel-swatch]")!);
    expect(tinted.width).toBe("7px");
    expect(tinted.height).toBe("7px");
    expect(tinted.borderRadius).toBe("2px");
    // Index 8 wraps to the third of six, as the token map cycles every six.
    expect(tinted.backgroundColor).toBe(asStyle(light.channelColor(2)));
    expect(tinted.outline).toBe(`1px solid ${light.markOutline("Error")}`);
    cleanup();
    renderRow({ record: levelRecord("Information"), channelIndex: 8 });
    expect(styleOf(document.querySelector("[data-evtx-channel-swatch]")!).outline).toBe("");
  });
});

describe("EvtxTimelineRow links cell (spec 8.7)", () => {
  const links = () => cell(/^Links:/);

  it("is empty when no count was supplied, and does not claim zero", () => {
    renderRow();
    expect(links()).toBeEmptyDOMElement();
    expect(links()).toHaveAttribute("data-evtx-links-cell", "empty");
    expect(links()).toHaveAccessibleName("Links: Empty");
    expect(links()).not.toHaveAttribute("title");
  });

  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
    "is empty for a count of %s, which is no link",
    (linkCount) => {
      renderRow({ linkCount });
      expect(links()).toBeEmptyDOMElement();
      expect(links()).toHaveAttribute("data-evtx-links-cell", "empty");
    },
  );

  it("shows a link icon and the count in 600 weight at the small size", () => {
    renderRow({ linkCount: 3 });
    expect(links()).toHaveTextContent("3");
    expect(links()).toHaveAttribute("data-evtx-links-cell", "count");
    expect(links()).toHaveAccessibleName("Links: 3");
    expect(links()).toHaveAttribute("title", "3 linked events");
    expect(links().querySelector("svg")).not.toBeNull();
    const style = styleOf(links());
    expect(style.fontWeight).toBe("600");
    expect(style.fontSize).toBe("10px");
    expect(style.fontFamily).toBe(tokens.fontFamilyNumeric);
  });

  it.each([
    [MIN_LOG_LIST_FONT_SIZE, "10px"],
    [13, "10px"],
    [16, "13px"],
    [MAX_LOG_LIST_FONT_SIZE, "17px"],
  ])("sizes the count at the font size minus 3 but never below 10: list font %i gives %s", (fontSize, expected) => {
    // The small size the Timeline used to pass floored at 9, below section 7.1's caption floor,
    // so the links cell derives its own from the font size.
    const metrics = getLogListMetrics(fontSize);
    renderRow({ linkCount: 3, fontSize: metrics.fontSize });
    expect(styleOf(links()).fontSize).toBe(expected);
  });

  it("says one linked event in the singular", () => {
    renderRow({ linkCount: 1 });
    expect(links()).toHaveAttribute("title", "1 linked event");
  });

  it("is link-colored on a plain row and takes the row's text color on tinted and selected rows", () => {
    renderRow({ record: levelRecord("Information"), linkCount: 2 });
    expect(styleOf(links()).color).toBe(tokens.colorBrandForegroundLink);
    cleanup();
    renderRow({ record: levelRecord("Information"), linkCount: 2, isSelected: true });
    expect(styleOf(links()).color).toBe(tokens.colorPaletteBlueForeground2);
    cleanup();
    setTheme("classic-cmtrace");
    renderRow({ record: levelRecord("Error"), linkCount: 2 });
    expect(styleOf(links()).color).toBe(
      asStyle(buildEvtxVisualTokens(CLASSIC[0][1]).levels.Error.rowText),
    );
  });

  it("renders no links cell when a saved configuration does not show the column", () => {
    const config: EvtxColumnConfig = sanitizeColumnConfig({
      order: ["level", "timestamp", "eventId", "channel", "provider", "message"],
      widths: { level: 40, timestamp: 165 },
    });
    renderRow({ columnConfig: config, columns: visibleColumns(config), linkCount: 3 });
    expect(screen.queryByRole("gridcell", { name: /^Links:/ })).toBeNull();
    expect(styleOf(cell(/^Event Time:/)).width).toBe("165px");
  });
});

describe("EvtxTimelineHeader (spec 8.7)", () => {
  function renderHeader(
    overrides: Partial<React.ComponentProps<typeof EvtxTimelineHeader>> = {},
  ) {
    const config = overrides.columnConfig ?? defaultColumnConfig();
    return render(
      <EvtxTimelineHeader
        columns={visibleColumns(config)}
        columnConfig={config}
        fontSize={13}
        headerLineHeight={24}
        sortField="time"
        sortDirection="desc"
        {...overrides}
      />,
    );
  }
  const header = () => document.querySelector<HTMLElement>("[data-evtx-table-header]")!;
  const headerCell = (id: string) =>
    document.querySelector<HTMLElement>(`[data-evtx-header-cell="${id}"]`)!;

  it("is hidden from assistive technology and adds no row to the grid", () => {
    renderHeader();
    expect(header()).toHaveAttribute("aria-hidden", "true");
    expect(screen.queryAllByRole("row")).toHaveLength(0);
    expect(screen.queryAllByRole("columnheader")).toHaveLength(0);
  });

  it("is Background3 with a Stroke1 bottom border, 600 weight at the font size minus one", () => {
    renderHeader();
    const style = styleOf(header());
    expect(style.backgroundColor).toBe(tokens.colorNeutralBackground3);
    expect(style.borderBottom).toBe(`1px solid ${tokens.colorNeutralStroke1}`);
    expect(style.fontWeight).toBe("600");
    expect(style.fontSize).toBe("12px");
    expect(style.color).toBe(tokens.colorNeutralForeground2);
  });

  it.each([
    [MIN_LOG_LIST_FONT_SIZE],
    [13],
    [MAX_LOG_LIST_FONT_SIZE],
  ])("is the metrics header line height plus 2 px at list font size %i", (listFontSize) => {
    const metrics = getLogListMetrics(listFontSize);
    renderHeader({
      fontSize: metrics.fontSize,
      headerLineHeight: metrics.headerLineHeight,
    });
    const style = styleOf(header());
    expect(style.height).toBe(`${metrics.headerLineHeight + 2}px`);
    expect(style.boxSizing).toBe("border-box");
    expect(style.fontSize).toBe(`${metrics.fontSize - 1}px`);
  });

  it("holds its labels at 4.5:1 on Background3 in every theme", () => {
    const failures: string[] = [];
    for (const [, theme] of THEMES) {
      const label = resolveToken(tokens.colorNeutralForeground2, theme);
      const background = resolveToken(tokens.colorNeutralBackground3, theme);
      const ratio = contrastRatio(label, background);
      if (ratio < 4.5) failures.push(`${theme.id} ${label} on ${background} = ${ratio.toFixed(2)}`);
    }
    expect(failures, failures.join("; ")).toEqual([]);
  });

  it("has one cell per visible column, in order, labeled with the column", () => {
    renderHeader();
    const ids = [...header().querySelectorAll("[data-evtx-header-cell]")].map((element) =>
      element.getAttribute("data-evtx-header-cell"),
    );
    expect(ids).toEqual(visibleColumns(defaultColumnConfig()).map((c) => c.id));
    expect(headerCell("timestamp")).toHaveTextContent("Event Time");
    // "Event ID" does not fit 52 px in 600 weight, so the header says "ID" and keeps the full
    // name as its tooltip; the cells and the chooser still use "Event ID".
    expect(headerCell("eventId")).toHaveTextContent(/^ID$/);
    expect(headerCell("eventId")).toHaveAttribute("title", "Event ID");
    expect(headerCell("provider")).toHaveTextContent("Provider");
    expect(headerCell("message")).toHaveTextContent("Description");
  });

  it("shows the Links header as the link icon, with the column name as a tooltip", () => {
    renderHeader();
    expect(headerCell("links")).toHaveTextContent("");
    expect(headerCell("links").querySelector("svg")).not.toBeNull();
    expect(headerCell("links")).toHaveAttribute("title", "Links");
  });

  it("puts every column at the same width and x as its row cell", () => {
    const config = sanitizeColumnConfig({
      order: ["level", "timestamp", "eventId", "channel", "provider", "message", "links"],
      widths: { channel: 133 },
    });
    renderHeader({ columnConfig: config });
    renderRow({ columnConfig: config, columns: visibleColumns(config), linkCount: 2 });
    const rowStyle = styleOf(screen.getByRole("row"));
    // Same left inset (4 px slot + 12 px padding) and the same right padding.
    expect(parseFloat(styleOf(header()).paddingLeft)).toBe(parseFloat(rowStyle.paddingLeft));
    expect(styleOf(header()).paddingRight).toBe(rowStyle.paddingRight);
    expect(styleOf(header()).gap).toBe(rowStyle.gap);
    for (const column of visibleColumns(config)) {
      const rowCell = styleOf(cell(new RegExp(`^${column.label}:`)));
      const headCell = styleOf(headerCell(column.id));
      expect(headCell.width, `${column.id} width`).toBe(rowCell.width);
      expect(headCell.flexShrink, `${column.id} flex-shrink`).toBe(rowCell.flexShrink);
      expect(headCell.flexGrow, `${column.id} flex-grow`).toBe(rowCell.flexGrow);
    }
    expect(styleOf(headerCell("channel")).width).toBe("133px");
  });

  it("shows the sort direction on the time header when sorted by time", () => {
    const view = renderHeader({ sortField: "time", sortDirection: "desc" });
    expect(headerCell("timestamp").querySelector("[data-evtx-sort-direction]")).toHaveAttribute(
      "data-evtx-sort-direction",
      "desc",
    );
    const down = headerCell("timestamp").querySelector("svg")!.innerHTML;
    view.unmount();
    renderHeader({ sortField: "time", sortDirection: "asc" });
    expect(headerCell("timestamp").querySelector("[data-evtx-sort-direction]")).toHaveAttribute(
      "data-evtx-sort-direction",
      "asc",
    );
    // A different glyph, not the same chevron with a different attribute.
    expect(headerCell("timestamp").querySelector("svg")!.innerHTML).not.toBe(down);
  });

  it.each(["eventId", "level", "provider", "channel"] as const)(
    "shows no direction on the time header when sorted by %s",
    (sortField) => {
      renderHeader({ sortField });
      expect(header().querySelector("[data-evtx-sort-direction]")).toBeNull();
    },
  );

  it("omits the links header when a saved configuration does not show the column", () => {
    const config = sanitizeColumnConfig({
      order: ["level", "timestamp", "message"],
      widths: { timestamp: 165 },
    });
    renderHeader({ columnConfig: config });
    expect(headerCell("links")).toBeNull();
    expect(styleOf(headerCell("timestamp")).width).toBe("165px");
  });
});
