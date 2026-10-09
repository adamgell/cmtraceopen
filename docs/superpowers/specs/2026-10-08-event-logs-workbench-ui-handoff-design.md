# Event Logs workbench: UI handoff specification

- **Date:** 2026-10-08
- **Parent issue:** [#539 Event Log Viewer Preview: validation and productization ledger](https://github.com/adamgell/cmtraceopen/issues/539), originally "Event Viewer: become best in class". This spec covers the presentation side of its Phase 3 (analysis UX), Phase 4 (unified timeline) and Phase 7 (diagnosis) items.
- **Status:** Approved by the maintainer on 2026-10-08. Every decision is recorded in §13.1.
- **Tracking issue:** [#823 Event Logs workbench UI (design handoff)](https://github.com/adamgell/cmtraceopen/issues/823), with one sub-issue per phase and follow-up (#825–#858). GitHub is the source of truth for status; this document is the design contract.
- **Design source:** Claude Design canvas "Event Log Viewer Redesign", page "Event Logs — full UI" (<https://claude.ai/artifact/51jKg6P4feMjy3DzSwbX8Z>). The canvas is private to the maintainer. Attach PNG exports of the referenced boards to each GitHub issue so the issues stay self-contained.
- **Baseline:** `main` at `558e93d5`.

## 1. Summary

This document turns the Event Logs workbench mockups into implementation contracts:

- the layout, measurements, colors, type, copy and interactions to build;
- the deviations required by the governing documents;
- the mapping from each mockup element to existing code and store fields;
- the new pure modules each element needs;
- a phased delivery plan, with ready-to-paste GitHub issue drafts in Appendix A.

The target is the closest achievable match to the mockups that still stays inside the event viewer epic's invariants and the design system's rules.

## 2. Precedence, fidelity and labels

### 2.1 Precedence

When two sources conflict, the higher one wins.

1. [Event viewer epic design](2026-08-18-event-viewer-epic-design.md): non-goals and invariants. The one that most shapes this spec is "No causality inferred from timestamp proximity alone."
2. [Event diagnosis output repair](2026-08-29-event-diagnosis-output.md): bounded diagnosis surfaces, render caps and the actionable-finding semantics.
3. Design system: [`docs/design-system/SKILL.md`](../../design-system/SKILL.md) and the theme TypeScript files under `src/lib/themes/`. Where `tokens.css` and the TS files disagree, the TS files win.
4. This specification.
5. The mockups.

### 2.2 Fidelity rule

The mockups define:

- region order and nesting;
- control order, grouping and labels;
- measurements, at a 1440×900 viewport, 100% zoom, with `logListFontSize` at its default of 13;
- visual hierarchy and interaction behavior.

Implementations match the measurements in §5 to within ±2 px.

Colors are never copied from the mockup source. Every color resolves through §6.

Every intentional difference from the mockups is listed in §4. Any other visible difference is a defect against this spec.

### 2.3 Labels used in this document

| Label | Meaning |
|---|---|
| **[Verified]** | Checked against the repository at the baseline commit, the installed packages, or Microsoft Learn. |
| **[Recommendation]** | The author's proposed decision. It may be overridden in review. |
| **[Unverified]** | Not yet confirmed. It must be validated before the dependent work starts. |
| **Q-n** | A question the maintainer has decided (§13.1). This numbering is local to this spec. Design-system open questions are always written "design-system OQ-n". |

## 3. Scope

### 3.1 In scope: v1 triage workbench

- **View bar:**
  - a layout switcher for Table, Grouped, Timeline, Charts and Correlation;
  - panel toggles for Channels, Insights and Correlation dock;
  - Group by, Columns and Export.
- **Filter row:** search, level toggles with counts, time window, and a "More filters" entry point.
- **Active filter chip row**, with a visible-count readout.
- **Event histogram**, with brush-to-filter.
- **Channel pane**, with per-channel activity sparklines, error and warning counts, coverage state, and a live-tail footer.
- **The five views:**
  - Table (the existing grid, restyled);
  - Grouped (an event-ID summary table);
  - Timeline (provider swimlanes);
  - Charts (a KPI and chart dashboard);
  - Correlation (chains plus a zoomed lane plot).
- **Correlation dock** under the main view, following the selected record.
- **Insights rail**, with an Insights tab (findings, level mix, top event IDs, correlation summary) and a Details tab (the selected event).
- **Event Logs status bar content and workspace toolbar action.** The status bar content extends the existing `event-log` branch in `StatusBar.tsx`; the toolbar action uses the `WorkspaceDefinition.toolbarAction` extension point.
- **A screenshot harness** for the Event Logs workspace, with a synthetic fixture equivalent to the mockup data.
- **Custom views and the view strip** ("+ New view", Q-5). These are user-saved presets of filters plus layout, with one built-in preset, Enrollment triage.
- **"Compare with previous period"** (Q-8). Loads an equal-length prior window on demand, so delta KPIs are real values rather than estimates.
- **Extra exports** (Q-6):
  - a Markdown report, redacted;
  - an EVTX subset, Windows only and unredacted, behind a confirmation gate.
- **"Add log source…"** (Q-11). Attaches text logs to the analysis session from the channel pane.
- **Global status bar aligned to the design system** (Q-7). This is 24 px with the brand background and applies to every workspace (§8.18).

### 3.2 In scope: v2 scenario views

- Built-in scenario presets for Autopilot / ESP, App installs and Stability, added to the v1 view strip.
- Three scenario layouts: Autopilot / ESP provisioning, App installs, and Stability (boot sessions and crashes).
- App installs and Autopilot / ESP summarize events and deep-link to the existing Intune and ESP Diagnostics workspaces (Q-13). They do not embed those workspaces' models.

### 3.3 Out of scope

- **Global toolbar and title bar.** This covers "Open EVTX…", Error lookup, the workspace selector and the theme menu. The mockup header row is a stand-in for existing chrome. The global status bar is in scope (§8.18).
- **Rust correlation-engine changes.** New identifier kinds such as `EventData/EnrollmentId` (Q-9) and a windowed timeline query (Q-10) are tracked as separate follow-up issues under #539 (§15.2).
- **DSRegCmd redesign.** Option A ("Verdict first") was selected and is specified in [its own handoff spec](2026-10-08-dsregcmd-verdict-first-handoff-design.md) (Q-14; Appendix B.3). Only the Phase 0a consistency fix is included here.

### 3.4 Mockup data disclaimer

All mockup data is fictional. This includes the Contoso machine names, the IDs, the counts and the user name "adele". Sample numbers are illustrative only and are not acceptance values. The synthetic screenshot fixture (Phase 2) reproduces the mockup dataset, so screenshots can be compared side by side. It replaces every user name with a neutral placeholder such as `user01`, in line with the epic's fixture rule.

## 4. Required deviations from the mockups

| # | Mockup | Implementation | Governing rule |
|---|---|---|---|
| D1 | Grid rows 24 px at 12 px font; header 26 px | Row height = `getLogListMetrics(logListFontSize).rowHeight`, which is 23 px at 13 px. Header height = `metrics.headerLineHeight` + 2 px padding. Grid text uses `metrics.fontSize`. | DS rule 3; epic Phase 3 font-sizing item |
| D2 | 30 px workspace footer with its own "Event Logs" pill and neutral background | Counts render in the global `StatusBar`, through its existing `event-log` branch. Per Q-7 the global bar becomes 24 px on `colorBrandBackground` for every workspace (§8.18). The "Event Logs" pill is the existing view label. | DS rules 3 and 5; DS: chrome is signage |
| D3 | Only Critical and Error rows tinted, faintly | Critical and Error rows use `severityPalette.error.background` / `.text`, row-wide. Warning rows use `severityPalette.warning.*`, row-wide. Information and Verbose use the default surface, with no zebra striping. | DS rule 1 |
| D4 | Timestamps, IDs, record IDs and counts in Cascadia Mono | Use `tokens.fontFamilyNumeric` with `font-variant-numeric: tabular-nums`. `LOG_MONOSPACE_FONT_FAMILY` is reserved for message text, EventData, raw XML, identifier values and log-line content. | DS rule 2 |
| D5 | Text glyphs ▾ ⛓ ✓ × ⚡ ↑ ↓ ✕ ◷ → | Fluent icons (§7.3) | DS: no emoji; Fluent icons only |
| D6 | Teal fills and borders on the active layout button, panel toggles, scenario cards, brush outline, chips, selected-row inset and exact connectors | Active toggles use `colorNeutralBackground1Selected` with `colorBrandForeground1` text. Selection uses the blue palette triplet (§6.2). Exact connectors use `colorPaletteBlueBorderActive`. Brand teal is kept only for primary buttons, the active-tab underline (rail tabs) and link text (`colorBrandForegroundLink`). | DS rule 5 |
| D7 | A "Time only" chain in the chain list, a dotted connector, and "1 time-only" in the summary | `timestampOnly` / `notCausal` relations are never chains, never drawn as connectors, and never counted as correlations. They appear only in a collapsed **"Nearby, not linked"** group and as unconnected context markers, labelled "Not linked". | Epic non-goal |
| D8 | Rail finding "DNS 1014 … precedes token broker failures" | Finding cards render only `DiagnosisFinding` output from the engine. The UI never synthesizes findings or wording that implies a temporal relationship. Mockup finding copy is illustrative. | Epic non-goal; diagnosis output spec |
| D9 | Strength labels Explicit / Secondary / Unresolved / Time only | Exact / Candidate / Ambiguous / Coverage blocked / Not linked. This aligns with `TimelineCorrelationStrength`, `DiagnosisCorrelationStatus` and the existing `UnifiedTimelineView` copy. | Consistency with the shipped vocabulary |
| D10 | Channel hues: System blue, Application orange, AAD green, DeviceManagement amber, Security pink | Per-theme cool-hue channel tokens in `severityPalette.eventLog` (see D22), so a channel color never reads as a severity (§6.3). | DS: no invented colors; Q-17; D22 |
| D11 | Heat-map 7-step blue ramp | No sequential ramp token exists. Per Q-3, use `color-mix()` of `mergeColors[0]` into `colorNeutralBackground1` at 6 fixed steps (15, 30, 45, 60, 75 and 90%), and file a design-system open question for a semantic ramp token. | DS: no invented colors |
| D12 | Dark EventData code block (`#121417` / `#e6e6e6`) | The existing `EvtxDetailPane` XML styling: `colorNeutralBackground3`, `colorNeutralForeground1`, `LOG_MONOSPACE_FONT_FAMILY` | DS: no invented colors |
| D13 | Level column glyph SVGs | Fluent icons with `aria-label` = level name (§7.3). These replace the current "ERR / WARN" text badges. | DS: Fluent icons only |
| D14 | Density select (Compact / Comfortable) | Omitted. Density follows the existing `logListFontSize` setting. | Epic Phase 3 font-sizing item |
| D15 | KPI sublabels "▲ 3× vs prior 24 h" and "4 new since yesterday" always visible | Rendered only after the user runs "Compare with previous period" and the prior window loads (§8.16). Before that, the sublabel is omitted, never estimated. Copy follows the actual window, for example "vs prior 24 h" or "new vs prior 7 days". | Evidence-first; no fabricated values |
| D16 | Grid footer "Virtualized list · rendering rows 1–260 of N" | Omitted. It is debug copy, and the counts already appear in the chip row and the status bar. | DS rule 6 |
| D17 | Search input text in a monospace font | UI font (`LOG_UI_FONT_FAMILY`) | DS rule 2 |
| D18 | Level dots 7 px; marker dots per mockup | Severity dots 8 px. Marker dots follow the marker store's categories. | DS component sizes |
| D19 | Chain titles written by hand ("Enrollment attempt 1 failed") | Derived from data: `{eventId} · {message head}` of the highest-severity member, with ties broken by earliest timestamp. A diagnosis finding title is used when the finding's evidence covers the whole chain. | No fabricated interpretation |
| D20 | v2 scenario layouts with the ESP phase Gantt, tracked-app table and IME detection details | Event-derived summaries plus "Open in ESP Diagnostics" / "Open in Intune Diagnostics" deep-links (§15.1) | Q-13 decision |
| D21 | Pill shapes (radius 12–14, circular toggles) on the live pill, panel toggles and filter chips | Radius 8 (`--cmt-radius-xl`) or the Fluent default rounded shape. Level and marker dots stay circular. | DS anti-pattern: "the app maxes at 8px" (Q-16) |
| D22 | Level and channel colors from Fluent palette tokens (§6.3) | Per-theme semantic tokens `severityPalette.eventLog` (critical, error, warning, information, verbose, and six channel colors, cool hues only), tuned in all seven themes and tested on resolved colors. Critical and Error share the red family; Level text uses `severityPalette.eventLog.text.*`; Error text is a true red in light themes (red-orange only in dark themes). Tinted-row text keeps D3's pairing (see §6.3). | Q-17; DS: a new color need is a semantic token in all seven themes |

## 5. Layout anatomy and measurements

These are reference measurements at 1440×900 with `logListFontSize` = 13 (call it *f*). Sizes written as `f−n` scale with the user's font setting.

### 5.1 Vertical stack (top to bottom)

| Region | Height | Padding / gap | Border | Notes |
|---|---|---|---|---|
| Global chrome | existing | — | — | Out of scope |
| View strip | auto (~30) | `6px 12px 0`, gap 6 | none | §8.15. Built-in and custom views; v2 adds the scenario presets. |
| View bar | auto (~40) | `6px 12px`, gap 8 | bottom `colorNeutralStroke2` | §8.2 |
| Filter row | auto (~38) | `6px 12px 4px`, gap 8 | none | §8.3 |
| Chip row | auto (~26) | `0 12px 6px`, gap 6 | none | Hidden when no chips and no brush |
| Histogram | 56 bars + ~16 axis | `0 12px 6px` | bottom `colorNeutralStroke2` | §8.5 |
| Body | flex 1 | — | — | §5.2 |
| Global status bar | 24 | `0 10px`, gap 10 | none (brand background) | §8.18 for styling, §8.14 for Event Logs content |

### 5.2 Body columns (left to right)

| Region | Width | Background | Border | Resizable |
|---|---|---|---|---|
| Channel pane | 250 default | `colorNeutralBackground2` | right `colorNeutralStroke2` | Yes. Keep `ChannelPicker` `MIN_SIDEBAR_WIDTH` 200 / `MAX_SIDEBAR_WIDTH` 500 and change `DEFAULT_SIDEBAR_WIDTH` 300 → 250 **[Verified constants]** |
| Main view | flex 1 | `colorNeutralBackground1` | — | — |
| Correlation dock (inside main, bottom) | 210 default height | `colorNeutralBackground2` | top `colorNeutralStroke1` | Yes **[Recommendation]**: 160 to 50vh, reusing the existing detail-pane resize pattern (`MIN_DETAIL_HEIGHT` / `MAX_DETAIL_RATIO`) |
| Insights rail | 340 default | `colorNeutralBackground2` | left `colorNeutralStroke2` | Yes **[Recommendation]**: 280 to 480 |

### 5.3 What moves from the current layout

| Current (`EventLogWorkspace.tsx`) | New home |
|---|---|
| `EventDiagnosisPanel`, a collapsed card above the body | Insights tab of the rail (§8.13). Coverage detail stays collapsed by default with `DETAIL_RENDER_CAP` (100) **[Verified]**. |
| `UnifiedTimelineView`, a fixed 320 px pane above the grid | Correlation view and dock. Its paging, cache and retry logic (`EVENT_LOG_TIMELINE_PAGE_SIZE` 1,000, `EVENT_LOG_TIMELINE_CACHE_*`, `EVENT_LOG_TIMELINE_AUTOMATIC_RETRY_LIMIT` 2) is extracted for reuse **[Verified constants]**. |
| `EvtxDetailPane`, a bottom pane at 300 px default | Details tab of the rail. The mockup summary sits at the top and the existing sections follow, so no capability is lost. |
| `EvtxFilterBar`, one bar | Split across the view bar (§8.2), filter row (§8.3) and chip row (§8.4). Saved filters, the quick-filter grammar, columns and export stay reachable. |

## 6. Color mapping

The light-theme hexes below are informative only. They were checked against `src/lib/themes/theme-light.ts`, `palettes.ts` and `@fluentui/tokens` 9.x. Components reference the tokens, never the hexes. Palette tokens exist in all seven themes, because the non-light themes take Fluent defaults through `createLightTheme` / `createDarkTheme` **[Verified]**.

### 6.1 Neutrals and brand

| Mockup hex | Used for | Token | Light value |
|---|---|---|---|
| `#ffffff` | Main surface, cards | `colorNeutralBackground1` | white |
| `#fafafa` | Panes, rail, dock, card headers | `colorNeutralBackground2` | `#fafafa` (grey 98) |
| `#f5f5f5` | Sticky table header, chips, expanded group | `colorNeutralBackground3` | `#f5f5f5` (grey 96) |
| `#f0f0f0` | Row dividers | `colorNeutralStroke3` | `#f0f0f0` (grey 94) |
| `#e0e0e0` | Region and card strokes, lane baselines | `colorNeutralStroke2` | `#e0e0e0` (grey 88) |
| `#d1d1d1` | Control borders, dividers | `colorNeutralStroke1` | `#d1d1d1` (grey 82) |
| `#242424` | Primary text | `colorNeutralForeground1` | grey 14 |
| `#424242` | Secondary text | `colorNeutralForeground2` | grey 26 |
| `#616161` | Tertiary text, axis labels | `colorNeutralForeground3` | grey 38 |
| `#007768` | Primary button background | `colorBrandBackground` | `#007768` |
| `#006959` | Links, link-style actions | `colorBrandForegroundLink` | `#006959` |
| `#007768` text / underline | Active rail tab | Fluent `TabList` default (brand underline) | — |

### 6.2 Selection and active states

| Mockup | Token(s) | Notes |
|---|---|---|
| `#cfe4fa` selected row + 3 px `#007768` inset | Background `colorPaletteBlueBackground2` (`#a9d3f2`), inset `box-shadow: inset 3px 0 0` `colorPaletteBlueBorderActive` (`#0078d4`), text `colorPaletteBlueForeground2` (Q-18) | Precedent: `secureboot/DiagnosticsTab.tsx` **[Verified]**. Also applies to the selected chain row, the selected app row (v2), the active view card in the view strip and the active "Time: brushed" chip. Decided in Q-1. |
| `#cfe4fa` active panel toggle, level toggle, scenario card | `colorNeutralBackground1Selected` + `colorBrandForeground1` text, 600 weight | DS toolbar active state |
| Active layout button (`#007768` fill, white text) | `colorNeutralBackground1Selected` + `colorBrandForeground1`, 600 weight | D6 |
| Exact-strength badge (`#cfe4fa` / `#0c3b5e` / `#007768`) | bg `colorPaletteBlueBackground2`, text `colorPaletteBlueForeground2` (`#004377`), border `colorPaletteBlueBorderActive` | Same triplet as selection |

### 6.3 Data colors

| Meaning | Mockup | Token |
|---|---|---|
| Critical (bars, dots, icons) | `#8b0a14` | `colorPaletteDarkRedBorderActive` (`#750b1c`) |
| Error (bars, dots) | `#d13438` | `colorPaletteRedBackground3` (`#d13438`), an exact match |
| Error (icon, text) | `#c50f1f` / `#b10e1c` | Icon and text follow the level rules below (`levels.Error.iconColor`, `railIconColor`, `selectedIconColor`, `textColor`). `severityPalette.status.error.foreground` measured 2.19:1 on the solarized-dark selection and 2.46:1 on the nord rail, which is why text is `eventLog.text.error`. |
| Warning (bars, dots) | `#eda100` | `colorPaletteMarigoldBackground3` (`#eaa300`) |
| Warning (icon, text) | `#bc4b09` / `#78350f` | Icon and text follow the level rules below (`levels.Warning.iconColor`, `railIconColor`, `selectedIconColor`, `textColor`), for the same reason as Error. Text on the Warning row tint stays `severityPalette.warning.text` (`#78350F`). |
| Information (bars) | `#c8d3de` | `colorNeutralStroke1` |
| Information (dots, icon) | `#9aa9b8` / `#0c3b5e` | `colorNeutralForeground4` (dots); `colorNeutralForeground3` (icon) |
| Verbose (bars, dots, icon) | none | Its own neutral, lighter and de-emphasized relative to Information (dimmer on dark themes), still gray, with a distance floor from Information so the §8.13 level-mix bar separates the two by color. Owner ruling (Adam, 2026-10-09); implemented as `severityPalette.eventLog` per Q-17. |
| Success / installed / running OK | `#107c10`, `#0e700e`, `#f1faf1` | `colorPaletteGreenBackground3`, `severityPalette.status.success.foreground`, `colorPaletteGreenBackground1`. The §8.1 live pill uses `eventLog.live` for its label and dot instead. |
| Row tint, Critical / Error | `#fde7e9` / `#fff5f5` | `severityPalette.error.background` (`#FEE2E2`) / `.text` (`#7F1D1D`) |
| Row tint, Warning | none | `severityPalette.warning.background` (`#FEF3C7`) / `.text` (`#78350F`) |
| Finding callout (`#fee2e2` / `#d13438` / `#7f1d1d`) | — | `severityPalette.error.background`, `colorPaletteRedBorder2`, `severityPalette.error.text` (exact match) |
| Ambiguous badge (`#fffef0` / `#78350f` / `#e8d44d`) | none | `severityPalette.warning.background` / `.text`, border `colorPaletteMarigoldBorder2`. #876 deviates in two places: the label falls back through `readableOn` to black or white when `.text` misses 4.5:1 (solarized-dark), and the border is `severityPalette.warning.text` (the marigold border is 2.16:1 on the light surface). |
| Candidate badge, connector | `#f0f0f0` / `#424242` | bg `colorNeutralBackground3`, text and dashed line `colorNeutralForeground2` |
| Not-linked marker | `#8a8f98` dotted | `colorNeutralStrokeAccessible`, 1 px dotted outline, no connector. #876 deviates from `colorNeutralForeground3`, which is 2.92:1 on the solarized-dark rail and 2.16 to 2.28:1 on the selection background. |
| Running bar / Retrying (v2) | `#2a78d6` | Designed in the v2 phases (#855), not Phase 1 (owner decision 2026-10-09). Intent: see the #855 hue bands (a cool blue or indigo). |
| Sleep (v2) | `#b7d3f6` | Designed in the v2 phases (#855), not Phase 1 (owner decision 2026-10-09). Intent: see the #855 hue bands (a muted violet). |
| Not started (v2 hatch) | `#e0e0e0` / `#f5f5f5` | Designed in the v2 phases (#855), not Phase 1 (owner decision 2026-10-09). Intent: `colorNeutralStroke2` / `colorNeutralBackground3`. |
| Channel categorical | see D10 | Per-theme semantic tokens in `severityPalette.eventLog`, cool hues only, per Q-17 and D22. Assigned by `channelColor(i)`, where `i` is the channel's position in channel display order (§8.6), cycling every six. Every placement passes the same `i` for a channel. The earlier `mergeColors` index sequence (0, 4, 5, 3, 6, 7) is superseded and is not the implementation. |
| Single-series bars (top IDs, crashes per day) | `#2a78d6` | `mergeColors[0]` |

`severityPalette` comes from `getThemeById(themeId).severityPalette`, as `LogListView.tsx` already does **[Verified]**. Phase 1 centralizes the v1 mappings above in `evtx-visual-tokens.ts`; the v2 scenario state colors (Running/Retrying, Sleep, Not started) are designed in the v2 phases (#855), not Phase 1 (owner decision 2026-10-09). Per Q-17, the level rows (Critical, Error, Warning, Information bars, dots and icons) and the channel row are superseded by `severityPalette.eventLog`; the tokens named above are the light-theme intent, not the implementation. Components never index palettes directly.

The level rules below are stated once and apply to all five levels. Components read the token map fields named here, never a palette or a phrase such as "the level color".

- **Level marks (bars, dots):** `levels.<L>.barColor` / `dotColor`, which are `severityPalette.eventLog.<level>`.
- **Level icons:** the grid icon is `levels.<L>.iconColor` (the mark, black or white below 3:1 on the row tint). Rail icons (the §8.13 Details header) and §8.8 group-row icons are `levels.<L>.railIconColor` (the mark). The selected row uses `levels.<L>.selectedIconColor` (`colorPaletteBlueForeground2`).
- **Marks on a non-neutral background:** a dot or swatch on a row tint, the selection background or a pressed toggle draws a 1 px outline in `markOutline(<level> | "selected" | "pressed")`. A sparkline on a selected row uses `selectedDataColor`.
- **Level text, all five levels:** `levels.<L>.textColor`, which is `severityPalette.eventLog.text.*`. Information and Verbose text are neutral grays, Verbose the dimmer.
- **Text on a level's own row tint:** uses `levels.<L>.rowText` on `levels.<L>.rowBackground` (D3's pairing, `severityPalette.<kind>.text` on `.background`). Classic Error rows stay yellow on red, because their red identity is the background.
- **Error text:** Critical and Error share the red family. In the light and classic themes the Error text is a true red; a red-orange Error is accepted in dark themes only.

Distance floors, in CIEDE2000. Critical and Error pairs, mark or text, within or across families, are 15; this governs both bullets below.
- Across families (level marks, level text, channels, live, single series, selection, brand): 20 when either color is a level mark, otherwise 15. Exempt: a level's text and its own mark; Information and Verbose across mark and text; the theme-owned selection, brand and single-series pairs.
- Within families: level marks are 20 apart, with the Verbose mark at least 10 from the Information mark. Critical, Error and Warning text are 20 apart. Channels are 15 apart.
- The live label and dot follow the cross-family rule: 20 from level marks and 15 from other families.

*Errata, 2026-10-09 (Phase 1 token review, #827 and #876):* scenario state colors moved to #855, channels follow D22 rather than `mergeColors`, Verbose has its own neutral, and the live source pill is a v1 token (§8.1).

Canvas and SVG rendering (for example the swimlanes) needs resolved color strings rather than `var(--…)` references. Resolve them once per theme change through `getComputedStyle`, following the approach in `getCanvasFont` (`src/lib/log-accessibility.ts`) **[Verified pattern]**.

## 7. Typography and iconography

### 7.1 Type scale

The mockup was drawn at a 12 px body. The implementation is anchored to *f* (`metrics.fontSize`, 13 by default), so every size follows the user's font setting.

| Role | Mockup | Implementation |
|---|---|---|
| Grid cell text | 12 | *f* (D1) |
| View, filter and chip controls; card titles | 12 | *f* − 1 |
| Secondary labels, legends, chips, rail body | 11 | *f* − 2 |
| Captions, eyebrows, badge text | 10 | max(10, *f* − 3) |
| Axis tick labels | 9 | max(9, *f* − 4). Precedent: `UnifiedTimelineView` uses `Math.max(9, fontSize - 3)` **[Verified]**. |
| KPI values | 22 / 20 | *f* + 9 / *f* + 7, numeric font, 600 weight |
| Rail detail title | 14 | *f* + 1, 600 weight |
| Correlation chain header | 14 | *f* + 1, 600 weight |

Eyebrow labels ("CHANNELS", "CHAINS · STRONGEST FIRST", "SCENARIO") keep the mockup's treatment: uppercase, 600 weight, `letter-spacing: .08em`, `colorNeutralForeground3`.

### 7.2 Font families

| Content | Family |
|---|---|
| UI chrome, labels, messages in cards | `LOG_UI_FONT_FAMILY` |
| Timestamps, event IDs, record IDs, PIDs / TIDs, counts, durations, KPI values, relative deltas (+3.3 s) | `tokens.fontFamilyNumeric` + `font-variant-numeric: tabular-nums` |
| Message column text, EventData, raw XML, log lines, identifier values (GUIDs, SIDs, `EventData/…` field paths), exit codes | `LOG_MONOSPACE_FONT_FAMILY` |

### 7.3 Icons

All names below were verified as exports of the installed `@fluentui/react-icons` **[Verified]**.

| Mockup | Icon |
|---|---|
| Critical level | `DismissCircle12Regular` (grid), `DismissCircle16Regular` (rail) |
| Error level | `ErrorCircle12Regular` / `ErrorCircle16Regular` |
| Warning level | `Warning12Regular` / `Warning16Regular` |
| Information level | `Info12Regular` / `Info16Regular` |
| Verbose level | `Circle12Regular` |
| ⛓ links column / count | `Link12Regular` (cell), `Link16Regular` (header) |
| ✓ on panel toggles | `Checkmark12Regular` |
| × chip remove, dock close | `Dismiss12Regular` |
| ▾ ▸ group chevrons, split button | `ChevronDown12Regular`, `ChevronRight12Regular` |
| ↑ ↓ previous / next event | `ArrowUp16Regular`, `ArrowDown16Regular` |
| → in link text | `ArrowRight12Regular`, trailing |
| Search | `Search16Regular` |
| ⚡ unclean shutdown (v2) | `Flash16Regular` |
| ✓ ✕ ◷ app states (v2) | `CheckmarkCircle12Regular`, `DismissCircle12Regular`, `Clock12Regular` |
| Coverage blocked | `PlugDisconnected16Regular` |
| Coverage note (channel not read) | `LockClosed16Regular` |
| Pause live tail | `Pause16Regular` |
| Copy as text | `Copy16Regular` |
| Filter to chain / finding | `Filter16Regular` |
| Layout buttons, optional leading icons | `TableSimple20Regular`, `GroupList20Regular`, `Timeline20Regular`, `ChartMultiple20Regular`, `Flowchart20Regular`, rendered at 16 px |

Severity is never conveyed by color alone. Each level icon carries an `aria-label`, and each row exposes the level in its accessible name.

## 8. Component specifications

Each subsection gives the mockup reference, the structure, the data source and the acceptance criteria. File names marked *(new)* do not exist at the baseline.

### 8.1 Workspace toolbar action: live source pill

- **Mockup:** `Workbench` header, "● Live · CONTOSO-LT-042".
- **Component:** `EvtxToolbarAction.tsx` *(new)*, registered via `WorkspaceDefinition.toolbarAction`. Precedent: `esp-diagnostics/index.ts` registers `toolbarAction` and `dock` **[Verified]**.
- **Visual:**
  - pill, radius 8 (the design-system maximum, D21), padding `3px 10px`, *f* − 2, 600 weight;
  - 7 px status dot;
  - live: a v1 token owned by Phase 1's token map (`liveSource`): bg `colorPaletteGreenBackground1`, border `colorPaletteGreenBackground3` as decoration, text and dot `liveSource.foreground` (the per-theme token `severityPalette.eventLog.live` (each theme's success foreground by default, with solarized-dark differing so the pill stays clear of the Warning mark)); text 4.5:1 and dot 3:1 on the pill background;
  - files: neutral bg3 / stroke1 / fg2, with the copy "Files · {n} sources".
- **Data:**
  - `sourceMode`, `tailMode`, `remoteMachine`;
  - the machine name: `remoteMachine`, otherwise the most frequent `records[].computer`, otherwise "This computer".
- **Acceptance:** shows live vs files state, and machine name, correctly. The tail state copy covers `subscription`, `polling`, `mixed` and `unsupported`. An `unsupported` tail renders "Live · not tailing".

### 8.2 View bar

- **Mockup:** `Workbench` row 2.
- **Component:** `EvtxViewBar.tsx` *(new)*.
- **Layout switcher:**
  - a segmented group, `role="tablist"`, `aria-label="Layout"`;
  - 1 px `colorNeutralStroke1` border, radius 6;
  - buttons 28 px tall, padding `0 14px`, *f* − 1, with 1 px dividers;
  - order: Table, Grouped, Timeline, Charts, Correlation;
  - active style per §6.2.
- **Divider:** 1×20 px, `colorNeutralStroke1`.
- **Panels:** label "Panels" (*f* − 2, fg2), then three toggles:
  - Fluent `ToggleButton`, default `shape="rounded"` (D21), `size="small"` (24 px);
  - checked state shows `Checkmark12Regular` and uses the §6.2 active style;
  - labels: "Channels", "Insights", "Correlation dock".
- **Right cluster:**
  - "Group by" `Dropdown` (size small): None, Event ID, Provider, Channel, Level, Day. It maps to the existing `setGroupBy` and the `EvtxGroupField` values `level | provider | channel | eventId | day` **[Verified]**.
  - "Columns ({visible})" button, opening the existing column picker.
  - "Export" menu:
    - the existing formats, through `evtx-export.ts`: CSV, TSV, JSON, Event XML, HTML and Raw Event XML **[Verified]**;
    - "Markdown report" (new, §8.17);
    - "EVTX subset…" (new, Windows only, §8.17).
- **State:** `activeView`, `panels.{channels,insights,dock}` and `railTab`, held in `evtx-layout-store.ts` *(new)*. This keeps presentation state out of `evtx-store.ts`, which is load-bearing for queries.
- **Acceptance:**
  - the switcher is keyboard-operable (arrow keys move between tabs);
  - toggles expose `aria-pressed`;
  - hiding a panel reflows the main view with no layout jump greater than one frame.

### 8.3 Filter row

- **Mockup:** `Workbench` row 3. The search placeholder with grammar hints comes from `Main`.
- **Search:**
  - `flex: 1 1 280px`, 28 px tall, 1 px `colorNeutralStroke1`, radius 4, `Search16Regular` leading icon;
  - placeholder "Search…   id:76  level:error  provider:AAD", taken from `Main`;
  - free text drives the existing `setFilterSearch` / quick filter;
  - field terms use the field grammar below.
- **Field grammar [Recommendation].** The mockups use field-scoped queries in two places: the `Main` placeholder, and the `Workbench` scenario queries (for example `provider:DeviceManagement OR id:1098,1014`). No existing quick-filter mode supports field prefixes (`EvtxQuickFilterMode` has six text modes **[Verified]**).
  - **Mode:** a new quick-filter mode, `fieldQuery`, implemented by a pure parser in `evtx-query-grammar.ts` *(new)*.
  - **Fields:**
    - `id:` (comma list and ranges, for example `id:1098,1014` or `id:4624-4634`);
    - `level:` (critical, error, warning, information, verbose);
    - `provider:`, `channel:` and `computer:` (case-insensitive substring);
    - `source:` (text-log source label, matching items in the analysis session);
    - `data.<Name>:` (an EventData field).
  - **Operators:** terms are ANDed. `OR` (upper case) between terms, `-` negation, quoted values, and bare words are free text.
  - **Errors:** a malformed term is shown inline under the input in `levels.Warning.textColor` (`severityPalette.eventLog.text.warning`), and the query is not applied.
  - **Compatibility:** older builds' `sanitizeQuickFilter` falls back to the default mode for the unknown mode value **[Verified fallback behavior]**, so saved filters remain loadable.
- **Level toggles:**
  - `role="group"`, `aria-label="Level"`, 26 px buttons, padding `0 9px`, *f* − 2;
  - each button: an 8 px dot in `levels.<L>.dotColor` (outlined per the marks rule when the toggle is pressed), the label (Critical, Error, Warning, Info, Verbose), then the count (numeric font, fg3, 400 weight);
  - pressed style per §6.2;
  - drive `toggleFilterLevel`;
  - counts come from the loaded `records` before level filtering, computed by `countByLevel` in `evtx-filter.ts` *(new function)*.
  - **[Unverified]** Whether toggling a level re-queries in live mode, given that levels are before-load criteria (`EvtxBeforeLoadCriteria.levels`). The UI must not imply instant local toggling if a re-query occurs. Show the existing loading affordance.
- **Time window:** a `Dropdown`, 28 px, with Last 1 h, Last 24 h, Last 7 days, Last 30 days and All. It maps to `EvtxTimeWindow` `1h | 24h | 7d | 30d | all` **[Verified]**. The mockup's "Custom…" option depends on Q-2.
- **More filters · {n}:** a 28 px secondary button that opens a popover (`shadow8`). The popover holds:
  - event IDs (`setFilterEventIds`);
  - the quick-filter grammar (mode, scope and action: `EvtxQuickFilterMode` has six modes, scope `allColumns | visibleColumns`, action `show | hide` **[Verified]**);
  - case sensitivity and highlight;
  - saved filters (load, save current, favorites).

  `{n}` is the count of active criteria that are not visible as level toggles, search or time window.
- **Acceptance:** every filter capability in the current `EvtxFilterBar` stays reachable within two interactions.

### 8.4 Chip row

- **Mockup:** `Workbench` row 4.
- **Chips:**
  - radius 8 (D21), padding `2px 8px 2px 10px`, *f* − 2, bg `colorNeutralBackground3`, border `colorNeutralStroke1`;
  - a trailing `Dismiss12Regular` button with an `aria-label` of the form "Remove {criterion}";
  - one chip per active criterion: channel subset ("Channels: 4 of 5"), event IDs, quick-filter hide rules ("Exclude: 7036, 16384"), search text, time range ("Time: brushed 09:00–09:45"), and record scope ("Chain: {title}" / "Finding: {title}");
  - the time-range chip uses the selection triplet (§6.2).
- **"Clear all":** a link (`colorBrandForegroundLink`, 600 weight).
- **Right side:** "Showing {visible} of {loaded}", numeric font, fg2.
- **Component:** `EvtxFilterChips.tsx` *(new)*.

### 8.5 Event histogram

- **Mockup:** `Workbench` histogram figure.
- **Component:** `EvtxHistogram.tsx` *(new)*. Bucketing lives in `evtx-histogram.ts` *(new, pure)*.
- **Geometry:**
  - bar area 56 px tall, 1 px gap between buckets;
  - stacking order bottom to top: Info, Warning, Error, Critical. Each non-empty segment is at least 2 px, with a 1 px `colorNeutralBackground1` separator on top;
  - legend column 84 px on the right, with 8 px swatches (radius 2) and labels at *f* − 3;
  - seven evenly spaced axis labels at *f* − 4, in the local or UTC time per `timeZoneMode`.
- **Bucketing:** the bucket count is **[Recommendation]** 72 for windows up to 24 h, giving 20-minute buckets. For other windows it is the nearest "nice" interval (1, 2, 5, 10, 15, 20 or 30 min; 1, 2, 3, 6 or 12 h; 1 day) yielding 48 to 96 buckets. Input is `visibleRecords` excluding the time-range criterion itself, so brushing never empties its own histogram.
- **Brush:**
  - drag horizontally to set a range;
  - overlay fill `colorNeutralBackground1Selected` at 60% opacity, 2 px side borders `colorNeutralForeground3` (D6);
  - Escape or the chip's × clears it.
  - Keyboard alternative: the histogram is focusable; ←/→ move a one-bucket cursor; Shift+←/→ extend the range; Enter applies.
- **Tooltip per bucket:** "{HH:mm}–{HH:mm} · {e} errors, {w} warnings, {i} info" (numeric font).
- **Accessibility:** `<figure>` with `aria-label="Events per {interval} over {window}, stacked by level"`. A visually hidden table of bucket counts is available to screen readers.
- **Performance target [Recommendation]:** ≤ 50 ms to rebucket 100k records on the Windows dev box. Bucketing is memoized on (`visibleRecords` identity, window, `timeZoneMode`).

### 8.6 Channel pane

- **Mockup:** `Workbench` left `nav`. The group headers, channel filter and "read" count come from `Main`.
- **Component:** `ChannelPicker.tsx` (restyle). Stats come from `evtx-channel-stats.ts` *(new, pure)*.
- **Header:**
  - eyebrow "CHANNELS", with "{read} of {total} read · {window} activity" right-aligned (*f* − 3, fg3);
  - padding `10px 12px 6px`.
- **Channel filter and grouping:** these already exist in `ChannelPicker` and are kept:
  - the "Filter channels..." input;
  - the tree that separates Windows Logs from the Applications and Services hierarchy (`buildTree`) **[Verified]**.

  Group headers render as in `Main`: `ChevronDown12Regular` / `ChevronRight12Regular`, then the group name (*f* − 2, 600 weight, fg2), collapsible.
- **Row** (padding `7px 12px`, gap 3, bottom border `colorNeutralStroke3`):
  1. A 10 px swatch (radius 2, `channelColor(i)` (§6.3 assignment); outlined per the marks rule on the selected row), the name (ellipsis), and the total right-aligned (numeric, *f* − 3).
  2. A sparkline, 18 px tall, 24 bins, indented 16 px. Bars use `channelColor(i)` (`selectedDataColor` on the selected row); empty bins draw as 1 px `colorNeutralStroke2`.
  3. "{e} err" (`levels.Error.textColor`), "{w} warn" (`levels.Warning.textColor`), and a status: "· live", "not read", "needs elevation", and so on.
- **Selection:** the existing checkbox and channel selection behavior stays. The selected row uses the selection triplet.
- **Unavailable channels:** a channel with a coverage gap of kind `accessDenied` renders the name in fg3 with "needs elevation", total "—" and a flat sparkline. `EvtxCoverageGapKind` includes `accessDenied`, `unsupported`, `missing`, `empty` and others **[Verified]**.
- **"ALSO CORRELATING" section:** lists the text-log sources in the analysis session with line counts, from `EventLogAnalysisSessionStatus.logItems` and the source labels. It ends with the "Add log source…" link (§8.19).
- **Footer:** padding `10px 12px`, top border `colorNeutralStroke2`. It reads "● Live tail · {n} channels" with a "Pause" / "Resume" link-button calling `stopLiveTail` / `startLiveTail` **[Verified actions]**. It is hidden when `sourceMode !== "live"`.

### 8.7 Table view

- **Mockup:** `Workbench` (`view=table`); `WB-Selected`.
- **Components:** `EvtxTimeline.tsx`, `EvtxTimelineRow.tsx` and `evtx-columns.ts` (restyle plus one column).
- **Header:**
  - sticky, bg `colorNeutralBackground3`, bottom `colorNeutralStroke1`, 600 weight at *f* − 1;
  - the time header shows the sort direction with `ChevronDown12Regular` / `ChevronUp12Regular`.
- **Default column widths** — the mockup widths scaled by 13/12 and rounded:

  | Column | Width | Default visible |
  |---|---|---|
  | level | 32 | yes |
  | timestamp | 154 | yes |
  | eventId | 52 | yes |
  | channel | 120 | yes |
  | provider | 162 | yes |
  | message | flex | yes |
  | `links` *(new id)* | 44 | yes |
  | others | unchanged | unchanged |

  Existing saved column configurations are preserved by `sanitizeColumnConfig`.
- **Row:**
  - height per D1; bottom border `colorNeutralStroke3`; background and text `levels.<L>.rowBackground` / `rowText` (D3); selection per §6.2;
  - the current 4 px level-colored left border is removed (the icon and row tint carry severity). The marker color keeps the left 4 px slot when a marker is present, so the epic's tagging and bookmark behavior is preserved;
  - Level cell: centered icon (§7.3) in `levels.<L>.iconColor`, or `selectedIconColor` on the selected row;
  - Time: numeric font at *f* − 1, fg2, `white-space: nowrap`;
  - ID: numeric font, 700 weight;
  - Channel: a 7 px swatch (radius 2, `channelColor(i)` (§6.3 assignment); outlined per the marks rule on tinted and selected rows) plus the short name, ellipsis, with the full name in a tooltip;
  - Provider: fg2, ellipsis;
  - Message: mono, fg1, ellipsis;
  - Links: `Link12Regular` plus the count, in `colorBrandForegroundLink`, 600 weight, *f* − 3. Empty when the record has no Exact or Candidate edge.
- **Interaction:**
  - clicking a row selects it, sets `railTab = "details"` and opens the rail if hidden (mockup behavior);
  - the existing keyboard handling, including bookmark on `b`, is unchanged;
  - with the dock open, selection changes recenter the dock.
- **Grouping:** when Group by is set in Table view, the existing in-grid group headers (`buildGroupedRows`) remain.

### 8.8 Grouped view

- **Mockup:** `WB-Grouped`.
- **Component:** `EvtxGroupedView.tsx` *(new)*. Summaries come from `buildGroupSummaries` in `evtx-filter.ts` *(new function)*.
- **Grouping key:** the first Group by field, defaulting to `eventId` when Group by is None. Rows are sorted by severity rank (Critical, Error, Warning, Information, Verbose), then count descending.
- **Header row:** sticky, bg3, *f* − 2, 600 weight. Columns: chevron 16 · level icon 20 (`railIconColor`) · ID 52 · Provider 170 · Typical message flex · Count 56 (right-aligned) · "{window} trend" 168 · Last seen 120.
- **Group row:**
  - padding `6px 12px`, *f* − 1, bottom `colorNeutralStroke2`;
  - when expanded: bg3 and 600 weight;
  - Typical message is the most frequent message for the key, with ties going to the latest;
  - Trend is a 24-bin sparkline, 18 px tall, in `levels.<L>.barColor`;
  - Last seen uses the numeric font at *f* − 3.
- **Expanded items:**
  - container bg2, padding `4px 0 6px 56px`;
  - up to 8 most recent items (time · message · "Linked" badge when the item has Exact or Candidate links);
  - then "Show all {n} in table", which applies an event-ID chip and switches to Table.
- **Acceptance:** the view renders 5,000 distinct groups with virtualization and stays at 60 fps on scroll on the Windows dev box **[Recommendation]**.

### 8.9 Timeline view: provider swimlanes

- **Mockup:** `WB-Timeline`.
- **Component:** `EvtxSwimlaneView.tsx` *(new)*. Lane building lives in `evtx-swimlanes.ts` *(new, pure)*.
- **Header line:**
  - title "Swimlanes by {provider|channel|event ID}" (*f*, 600 weight);
  - help text "each dot is one event · larger = more severe · drag to zoom" (*f* − 2, fg2);
  - a legend of dots sized 10, 9, 7 and 5 px for Critical through Info;
  - a "Lanes:" dropdown (Provider, Channel, Event ID).
- **Lanes:**
  - 36 px tall, bottom border `colorNeutralStroke3`;
  - label block 172 px plus 8 px padding (name, then "{n} events" at *f* − 3, fg3);
  - a 1 px `colorNeutralStroke2` baseline at the vertical center;
  - the top 12 lanes by count, then a final "Other ({n} lanes)" lane.
- **Dots:**
  - positioned by timestamp across the window;
  - Info dots at 55% opacity; non-Info dots get a 1 px `colorNeutralBackground1` ring;
  - z-order puts severity on top.
- **Rendering [Recommendation]:** a `<canvas>` per lane plus a DOM hit-test layer, because SVG with more than 20k nodes is a known jank risk. Colors are resolved per §6.
- **Brush:** shares the histogram's time-range criterion and overlay. Dragging inside the lanes sets it.
- **Click a dot:** select the nearest record (within 4 px) and open Details.

### 8.10 Charts view

- **Mockup:** `WB-Charts`.
- **Component:** `EvtxChartsView.tsx` *(new, lazy-loaded with `React.lazy` so the chart library stays out of the initial bundle)*. Data comes from `evtx-chart-data.ts` *(new, pure)*.
- **KPI grid:**
  - six columns, gap 10;
  - each card: border `colorNeutralStroke2`, radius 6, padding `10px 12px`, label *f* − 2 fg2, value per §7.1, sublabel *f* − 3.

  | Tile | Value | Sublabel (only when derivable, D15) |
  |---|---|---|
  | Events ({window}) | visible count | "{c} channels · {l} text logs" |
  | Errors | Error count | After a comparison: "▲ {r}× vs prior {window}" or "▼ …". With a prior count of 0 the copy is "{n} new vs 0 in prior {window}", never "∞×". |
  | Warnings | Warning count | "Top 2 IDs = {p}%" |
  | Critical | Critical count | "{provider} {id}" of the most frequent Critical event |
  | Distinct event IDs | Distinct (provider, ID) pairs | After a comparison: "{n} new vs prior {window}" |
  | Correlation chains | Chain count (Exact + Candidate only, D7) | "{n} exact" |

  - A "Compare with previous period" secondary button sits right-aligned above the KPI grid (§8.16). While a comparison is active it reads "Comparing with {start}–{end}", followed by a `Dismiss12Regular` "Clear comparison" button.

- **Figures:**
  - a 2×2 grid, gap 12;
  - each figure: border `colorNeutralStroke2`, radius 6, padding `10px 12px`;
  - caption: title *f* − 1 600 weight, then a qualifier at *f* − 3 fg3.

  1. **Events by channel:**
     - rows of label (150 px) · bar (14 px, `channelColor(i)` (§6.3 assignment), radius `0 4px 4px 0`) · value (40 px, numeric);
     - tooltip "{channel}: {n} events, {e} errors, {w} warnings".
  2. **Top event IDs:**
     - rows of ID (44 px, numeric bold) · provider (170 px) · bar (12 px, `singleSeries`) · count (34 px);
     - top 9;
     - the caption qualifier lists the IDs excluded by active quick-filter hide rules, for example "excluding 7036 / 16384". The list is not hard-coded.
  3. **Activity by hour and channel:**
     - a heat map: 120 px label column plus 24 cells, gap 2, 18 px tall, radius 2;
     - colors from `heatSteps` (D11);
     - tooltip "{channel} · {HH}:00 · {n} events".
  4. **Errors and warnings per hour:**
     - stacked columns, 120 px tall, Error on the bottom and Warning on top;
     - footer legend plus "Peak: {HH:mm} ({n})".
- **Library choice [Recommendation]:**
  - figures 3 and 4 use `HeatMapChart` and `VerticalStackedBarChart` from `@fluentui/react-charts` 9.3.25. Both exports were verified **[Verified]**, and the sysmon workspace sets the precedent for the library.
  - figures 1 and 2 are token-styled rows with no chart library. Their layout (label, then bar, then value) differs from `HorizontalBarChart`'s label-above layout, and they need no axes.
  - Phase 14 includes a short spike. If the Fluent charts cannot match the mockup's density without style overrides beyond their public props, figures 3 and 4 also fall back to token-styled SVG. That decision is recorded in the PR.

### 8.11 Correlation view

- **Mockup:** `WB-Correlation` is the primary reference. From `Focus` ("Correlation C") the spec also adopts the overview strip with its zoom band, the marker-shape legend, the "Why these are linked" table and the "Not placed" entry.
- **Components:**
  - `EvtxCorrelationView.tsx` *(new)*;
  - `EvtxCorrelationLanes.tsx` *(new, shared with the dock)*;
  - `evtx-correlation-chains.ts` *(new, pure)*.
- **Chain model** (`evtx-correlation-chains.ts`) **[Decided, Q-4]**:
  - Input: `TimelineCorrelationEdge[]`, which carries `strength` `exact | candidate | ambiguous`, plus `key`, `evidence` and `coverage` **[Verified]**. Also `DiagnosisCorrelationEdge[]`, with `basis` `exactIdentifier | candidateIdentifier | timestampOnly` and `status` `exact | candidate | ambiguous | coverageBlocked | notCausal` **[Verified]**.
  - **Chain** = a connected component over `exact` and `candidate` edges. Chain strength = the weakest edge in the component, so a single candidate edge makes the whole chain Candidate.
  - `ambiguous` edges never merge components. They are listed as single "Ambiguous" items.
  - `coverageBlocked` relations are listed as "Coverage blocked" items, with `PlugDisconnected16Regular`.
  - `timestampOnly` / `notCausal` relations populate "Nearby, not linked" only (D7).
  - Ordering: Exact chains, then Candidate, then Ambiguous, then Coverage blocked. Within each group, by member count descending, then earliest timestamp.
  - Render cap: 100 chain rows, with "Showing the first 100 of {n}; {m} omitted." This follows the existing `UNPLACED_PREVIEW_LIMIT` pattern **[Verified]**.
  - If `totalEdges` exceeds the edges available in the preview, show the existing copy "Correlation details are paged and bounded" and the omitted count (Q-10).
- **Left list:**
  - 250 px, bg2, right `colorNeutralStroke2`;
  - eyebrow "CHAINS · STRONGEST FIRST";
  - rows (padding `8px 12px`, gap 3, bottom `colorNeutralStroke2`): strength badge (*f* − 4, 700 weight, radius 8, padding `1px 6px`), "{n} entries" right-aligned, the title (*f* − 1, 600 weight, D19), and the span "HH:mm:ss–HH:mm:ss" (numeric, *f* − 3);
  - selected row uses the selection triplet;
  - a collapsed disclosure, "Nearby, not linked ({n})", appears below the chains;
  - a final **"Not placed ({u})"** row appears when the analysis session has unplaced items. It reads "Text-log lines without timestamps are listed, never guessed onto the timeline." at *f* − 3, fg2. Selecting it replaces the detail area with the **unplaced list** (§8.11a).
- **Detail header:**
  - title (*f* + 1, 600 weight) and strength badge;
  - "key {kind} {value} · {start}–{end}". The value is mono and truncated in the middle to 12 characters with the full value in a tooltip; the times use the numeric font;
  - legend: a solid 2 px line for "exact", a dashed line for "candidate", and a dotted-outline marker for "not linked (no line)";
  - a marker-shape legend, as in `Focus`: a circle for "Event" and a rounded square for "Log line".
- **Overview strip** (from `Focus`):
  - placed above the lane plot, 48 px tall, border stroke2, radius 6;
  - caption "Overview" with the hint "drag the band to zoom" (*f* − 3, fg3);
  - shows every chain's span across the full session window as a thin bar in `strengths.<s>.border` (the solid hue of the strength; `background` is a pale fill and `foreground` is label text), with the selected chain at full opacity and the others at 40%;
  - a draggable, resizable **zoom band** (fill `colorNeutralBackground1Selected` at 60% opacity, 2 px side handles `colorNeutralForeground3`) sets the lane plot's window. By default the band equals the chain span padded by 25%;
  - keyboard: ←/→ move the band, Shift+←/→ resize it, Home resets it;
  - the axis shows 5 ticks (numeric, *f* − 4).
- **Lane plot:**
  - 240 px tall, border `colorNeutralStroke2`, radius 6, padding `6px 10px`;
  - one lane per source: event channels plus text-log files;
  - lane label 184 px at *f* − 2, fg2;
  - the window is the chain span padded by 25% on each side, with a minimum of 10 s;
  - markers are 14 px. Events are circles and log lines are 3 px rounded squares, filled with `levels.<L>.dotColor`, with a 2 px `colorNeutralBackground1` ring and a 1 px `dotColor` outer ring. Labels sit at *f* − 3 on bg1;
  - members outside the window are pinned at the edge at 55% opacity, with labels "← {id} · {Δ} earlier" or "{id} · {Δ} later →";
  - connectors: SVG `vector-effect: non-scaling-stroke`. Exact edges are 2.5 px solid `colorPaletteBlueBorderActive`. Candidate edges are 1.5 px dashed (`5 4`) `colorNeutralForeground2`. Not-linked items get no connector.
- **Cards below** (wrap, `flex: 1 1 300px`, border stroke2, radius 6):
  - **"Why these are linked":**
    - a one-line plain statement generated from the edge kinds, for example "One {key kind} value matches across {n} entries on one machine";
    - then a table, following `Focus`, with columns **Entry** (`{eventId} · {channel}` for events, `{source} · line {n}` for logs) and **Where the key appears** (`{field} = {value}`, with the value in mono). Rows come from `TimelineCorrelationEvidence` (`originId`, `field`, `value`) **[Verified]**.
  - **"Sequence":**
    - members in timestamp order: the first shows its absolute time (numeric), later ones show "+{Δ}";
    - the highest-severity member is 600 weight;
    - actions: "Filter table to chain" (primary, `Filter16Regular`), which applies the record-scope chip and switches to Table; and "Copy as text" (secondary, `Copy16Regular`), which copies the sequence and evidence as plain text.
- **Acceptance:**
  - no UI path renders a connector, chain or count for `timestampOnly` / `notCausal`;
  - every Exact or Candidate connector is traceable to at least one evidence row in "Why these are linked".

### 8.11a Unplaced items list

- **Mockup:** the `Main` and `Focus` "Not placed" cards, with their "Review unplaced lines" action.
- **Entry points:**
  - the "Not placed ({u})" row in the chain list (§8.11);
  - "Review unplaced lines" in the rail's Chains tab and in the Correlation summary card (§8.13).
- **Content:**
  - a header stating "{u} items carry no timestamp. Placing them would invent an order the evidence does not support." (copy from `Main`);
  - then the items from `UnifiedTimeline.unplaced` (`UnplacedItem`: `origin`, `reason: "missingTimestamp"` **[Verified]**): the source label (`originLabel`), the line or record context (`originContext`) and the message;
  - capped at `UNPLACED_PREVIEW_LIMIT` (100) with the omitted count **[Verified constant]**.
- **Actions:**
  - "Copy as text";
  - for log lines, "Open in Log Viewer", which opens the source at that line through the existing log workspace. Opening at a specific line is **[Unverified]** and is confirmed in Phase 10b.
  - Items are never assigned a position on any timeline.

### 8.12 Correlation dock

- **Mockup:** `WB-Selected` (dock open with a selected row).
- **Component:** `EvtxCorrelationDock.tsx` *(new)*, using `EvtxCorrelationLanes`.
- **Header** (padding `6px 12px`):
  - "Correlation" (*f* − 1, 600 weight);
  - "around Event {id} · {time} · window ±{w} · {n} sources" (*f* − 2, fg2; numerals in the numeric font), with copy from `Main`;
  - spacer;
  - a **window** dropdown (24 px, `aria-label="Correlation window"`) with ±30 s, ±75 s (the default), ±2 min and ±5 min, as in `Main`;
  - "Open in Correlation view" (24 px secondary), which selects the chain containing the record;
  - a collapse button (`ChevronDown12Regular`, `aria-label="Collapse correlation"`) that reduces the dock to its header row;
  - a close button (`Dismiss12Regular`, `aria-label="Close correlation dock"`).
- **Body:**
  - an inner panel (margin `0 12px 8px`, bg1, border stroke2, radius 6);
  - up to 5 lanes for the sources with items in the window, each 20% tall, with labels 170 px at *f* − 3;
  - 12 px markers;
  - connectors only for edges touching the selected record's chain.
- **Chain summary line** (from `Main`): below the lanes, the selected record's chain is shown as its strength badge, title, `key: {kind} {value}` (mono) and its members as "time · id · message" steps (up to 4).
  - A final line reads "Also nearby: {id} ({reason}) · …". The reason is "same session, candidate" for Candidate relations, and "time only, not linked" for `timestampOnly` / `notCausal` relations (D7).
- **Window:** ± the selected window around the selected record's `timestampEpoch`. The default is ±75 s, and the choice persists with the layout state.
- **Data:** analysis-session timeline items within the window. `queryEventLogAnalysisTimeline(sessionId, offset, limit)` is offset-based only **[Verified]**, so the window must be located either by a binary search over pages or by a new windowed query (Q-10).
- **Empty state:** "No other sources have entries within ±75 s." When the record has no timestamp, the message is "This event has no timestamp; it cannot be placed." (copy aligned with `unplacedSummary`).

### 8.13 Insights rail

- **Mockup:**
  - `Workbench` (Insights tab) and `WB-Selected` (Details tab);
  - `Main` (finding-card detail, coverage note);
  - `Correlations` ("Correlation B", chain cards);
  - `Selected` (Context ±5 min, Details / XML).
- **Component:** `EvtxInsightsRail.tsx` *(new)*. It hosts the restyled `EventDiagnosisPanel`, `EvtxRailChains.tsx` *(new)* and `EvtxDetailPane`.
- **Tabs:**
  - a Fluent `TabList` (size small), padding-left 6, bottom border stroke2;
  - tabs: "Insights {n}", "Chains {n}" and "Details". Counts are fg3, 400 weight, as in `Main`, and the third tab reads "Event {id}" while a record is selected;
  - active tab: brand underline and brand text (an allowed DS use).
- **Body:** padding 12, gap 12, scrolls independently.

**Insights tab**

1. **Finding cards**, one per actionable `DiagnosisFinding`:
   - which findings: `class !== "coverageGap"`, consistent with `actionableFindingCount`. Sorted by severity (`critical` > `error` > `warning` > `info`), then confidence (`high` > `medium` > `low` > `unknown`) **[Verified enums]**;
   - card: bg1, border stroke2, a 3 px top border in `levels.<L>.barColor`, radius 6, padding `10px 12px`, gap 6;
   - eyebrow: the severity word uppercased (*f* − 3, 700 weight, letter-spacing .08em, `levels.<L>.textColor`);
   - the eyebrow's right side shows the confidence ("{confidence} confidence", mono, *f* − 3, fg3), as in `Main`;
   - title (*f*, 600 weight);
   - `summary` (*f* − 2, line-height 1.5, fg2);
   - an **evidence block** (bg3, radius 4, padding `6px 8px`, mono *f* − 2) listing up to 3 evidence references from `DiagnosisFinding.evidence`, for example `76 · DeviceManagement/Admin · record 88456`, then "+{n} more";
   - **recommended checks**: the first item of `DiagnosisFinding.recommendedChecks` at *f* − 2, with "+{n} more checks" expanding the rest **[Verified field]**;
   - the link "Filter to {n} events" plus `ArrowRight12Regular`, applying a record-scope chip built from the finding's `event` evidence.
   - **Empty state:** the `DiagnosisOverview.headline`, plus "No actionable findings."
2. **Coverage note** (from `Main`), shown when any loaded channel has an `accessDenied` gap:
   - bg `colorNeutralBackground4`, radius 6, with a lock icon (`LockClosed16Regular`);
   - the text "{channel} channel not read. Findings may be incomplete.";
   - an "Elevate" link-button that opens the existing `RestartAsAdministratorDialog` **[Verified component]**;
   - hidden when already elevated (`get_app_elevation_state`) or on non-Windows platforms.

   This replaces the current `EvtxCoverageBanner` placement above the grid. The banner's other gap kinds move into the coverage disclosure.
3. **Coverage disclosure** ("Coverage gaps ({n})"): collapsed by default, `DETAIL_RENDER_CAP` 100 with an omitted count. This preserves the diagnosis output spec's bounded-detail rule.
4. **Level mix** card:
   - a stacked bar, 12 px, radius 3, gap 2. Each segment has a minimum flex of 0.6% so rare levels stay visible;
   - legend at *f* − 3: "{label} {n}".
5. **Top event IDs** card, captioned "click to filter":
   - top 7 rows, each an ID (40 px numeric bold), a bar (10 px, `levels.<L>.barColor`) and a count (30 px);
   - clicking a row applies an event-ID chip through the quick filter's `eventIds` mode, an on-load criterion that does not re-query **[Recommendation]**.
6. **Correlation summary** card:
   - "{e} exact · {c} candidate · {a} ambiguous";
   - "{n} nearby, not linked" on its own line in fg3;
   - the existing `unplacedSummary` text when items are unplaced, with the link "Review unplaced lines" (§8.11a);
   - the link "Open correlation view".

**Chains tab** (from `Correlations`, "Correlation B — chains in the rail")

1. **Legend:** "Exact match" (solid line), "Candidate identity" (dashed line), and "Not linked" (dotted-outline marker, no line). This is D9 vocabulary in place of `Main`'s Explicit / Secondary / Time-adjacent.
2. **Chain cards**, one per Exact or Candidate chain from `evtx-correlation-chains.ts`, in the same order and with the same cap as the Correlation view:
   - card: bg1, border stroke2, radius 6, padding `10px 12px`, gap 6. The card for the selected record's chain uses the selection triplet;
   - row 1: strength badge, spacer, and the span (numeric, *f* − 3, fg3);
   - title (*f*, 600 weight, D19);
   - `key: {kind} {value}` (mono, *f* − 3, fg2);
   - steps (an ordered list of up to 6): a level dot (8 px, `levels.<L>.dotColor`, outlined per the marks rule on the selected card), the time (numeric, *f* − 3, 52 px), a kind chip (`EVT` or `LOG`, mono *f* − 4, 700 weight; `EVT` on the blue triplet background, `LOG` on bg4), then the message. Further steps collapse into "+{n} more";
   - actions: "Show in table" (applies the record-scope chip and switches to Table) and "Open in correlation view".
3. **Ambiguous and Coverage blocked** items follow as compact rows (badge, title, span), with no steps.
4. **"Nearby, not linked ({n})"**: a collapsed disclosure listing time-adjacent items with the reason "time only, not linked". It has no strength badge and no connector vocabulary (D7).
5. **"Not placed ({u})"** card (bg4, radius 6): the `Main` copy, plus "Review unplaced lines" (§8.11a).
6. **Empty state:** "No linked events. Correlation requires a shared identifier; time proximity alone is not a link."

**Details tab** (the selected record)

1. **Header:**
   - the level icon at 16 px (`RailIcon` in `levels.<L>.railIconColor`; the header sits on the rail);
   - "Event {eventId}" (*f* + 1, 600 weight);
   - the level word (*f* − 2, 600 weight, `levels.<L>.textColor`);
   - spacer;
   - previous / next buttons, 24 px, `ArrowUp16Regular` / `ArrowDown16Regular`, labelled "Previous event" / "Next event", moving through `visibleRecords`;
   - a close button (`Dismiss12Regular`, `aria-label="Close details"`) that clears the selection and returns to the Insights tab, as in `Selected`.

   Below the header sits a sub-tab row, "Details | XML", as in `Selected`. XML shows the existing raw XML section of `EvtxDetailPane`; the sections below belong to Details.
2. **Message** (*f*, 600 weight, line-height 1.4).
3. **"{time} · {computer}"**, with the time in the numeric font and `timeZoneMode` applied.
4. **Definition grid** (`84px 1fr`, gap `4px 10px`, *f* − 2; terms in fg2):
   - Channel (full name);
   - Provider;
   - Record ID (numeric, `eventRecordIdText`);
   - Process "PID {processId} · TID {threadId}" (numeric);
   - User SID (mono, raw).
5. **EventData preview**: the first 6 fields, styled per D12, with "Show all" expanding into the existing `EvtxDetailPane` sections.
6. **"Same ID in {window}"** card:
   - a 24-bin sparkline, 22 px tall;
   - "{n} occurrences · first {time}".
7. **Context ±5 min** (from `Selected`):
   - eyebrow "CONTEXT ±5 MIN", with "events + text logs" right-aligned (fg3);
   - a bordered list (bg1, stroke2, radius 6) of the 12 nearest analysis-timeline items within ±5 min of the selected record, events and log lines interleaved by time;
   - each row: the time (numeric, *f* − 3, 52 px), a kind chip (`EVT` / `LOG` as in the Chains tab), the message (*f* − 2), and a second line with the relative offset and source ("+3.3 s · IntuneManagementExtension.log", fg3);
   - the selected record's own row is highlighted with the selection triplet;
   - this is context only: no row claims a relationship. Rows that share an Exact or Candidate edge with the selected record show the `Link12Regular` icon;
   - the footer link "Open full correlation timeline" opens the Correlation view, with the zoom band set to the same ±5 min window;
   - data comes from the same window locator as the dock (`evtx-correlation-window.ts`).
8. **Finding callout**, shown only when the record is evidence of a finding:
   - "Part of finding: {title}" plus `ArrowRight12Regular`;
   - styled with `findingCallout` (§6.3);
   - activating it switches to the Insights tab and focuses that card.
9. **Existing `EvtxDetailPane` sections**: copy actions and markers, collapsible and unchanged in capability. XML is reached through the sub-tab.

### 8.14 Status bar content (Event Logs)

- **Where:** the global `StatusBar.tsx` already builds Event Logs status text in its `activeView === "event-log"` branch, using `useEvtxStore` (`records.length`, `sourceMode`, `isLoading`, `loadedChannels`, `loadElapsedMs`) **[Verified]**. Extend that branch, and its test `StatusBar.event-log.test.tsx`, rather than adding a `statusBarContent` component.
- **Left:** "{Live|Files} · {c} channels · {l} text logs · {n} events · {e} errors · {w} warnings", with counts in the numeric font.
- **Right:** "{View} view · Updated {time}". "Updated" is the last load or tail append time. While a query is running, the existing "Querying event logs..." / "{n} events loaded..." text is kept.
- **Correlation view variant** (from `Focus`): in the Correlation view, the left segment reads "Correlation · {n} chains · {e} exact, {c} candidate, {a} ambiguous · {u} not placed". Nearby items are not counted here (D7).
- **Note:** the mockup's "Event Logs" pill is the global view label, `statusLabel`, which currently reads "Event Log (Preview)" **[Verified]**. Its styling follows §8.18.

### 8.15 View strip: built-in and custom views

- **Mockup:** `Workbench` row 1 ("SCENARIO" strip and "+ New view").
- **Components:** `EvtxViewStrip.tsx` *(new)*; presets in `evtx-views.ts` *(new, pure)*.
- **Strip:**
  - eyebrow "VIEWS" (§7.1 eyebrow treatment);
  - one card per view, radius 6, padding `4px 10px`, *f* − 2: the name at 600 weight, then a short subtitle in fg3;
  - the active card uses the selection triplet (§6.2);
  - a "+ New view" button: 1 px dashed `colorNeutralStroke1`, radius 6;
  - the source line "Source: {machine} · {live|files}" is right-aligned in fg3.
- **Preset model [Recommendation]:**

  ```ts
  interface EvtxView {
    id: string;
    name: string;
    builtIn: boolean;
    criteria: EvtxFilterCriteria;          // existing saved-filter model, without transient criteria
    layout: { activeView: EvtxLayoutView; panels: { channels: boolean; insights: boolean; dock: boolean } };
    lastUsed: number | null;
  }
  ```

  - Transient criteria (`timeRange`, `scopeRecordIds`) are never stored in a view (Q-2).
  - Storage and export/import reuse the saved-filter persistence and sanitization approach (`evtx-saved-filters.ts`). The view schema is versioned separately (`SAVED_VIEW_SCHEMA = 1`).
- **"+ New view":** opens a dialog (8 px radius, `shadow16`, 24 px padding, per DS "Adding a new dialog") with:
  - Name (required);
  - "Include current layout" (checked by default).

  It saves the current filters and layout. Built-in views cannot be edited or deleted. A custom view's context menu offers Rename, Update from current, Duplicate, Delete and Export.
- **Built-in view (v1):** "Enrollment triage" (Q-12). Its criteria select:
  - `Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin` events 75 (Auto MDM Enroll: Succeeded) and 76 (Failed) **[Verified, Microsoft Learn]**;
  - the AAD Operational channel at Warning and above;
  - DNS-Client 1014.

  The view is a filter only. Its subtitle must not imply that these events are related. The exact criteria are reviewed in the Phase 16 PR.
- **v2:** adds the built-in Autopilot / ESP, App installs and Stability views, which also switch the main area to their scenario layouts (§15.1).

### 8.16 Compare with previous period

- **Trigger:** the "Compare with previous period" button in the Charts view (§8.10). The comparison is off by default and runs only on demand (Q-8).
- **Window:** equal length, immediately before the current window. For example, the current "Last 24 h" compares with the 24 h before that.
- **Live mode:**
  - issues a separate query with `time: { kind: "between", from, to }` (ISO 8601 UTC). The Rust `TimeWindow` already supports `Between { from, to }`, and `evtx_query_channels` accepts the parser's `EventQueryFilter` directly **[Verified]**;
  - the TypeScript `EventQueryFilterSubset.time` type currently admits only `{ kind: "last" }` **[Verified]**, so Phase 17a widens it;
  - no Rust change is needed.
- **Files mode:**
  - computed locally from the loaded records when they cover the prior window;
  - otherwise the button is disabled, with the tooltip "The loaded files do not cover the previous period."
- **Aggregation, not retention:** comparison records stream into an aggregator (level counts, the distinct (provider, ID) set, per-channel counts) and are then discarded. They never enter `records`, the grid, the diagnosis or the analysis session.
  - **[Unverified]** how streamed query batches are routed in `evtx-store.ts`, given that the store registers Tauri event listeners at module load. Phase 17b must route comparison request IDs to the aggregator and prove with a test that no comparison record reaches `records`.
- **Cancel:** changing sources, channels or the time window cancels an in-flight comparison and clears the result.

### 8.17 Export additions

**Markdown report** (all platforms)

- **Producer [Recommendation]:** a new backend command, `evtx_render_analysis_report` *(new)*, in `src-tauri/src/event_log/analysis_session.rs`. It belongs on the analysis session rather than as an `ExportFormat` in `export.rs`, because only the analysis session holds the diagnosis (`evtx_diagnose_analysis_session`), while the export session has no diagnosis data **[Verified]**.
- **Input:** the frontend sends the report scope rather than content:
  - the visible record IDs;
  - chain membership, computed in `evtx-correlation-chains.ts`, as record IDs with their strength and evidence references;
  - a filter summary.

  The command looks the records up inside the session. This way, record text never crosses into the report unredacted.
- **Redaction:** text fields go through the same `redact_text` used by the existing JSON, XML and HTML exports, and the diagnosis summary through `redacted_display_projection` **[Verified functions]**. The frontend saves the returned Markdown through the existing export save path.
- **Contents:**
  - a header with source mode, machine (redacted), window, active filters and counts;
  - findings (engine output only);
  - Exact and Candidate chains, each with its evidence lines;
  - a separately headed "Nearby, not linked" section, with no causal wording;
  - top event IDs and the level mix;
  - a visible-events table capped at 500 rows, with an omitted count.
- **Acceptance:** a test proves the report contains no unredacted machine name, user SID or tenant ID taken from the synthetic fixture.

**EVTX subset…** (Windows only)

- Uses `EvtExportLog` (`winevt.h`, Wevtapi.dll) **[Verified, Microsoft Learn]**:
  - with `EvtExportLogChannelPath` for live channels and `EvtExportLogFilePath` for `.evtx` sources;
  - one output file per source log, because the API cannot merge log files;
  - the target file must not already exist, unless `EvtExportLogOverwrite` is set.
- **Query:** the selected or visible records are expressed per source as an XPath or structured XML query over `EventRecordID`. Because XPath is limited to about 20 expressions, contiguous record IDs are compressed into ranges and a structured XML query is used when the expression count exceeds that limit.
- **Localized messages [Recommendation]:** call `EvtArchiveExportedLog` after the export, so the file renders on machines without the provider installed.
- **Unredacted gate:** the export copies raw events, so the shared redaction module cannot apply. Before export, a confirmation dialog says:

  > "These .evtx files are not redacted. They contain the original machine names, user SIDs, and other identifiers."

  The dialog's buttons are "Export unredacted" and "Cancel", with focus on Cancel by default.
- **Output:** files go to a user-chosen folder, named `{source-label}-subset.evtx`. A summary toast lists the files and the record count for each.
- **Platform:** hidden on macOS and Linux. A remote-machine source is out of scope until remote export is verified, so the item is disabled there with the tooltip "Not available for remote sources."
- **New Tauri command:** `evtx_export_subset` *(new)*. It falls under the epic's Windows-lab evidence requirement.

### 8.18 Global status bar aligned to the design system

This applies to all workspaces (Q-7).

- **Current state [Verified]:** `StatusBar.tsx` uses `minHeight: "34px"`, `padding: "6px 10px"`, background `colorNeutralBackground2`, a top border `colorNeutralStroke2`, and colored status text (`colorPaletteBlueForeground2`, `colorPaletteRedForeground1` / `2`, `colorPaletteGreenForeground1`, `colorPaletteMarigoldForeground2`, `colorPaletteYellowForeground2`).
- **Target (DS rules 3 and 5):**
  - height 24 px, padding `0 10px`, font 12 px;
  - background `colorBrandBackground`;
  - all text and icons in `colorNeutralForegroundOnBrand` when it reaches 4.5:1 against the brand background, otherwise black or white, whichever contrasts more. The theme token misses 4.5:1 in classic-cmtrace, nord and solarized-dark (decided by Adam, Phase 0b; hotdog-stand, which also failed, was removed in #878);
  - no top border.
- **Tone handling:**
  - colored text on a brand background fails contrast, so status tone is conveyed by a 12 px Fluent icon plus the label (for example `ErrorCircle12Regular`, `Warning12Regular`, `CheckmarkCircle12Regular`), all in the on-brand foreground;
  - the 6 px Graph API indicator dot keeps its fill but gains a 1 px `colorNeutralForegroundOnBrand` ring, and its label stays visible.
- **Other workspace content:** contributions inside the bar, currently only `EspStatusBarContent.tsx` (which uses neutral and palette foregrounds **[Verified]**), adopt the same on-brand foreground rule.
- **Acceptance:**
  - every workspace's status bar is captured in the screenshot harness in light, dark and high-contrast themes;
  - every status-bar text and icon pair meets WCAG AA contrast (4.5:1) against `colorBrandBackground` in each theme. The value is measured and recorded in the PR.
- **Risk:** this changes every workspace's chrome and every committed screenshot. It ships as its own phase (0b), separate from the Event Logs work.

### 8.19 Add log source…

- **Mockup:** the "Add log source…" link in the channel pane.
- **Mechanism [Verified]:** the analysis session's text-log entries come from the global log store (`useLogStore` `entries`, `activeSource` and `sourceOpenMode`), scoped by `scopeLogEntries`. A rebuild of the analysis session picks up new entries.
- **Behavior:**
  1. The link opens the existing text-log open flow (file or folder).
  2. On success, Event Logs rebuilds its analysis session.
  3. The "Also correlating" list shows the new source and its line count.
- **[Unverified]:** whether the existing log open path switches the active workspace (compare `ensureWorkspaceVisible` in `event-log/index.ts`). If it does, Phase 19 adds an option to open without switching, and the focus stays on Event Logs.
- **Merged vs single source:** when `sourceOpenMode` is not `"merged"`, only the active log source is correlated. The channel pane says which: "Correlating: active log source only" or "all open logs".

## 9. Interaction model

| Trigger | Result |
|---|---|
| Row click (any view) | Select the record, set `railTab = "details"`, and show the rail if it is hidden. Recenter the dock if it is open. |
| Layout button | Switch `activeView`. Selection and filters persist across views. |
| Panel toggle | Show or hide a region. Collapsing never discards state. |
| Histogram or swimlane drag | Set the time-range criterion (chip appears). Escape clears it. |
| Rail "Top event IDs" row | Apply an event-ID chip; the view does not change. |
| Finding "Filter to {n} events" / chain "Filter table to chain" | Apply a record-scope chip and switch to Table. |
| "Open in Correlation view" (dock or rail) | Switch to Correlation and preselect the relevant chain. |
| Chip × / "Clear all" | Remove one or all criteria. "Clear all" does not reset channel selection or time window. |
| Previous / next in Details | Move selection through `visibleRecords` and keep the row scrolled into view. |

**Record scope criterion [Recommendation].** This is a new, transient on-load criterion, `scopeRecordIds: ReadonlySet<number> | null`, evaluated in `selectVisibleRecords`. It is not persisted in saved filters.

**Time-range criterion.** This is a new, transient on-load criterion, `timeRange: { startMs: number; endMs: number } | null`. Per Q-2 it is never persisted in saved filters or views. `SAVED_FILTER_SCHEMA` stays at 2 **[Verified current value]**, and the time-window dropdown gets no "Custom…" option.

**Diagnosis scope.** This is unchanged. Diagnosis continues to use `visibleRecords` / `visibleTimeline`, per the diagnosis output spec. A brushed or scoped view therefore yields a scoped diagnosis, and the rail states the scope ("Scoped to {n} visible events").

**Layout persistence [Recommendation].** Persist `activeView`, panel visibility, rail tab, rail width and dock height between sessions using the same persistence mechanism as other workspace UI preferences. That mechanism is **[Unverified]** and must be confirmed in Phase 3. No persisted state may contain record content.

## 10. Accessibility

- Every interactive element is reachable by keyboard in visual order. Focus rings use Fluent defaults.
- Severity is conveyed by icon, text and row tint together, never by color alone.
- Charts:
  - each `<figure>` has an `aria-label` describing the series;
  - the histogram and heat map provide visually hidden tables;
  - tooltips are supplementary and never the only carrier of a value.
- Live-tail appends announce through a polite live region at most once every 5 s ("{n} new events").
- The high-contrast theme must be verified for each new component. Palette tokens resolve through Fluent's high-contrast mapping, and any component that looks wrong there is a defect.
- Motion: transitions are ≤ 200 ms and are disabled under `prefers-reduced-motion`.

## 11. Performance

- The grid keeps TanStack Virtual. Grouped and chain lists virtualize above 200 rows.
- Every derivation module (histogram, channel stats, chart data, swimlanes, chains, group summaries) is pure, memoized on input identity, and debounced at 75 ms during live tail. The 75 ms value follows the `DIAGNOSIS_DEBOUNCE_MS` precedent **[Verified]**.
- The Charts view, swimlane canvas and Correlation view are lazy-loaded.
- **Budget [Recommendation]:** at 100k loaded records on the Windows dev box, switching views takes ≤ 150 ms to first paint, and a filter change takes ≤ 100 ms before the grid updates. These are measured in the Phase 20 fidelity pass and recorded in the PR.

## 12. Data mapping and gaps

| Mockup element | Source | Status |
|---|---|---|
| Level counts | `records` → `countByLevel` | New pure function |
| Visible / loaded counts | `selectVisibleRecords` / `records.length` | Exists |
| Per-channel totals, errors, warnings, sparkline | `records` → `evtx-channel-stats.ts` | New |
| Channel coverage state | `coverageDetails` (`EvtxCoverageGap`) | Exists |
| Text logs being correlated, line counts | Analysis session `logItems` and source labels | Exists. Source labels per file are **[Unverified]**. |
| Histogram, hourly charts, heat map | `visibleRecords` → pure modules | New |
| Group summaries | `visibleRecords` → `buildGroupSummaries` | New |
| Links count per row | Timeline edges indexed by origin id | New index. Origin id format via `timelineOriginId` **[Verified]**. |
| Chains, strengths, evidence | `TimelineCorrelationEdge`, `DiagnosisCorrelationEdge` | Exists; chaining is new |
| Findings, overview | `DiagnosisSummary.findings`, `.overview` | Exists |
| "Same ID" sparkline and first seen | `records` filtered by (provider, eventId) | New, trivial |
| Dock ±75 s items | Analysis timeline pages | Client-side window locator in v1. A backend windowed query is a follow-up issue (Q-10). |
| KPI deltas vs prior window | On-demand comparison query (live) or loaded records (files) | New aggregator (§8.16); the TS filter type is widened, with no Rust change |
| Markdown report | Redacted normalized records + `redacted_display_projection` | New backend export format (§8.17) |
| EVTX subset | `EvtExportLog` per source (Windows) | New Tauri command (§8.17) |
| Additional text-log sources | Global log store → `scopeLogEntries` → analysis session rebuild | Exists; the open-without-switching behavior is **[Unverified]** (§8.19) |
| "Matches dsregcmd: MdmUrl empty" (mockup finding body) | Only if the engine emits `dsregcmdRaw` evidence (`DiagnosisEvidence` kind exists **[Verified]**) | Engine-dependent. The UI renders only what is supplied. |
| `EventData/EnrollmentId` as an explicit chain key | `TimelineCorrelationKeyKind` has no such kind **[Verified]** | Backend change, tracked as a separate #539 issue (Q-9). Until then such links can only appear as `secondary` (Candidate). |

## 13. Decisions and remaining checks

### 13.1 Decisions (recorded 2026-10-08)

| ID | Question | Decision | Where applied |
|---|---|---|---|
| Q-1 | Which selection color should Event Logs use? | Light blue: the blue palette triplet (`colorPaletteBlueBackground2`, `colorPaletteBlueBorderActive`, `colorPaletteBlueForeground2`), as in the secureboot precedent | §6.2 |
| Q-2 | Should the histogram brush persist in saved filters? | No. It is transient, `SAVED_FILTER_SCHEMA` stays at 2, and there is no "Custom…" time window. | §9, Phase 6a |
| Q-3 | How should the heat map be colored without a ramp token? | Interim `color-mix()` steps of `mergeColors[0]`, and file a design-system open question for a semantic ramp token | D11, §15.2 |
| Q-4 | How are correlation chains formed? | Connected components over exact and candidate edges. Strength is the weakest edge, and ambiguous edges never merge components. | §8.11, Phase 9 |
| Q-5 | Is "+ New view" wanted? | Yes, in v1: user presets of filters plus layout | §8.15, Phase 16 |
| Q-6 | Are the "EVTX subset" and "Markdown report" exports wanted? | Yes, in v1. The Markdown report is redacted. The EVTX subset is Windows only and unredacted, behind an explicit confirmation gate. | §8.17, Phases 18a and 18b |
| Q-7 | Status bar: 34 px neutral in code vs 24 px brand in the design system? | Fix the code to match the design system now, in every workspace | §8.18, Phase 0b |
| Q-8 | Should delta KPIs be supported? | Yes, on demand only, comparing with an equal-length prior window | §8.16, Phases 17a and 17b |
| Q-9 | Should `EventData` identifiers such as `EnrollmentId` become explicit correlation key kinds? | Yes, as a separate backend issue under #539 | §15.2 |
| Q-10 | How does the dock find the ±75 s window? | Client-side binary search over cached pages in v1, with a backend windowed query as a follow-up issue | §8.12, Phase 11, §15.2 |
| Q-11 | Should "Add log source…" be supported? | Yes, in v1 | §8.19, Phase 19 |
| Q-12 | Which events does the Enrollment triage preset use? | 75 and 76, which are documented by Microsoft Learn. Event 72 is excluded. | §8.15 |
| Q-13 | Where does the v2 App installs and Autopilot / ESP data come from? | Deep-link first: the views summarize events and link to the Intune and ESP Diagnostics workspaces. Those workspaces' models are not embedded. | §3.2, §15.1 |
| Q-14 | How are the DSRegCmd redesign mockups handled? | Option A ("Verdict first"), specified in a separate handoff spec with its own umbrella issue. Option B is kept for reference only. | §3.3, Appendix B.3 |
| Q-15 | Which earlier Event Logs exploration elements are carried into the spec? | All four offered: the Context ±5 min list, the Correlation overview with zoom band, the review of unplaced lines, and chains in the rail | §8.11, §8.11a, §8.13, Appendix B.2 |
| Q-16 | Do pill shapes follow the mockups (12–14 px) or the design system's 8 px maximum? | 8 px maximum, with no design-system exception. This applies to this spec and the DSRegCmd spec. | D21, §8.1, §8.2, §8.4 |
| Q-17 | The §6.3 level and channel tokens collapse in some themes: in high contrast, Info, Warning and Error bars all resolve to white and Critical matches the selection cyan; in the dark themes Critical and Error are indistinguishable; in four themes a channel color equals Warning. How are they sourced? | Per-theme semantic tokens (`severityPalette.eventLog`) in all seven themes, enforced by tests on resolved colors (decided 2026-10-08, found by the Phase 1 charter review) | D22, §6.3, Phase 1 |
| Q-18 | §6.2 said selected-row text is `colorNeutralForeground1`, but Q-1 names `colorPaletteBlueForeground2` as the triplet's text. Which wins? | The Q-1 triplet. `colorNeutralForeground1` on the selection background measured 3.21:1 in solarized-dark and 1.47:1 in hotdog-stand. | §6.2 |

### 13.2 Items still to verify inside phases

| Item | Phase |
|---|---|
| Whether level toggles re-query in live mode (`EvtxBeforeLoadCriteria.levels`) | 5 |
| The persistence mechanism for layout state and saved views | 3, 16 |
| How streamed query batches are routed in `evtx-store.ts`, so that comparison records never reach `records` | 17a |
| Whether the text-log open path switches the active workspace | 19 |
| Per-file source labels for text logs in the analysis session | 8 |
| Whether excluding regenerated `screenshots/*.png` from the five-file limit is acceptable for Phase 0b; otherwise they are regenerated in a separate commit | 0b |
| Whether the log workspace can open a source at a specific line ("Open in Log Viewer" from the unplaced list) | 10b |
| Kernel-Power 42 and Power-Troubleshooter 1 as sleep/resume markers (community sources only), and the failed-resume heuristic | S2 (Windows lab) |
| Application Error 1000 event-data field names for application, module and exception code | S2 |
| Autopilot policy events (101, 103) as the source for profile, deployment mode and join type tiles | S4 |
| MsiInstaller 1040 as a reliable transaction-start pair for install duration | S3 |

## 14. Verification

### 14.1 Per phase

These requirements follow `CLAUDE.md` and the epic.

- Re-read every file before editing it.
- No more than 5 files per phase.
- Stop for approval between phases.
- `npx tsc --noEmit`.
- `npm test -- <touched test files>`, then `npm test` before the final phase PR.
- `git diff --check`.
- If any Rust is touched (Phases 18a and 18b, and the Q-9 and Q-10 follow-ups), also run these from `src-tauri/`: `cargo check --locked --features event-log`, `cargo test --locked --features event-log` and `cargo clippy --locked --features event-log --all-targets -- -D warnings`, plus the epic's wasm32 parser check.
- Phase 0b: run the full `npm run screenshots` for every workspace.
- From Phase 3 onward: `npm run screenshots -- -g event-logs`, with the PNGs attached to the PR beside the matching canvas board export. Reviewers compare them against §5 measurements and §4 deviations.
- CodeRabbit plus an independent review, per the epic.

### 14.2 Screenshot fixture

The fixture is `e2e/fixtures/event-log-data.ts` *(new)*.

- **Generator:** a TypeScript port of the mockup generator (`wbBuild` in `Workbench.dc.html`): a seeded PRNG (seed 1337), 25 templates, about 1,331 events across System, Application, AAD/Operational and DeviceManagement/Admin, plus Security reported as an `accessDenied` coverage gap.
- **Injection:** the payloads are injected through `window.__e2e_ipc_overrides__` in `e2e/screenshots/capture.spec.ts`. The shim checks per-test overrides first **[Verified]**.
- **Commands to override:**
  - `evtx_parse_files`;
  - `evtx_create_analysis_session`, `evtx_append_analysis_chunk`, `evtx_finalize_analysis_session`, `evtx_query_analysis_timeline`, `evtx_diagnose_analysis_session` and `evtx_close_analysis_session` **[Verified command names]**.
- **Contents:** synthetic only. No real machine names, SIDs, tenant IDs or user names.
- **Real exports:** any real `.evtx` used for manual validation stays in a git-ignored local folder and is never committed.

### 14.3 Windows-lab evidence

These checks run before the epic closes. Each is a real-machine run whose screenshots are attached to the phase PR.

- Live channels with tail active, plus one file-mode `.evtx` set.
- Elevated and non-elevated runs, with Security showing "needs elevation" when not elevated.
- Default and largest `logListFontSize`, and the high-contrast theme.
- 100k-record performance figures (§11).
- EVTX subset export (Phase 18b) from a live channel and from an `.evtx` file, with each output opened in Event Viewer.
- The 24 px on-brand status bar (Phase 0b) in light, dark and high-contrast themes.

## 15. Delivery plan

| Phase | Title | Files (≤ 5) | Depends on |
|---|---|---|---|
| 0a | DSRegCmd MDM visibility consistency | `dsregcmd/dsregcmd-formatters.ts`, `dsregcmd/dsregcmd-formatters.test.ts`, `dsregcmd/DsregcmdSidebar.tsx`, `e2e/fixtures/screenshot-data.ts` | — |
| 0b | Global status bar aligned to the design system (all workspaces) | `src/components/layout/StatusBar.tsx`, `src/components/layout/StatusBar.workspace-label.test.tsx`, `esp-diagnostics/EspStatusBarContent.tsx`, `e2e/screenshots/capture.spec.ts` (status-bar captures in three themes) | — |
| 1 | Event Logs visual token map | `evtx-visual-tokens.ts`*, `evtx-visual-tokens.test.ts`*, `src/lib/constants.ts`, `src/lib/themes/palettes.ts`, `src/lib/color-contrast.ts`* | none |
| 2 | Event Logs screenshot harness | `e2e/fixtures/event-log-data.ts`*, `e2e/screenshots/capture.spec.ts` | — |
| 3 | Layout state, view bar, three-column shell | `evtx-layout-store.ts`*, `evtx-layout-store.test.ts`*, `EvtxViewBar.tsx`*, `EvtxViewBar.test.tsx`*, `EventLogWorkspace.tsx` | 1, 2 |
| 4 | Insights rail (Insights / Details) | `EvtxInsightsRail.tsx`*, `EvtxInsightsRail.test.tsx`*, `EventDiagnosisPanel.tsx`, `EvtxDetailPane.tsx`, `EventLogWorkspace.tsx` | 3 |
| 4b | Coverage note with Elevate action in the rail | `EvtxCoverageBanner.tsx`, `EvtxCoverageBanner.test.tsx`, `EventDiagnosisPanel.tsx`, `EventLogWorkspace.tsx` | 4 |
| 5 | Filter row and chip row | `EvtxFilterBar.tsx`, `EvtxFilterBar.test.ts`, `EvtxFilterChips.tsx`*, `EvtxFilterChips.test.tsx`*, `evtx-filter.ts` | 3 |
| 5b | Field-scoped search grammar | `evtx-query-grammar.ts`*, `evtx-query-grammar.test.ts`*, `evtx-filter.ts`, `evtx-filter.test.ts`, `EvtxFilterBar.tsx` | 5 |
| 6a | Transient time-range and record-scope criteria | `evtx-filter.ts`, `evtx-filter.test.ts`, `evtx-saved-filters.test.ts` (proves exclusion), `evtx-store.ts` | 5 |
| 6b | Event histogram with brush | `evtx-histogram.ts`*, `evtx-histogram.test.ts`*, `EvtxHistogram.tsx`*, `EvtxHistogram.test.tsx`*, `EventLogWorkspace.tsx` | 6a |
| 7 | Table restyle and links column | `EvtxTimelineRow.tsx`, `EvtxTimelineRow.test.tsx`, `evtx-columns.ts`, `evtx-columns.test.ts`, `EvtxTimeline.tsx` | 1, 3 |
| 8 | Channel pane restyle | `ChannelPicker.tsx`, `ChannelPicker.test.tsx`, `evtx-channel-stats.ts`*, `evtx-channel-stats.test.ts`* | 1, 3 |
| 9 | Correlation chain model | `evtx-correlation-chains.ts`*, `evtx-correlation-chains.test.ts`* | — |
| 10 | Correlation view | `EvtxCorrelationLanes.tsx`*, `EvtxCorrelationView.tsx`*, `EvtxCorrelationView.test.tsx`*, `UnifiedTimelineView.tsx` (extract paging hook), `EventLogWorkspace.tsx` | 6a, 9 |
| 10b | Correlation overview, zoom band and unplaced list | `EvtxCorrelationOverview.tsx`*, `EvtxCorrelationOverview.test.tsx`*, `EvtxUnplacedList.tsx`*, `EvtxUnplacedList.test.tsx`*, `EvtxCorrelationView.tsx` | 10 |
| 10c | Chains tab in the rail | `EvtxRailChains.tsx`*, `EvtxRailChains.test.tsx`*, `EvtxInsightsRail.tsx` | 4, 9, 10b |
| 11 | Correlation dock (client-side window locator) | `EvtxCorrelationDock.tsx`*, `EvtxCorrelationDock.test.tsx`*, `evtx-correlation-window.ts`*, `evtx-correlation-window.test.ts`*, `EventLogWorkspace.tsx` | 10 |
| 11b | Details context ±5 min | `EvtxDetailContext.tsx`*, `EvtxDetailContext.test.tsx`*, `EvtxDetailPane.tsx` | 4, 11 |
| 12 | Grouped view | `EvtxGroupedView.tsx`*, `EvtxGroupedView.test.tsx`*, `evtx-filter.ts`, `evtx-filter.test.ts` | 3, 7 |
| 13 | Timeline swimlanes | `EvtxSwimlaneView.tsx`*, `EvtxSwimlaneView.test.tsx`*, `evtx-swimlanes.ts`*, `evtx-swimlanes.test.ts`* | 6a |
| 14 | Charts view | `EvtxChartsView.tsx`*, `EvtxChartsView.test.tsx`*, `evtx-chart-data.ts`*, `evtx-chart-data.test.ts`* | 9 (chain KPI) |
| 15 | Event Logs status bar content and toolbar action | `src/components/layout/StatusBar.tsx`, `src/components/layout/StatusBar.event-log.test.tsx`, `EvtxToolbarAction.tsx`*, `EvtxToolbarAction.test.tsx`*, `index.ts` | 0b, 3 |
| 16 | View strip and custom views (Enrollment triage built in) | `evtx-views.ts`*, `evtx-views.test.ts`*, `EvtxViewStrip.tsx`*, `EvtxViewStrip.test.tsx`*, `EventLogWorkspace.tsx` | 3, 5, 6a |
| 17a | Comparison query and aggregator | `types.ts` (widen `EventQueryFilterSubset.time`), `evtx-comparison.ts`*, `evtx-comparison.test.ts`*, `evtx-store.ts` | 3 |
| 17b | "Compare with previous period" in Charts | `EvtxChartsView.tsx`, `EvtxChartsView.test.tsx`, `evtx-chart-data.ts`, `evtx-chart-data.test.ts` | 14, 17a |
| 18a | Markdown report export (redacted) | `src-tauri/src/event_log/analysis_session.rs`, `src-tauri/src/lib.rs` (register command), `src/lib/commands.ts`, `evtx-export.ts`, `evtx-export.test.ts` | 4, 9 |
| 18b | EVTX subset export (Windows, unredacted gate) | `src-tauri/src/event_log/export_subset.rs`*, `src-tauri/src/event_log/mod.rs`, `src-tauri/src/lib.rs`, `src/lib/commands.ts`, `EvtxExportSubsetDialog.tsx`* | 3 |
| 19 | Add log source | `ChannelPicker.tsx`, `ChannelPicker.test.tsx`, `EventLogWorkspace.tsx`, plus the log-open path file identified in Phase 8 (**[Unverified]**) | 8 |
| 20 | Fidelity, accessibility and performance pass | No new files; fixes are filed as follow-ups if they exceed 5 files | All of the above |
| S1 (v2) | Built-in scenario views | `evtx-views.ts`, `evtx-views.test.ts`, `EventLogWorkspace.tsx` | 20 |
| S2 (v2) | Stability view | `evtx-boot-sessions.ts`*, `evtx-boot-sessions.test.ts`*, `EvtxStabilityView.tsx`*, `EvtxStabilityView.test.tsx`* | S1 |
| S3 (v2) | App installs view (deep-link) | `evtx-app-installs.ts`*, `evtx-app-installs.test.ts`*, `EvtxAppInstallsView.tsx`*, `EvtxAppInstallsView.test.tsx`* | S1 |
| S4 (v2) | Autopilot / ESP view (deep-link) | `evtx-provisioning.ts`*, `evtx-provisioning.test.ts`*, `EvtxProvisioningView.tsx`*, `EvtxProvisioningView.test.tsx`* | S1 |

`*` marks new files. Paths without a directory are under `src/workspaces/event-log/`, except `dsregcmd/` and `esp-diagnostics/`, which are under `src/workspaces/`.

Phase 0b regenerates the committed `screenshots/*.png` files. Those are generated output. Confirm whether they count toward the five-file limit; if they do, they are regenerated in a separate commit (§13.2).

### 15.1 v2 scenario notes

Per Q-13, the v2 scenario views summarize what the event logs show and deep-link to the existing workspaces for model-level detail. They do not embed the Intune or ESP Diagnostics models.

Every scenario view keeps the standard chrome: the view strip, the view bar (with "Show as table" in place of the layout tablist, as in the mockup), the filter row, the channel pane and the rail. Each element of the scenario boards is listed below with its source. Elements marked D20 are replaced by deep-link actions.

**Stability (S2), board `WB-Stability`**

Boot sessions and crashes are derived only from these events:

- documented on Microsoft Learn **[Verified]**:
  - Kernel-Power 41 (rebooted without a clean shutdown);
  - EventLog 6008 (the previous shutdown was unexpected);
  - User32 1074 (an application or user initiated a restart);
  - EventLog 6006 (clean stop) and 6009 (boot);
  - Kernel-General 12 and 13 (OS start and stop);
  - WER-SystemErrorReporting 1001 (bugcheck);
  - Application Error 1000 (application crash, with faulting application, faulting module and exception code in the event data).
- documented only in community sources **[Unverified]**, to be confirmed in the Windows lab before Phase S2:
  - Kernel-Power 42 ("The system is entering sleep");
  - Power-Troubleshooter 1 ("The system has returned from a low power state").

Event 1001 also exists under Windows Error Reporting in the Application log (APPCRASH), so every rule must match on provider as well as ID.

| Mockup element | Source | Notes |
|---|---|---|
| KPI tile: Powered-on time (% of window) | Session spans from boot (12, 6009) to shutdown (13, 6006, 1074) or to an unclean marker (41, 6008), minus sleep spans | Sleep spans depend on the unverified 42 and Power-Troubleshooter 1 |
| KPI tile: Unclean shutdowns | Count of sessions ended by 41 or 6008 | Sublabel "Kernel-Power 41 + EventLog 6008" |
| KPI tile: App crashes | Count of Application Error 1000 | Sublabel names the top faulting application |
| KPI tile: Bugchecks | Count of WER-SystemErrorReporting 1001 | "no BugCheck" copy when 0 |
| KPI tile: Failed resumes | 41 whose preceding power event is a sleep (42) with no resume (Power-Troubleshooter 1) | **[Unverified heuristic]**. Shipped only after Windows-lab confirmation; otherwise the tile is omitted. |
| Boot sessions bar (running, sleep, crash ticks, unclean markers) | As above. Crash ticks come from 1000; unclean markers use `Flash16Regular` | Intent only, designed in the v2 phases (#855, owner decision 2026-10-09; matches §6.3): running a cool blue or indigo, sleep a muted violet (see the #855 hue bands) |
| Session cards (span, end state, uptime, crashes, errors, sleep/resume) | Session model in `evtx-boot-sessions.ts` | Intent only, designed in #855 (owner decision 2026-10-09): End-state badge: Running (a cool blue or indigo per the #855 hue bands; Succeeded green), Clean · {reason} (neutral), Unclean · Kernel-Power 41 (color owned by #855) |
| "Last events before the unclean shutdown" list | The N records before the session end, plus an explicit "No clean-shutdown events (1074 / 6006) before power loss" row when none exist | **Context only, with no causal wording** (D8) |
| Top crashing apps (count, module, exception code) | Event 1000 data fields: faulting application, module and exception code | Event-data field names are confirmed against real 1000 records in Phase S2 |
| App crashes per day | Event 1000 bucketed by local day | Single-series bars use `singleSeries` |

**Autopilot / ESP (S4), board `WB-Autopilot`**

The event sources are documented by Microsoft Learn **[Verified]**:

- `Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot` (event IDs 100–172 and 807–908);
- `Microsoft-Windows-Provisioning-Diagnostics-Provider/Admin` (ESP);
- DeviceManagement-Enterprise-Diagnostics-Provider 75 and 76 for MDM enrollment.

| Mockup element | Source | Notes |
|---|---|---|
| Provisioning result banner (headline + summary, "Open in ESP Diagnostics", "Export session") | Only from a diagnosis finding with `EventDiagnosis.family` `autopilot` or `esp` **[Verified enum]**. It uses the finding's title and summary; with no such finding, the banner reads "No provisioning failure finding" in neutral styling | The UI never composes a failure narrative (D8). "Export session" runs the Markdown report (§8.17) scoped to the scenario. |
| Metadata tiles (Device, Profile, Deployment mode, Join type, Started, Elapsed) | Device from `records[].computer`. Profile, deployment mode and join type from the Autopilot policy events (101 and 103 carry policy names and values) **[Unverified field mapping]**. Started and Elapsed come from the first and last Autopilot or Provisioning event | A tile without a source value shows "—" rather than a guess |
| Provisioning phases Gantt | Milestones from the Autopilot channel (profile download 153/161, TPM attestation errors 171/172) and the 75/76 enrollment events, rendered with Fluent `GanttChart` **[Verified export]** | Phase-level ESP status (device setup, account setup, per-category counts, timeouts) belongs to the ESP model. It is **D20**: "Open in ESP Diagnostics". |
| "Tracked by ESP · blocking apps" table | ESP model | **D20**: replaced by a card linking to ESP Diagnostics |
| "Provisioning events" list | Records from the three channels above, newest last, with level dots | — |

**App installs (S3), board `WB-Apps`**

MsiInstaller events 11707 (installation succeeded), 11708 (installation failed) and 1033 (installation completed with status %4) are documented **[Verified]**. Event 1033 carries a status field, so success must be read from that field, not inferred from the ID.

| Mockup element | Source | Notes |
|---|---|---|
| KPI tiles (targeted, installed, failed, reboot pending, attempts) | MSI events grouped by product name. "Targeted" and "required/available" intent come from Intune, not from events | **D20** for targeted counts and intent. Event-derived tiles are Installed, Failed, Reboot pending (1033 status 3010) and Attempts. |
| Install attempts strip (one bar per attempt, labelled with the exit code) | 1033 / 11707 / 11708 per product, positioned by time; exit code from the 1033 status | "Detected (no action)" attempts come from IME and are **D20** |
| Attempt history table (#, started, duration, exit code, detection, evidence) | Started and exit code come from MSI events. Duration needs the start event (MsiInstaller 1040 "Beginning a Windows Installer transaction"), which is in the sample data but **[Unverified]** as a reliable pair. Detection comes from IME. | Detection shows "Open in Intune Diagnostics" (**D20**). Evidence links to the record. |
| Error lookup card (for example 1603) | The existing error-code lookup (`DiagnosisErrorToken` with `description` and `category` **[Verified type]**; the global Error lookup) | Copy comes from the lookup data, never hand-written |
| MSI log excerpt | Only when the MSI verbose log is attached as a text-log source through "Add log source…" (§8.19). The excerpt shows lines around "Return value 3" | Hidden otherwise |
| Content card (size, Delivery Optimization peers, download time, hash) | IME / Delivery Optimization data | **D20**: "Open in Intune Diagnostics" |

**D20 (v2).** The scenario layouts show only what the event logs support. Model-derived panels in the mockups are replaced by deep-link actions until a later decision embeds those models:

- the ESP phase Gantt detail and the tracked-app table;
- the Intune targeting and intent;
- IME detection and content details.

### 15.2 Follow-up issues (outside the phase sequence)

| Follow-up | Decision | Notes |
|---|---|---|
| Rust correlation key kinds for `EventData` identifiers such as `EnrollmentId` | Q-9 | Child of #539. Requires cargo gates, the wasm32 parser check and Windows-lab evidence. Once it lands, such links can be Exact rather than Candidate. |
| Windowed analysis-timeline query (`startMs`, `endMs`, `limit`) and full edge paging | Q-10 | Child of #539. Once it lands, Phase 11's client-side locator calls it instead. |
| Design-system open question: a semantic sequential data-ramp token in all seven themes | Q-3 | Add an `OQ-n` entry to `docs/design-system/OPEN-QUESTIONS.md`. Once it lands, D11's interim `color-mix()` is replaced. |

## 16. Corrections to earlier notes

During design review, the DSRegCmd "MDM shows Unknown while the sidebar shows No" discrepancy was described as a product bug. Verification shows that the parser emits `mdm_enrolled` only as `Some(true)` or `None` (`crates/cmtraceopen-parser/src/dsregcmd/derive.rs`; the upgrade logic in `extended.rs` only ever sets `Some(true)`) **[Verified]**.

The `false` state is therefore reachable only through the screenshot fixture (`e2e/fixtures/screenshot-data.ts` sets `mdmEnrolled: false`). Even so, it is a real inconsistency between two formatters for a type that allows `false`. Phase 0a makes both views agree, and fixes the fixture to reflect the parser's actual output.

---

## Appendix A. GitHub issue drafts

Conventions:

- These drafts were published as issues #823–#858 on 2026-10-08. The issues are now authoritative for scope and status.
- Each draft is ready to paste.
- Titles use sentence case.
- Labels are suggestions; the repository's label set was not readable from this session.
- Every implementation issue links this spec and #539.
- Attach the matching canvas board exports (PNG) to each UI issue.

### A.0 Umbrella

**Title:** Event Logs workbench UI (design handoff)

**Labels (suggested):** `event-log`, `ui`, `epic-child`

```markdown
Parent: #539 (Phase 3 analysis UX, Phase 4 unified timeline, Phase 7 diagnosis presentation)
Spec: docs/superpowers/specs/2026-10-08-event-logs-workbench-ui-handoff-design.md

Implements the Event Logs workbench mockups (Claude Design canvas, "Event Logs — full UI" page)
as close to the mockups as the epic invariants and design system allow. Every intentional
difference is listed in spec §4 (and D20 for v2); anything else is a defect.

### Phases
- [ ] 0a — DSRegCmd MDM visibility consistency
- [ ] 0b — Global status bar aligned to the design system (all workspaces)
- [ ] 1 — Event Logs visual token map
- [ ] 2 — Event Logs screenshot harness
- [ ] 3 — Layout state, view bar, three-column shell
- [ ] 4 — Insights rail
- [ ] 4b — Coverage note with Elevate action
- [ ] 5 — Filter row and chip row
- [ ] 5b — Field-scoped search grammar
- [ ] 6a — Transient time-range and record-scope criteria
- [ ] 6b — Event histogram with brush
- [ ] 7 — Table restyle and links column
- [ ] 8 — Channel pane restyle
- [ ] 9 — Correlation chain model
- [ ] 10 — Correlation view
- [ ] 10b — Correlation overview, zoom band and unplaced list
- [ ] 10c — Chains tab in the rail
- [ ] 11 — Correlation dock
- [ ] 11b — Details context ±5 min
- [ ] 12 — Grouped view
- [ ] 13 — Timeline swimlanes
- [ ] 14 — Charts view
- [ ] 15 — Event Logs status bar content and toolbar action
- [ ] 16 — View strip and custom views
- [ ] 17a — Comparison query and aggregator
- [ ] 17b — Compare with previous period
- [ ] 18a — Markdown report export
- [ ] 18b — EVTX subset export (Windows)
- [ ] 19 — Add log source
- [ ] 20 — Fidelity, accessibility and performance pass
- [ ] v2: S1 built-in scenario views · S2 stability · S3 app installs · S4 Autopilot / ESP

### Follow-ups (separate issues under #539)
- [ ] EventData identifier correlation keys (Q-9)
- [ ] Windowed analysis-timeline query (Q-10)
- [ ] Design-system OQ: sequential data-ramp token (Q-3)

### Decisions (spec §13.1, recorded 2026-10-08)
Q-1 light-blue selection · Q-2 brush transient · Q-3 interim heat-map mix · Q-4 weakest-edge chains ·
Q-5/6/8/11 custom views, extra exports, delta KPIs and add-log-source in v1 · Q-7 status bar to DS now ·
Q-9/Q-10 backend follow-ups · Q-12 events 75 and 76 · Q-13 deep-link first

### Invariants (from #539)
- No causality from timestamp proximity alone: time-only relations are never chains, connectors, or counts.
- Findings come only from the diagnosis engine.
- Exports are redacted, except the Windows EVTX subset, which ships behind an explicit unredacted confirmation.
- No real tenant data in fixtures.
```

### A.1 Phase 0a: DSRegCmd MDM visibility consistency

**Labels:** `dsregcmd`, `bug`

```markdown
Spec: §16, §15 (Phase 0a)

`getMdmVisibilityLabel` / `toneForMdmVisibility` (dsregcmd-formatters.ts) map `mdmEnrolled === false`
to "Unknown"/neutral, while `DsregcmdSidebar.tsx` renders "No". The parser emits only `true` or `null`
today, so the inconsistency is visible only through `e2e/fixtures/screenshot-data.ts` (`mdmEnrolled: false`).

### Scope (4 files)
- dsregcmd-formatters.ts: `false` → "Not enrolled", tone "warn"; `null` → "Unknown" (unchanged).
- dsregcmd-formatters.test.ts: cover true / partial / false / null.
- DsregcmdSidebar.tsx: use `getMdmVisibilityLabel` instead of the inline ternary.
- e2e/fixtures/screenshot-data.ts: `mdmEnrolled: null` to match parser output.

### Acceptance
- Both surfaces show the same label for every `mdmEnrolled` value.
- `npx tsc --noEmit`, `npm test -- dsregcmd`, `git diff --check` pass.
```

### A.2 Phase 0b: Global status bar aligned to the design system

**Labels:** `ui`, `design-system`

```markdown
Spec: §8.18, Q-7, DS rules 3 and 5

`StatusBar.tsx` renders at minHeight 34px on colorNeutralBackground2 with colored status text.
SKILL.md specifies a 24px status bar on the brand background. This aligns the code with the design
system for every workspace.

### Scope (4 files + regenerated screenshots)
- `src/components/layout/StatusBar.tsx`: 24px, padding 0 10px, colorBrandBackground,
  colorNeutralForegroundOnBrand for all text and icons, no top border; tone shown by 12px Fluent icon + label;
  Graph API dot gains an on-brand ring.
- `src/components/layout/StatusBar.workspace-label.test.tsx`: height/background/foreground assertions.
- `src/workspaces/esp-diagnostics/EspStatusBarContent.tsx`: adopt the on-brand foreground rule.
- `e2e/screenshots/capture.spec.ts`: status-bar captures in light, dark and high-contrast themes.

### Acceptance
- WCAG AA (4.5:1) for every status-bar text/icon pair against colorBrandBackground in each theme; values recorded in PR.
- All workspace screenshots regenerated and reviewed. Confirm whether the regenerated PNGs count toward the five-file limit;
  if they do, regenerate them in a separate commit.
- tsc / tests / diff-check pass.
```

### A.3 Phase 1: Event Logs visual token map

**Labels:** `event-log`, `ui`, `design-system`

```markdown
Spec: §6, §7.3

### Scope (5 files)
- `evtx-visual-tokens.ts` (new): level → {barColor, dotColor, iconColor, textColor, icon, rowBackground, rowText}; `markOutline(context)`; `selectedDataColor`;
  strength → badge triplet; selection triplet (Q-1: colorPaletteBlueBackground2 / BorderActive / Foreground2);
  channel colors as per-theme semantic tokens (Q-17, D22); heat-map steps (Q-3 interim color-mix).
  live source pill triplet (`liveSource`, §8.1). v2 scenario state colors are out of scope (#855).
  Inputs: Fluent `tokens` + `getThemeById(themeId).severityPalette`.
- `src/lib/constants.ts`, `src/lib/themes/palettes.ts`, `src/lib/color-contrast.ts` (new): the per-theme `severityPalette.eventLog` tokens (D22) and the contrast helpers behind the floors in §6.3.
- `evtx-visual-tokens.test.ts` (new): deterministic channel assignment in display order, cycling every six; every level and strength mapped; no hex literals in the module; semantic hue bands (Critical and Error red family, Warning amber, channels cool); WCAG floors per placement (3:1 marks, 4.5:1 text); the CIEDE2000 floors of §6.3 per family pair.

### Acceptance
- No component in later phases references a palette or hex directly.
- tsc / tests / diff-check pass.
```

### A.4 Phase 2: Event Logs screenshot harness

**Labels:** `event-log`, `testing`

```markdown
Spec: §14.2

### Scope (2 files)
- `e2e/fixtures/event-log-data.ts` (new): TS port of the mockup generator (seed 1337, 25 templates,
  ~1,331 events; Security as an accessDenied coverage gap); synthetic analysis-session and diagnosis payloads.
  Placeholder user names only.
- `e2e/screenshots/capture.spec.ts`: `event-logs` captures (table, selected + dock, grouped, timeline,
  charts, correlation) using `window.__e2e_ipc_overrides__` for the evtx_* commands listed in §14.2.

### Acceptance
- `npm run screenshots -- -g event-logs` produces deterministic PNGs at 1440×900 @2x.
- Fixture contains no real machine names, SIDs, tenant IDs, or user names.
- Before Phase 3 the captures show the current UI (baseline for comparison).
```

### A.5 Phase 3: Layout state, view bar, three-column shell

**Labels:** `event-log`, `ui`

```markdown
Spec: §5, §8.2, §9 (layout persistence)

### Scope (5 files)
- `evtx-layout-store.ts` (+ test, new): activeView, panels {channels, insights, dock}, railTab, railWidth, dockHeight.
- `EvtxViewBar.tsx` (+ test, new): layout tablist, panel toggles, Group by, Columns, Export menu (existing formats).
- `EventLogWorkspace.tsx`: channel pane | main | rail columns; Table is the only view wired in this phase
  (others render a "Not implemented in this phase" placeholder behind the same tablist).

### Acceptance
- Measurements per spec §5.1–5.2 (±2 px) in the Phase 2 screenshots.
- Keyboard: tablist arrow navigation; toggles expose aria-pressed.
- Confirm and document the persistence mechanism for layout state (spec §13.2).
- tsc / tests / diff-check / screenshots pass.
```

### A.6 Phase 4: Insights rail

**Labels:** `event-log`, `ui`, `diagnosis`

```markdown
Spec: §5.3, §8.13

### Scope (5 files)
- `EvtxInsightsRail.tsx` (+ test, new): tabs Insights / Details ("Event {id}" when selected).
- `EventDiagnosisPanel.tsx`: rail variant — finding cards (actionable only, sorted severity → confidence),
  collapsed coverage disclosure with DETAIL_RENDER_CAP, level mix, top event IDs, correlation summary.
- `EvtxDetailPane.tsx`: summary header (with close button) + "Details | XML" sub-tabs + definition grid + EventData preview,
  existing sections below.
- `EventLogWorkspace.tsx`: remove top diagnosis card and bottom detail pane; mount rail.

### Acceptance
- No finding text is generated by the UI; empty state shows overview headline + "No actionable findings."
- Coverage detail collapsed by default and capped with an omitted count.
- Row click switches to Details and opens the rail if hidden.
- tsc / tests / diff-check / screenshots pass.
```

### A.6b Phase 4b: Coverage note with Elevate action

**Labels:** `event-log`, `ui`, `diagnosis`

```markdown
Spec: §8.13 (Insights tab item 2), mockup `Main`

### Scope (4 files)
- `EvtxCoverageBanner.tsx` (+ existing test): rail variant — "{channel} channel not read. Findings may be incomplete."
  with lock icon and "Elevate" action opening the existing RestartAsAdministratorDialog; hidden when elevated or non-Windows.
- `EventDiagnosisPanel.tsx`: render the note above the coverage disclosure.
- `EventLogWorkspace.tsx`: remove the banner from above the grid.

### Acceptance
- Shown only when an accessDenied gap exists; other gap kinds stay in the coverage disclosure.
- tsc / tests / diff-check / screenshots pass.
```

### A.7 Phase 5: Filter row and chip row

**Labels:** `event-log`, `ui`, `filters`

```markdown
Spec: §8.3, §8.4

### Scope (5 files)
- `EvtxFilterBar.tsx` (+ existing test): search, level toggles with counts, time window (no "Custom…", Q-2),
  "More filters · {n}" popover (event IDs, quick-filter grammar, case, highlight, saved filters).
- `EvtxFilterChips.tsx` (+ test, new): chips, Clear all, "Showing {visible} of {loaded}".
- `evtx-filter.ts`: `countByLevel(records)`.

### Acceptance
- Every capability of the current filter bar reachable within two interactions.
- Verify and document whether level toggles re-query in live mode; show loading state if so.
- tsc / tests / diff-check / screenshots pass.
```

### A.7b Phase 5b: Field-scoped search grammar

**Labels:** `event-log`, `filters`

```markdown
Spec: §8.3 (field grammar), mockups `Main` (placeholder) and `Workbench` (scenario queries)

### Scope (5 files)
- `evtx-query-grammar.ts` (+ test, new): parser for id:, level:, provider:, channel:, computer:, source:, data.<Name>:,
  OR, negation, quoted values; structured errors.
- `evtx-filter.ts` (+ test): `fieldQuery` quick-filter mode evaluated in selectVisibleRecords.
- `EvtxFilterBar.tsx`: placeholder "Search…   id:76  level:error  provider:AAD"; inline error under the input.

### Acceptance
- Unknown mode falls back safely in older builds (sanitizeQuickFilter); saved-filter round trip covered.
- tsc / tests / diff-check / screenshots pass.
```

### A.8 Phase 6a: Transient time-range and record-scope criteria

**Labels:** `event-log`, `filters`

```markdown
Spec: §9 (criteria), Q-2

### Scope (4 files)
- `evtx-filter.ts` (+ test): transient on-load `timeRange` and `scopeRecordIds` in `selectVisibleRecords`.
- `evtx-saved-filters.test.ts`: proves neither criterion is serialized; SAVED_FILTER_SCHEMA stays 2.
- `evtx-store.ts`: setters and clear actions.

### Acceptance
- Diagnosis continues to use visibleRecords / visibleTimeline (scoped diagnosis when brushed or scoped).
- tsc / tests / diff-check pass.
```

### A.9 Phase 6b: Event histogram with brush

**Labels:** `event-log`, `ui`, `charts`

```markdown
Spec: §8.5

### Scope (5 files)
- `evtx-histogram.ts` (+ test, new): nice-interval bucketing (48–96 buckets), level stacking, excludes own time-range.
- `EvtxHistogram.tsx` (+ test, new): 56 px bars, legend, axis, brush (mouse + keyboard), hidden data table.
- `EventLogWorkspace.tsx`: mount under the chip row.

### Acceptance
- 100k-record rebucket ≤ 50 ms on the Windows dev box (record figure in PR).
- Brush sets the time chip; Escape and chip × clear it.
- tsc / tests / diff-check / screenshots pass.
```

### A.10 Phase 7: Table restyle and links column

**Labels:** `event-log`, `ui`

```markdown
Spec: §4 (D1, D3, D4, D13), §8.7

### Scope (5 files)
- `EvtxTimelineRow.tsx` (+ test): row-wide severity tint, level icons, numeric font for time/ID,
  light-blue selection triplet (Q-1), marker slot preserved, links cell.
- `evtx-columns.ts` (+ test): `links` column id; new default widths; existing configs preserved.
- `EvtxTimeline.tsx`: header styling; row height from getLogListMetrics only.

### Acceptance
- Error and Critical rows tinted row-wide with `levels.<L>.rowBackground` / `rowText` (`severityPalette.error`); Warning likewise (`severityPalette.warning`).
- Level communicated by icon + accessible name, not color alone.
- tsc / tests / diff-check / screenshots pass.
```

### A.11 Phase 8: Channel pane restyle

**Labels:** `event-log`, `ui`

```markdown
Spec: §8.6

### Scope (4 files)
- `evtx-channel-stats.ts` (+ test, new): per-channel totals, errors, warnings, 24-bin activity.
- `ChannelPicker.tsx` (+ test): header "{read} of {total} read", existing filter box and Windows Logs / services tree
  with collapsible group headers, swatch, sparkline, counts, coverage state ("needs elevation"),
  "Also correlating" section (link to Add log source arrives in Phase 19), live-tail footer with Pause/Resume;
  DEFAULT_SIDEBAR_WIDTH 300 → 250.

### Acceptance
- accessDenied channels render "needs elevation", "—", flat sparkline.
- Identify and record the text-log open path file for Phase 19, and the per-file source labels (spec §13.2).
- tsc / tests / diff-check / screenshots pass.
```

### A.12 Phase 9: Correlation chain model

**Labels:** `event-log`, `correlation`

```markdown
Spec: §8.11 (chain model), Q-4, invariant D7

### Scope (2 files)
- `evtx-correlation-chains.ts` (+ test, new): connected components over exact + candidate edges;
  strength = weakest edge; ambiguous and coverageBlocked as singleton items;
  timestampOnly / notCausal → "nearby, not linked" only; ordering; render cap 100 with omitted count;
  titles per D19.

### Acceptance
- Property tests: no timestampOnly/notCausal relation ever appears in a chain or chain count.
- Deterministic ordering for identical input.
- tsc / tests / diff-check pass.
```

### A.13 Phase 10: Correlation view

**Labels:** `event-log`, `ui`, `correlation`

```markdown
Spec: §8.11

### Scope (5 files)
- `EvtxCorrelationLanes.tsx` (new): shared lane renderer (markers, edge pins, connectors by strength).
- `EvtxCorrelationView.tsx` (+ test, new): chain list, header, lane plot, "Why these are linked", "Sequence",
  "Filter table to chain", "Copy as text".
- `UnifiedTimelineView.tsx`: extract paging/cache/retry into a reusable hook (no behavior change).
- `EventLogWorkspace.tsx`: wire the Correlation view.

### Acceptance
- Every connector traceable to ≥ 1 evidence row.
- Not-linked items render without connectors and labelled "Not linked".
- tsc / tests / diff-check / screenshots pass.
```

### A.13b Phase 10b: Correlation overview, zoom band and unplaced list

**Labels:** `event-log`, `ui`, `correlation`

```markdown
Spec: §8.11 (overview strip, Not placed row), §8.11a, mockup `Focus`

### Scope (5 files)
- `EvtxCorrelationOverview.tsx` (+ test, new): 48 px overview of all chain spans with draggable/resizable zoom band
  (mouse + keyboard) controlling the lane window.
- `EvtxUnplacedList.tsx` (+ test, new): unplaced items (UnifiedTimeline.unplaced), cap 100 with omitted count,
  Copy as text, Open in Log Viewer (confirm open-at-line support).
- `EvtxCorrelationView.tsx`: mount overview; "Not placed (n)" row; "Why these are linked" as Entry / Where the key appears table;
  Event / Log line shape legend.

### Acceptance
- Unplaced items are never positioned on any timeline.
- tsc / tests / diff-check / screenshots pass.
```

### A.13c Phase 10c: Chains tab in the rail

**Labels:** `event-log`, `ui`, `correlation`

```markdown
Spec: §8.13 (Chains tab), mockup `Correlations` ("Correlation B")

### Scope (3 files)
- `EvtxRailChains.tsx` (+ test, new): legend (Exact match / Candidate identity / Not linked), chain cards with steps and
  EVT/LOG chips, Show in table, Open in correlation view, Ambiguous/Coverage blocked rows, "Nearby, not linked" disclosure,
  "Not placed" card, empty state.
- `EvtxInsightsRail.tsx`: add the "Chains {n}" tab.

### Acceptance
- Same ordering, cap, and D7 rules as the Correlation view (shared chain model).
- tsc / tests / diff-check / screenshots pass.
```

### A.14 Phase 11: Correlation dock

**Labels:** `event-log`, `ui`, `correlation`

```markdown
Spec: §8.12, Q-10

### Scope (5 files)
- `evtx-correlation-window.ts` (+ test, new): locate the ±75 s window by binary search over cached timeline pages
  (6-page cap, explicit "incomplete" result). Isolated behind one function so the Q-10 backend query can replace it.
- `EvtxCorrelationDock.tsx` (+ test, new): header with window dropdown (±30 s / ±75 s / ±2 min / ±5 min) and collapse,
  lanes, chain summary line with "Also nearby: … (time only, not linked)", empty/unplaced states, "Open in Correlation view".
- `EventLogWorkspace.tsx`: dock under main view, resizable 160 px–50vh.

### Acceptance
- Selection change recenters the dock; incomplete windows show an explicit notice.
- tsc / tests / diff-check / screenshots pass.
```

### A.14b Phase 11b: Details context ±5 min

**Labels:** `event-log`, `ui`

```markdown
Spec: §8.13 (Details tab item 7), mockup `Selected`

### Scope (3 files)
- `EvtxDetailContext.tsx` (+ test, new): 12 nearest timeline items within ±5 min (events + log lines), EVT/LOG chips,
  relative offsets, link icon only for Exact/Candidate-linked rows, "Open full correlation timeline".
- `EvtxDetailPane.tsx`: mount the section.

### Acceptance
- No relationship wording for rows without an edge.
- Uses evtx-correlation-window.ts (no new paging code).
- tsc / tests / diff-check / screenshots pass.
```

### A.15 Phase 12: Grouped view

**Labels:** `event-log`, `ui`

```markdown
Spec: §8.8

### Scope (4 files)
- `evtx-filter.ts` (+ test): `buildGroupSummaries` (typical message, count, 24-bin trend, last seen, severity sort).
- `EvtxGroupedView.tsx` (+ test, new): summary table, expandable rows (8 items), "Show all {n} in table".

### Acceptance
- 5,000 groups virtualized and smooth on the Windows dev box.
- tsc / tests / diff-check / screenshots pass.
```

### A.16 Phase 13: Timeline swimlanes

**Labels:** `event-log`, `ui`, `charts`

```markdown
Spec: §8.9

### Scope (4 files)
- `evtx-swimlanes.ts` (+ test, new): lanes by provider/channel/event ID, top 12 + "Other".
- `EvtxSwimlaneView.tsx` (+ test, new): canvas lanes with resolved theme colors, hit-testing, shared brush.

### Acceptance
- Dot click selects the nearest record (≤ 4 px).
- Theme switch re-resolves colors without reload.
- tsc / tests / diff-check / screenshots pass.
```

### A.17 Phase 14: Charts view

**Labels:** `event-log`, `ui`, `charts`

```markdown
Spec: §8.10, D11, D15

### Scope (4 files)
- `evtx-chart-data.ts` (+ test, new): KPIs (derivable sublabels only), channel bars, top IDs
  (caption reflects active hide rules), hour × channel matrix, hourly errors/warnings, peak.
- `EvtxChartsView.tsx` (+ test, new, lazy): KPI grid + 2×2 figures; HeatMapChart and VerticalStackedBarChart
  spike recorded in the PR (fallback: token-styled SVG). Heat map uses the Q-3 interim color-mix steps.

### Acceptance
- No comparative sublabels until Phase 17b's comparison runs.
- Each figure has an aria-label; histogram-style figures have hidden tables.
- tsc / tests / diff-check / screenshots pass.
```

### A.18 Phase 15: Event Logs status bar content and toolbar action

**Labels:** `event-log`, `ui`

```markdown
Spec: §8.1, §8.14

### Scope (5 files)
- `src/components/layout/StatusBar.tsx`: extend the existing `activeView === "event-log"` branch
  (source mode, channels, text logs, counts, view, updated time), on the Phase 0b on-brand styling.
- `src/components/layout/StatusBar.event-log.test.tsx`: cover the new segments, including the Correlation view variant
  ("Correlation · {n} chains · {e} exact, {c} candidate, {a} ambiguous · {u} not placed"; no nearby count).
- `EvtxToolbarAction.tsx` (+ test, new): live/files pill with machine name and tail state.
- `index.ts`: register `toolbarAction`.

### Acceptance
- Counts match the chip row and the grid.
- tsc / tests / diff-check / screenshots pass.
```

### A.19 Phase 16: View strip and custom views

**Labels:** `event-log`, `ui`, `filters`

```markdown
Spec: §8.15, Q-5, Q-12

### Scope (5 files)
- `evtx-views.ts` (+ test, new): `EvtxView` model (criteria + layout), sanitization, SAVED_VIEW_SCHEMA = 1,
  export/import, built-in "Enrollment triage" (DeviceManagement-Enterprise-Diagnostics-Provider/Admin 75 and 76,
  AAD Operational Warning+, DNS-Client 1014).
- `EvtxViewStrip.tsx` (+ test, new): view cards, "+ New view" dialog (name, include layout), context menu
  (Rename, Update from current, Duplicate, Delete, Export); built-ins read-only.
- `EventLogWorkspace.tsx`: mount the strip above the view bar.

### Acceptance
- Transient criteria (timeRange, scopeRecordIds) are never stored in a view.
- Built-in view copy makes no claim that its events are related.
- tsc / tests / diff-check / screenshots pass.
```

### A.20 Phase 17a: Comparison query and aggregator

**Labels:** `event-log`, `filters`

```markdown
Spec: §8.16, Q-8

### Scope (4 files)
- `types.ts`: widen `EventQueryFilterSubset.time` to include `{ kind: "between"; from?: string | null; to?: string | null }`
  (the Rust `TimeWindow::Between` and `evtx_query_channels` already accept it; no Rust change).
- `evtx-comparison.ts` (+ test, new): prior-window computation (equal length), live query via a dedicated request ID,
  files-mode local computation, aggregation (level counts, distinct provider+ID set, per-channel counts), cancel.
- `evtx-store.ts`: route comparison request IDs to the aggregator.

### Acceptance
- Test proves no comparison record reaches `records`, the grid, diagnosis, or the analysis session.
- Changing source, channels, or window cancels an in-flight comparison.
- tsc / tests / diff-check pass.
```

### A.21 Phase 17b: Compare with previous period

**Labels:** `event-log`, `ui`, `charts`

```markdown
Spec: §8.10, §8.16, D15

### Scope (4 files)
- `evtx-chart-data.ts` (+ test): delta sublabels ("▲ {r}× vs prior {window}", "{n} new vs prior {window}",
  zero-baseline copy).
- `EvtxChartsView.tsx` (+ test): "Compare with previous period" button, active-comparison label, Clear comparison;
  disabled state with tooltip in files mode when the prior period is not loaded.

### Acceptance
- No delta is shown before the comparison completes; no "∞×".
- tsc / tests / diff-check / screenshots pass.
```

### A.22 Phase 18a: Markdown report export

**Labels:** `event-log`, `export`, `rust`

```markdown
Spec: §8.17, Q-6

### Scope (5 files)
- `src-tauri/src/event_log/analysis_session.rs`: `evtx_render_analysis_report` — looks up scoped records in the session,
  applies `redact_text` and `redacted_display_projection`, renders Markdown (header, findings, Exact/Candidate chains with
  evidence, separate "Nearby, not linked" section, top IDs, level mix, events table capped at 500 with omitted count).
  Inline Rust tests.
- `src-tauri/src/lib.rs`: register the command.
- `src/lib/commands.ts`: typed wrapper.
- `evtx-export.ts` (+ test): "Markdown report" menu entry and save path.

### Acceptance
- Test: report built from the synthetic fixture contains no unredacted machine name, SID, or tenant ID.
- From `src-tauri/`: `cargo check --locked --features event-log`, `cargo test --locked --features event-log` and `cargo clippy --locked --features event-log --all-targets -- -D warnings` pass; wasm32 parser check, tsc, tests, diff-check pass.
```

### A.23 Phase 18b: EVTX subset export (Windows)

**Labels:** `event-log`, `export`, `rust`, `windows`

```markdown
Spec: §8.17, Q-6

### Scope (5 files)
- `src-tauri/src/event_log/export_subset.rs` (new): `evtx_export_subset` using EvtExportLog
  (EvtExportLogChannelPath for live channels, EvtExportLogFilePath for .evtx sources), one file per source,
  EventRecordID ranges, structured XML query above ~20 expressions, EvtArchiveExportedLog for messages.
  Windows-only (cfg). Inline Rust tests for query building.
- `src-tauri/src/event_log/mod.rs`, `src-tauri/src/lib.rs`: module + command registration.
- `src/lib/commands.ts`: typed wrapper.
- `EvtxExportSubsetDialog.tsx` (new): folder pick + unredacted confirmation
  ("These .evtx files are not redacted…", focus on Cancel); hidden on macOS/Linux; disabled for remote sources.

### Acceptance
- Windows-lab evidence: live-channel and file-source subsets open in Event Viewer with the expected record counts.
- cargo gates (Windows and non-Windows builds), tsc, tests, diff-check pass.
```

### A.24 Phase 19: Add log source

**Labels:** `event-log`, `ui`

```markdown
Spec: §8.19, Q-11

### Scope (≤ 5 files)
- `ChannelPicker.tsx` (+ test): "Add log source…" link; "Correlating: active log source only / all open logs" note.
- `EventLogWorkspace.tsx`: rebuild the analysis session when log-store entries change.
- Log open path (file identified in Phase 8): open text logs without switching the active workspace, if it currently switches.

### Acceptance
- A newly opened text log appears in "Also correlating" with its line count and in the Correlation view lanes.
- Focus stays on Event Logs.
- tsc / tests / diff-check / screenshots pass.
```

### A.25 Phase 20: Fidelity, accessibility and performance pass

**Labels:** `event-log`, `qa`

```markdown
Spec: §4, §5, §10, §11, §14.3

- Side-by-side screenshot comparison against each canvas board; list residual differences
  (each either fixed or added to §4 with rationale).
- Keyboard-only walkthrough of every view; screen-reader pass on rail, histogram, charts, view strip and dialogs.
- High-contrast theme and largest font size captures, including the on-brand status bar.
- 100k-record performance figures (view switch, filter change, histogram rebucket).
- Windows-lab evidence per #539 (live + file, elevated + non-elevated, EVTX subset export).
```

### A.26 v2: Scenario views (S1–S4)

**Labels:** `event-log`, `ui`, `v2`

```markdown
Spec: §3.2, §15.1 (D20), Q-13

- S1: built-in Autopilot / ESP, App installs and Stability views in `evtx-views.ts`; scenario layouts switch the main area.
- S2: Stability — boot sessions from documented IDs (41, 6008, 1074, 6006, 6009, 12, 13; 1001 with provider match),
  crash summaries; "last events before unclean shutdown" as context only.
- S3: App installs — MSI 11707/11708/1033 (status read from 1033's field); attempt strip and KPIs from events;
  "Open in Intune Diagnostics" for IME-level detail.
- S4: Autopilot / ESP — ModernDeployment-Diagnostics-Provider/Autopilot and Provisioning-Diagnostics-Provider/Admin
  milestones (GanttChart) and event list; "Open in ESP Diagnostics" for phase and tracked-app detail.

Each S-phase ≤ 5 files; cut as separate issues when v1 Phase 20 completes.
```

### A.27 Follow-up: EventData identifier correlation keys

**Labels:** `event-log`, `correlation`, `rust`

```markdown
Parent: #539 · Spec: §12, §15.2, Q-9

Add explicit correlation key kinds for EventData identifiers such as `EnrollmentId` to the unified-timeline
correlation engine (`TimelineCorrelationKeyKind` currently has activityId, relatedActivityId,
providerChannelEventRecord, processStart, sessionId, deviceId, userId, secondary).

### Acceptance
- Exact edges only when the identifier is unique within one normalized machine (existing exact-match rules).
- cargo gates, wasm32 parser check, Windows-lab evidence on an enrollment failure corpus.
```

### A.28 Follow-up: Windowed analysis-timeline query

**Labels:** `event-log`, `rust`, `performance`

```markdown
Parent: #539 · Spec: §8.12, §15.2, Q-10

Add a windowed query (`startMs`, `endMs`, `limit`) to the analysis session and full edge paging, so the correlation dock
and chain model no longer depend on client-side page search and `edgesPreview`.

### Acceptance
- Phase 11's `evtx-correlation-window.ts` calls the new query with no UI change.
- cargo gates; 100k-record latency recorded.
```

### A.29 Follow-up: Design-system open question for a sequential data-ramp token

**Labels:** `design-system`

```markdown
Spec: D11, §15.2, Q-3

Add an OQ entry to docs/design-system/OPEN-QUESTIONS.md proposing a semantic sequential ramp
(for heat maps and density) defined in all seven themes. When resolved, replace the Charts heat-map
color-mix interim in `evtx-visual-tokens.ts`.
```

## Appendix B. Mockup coverage

The canvas "Event Log Viewer Redesign" holds 25 boards on five pages. They were checked against the published canvas (`project/canvas.json`, version `1791478408-d328`) on 2026-10-08. Every board is accounted for below.

**Status key:**

| Status | Meaning |
|---|---|
| **Built** | Every element is specified. Differences are listed in §4. |
| **Adopted** | Elements from an earlier exploration are carried into the spec (Q-15). |
| **Reference** | A current-state baseline, not a design to build. |
| **Separate spec** | Covered by its own handoff document. |

### B.1 Event Logs — full UI (9 boards)

| Board | Shows | Status | Spec sections |
|---|---|---|---|
| `Workbench` (interactive) | Default Table layout and Insights rail. Its props switch scenario, view, panels and selection. | Built | §5, §8.1–§8.7, §8.13, §8.15 |
| `WB-Selected` | Selected event, Details tab, dock open | Built | §8.7, §8.12, §8.13 |
| `WB-Grouped` | Grouped by event ID, 76 expanded | Built | §8.8 |
| `WB-Timeline` | Provider swimlanes | Built | §8.9 |
| `WB-Charts` | KPI and chart dashboard | Built | §8.10, §8.16 |
| `WB-Correlation` | Chain list and lane plot | Built | §8.11 |
| `WB-Autopilot` | Scenario: Autopilot / ESP | Built (v2), with D20 deep-links | §15.1 |
| `WB-Apps` | Scenario: App installs | Built (v2), with D20 deep-links | §15.1 |
| `WB-Stability` | Scenario: Stability | Built (v2). The sleep and failed-resume parts are **[Unverified]**. | §15.1 |

### B.2 Event Logs redesign — earlier explorations (5 boards)

| Board | Shows | Status | Elements carried into the spec |
|---|---|---|---|
| `Main` (findings rail) | Channel tree, findings rail, coverage note | Adopted | Channel group headers, filter box and "{read} of {total} read" (§8.6). Search placeholder with field grammar (§8.3). Finding-card evidence block, recommended checks and confidence (§8.13). Coverage note with Elevate (§8.13, Phase 4b). |
| `Selected` (detail + context) | Detail panel with Context ±5 min | Adopted | Details / XML sub-tabs, close button, Context ±5 min list (§8.13, Phase 11b) |
| `Dock` ("Correlation A") | Dock under the table | Adopted | Window dropdown, collapse button, chain summary line with "Also nearby" (§8.12) |
| `Correlations` ("Correlation B") | Chains in the rail | Adopted | Chains tab with chain cards, "Not placed" card and "Review unplaced lines" (§8.13, Phase 10c; §8.11a) |
| `Focus` ("Correlation C") | Dedicated correlation view | Adopted | Overview strip with zoom band, shape legend, "Why these are linked" table, "Not placed" row (§8.11, Phase 10b). Correlation status-bar variant (§8.14). |

Elements of these boards that were **not** carried over, because the full-UI page supersedes them:

| Element | Board | Replaced by |
|---|---|---|
| Top-level "Events / Correlation" tabs | `Focus` | The layout tablist (§8.2) |
| "Views" dropdown in the filter row | `Main` | The view strip (§8.15) |
| Level chip ("Level: Error, Warning") | `Main` | Level toggles (§8.3). Chips are kept for the other criteria. |
| Explicit / Secondary / Time-adjacent wording | `Main`, `Correlations`, `Focus` | D9 vocabulary and D7 handling |

### B.3 DSRegCmd redesign (2 boards)

| Board | Status | Notes |
|---|---|---|
| `DSReg-OptionA` ("Verdict first") | Separate spec | Selected design (Q-14). It is specified in [`2026-10-08-dsregcmd-verdict-first-handoff-design.md`](2026-10-08-dsregcmd-verdict-first-handoff-design.md), which has its own umbrella issue. |
| `DSReg-OptionB` ("Check by check") | Not selected | Kept on the canvas for reference only (Q-14) |

### B.4 Current UI (5 boards) and Captures (4 boards)

| Board | Status | Notes |
|---|---|---|
| `Current-EventLog` | Reference | The baseline that §5.3 maps from |
| `Current-LogViewer`, `Current-Intune`, `Current-DSRegCmd`, `Current-ESP` | Reference | Current-state rebuilds; nothing to implement |
| `Capture-LogViewer`, `Capture-Intune`, `Capture-DSRegCmd`, `Capture-ESP` | Reference | Screenshots from `npm run screenshots` (2026-10-07) |

**Totals:**

| Group | Boards |
|---|---|
| Built | 9 |
| Adopted | 5 |
| Separate spec | 1 |
| Not selected | 1 |
| Reference | 9 |
| **All boards** | **25** |

## Appendix C. Sources

- Microsoft Learn: [Diagnose MDM enrollment](https://learn.microsoft.com/windows/client-management/mdm-diagnose-enrollment) (events 75 and 76).
- Microsoft Learn: [Troubleshoot Windows device enrollment errors in Intune](https://learn.microsoft.com/troubleshoot/mem/intune/device-enrollment/troubleshoot-windows-enrollment-errors) (Auto MDM Enroll: Failed).
- Microsoft Learn: [Troubleshoot unexpected reboots using system event logs](https://learn.microsoft.com/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs) (13, 41, 1001, 1074, 6008, 6009).
- Microsoft Learn: [Advanced troubleshooting for Event ID 41](https://learn.microsoft.com/troubleshoot/windows-client/performance/event-id-41-restart) (41, 1074, 6006, 6008).
- Microsoft Learn: [Windows Autopilot troubleshooting FAQ](https://learn.microsoft.com/autopilot/troubleshooting-faq) (Autopilot log location and event IDs).
- Microsoft Learn: [Troubleshooting Microsoft Entra device registration and Windows Autopilot](https://learn.microsoft.com/troubleshoot/mem/intune/device-enrollment/azure-ad-device-registration-autopilot) (Provisioning-Diagnostics-Provider/Admin).
- Microsoft Learn: [Event Logging (Windows Installer)](https://learn.microsoft.com/windows/win32/msi/event-logging) (1033, 11707, 11708).
