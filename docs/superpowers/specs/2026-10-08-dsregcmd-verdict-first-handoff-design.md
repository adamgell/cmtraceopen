# DSRegCmd verdict-first redesign: UI handoff specification

- **Date:** 2026-10-08
- **Companion spec:** [Event Logs workbench UI handoff](2026-10-08-event-logs-workbench-ui-handoff-design.md). Its decision Q-14 selected DSRegCmd Option A ("Verdict first") and asked for this separate spec.
- **Status:** Approved by the maintainer on 2026-10-08. QD-1 to QD-5 are recorded in §11; QD-6 uses the recommendation.
- **Tracking issue:** [#824 DSRegCmd verdict-first redesign (design handoff)](https://github.com/adamgell/cmtraceopen/issues/824), with one sub-issue per phase and follow-up (#859–#870). GitHub is the source of truth for status; this document is the design contract.
- **Design source:** Claude Design canvas "Event Log Viewer Redesign" (<https://claude.ai/artifact/51jKg6P4feMjy3DzSwbX8Z>): page "DSRegCmd redesign", board `DSReg-OptionA` (1440×1320), with baseline boards `Current-DSRegCmd` and `Capture-DSRegCmd`. Attach PNG exports of these boards to each GitHub issue.
- **Baseline:** `main` at `558e93d5`.

## 1. Summary

Option A replaces today's DSRegCmd page. That page leads with a header bar, seven stat cards, a health summary, then issues, facts, timeline, flows, explainer and export. Option A instead puts the answer first:

1. **A verdict banner.** It has a one-line headline, counts, capture confidence, and seven status chips.
2. **Ranked finding cards.** Each card shows its evidence and next check.
3. **Grouped facts** for reference.

A left "On this page" navigation replaces the triage sidebar.

This spec maps every mockup element to existing code and data. Where the mockup's sample copy claims more than the evidence supports, the spec says so and gives evidence-backed copy instead.

## 2. Precedence, fidelity and labels

This spec follows the companion spec's §2 without change:

- **Precedence:** governing documents rank above this spec, and this spec ranks above the mockups;
- **Fidelity:** match the measurements to within ±2 px at 1440 px wide, take colors only from tokens, and treat any unlisted difference as a defect;
- **Labels:** **[Verified]**, **[Recommendation]**, **[Unverified]**.

Questions local to this spec are numbered **QD-n**. Their decisions are in §11.

The governing documents are:

- **Design system:** `docs/design-system/SKILL.md` and `src/lib/themes/*`.
- **Microsoft Learn semantics for `dsregcmd /status`.** The rule most relevant here: empty MDM URL fields mean MDM isn't configured or the user isn't in MDM scope, and the presence of MDM URLs "doesn't guarantee that the device is managed by an MDM" **[Verified, Microsoft Learn]**.
- **The epic's evidence-first stance.** The UI never states more than the parser's output supports.

## 3. Scope

### 3.1 In scope

- **Workspace toolbar action:**
  - a "Capture now" split button;
  - inline "Paste · Open file · Open folder" links.

  These replace the workspace's own header row.
- **Left navigation:**
  - a source card;
  - "On this page" anchors with counts.

  This replaces the content of `DsregcmdSidebar`.
- **Verdict banner:** headline, counts, capture confidence, Copy summary, an Export menu, and seven status chips.
- **Findings:** ranked cards with a rule ID, evidence strip, next check and action link.
- **Facts:** grouped key–value cards for reference, with the existing "Show not reported fields" toggle.
- **Flows, Timeline, Event Logs, Export and raw input:** the existing sections, restyled to Option A and reached from the navigation.
- **Status bar text** for dsregcmd.
- **Empty, analyzing and error states** in the new layout.
- **Screenshot harness update.** The fixture changes so it uses diagnostic IDs the engine actually emits (§14).

### 3.2 Out of scope

- **Option B** ("Check by check"). It was not selected (companion spec Q-14).
- **The `DsregcmdEventLogSurface` internals.** The Event Logs section keeps its current component; only the entry point moves.
- **Global chrome.** That covers the title bar, workspace selector, theme menu and Error lookup. The global status bar's styling comes from the companion spec, Phase 0b.
- **Changing what the parser derives.** Two backend follow-ups are recorded in §14.

### 3.3 Mockup data disclaimer

The Option A sample data comes from the screenshot fixture (`e2e/fixtures/screenshot-data.ts`), not from the rule engine. Two of its diagnostic IDs do not exist in the engine:

- `mdm-not-enrolled`, titled "Device is Entra joined but not MDM enrolled";
- `no-onprem-sso`, titled "No on-premises SSO artifacts present".

`crates/cmtraceopen-parser/src/dsregcmd/rules.rs` and `extended.rs` define neither **[Verified]**. The mockup copy for these two findings, and the headline built on them, are therefore illustrative only.

## 4. Required deviations from the mockup

| # | Mockup | Implementation | Rule |
|---|---|---|---|
| DD1 | Headline "Entra joined, but not managed by Intune" | Headline is templated from parser output (§8.3). For the mockup's data (empty MDM URLs, no registry evidence) it reads "Entra joined · No MDM URLs reported". | Microsoft Learn MDM URL semantics; evidence-first |
| DD2 | MDM chip "Not enrolled" (warning) | The MDM chip has five evidence-based states (§8.4). With empty URLs and no registry evidence it reads "No URLs" (neutral), with a tooltip explaining what that does and doesn't mean. | Microsoft Learn; the existing copy "Missing fields are not proof that management is broken" |
| DD3 | Status-bar text "Not MDM managed" | The status bar uses the MDM chip's label (§8.13) | Same |
| DD4 | Pill chips with 14 px radius | 8 px radius (`--cmt-radius-xl`, the design-system maximum) | DS anti-pattern: "the app maxes at 8px" |
| DD5 | Teal-bordered "DSREGCMD" badge in the source card; teal inset bar plus blue tint on the active nav item | The badge uses a neutral outline (`colorNeutralStroke1` / `colorNeutralForeground2`). The active nav item uses the existing sidebar selection pattern: `colorNeutralBackground1Selected`, a 3 px `colorCompoundBrandStroke` left border, and `colorBrandForeground1` text (`FileSidebar.tsx`) **[Verified]**. | DS rule 5 (brand is allowed on selected sidebar items, not on borders) |
| DD6 | Glyphs ✓ ⚠ ⓘ ▾ → | Fluent icons (§7.3) | DS: no emoji |
| DD7 | Monospace for counts and day counts ("17 lines · 701 chars", "3101 days") | `tokens.fontFamilyNumeric` with tabular numerals. Mono stays for raw keys and values in the evidence strip and Facts. | DS rule 2 |
| DD8 | Counts subline "1 warning · 1 info · 0 errors" | Errors first: "0 errors · 1 warning · 1 info". This matches the mockup's own status bar and today's app. | Consistency |
| DD9 | "(empty)" for blank values, in amber | "Not reported" (the existing `NOT_REPORTED_LABEL`, changed to sentence case). Amber is used only when a Warning or Error finding cites that key as evidence; otherwise the text is `colorNeutralForeground3`. | Evidence-first; DS sentence case |
| DD10 | Finding link "View 3 related events" | Today, no dsregcmd diagnostic is linked to event-log entries: the dsregcmd event-log path never fills `linkedDiagnosticId` **[Verified]**. Until QD-1 is decided, the link reads "Open event logs" and makes no claim of a relationship. | Evidence-first |
| DD11 | Facts shows six compact groups | All existing fact groups are kept. The six mockup groups come first, under the mockup titles, and the rest follow in their current order (QD-3). | No capability loss |
| DD12 | Status bar 32 px with its own pill | The global status bar (companion spec, Phase 0b). The pill is the view label. | DS rule 3 |
| DD13 | Capture-time copy "Live capture · 7/13/2026 9:12 AM" | Shown only for live captures, using a new client-side `capturedAt` timestamp. File and paste sources show their kind and name, never an inferred time (§8.2). | Evidence-first |

## 5. Layout and measurements (1440 px wide)

| Region | Measurement | Notes |
|---|---|---|
| Workspace toolbar action | Inside the global toolbar row | §8.1 |
| Body | Two columns, wrapping (`flex-wrap`) | — |
| Left navigation | `flex: 1 1 220px; max-width: 240px`, bg `colorNeutralBackground2`, right border `colorNeutralStroke2` | Workspace `sidebar` slot. The width follows the shell's sidebar width when it is resizable. |
| Source card | Padding 16, gap 4, bottom border stroke2 | §8.2 |
| "ON THIS PAGE" eyebrow | Padding `14px 16px 6px` | Eyebrow treatment per the companion spec §7.1 |
| Nav item | Padding `7px 16px`, text *f*, count *f* − 2 in fg3 | — |
| Main column | `flex: 999 1 560px`, padding `24px 28px`, gap 20, scrolls vertically | Single column |
| Verdict banner | Radius 8, padding `18px 20px`, gap 14 | §8.3 |
| Section heading (h2) | 16 px, 600 weight, with a caption at *f* − 1 in fg3 | "Findings", "Facts", "Flows", "Timeline", "Export" |
| Finding card | Radius 6, padding `14px 16px`, gap 8, 3 px top border | §8.5 |
| Facts grid | `repeat(auto-fill, minmax(300px, 1fr))`, gap 12 | §8.6 |
| Global status bar | 24 px | Companion spec §8.18 |

*f* is `logListFontSize` (13 by default). The mockup's 12 px body maps to *f* − 1 and its 11 px to *f* − 2, as in the companion spec §7.1.

## 6. Color mapping

The neutrals, brand and link colors are the same as in the companion spec §6.1. The additions are:

| Mockup | Used for | Token |
|---|---|---|
| `#fffef0` / `#e8d44d` | Verdict banner, Warning tone | bg `colorPaletteYellowBackground1` (`#fffef5`), border `colorPaletteMarigoldBorder2` (`#eaa300`) |
| — | Verdict banner, Error tone | bg `severityPalette.error.background`, border `colorPaletteRedBorder2` |
| — | Verdict banner, Healthy tone | bg `colorPaletteGreenBackground1` (`#f1faf1`), border `colorPaletteGreenBackground3` |
| — | Verdict banner, Neutral tone (analyzing, no diagnostics) | bg `colorNeutralBackground2`, border `colorNeutralStroke1` |
| `#bc4b09` | Warning icon, Warning eyebrow, Warning chip border | `severityPalette.status.warning.foreground` (`#bc4b09`, exact) |
| `#0c3b5e` | Info eyebrow | `colorPaletteBlueForeground2` (`#004377`) |
| — | Error eyebrow, Error chip | `severityPalette.status.error.foreground` (`#b10e1c`) |
| `#f1faf1` / `#107c10` / `#0e700e` | Pass chip | bg `colorPaletteGreenBackground1`, border `colorPaletteGreenBackground3`, text `severityPalette.status.success.foreground` (all exact) |
| `#fffef0` / `#bc4b09` / `#78350f` | Warn chip | bg `colorPaletteYellowBackground1`, border `severityPalette.status.warning.foreground`, text `severityPalette.warning.text` (`#78350F`, exact) |
| — | Bad chip | bg `severityPalette.error.background`, border `colorPaletteRedBorder2`, text `severityPalette.error.text` |
| `#f5f5f5` / `#d1d1d1` / `#424242` | Neutral (unknown) chip | bg `colorNeutralBackground3`, border `colorNeutralStroke1`, text `colorNeutralForeground2` |
| `#f5f5f5` | Evidence strip | `colorNeutralBackground3` |
| `#78350f` | A value cited as evidence by a Warning finding | `severityPalette.warning.text` (DD9) |

## 7. Typography and icons

### 7.1 Type

| Element | Mockup | Implementation |
|---|---|---|
| Verdict headline (h1) | 20 / 1.25, 600 | 20 px, line-height 1.25, 600 weight. Fixed at 20 px, per the DS dialog-title size. |
| Verdict subline | 12 | *f* − 1, fg2. Counts in the numeric font. |
| Section heading (h2) | 16 | 16 px, 600 weight |
| Finding title (h3) | 15 | *f* + 2, 600 weight |
| Finding body, next check, links | 12 | *f* − 1 |
| Eyebrows (severity, "EVIDENCE", "ON THIS PAGE") | 9–10, 700, letter-spacing .08em | max(9, *f* − 4) for the "EVIDENCE" label and max(10, *f* − 3) for the others, uppercase |
| Evidence values, fact keys and values, rule ID | 11 mono | *f* − 2, `LOG_MONOSPACE_FONT_FAMILY` |
| Chip text | 11 | *f* − 2. The key is 600 weight; the value is regular, in the numeric font when numeric. |

### 7.2 Icons

All names below are verified exports of the installed `@fluentui/react-icons` **[Verified]**.

| Use | Icon |
|---|---|
| Verdict, Warning / Error / Healthy / Neutral | `Warning24Regular` / `ErrorCircle24Regular` / `CheckmarkCircle24Regular` / `Info24Regular` |
| Chip, Pass / Warn / Bad / Neutral | `CheckmarkCircle12Regular` / `Warning12Regular` / `DismissCircle12Regular` / `Info12Regular` |
| Capture now / Paste / Open file / Open folder | `Camera16Regular` / `ClipboardPaste16Regular` / `DocumentText16Regular` / `FolderOpen16Regular` |
| Split-button chevron | `ChevronDown12Regular` |
| Copy summary / Export | `Copy16Regular` / `ArrowDownload16Regular` |
| Link arrows | `ArrowRight12Regular` |
| "How to read this page" | `QuestionCircle16Regular` |

## 8. Component specifications

### 8.1 Workspace toolbar action

- **Mockup:** the `DSReg-OptionA` header ("Capture now ▾", "or Paste · Open file · Open folder").
- **Component:** `DsregcmdToolbarAction.tsx` *(new)*, registered through `WorkspaceDefinition.toolbarAction` **[Verified extension point]**.
- **Split button:**
  - a Fluent `SplitButton`, `appearance="primary"`, labelled "Capture now";
  - it calls `captureDsregcmdSource()`;
  - its menu offers "Paste", "Open text file..." and "Open evidence folder...", which call `pasteDsregcmdSource()`, `openSourceFileDialog()` and `openSourceFolderDialog()` from `useAppActions` **[Verified]**.
- **Inline links:** "or Paste · Open file · Open folder", at *f* − 2 in fg3, using subtle link buttons for the same three actions.
- **State:** all controls are disabled while `isAnalyzing` is true.
- **Removed:** the workspace's own header row in `DsregcmdWorkspace.tsx`, which held the title "dsregcmd Workspace", the source path and four buttons. The source details move to the source card (§8.2). The title-cased labels "Open Text File" and "Open Evidence Folder" become sentence case.

### 8.2 Left navigation

- **Component:** `DsregcmdSidebar.tsx`, rewritten. Today it shows triage-summary text, top findings and source buttons; all of that is replaced, because the verdict now carries the summary.
- **Source card:**
  - a neutral outline badge reading "DSREGCMD" (DD5);
  - the source name (`sourceContext.displayLabel`) at *f*, 600 weight;
  - a kind line at *f* − 2, fg2:
    - "Live capture · {capturedAt}" for `source.kind === "capture"`;
    - "Text file · {file name}" for files;
    - "Evidence folder · {folder name}" for folders;
    - "Pasted text" for clipboard and text sources;
  - "{rawLineCount} lines · {rawCharCount} chars" (numeric, *f* − 3, fg3) **[Verified fields]**;
  - when `bundlePath` or `evidenceFilePath` is set, a "Show paths" disclosure with the paths in mono. This keeps the paths that today's header shows.
- **`capturedAt` (DD13):** a new optional `capturedAt: string | null` on `DsregcmdSourceContext`. It is set from the client clock when a live capture completes, and stays null for every other source kind.
- **"ON THIS PAGE":**

  | Item | Count | Target |
  |---|---|---|
  | Overview | — | Verdict banner |
  | Findings | `diagnostics.length` | Findings section |
  | Facts | Visible fact rows (respects "Show not reported fields") | Facts section |
  | Flows | — | Flows section |
  | Timeline | `timelineItems.length` | Timeline section |
  | Event Logs | `eventLogAnalysis.totalEntryCount` | Switches `activeTab` to `"event-logs"` (QD-6). Disabled, showing "—", when `eventLogAnalysis` is null. |
  | Export | — | Export section |

  - Scroll-spy marks the item for the section at the top of the main column.
  - The active item uses the DD5 style. Items are `<a>` elements with `aria-current="location"` when active.
  - Keyboard: Tab moves through the items and Enter activates one. While the Event Logs view is showing, every item except Event Logs returns to the analysis view and scrolls to its section.

### 8.3 Verdict banner

- **Component:** `DsregcmdVerdict.tsx` *(new)*. Its logic lives in `dsregcmd-verdict.ts` *(new, pure)*.
- **Tone** (banner colors and icon, §6): Error if any diagnostic has severity `Error`, else Warning if any has `Warning`, else Healthy if the join type is `EntraIdJoined` or `HybridEntraIdJoined`, else Neutral.
- **Headline template [Decided, QD-2]:** `{join clause} · {management clause}`. Every clause maps to a parser field, and no free text is generated.

  | Join type (`derived.joinType`) | Join clause |
  |---|---|
  | `EntraIdJoined` | "Entra joined" |
  | `HybridEntraIdJoined` | "Hybrid Entra joined" |
  | `NotJoined` | "Not joined to Entra ID" (no management clause) |
  | `Unknown` | "Join state not reported" (no management clause) |

  | MDM state (§8.4) | Management clause |
  |---|---|
  | Enrolled (registry) | "MDM enrollment confirmed in registry" |
  | No enrollment (registry) | "No MDM enrollment in registry" |
  | URLs present | "MDM URLs present" |
  | URLs partial | "MDM URLs partially reported" |
  | No URLs | "No MDM URLs reported" |

  When a diagnostic has severity `Error`, a second line in the headline block reads "Top issue: {title}". This mirrors `getSummaryText`'s "Top issue" **[Verified]**.
- **Subline:** "{e} errors · {w} warnings · {i} info · Capture confidence: {label} ({reason})", where:
  - the label is `formatConfidenceLabel`;
  - the reason is `getDisplayConfidenceAssessment(...).reason`, truncated to 80 characters with the full text in a tooltip **[Verified functions]**;
  - the counts use the numeric font.
- **Actions** (right-aligned, Fluent `size="small"`, secondary):
  - "Copy summary" calls the existing `handleCopySummary`;
  - "Export" opens a menu: Copy JSON, Copy status text, Save JSON..., Save summary... and Show raw input. These are the existing handlers; "Copy status text" goes through `redactDsregcmdStatusText`, as it does today **[Verified]**.
- **Chips row:** the seven chips from §8.4, wrapping, gap 8.
- **Accessibility:** the banner is a `<section aria-label="Verdict">`. The icon carries an `aria-label` naming the tone, and the headline is the page's only `h1`.

### 8.4 Status chips

- Radius 8 (DD4), padding `4px 12px 4px 10px`, gap 6.
- Each chip shows an icon, the key at 600 weight, then the value.
- The tooltip shows the explanatory caption the matching stat card carries today. Each caption is wrapped by `qualifyByCaptureConfidence` where it is today **[Verified]**.

| Chip | Value | Tone |
|---|---|---|
| Join | `derived.joinTypeLabel` | `toneForJoinType(derived.joinType)` **[Verified]** |
| Device auth | `facts.deviceDetails.deviceAuthStatus` ("SUCCESS", "FAILED. …"), or "Not reported" | Pass when `SUCCESS`, Bad when any other non-null value, Neutral when null. Status meanings per Microsoft Learn **[Verified]**. |
| PRT | "Present", "Present · stale {h} h" (from `stalePrt` / `prtAgeHours`), "Missing" or "Not reported" | `toneForPrtState(azureAdPrtPresent, stalePrt)` **[Verified]** |
| MDM | The MDM state below (DD2) | See below |
| WHfB | `getNgcReadinessValue(result)` (for example "Configured", "Recovery Required", "Key Health Issue") | `toneForNgcReadiness(result)` **[Verified]** |
| Certificate | "{n} days left" (numeric) from `certificateDaysRemaining`, or "Not reported" | Warn when `certificateExpiringSoon`, otherwise Pass when known and Neutral when unknown |
| Stage | `getDisplayPhaseAssessment(...).label` (for example "Post-Join") | Always Neutral with the Info icon, as in the mockup. The tooltip is the phase summary. |

**MDM state** (`getMdmState` in `dsregcmd-verdict.ts`). The rules are evaluated in order, and the first match wins.

| State | Rule | Chip label | Tone |
|---|---|---|---|
| Enrolled (registry) | The diagnostic `mdm-confirmed-via-registry` is present, or `enrollmentEvidence` has an entry with `enrollmentState === 1` whose GUID matches `scheduledTaskEvidence.enterpriseMgmtGuids` (the same rule as `apply_enrollment_cross_reference`) **[Verified]** | "Enrolled (registry)" | Pass |
| No enrollment (registry) | The diagnostic `enrollment-missing-on-joined` is present **[Verified ID]** | "No enrollment (registry)" | Warn |
| URLs present | `mdmUrl` and `mdmComplianceUrl` are both non-null | "URLs present" | Neutral. Microsoft Learn: URLs don't guarantee management. |
| URLs partial | Exactly one of `mdmUrl` or `mdmComplianceUrl` is non-null | "URLs partial" | Neutral |
| No URLs | Both are null | "No URLs" | Neutral. Tooltip: "Empty MDM URLs mean MDM isn't configured or this user isn't in MDM scope. They don't show whether the device is managed." |

Today's "Present / Partial / Unknown" visibility label does not change. It is still used where today's copy reads "MDM visibility …". The Phase 0a fix in the companion spec stays valid.

### 8.5 Findings

- **Heading:** "Findings", with the caption "{n} · ranked by severity".
- **Order:** `Error` > `Warning` > `Info`. The engine's emission order is kept inside each severity (a stable sort).
- **Component:** `DiagnosticInsightsCard.tsx` (`IssueCard`), restyled to the mockup.
  - **Card:** bg1, stroke2 border, a 3 px top border in the severity color (§6), radius 6, padding `14px 16px`, gap 8.
  - **Eyebrow row:** the severity word uppercased, in the severity color; then, right-aligned, "rule: {id}" (mono, 400 weight, fg3), where `id` is `DsregcmdDiagnosticInsight.id` **[Verified field]**.
  - **Title:** `title`.
  - **Body:** `summary`, at *f* − 1, line-height 1.5, fg2.
  - **Evidence strip:**
    - bg3, radius 4, padding `6px 10px`;
    - the "EVIDENCE" label, then the `evidence[]` items joined with " · " (mono);
    - if the strip overflows two lines, it truncates with "+{n} more", which expands it.
  - **Next row:**
    - "Next: {nextChecks[0]}" at *f* − 1. Further checks expand under "+{n} more checks";
    - the right-aligned action link (DD10):
      - "View raw lines": when at least one evidence item names a raw dsregcmd key, it opens the raw input with those lines highlighted (§8.10);
      - "Open event logs": when `eventLogAnalysis` is present, it switches to the Event Logs view. It reads "View {n} linked events" only if QD-1 adds diagnostic links.
  - **Suggested fixes:** `suggestedFixes[]` (today rendered by `IssueCard`) appears below in a collapsed "Suggested fixes ({n})" disclosure, so no content is lost **[Verified field]**.
- **Empty state:** "No diagnostics were produced for this dsregcmd capture." This is the existing copy.

### 8.6 Facts

- **Heading:** "Facts", with the caption "raw dsregcmd values, grouped · reference only". A right-aligned toggle reads "Show not reported fields" (the existing `showNotReported` state).
- **Component:** `FactGroupRenderer.tsx` (`FactsTable`), restyled.
  - Card: stroke2 border, radius 6.
  - Header: padding `8px 12px`, bg2, bottom stroke2, *f* − 1, 600 weight.
  - Rows: padding `6px 12px`, bottom stroke3, mono at *f* − 2. The key is in fg2 on the left; the value is right-aligned at 600 weight.
  - The value colors follow DD9 and the existing `FactRow.tone` (`good` / `warn` / `bad`) **[Verified]**.
- **Group order and titles [Decided, QD-3].** The existing `getFactGroups` output is reordered and six groups are retitled:

  | Order | Existing group ID | Title shown |
  |---|---|---|
  | 1 | `join-state` | Join posture |
  | 2 | `sso-prt` | PRT & session |
  | 3 | `tenant-device` | Device authentication |
  | 4 | `management` | Management |
  | 5 | `policy-evidence` | NGC / WHfB |
  | 6 | `phase-evidence` | Capture |
  | 7+ | `diagnostics`, `prejoin-registration`, `service-endpoints`, `os-version`, `proxy-config`, `enrollment-status`, `enterprise-mgmt-tasks`, `endpoint-connectivity`, `scp-config` | Existing titles, in the existing order |

  The group IDs are verified in `fact-group-builders.ts` **[Verified]**. Group contents do not change.

### 8.7 Flows

- These are the existing seven `FlowBox` items: current phase, join posture, device authentication, management, PRT and session, NGC readiness, and capture trust.
- They are restyled as Option A cards: stroke2 border, radius 6, padding `12px 14px`, and a 3 px left border in the tone color, using the §8.4 Pass / Warn / Bad / Neutral tokens.
- The "Management" flow keeps its existing copy, "Missing fields are not proof that management is broken" **[Verified]**.

### 8.8 Timeline

- These are the existing `buildTimelineItems` entries **[Verified]**, restyled. A vertical rail uses `colorNeutralStroke1`, with 8 px tone dots and cards in the §8.4 tone colors.
- The existing yellow, green and neutral palette choices are replaced by the §8.4 chip tokens, so warning and success look the same across the page.

### 8.9 Event Logs

- The section is not inlined. Selecting "Event Logs" in the navigation sets `activeTab` to `"event-logs"` and renders the existing `DsregcmdEventLogSurface` in the main column (QD-6).
- A back link, "Back to analysis", returns to the previous scroll position.
- The current tab strip ("Analysis | Event Logs") is removed, because the navigation replaces it.

### 8.10 Export and raw input

- **Export section:**
  - the existing buttons, in sentence case, as Fluent `size="small"` secondary buttons: Copy JSON, Copy status text, Copy summary, Save JSON..., Save summary..., Show raw input;
  - the existing success and error toast (`exportStatus`) is kept **[Verified]**.
- **Raw input panel:** this is today's `showRawInput` block, moved into `DsregcmdRawInput.tsx` *(new)*.
  - Line numbers in the numeric font, and the content in mono.
  - **Highlighting [Recommendation]:** when the panel is opened from a finding's "View raw lines", every line whose key (the text before the first ":", trimmed) matches a key named in that finding's `evidence[]` is highlighted with the selection triplet from the companion spec §6.2. The view scrolls to the first match.
  - The panel shows the unprojected `rawInput`, locally only, as it does today. Copy and save go through the redaction path, as today.

### 8.11 How to read this page

- The existing "Explainer" section's three notes become a collapsed disclosure at the end of the main column, "How to read this page", with `QuestionCircle16Regular` (QD-4). They are not shown as a full section.
- The copy is unchanged, apart from sentence case.

### 8.12 Empty, analyzing and error states

| State | Navigation | Main column |
|---|---|---|
| No source | Source card reads "No source loaded"; the navigation items are disabled | The existing `EmptyWorkspace` copy, with the three load actions as buttons: Capture now (primary), Paste, Open file, Open folder |
| Analyzing | Source card shows the requested source; the navigation is disabled | Verdict banner in the Neutral tone, with a Fluent `Spinner` (size tiny) and `analysisState.message` / `detail` **[Verified fields]** |
| Error | Source card shows the requested source | Verdict banner in the Error tone, headed "dsregcmd analysis failed", with `analysisState.lastError`. A "Try again" button **[Recommendation]** repeats the last request using `analysisState.requestedKind` / `requestedPath` **[Verified fields]**: it re-runs the capture, re-reads the clipboard, or reopens the file or folder. |

### 8.13 Status bar

- **Where:** the existing dsregcmd branch of `StatusBar.tsx` **[Verified]**, using the companion spec's Phase 0b styling.
- **Left:** "dsregcmd · {source label} · {join type label} · MDM {MDM chip label}" (DD3).
- **Right:** "{e} errors | {w} warnings | {i} info" (numeric). The analyzing and error branches are kept.

## 9. Interaction and accessibility

- **Landmarks:**
  - one `h1` (the verdict);
  - section headings at `h2`, and finding titles at `h3`;
  - the navigation is `<nav aria-label="Source and sections">`, as in the mockup.
- **Chips:** each chip is a `role="listitem"` inside a `role="list"` labelled "Status". The tooltip text is also exposed through `aria-description`.
- **Focus:** Copy summary and Export keep focus after they act. Toast messages announce through a polite live region.
- **Color:** tone is never conveyed by color alone. Every chip and card has an icon or text label.
- **Reduced motion:** the scroll animation from the navigation is disabled under `prefers-reduced-motion`.

## 10. Data mapping

| Mockup element | Source | Status |
|---|---|---|
| Headline, tone | `derived.joinType` plus the MDM state plus diagnostic severities | New pure logic (`dsregcmd-verdict.ts`) |
| Counts | `diagnostics[].severity` | Exists |
| Capture confidence | `getDisplayConfidenceAssessment` / `formatConfidenceLabel` | Exists |
| Join, PRT, WHfB, Certificate and Stage chips | Existing derived fields and tone functions | Exists |
| Device auth chip | `facts.deviceDetails.deviceAuthStatus` | Exists |
| MDM chip | `getMdmState` from diagnostics, `enrollmentEvidence`, `scheduledTaskEvidence` and `managementDetails` | New pure logic |
| Finding rule ID, evidence, next check, fixes | `DsregcmdDiagnosticInsight` (`id`, `evidence`, `nextChecks`, `suggestedFixes`) | Exists |
| "View 3 related events" | No dsregcmd diagnostic-to-event links today | QD-1 |
| Facts | `getFactGroups` | Exists (reordered) |
| Source card time | `capturedAt` | New field, set on live capture only |
| Lines and characters | `rawLineCount` / `rawCharCount` | Exists |

## 11. Decisions

| ID | Question | Decision (2026-10-08) | Where applied |
|---|---|---|---|
| QD-1 | Should finding cards link to related event-log entries? Today no dsregcmd diagnostic is linked to event entries (§14 item 3). | Ship a plain "Open event logs" link now. File a backend follow-up to add error-code linking; once it lands, the link becomes "View {n} linked events". | §8.5, DD10, Appendix A.12 |
| QD-2 | How is the verdict headline built? | Templated from parser fields (§8.3) | §8.3, D1 |
| QD-3 | How many fact groups are shown? | All existing groups, with the six mockup groups first under the mockup titles | §8.6, DD11 |
| QD-4 | What happens to the Explainer? | A collapsed "How to read this page" disclosure | §8.11 |
| QD-5 | Pill radius | 8 px, the design-system maximum, with no exception. This also applies to the companion spec (its Q-16, D21). | DD4, §8.4 |
| QD-6 | How does the Event Logs navigation item behave? | The recommendation is applied: it switches the main column to the existing surface. This was not separately confirmed. | §8.2, §8.9 |

## 12. Verification

- Per phase, as in the companion spec §14.1: re-read before editing, ≤ 5 files, `npx tsc --noEmit`, the targeted `npm test`, `git diff --check`, and approval between phases.
- Screenshots: `npm run screenshots -- -g dsregcmd`. The existing test (`capture.spec.ts`, `test("dsregcmd")`) **[Verified]** is extended to capture the empty, analyzing, healthy, warning and error variants. The PNGs are attached beside the canvas export.
- Windows-lab evidence: one live capture, one evidence-bundle folder and one pasted output. Include at least one device with registry-confirmed enrollment, and one Entra-joined device with no enrollment, to exercise the MDM states.
- Unit tests for `dsregcmd-verdict.ts` cover every join type × MDM state × severity mix, and assert that no headline contains "not managed" or "managed by Intune".

## 13. Delivery plan

| Phase | Title | Files (≤ 5) | Depends on |
|---|---|---|---|
| D1 | Verdict and MDM state logic | `dsregcmd-verdict.ts`*, `dsregcmd-verdict.test.ts`* | Companion Phase 0a |
| D2 | Toolbar action; remove the workspace header and tab strip | `DsregcmdToolbarAction.tsx`*, `DsregcmdToolbarAction.test.tsx`*, `index.ts`, `DsregcmdWorkspace.tsx` | — |
| D3 | Left navigation and source card | `DsregcmdSidebar.tsx`, `DsregcmdSidebar.test.tsx`*, `dsregcmd-store.ts`, `types.ts` (`capturedAt`), `src/lib/dsregcmd-source.ts` | D2 |
| D4 | Verdict banner and chips | `DsregcmdVerdict.tsx`*, `DsregcmdVerdict.test.tsx`*, `DsregcmdWorkspace.tsx` | D1, D2 |
| D5 | Finding cards | `DiagnosticInsightsCard.tsx`, `DiagnosticInsightsCard.test.tsx`*, `DsregcmdWorkspace.tsx` | D4 |
| D6 | Facts | `FactGroupRenderer.tsx`, `FactGroupRenderer.test.tsx`*, `fact-group-builders.ts`, `fact-group-builders.test.ts`, `dsregcmd-formatters.ts` ("Not reported") | D4 |
| D7 | Flows, Timeline, Export, raw input, "How to read this page" | `PolicyEvidencePane.tsx`, `DsregcmdRawInput.tsx`*, `DsregcmdRawInput.test.tsx`*, `DsregcmdWorkspace.tsx`, `DsregcmdWorkspace.test.tsx` | D5 |
| D8 | Status bar text | `src/components/layout/StatusBar.tsx`, `src/components/layout/StatusBar.dsregcmd.test.tsx`* | Companion Phase 0b, D1 |
| D9 | Fixture realism and screenshots | `e2e/fixtures/screenshot-data.ts`, `e2e/screenshots/capture.spec.ts` | D7 |
| D10 | Fidelity and accessibility pass | No new files | All of the above |

`*` marks new files. Paths without a directory are under `src/workspaces/dsregcmd/`.

`src/lib/dsregcmd-source.ts` exists **[Verified: imported by `index.ts`]**. Its exact capture-completion hook is confirmed in D3.

## 14. Findings for follow-up (outside this UI work)

1. **`mdm_enrolled` conflates URL presence with enrollment.** `derive.rs` sets `mdm_enrolled = Some(true)` whenever `MdmUrl` or `MdmComplianceUrl` is present **[Verified]**. Microsoft Learn states that URL presence does not guarantee the device is managed **[Verified]**.
   - This spec avoids the problem in the UI with `getMdmState`.
   - Recommended backend follow-up: split the field into `mdmUrlsPresent` and a registry-confirmed `mdmEnrolled`, then update the "Present / Partial / Unknown" label sources.
2. **The screenshot fixture uses diagnostic IDs the engine never emits** (`mdm-not-enrolled`, `no-onprem-sso`) **[Verified]**. Phase D9 replaces them with real engine IDs (for example `join-type-entraid`; or `enrollment-missing-on-joined`, which needs `enrollmentEvidence` in the fixture), so that screenshots show reachable states.
3. **No dsregcmd diagnostic-to-event links.** The dsregcmd event-log path calls `build_event_log_analysis` without diagnostics, so `linkedDiagnosticId` is never filled for dsregcmd **[Verified]**. This is QD-1.

---

## Appendix A. GitHub issue drafts

These drafts were published as issues #824 and #859–#870 on 2026-10-08. The issues are now authoritative for scope and status.

Conventions match the companion spec's Appendix A: the labels are suggestions, and every issue links this spec, the companion spec and the canvas board export.

### A.0 Umbrella

**Title:** DSRegCmd verdict-first redesign (design handoff)

**Labels (suggested):** `dsregcmd`, `ui`

```markdown
Spec: docs/superpowers/specs/2026-10-08-dsregcmd-verdict-first-handoff-design.md
Design: Claude Design canvas, page "DSRegCmd redesign", board DSReg-OptionA (Option A — Verdict first)
Related: Event Logs workbench handoff (Phase 0a MDM label consistency, Phase 0b status bar)

### Phases
- [ ] D1 — Verdict and MDM state logic
- [ ] D2 — Toolbar action; remove workspace header and tab strip
- [ ] D3 — Left navigation and source card
- [ ] D4 — Verdict banner and chips
- [ ] D5 — Finding cards
- [ ] D6 — Facts
- [ ] D7 — Flows, Timeline, Export, raw input, "How to read this page"
- [ ] D8 — Status bar text
- [ ] D9 — Fixture realism and screenshots
- [ ] D10 — Fidelity and accessibility pass

### Invariants
- The UI never states that a device is or is not managed unless registry evidence says so (Microsoft Learn: MDM URLs don't guarantee management).
- Headlines and chips are templated from parser fields; no free-text inference.
- Copy and save paths keep using the redaction projection.

### Follow-ups
- [ ] Split `mdm_enrolled` into URL presence vs registry-confirmed enrollment (backend)
- [ ] Link dsregcmd diagnostics to event-log entries (backend, QD-1)
```

### A.1 D1: Verdict and MDM state logic

```markdown
Spec: §8.3, §8.4 (MDM state)

### Scope (2 files)
- `dsregcmd-verdict.ts` (new): verdict tone, headline template (join clause × management clause), top-issue line,
  `getMdmState` (Enrolled (registry) / No enrollment (registry) / URLs present / URLs partial / No URLs), diagnostic sort.
- `dsregcmd-verdict.test.ts` (new): full matrix; asserts no headline contains "not managed" or "managed by Intune".

### Acceptance
- Pure module, no React imports. tsc / tests / diff-check pass.
```

### A.2 D2: Toolbar action; remove workspace header and tab strip

```markdown
Spec: §8.1, §8.9

### Scope (4 files)
- `DsregcmdToolbarAction.tsx` (+ test, new): "Capture now" SplitButton (menu: Paste, Open text file..., Open evidence folder...),
  inline links; disabled while analyzing.
- `index.ts`: register `toolbarAction`.
- `DsregcmdWorkspace.tsx`: remove the header row and the Analysis | Event Logs tab strip.

### Acceptance
- All four load paths still work (capture, paste, file, folder). tsc / tests / diff-check / screenshots pass.
```

### A.3 D3: Left navigation and source card

```markdown
Spec: §8.2, DD5, DD13

### Scope (5 files)
- `DsregcmdSidebar.tsx` (+ test, new test): source card (neutral badge, label, kind line, lines/chars, path disclosure),
  "On this page" with counts, scroll-spy, sidebar selection pattern, Event Logs switch.
- `dsregcmd-store.ts`: active section; `types.ts`: optional `capturedAt` on DsregcmdSourceContext.
- `src/lib/dsregcmd-source.ts`: set `capturedAt` on live capture only.

### Acceptance
- No capture time shown for file/folder/paste sources. tsc / tests / diff-check / screenshots pass.
```

### A.4 D4: Verdict banner and chips

```markdown
Spec: §8.3, §8.4, §6, DD1–DD4

### Scope (3 files)
- `DsregcmdVerdict.tsx` (+ test, new): tone colors, icon, h1 headline, top-issue line, subline, Copy summary, Export menu,
  seven chips (8 px radius) with existing captions as tooltips.
- `DsregcmdWorkspace.tsx`: replace the seven StatCards and the Health Summary section with the verdict.

### Acceptance
- Mockup data renders "Entra joined · No MDM URLs reported" with the MDM chip "No URLs" (neutral).
- tsc / tests / diff-check / screenshots pass.
```

### A.5 D5: Finding cards

```markdown
Spec: §8.5, DD10

### Scope (3 files)
- `DiagnosticInsightsCard.tsx` (+ test, new test): severity eyebrow + "rule: {id}", title, summary, evidence strip,
  "Next:" line, action link (View raw lines / Open event logs), collapsed suggested fixes.
- `DsregcmdWorkspace.tsx`: "Findings · {n} · ranked by severity" heading and stable severity sort.

### Acceptance
- No "related events" wording without diagnostic links. tsc / tests / diff-check / screenshots pass.
```

### A.6 D6: Facts

```markdown
Spec: §8.6, DD9, DD11

### Scope (5 files)
- `FactGroupRenderer.tsx` (+ test, new test): compact card style, evidence-aware amber values.
- `fact-group-builders.ts` (+ test): group order and the six retitled groups.
- `dsregcmd-formatters.ts`: NOT_REPORTED_LABEL → "Not reported".

### Acceptance
- No group or row removed; "Show not reported fields" still works. tsc / tests / diff-check / screenshots pass.
```

### A.7 D7: Flows, Timeline, Export, raw input, "How to read this page"

```markdown
Spec: §8.7, §8.8, §8.10, §8.11

### Scope (5 files)
- `PolicyEvidencePane.tsx`: SectionFrame / FlowBox restyle (tone left border, §8.4 tokens).
- `DsregcmdRawInput.tsx` (+ test, new): numbered raw input, evidence-key highlighting and scroll-to-first-match.
- `DsregcmdWorkspace.tsx` (+ existing test): timeline restyle, sentence-case export buttons, "How to read this page" disclosure.

### Acceptance
- Copy/save continue through `redactDsregcmdStatusText`. tsc / tests / diff-check / screenshots pass.
```

### A.8 D8: Status bar text

```markdown
Spec: §8.13, DD3

### Scope (2 files)
- `src/components/layout/StatusBar.tsx`: dsregcmd branch left/right text per spec, numeric counts.
- `src/components/layout/StatusBar.dsregcmd.test.tsx` (new).

### Acceptance
- Depends on Event Logs Phase 0b styling. tsc / tests / diff-check pass.
```

### A.9 D9: Fixture realism and screenshots

```markdown
Spec: §3.3, §12, §14 item 2

### Scope (2 files)
- `e2e/fixtures/screenshot-data.ts`: replace `mdm-not-enrolled` / `no-onprem-sso` with engine diagnostic IDs and
  matching evidence; add variants for healthy, warning (enrollment-missing-on-joined with enrollmentEvidence) and error.
- `e2e/screenshots/capture.spec.ts`: capture empty, analyzing, healthy, warning, error variants.

### Acceptance
- Every diagnostic ID in fixtures exists in rules.rs or extended.rs.
```

### A.10 D10: Fidelity and accessibility pass

```markdown
Spec: §4, §5, §9, §12

- Side-by-side comparison with DSReg-OptionA; list residual differences (fix or add to §4).
- Keyboard and screen-reader pass (landmarks, chips list, navigation).
- Windows-lab captures: live, bundle, paste; registry-confirmed enrollment and no-enrollment devices.
```

### A.11 Follow-up: Split `mdm_enrolled`

**Labels:** `dsregcmd`, `rust`

```markdown
Spec: §14 item 1

`derive.rs` sets `mdm_enrolled = Some(true)` when MdmUrl or MdmComplianceUrl is present. Microsoft Learn: the presence of
MDM URLs doesn't guarantee the device is managed. Split into `mdm_urls_present` and registry-confirmed `mdm_enrolled`
(keep `apply_enrollment_cross_reference`), update TS types and the visibility label sources.

### Acceptance
- cargo check / test / clippy -D warnings; wasm32 parser check; TS callers updated; Windows-lab evidence.
```

### A.12 Follow-up: Link dsregcmd diagnostics to event-log entries

**Labels:** `dsregcmd`, `event-log`, `rust`

```markdown
Spec: §14 item 3, QD-1

Pass dsregcmd diagnostics into the dsregcmd event-log analysis so `linkedDiagnosticId` can be filled
(error-code match, as the Intune path does). Then D5's link can read "View {n} linked events".
```

## Appendix B. Mockup coverage

Every element of `DSReg-OptionA` is listed below.

| Mockup element | Spec section | Status |
|---|---|---|
| "Capture now ▾" split button and "or Paste · Open file · Open folder" | §8.1 | Built |
| Error lookup, workspace selector, theme menu | — | Global chrome (out of scope) |
| Source card (badge, name, capture time, lines and characters) | §8.2 | Built, with DD5 and DD7 |
| "ON THIS PAGE" navigation (Overview, Findings, Facts, Flows, Timeline, Event Logs, Export) with counts | §8.2 | Built |
| Verdict banner (icon, headline, counts and confidence, Copy summary, Export) | §8.3 | Built, with DD1 and DD8 |
| Seven status chips | §8.4 | Built, with DD2 and DD4 |
| Findings heading and caption | §8.5 | Built |
| Finding cards (severity, rule, title, body, evidence, next check, link) | §8.5 | Built, with DD10 |
| Facts heading and grouped cards | §8.6 | Built, with DD9 and DD11 |
| Footer status bar | §8.13 | Built, with DD3 and DD12 |
| Flows, Timeline and Export sections (navigation targets, not drawn on the board) | §8.7, §8.8, §8.10 | Existing content, restyled |

Other DSRegCmd boards:

| Board | Status |
|---|---|
| `DSReg-OptionB` | Not selected (companion spec Q-14) |
| `Current-DSRegCmd` | Baseline. Each of its elements is either mapped above or explicitly replaced: the stat cards become chips, Health Summary becomes the verdict, the Explainer becomes the disclosure, and the tab strip becomes the navigation. |
| `Capture-DSRegCmd` | Baseline screenshot |

## Appendix C. Sources

- Microsoft Learn: [Troubleshoot devices by using the dsregcmd command](https://learn.microsoft.com/entra/identity/devices/troubleshoot-device-dsregcmd) (device state table, DeviceAuthStatus values, tenant details and MDM URL semantics, SSO and NGC fields).
