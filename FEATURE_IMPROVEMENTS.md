# CMTrace Open — Feature Improvements Roadmap

Internal planning document focused on unfinished work. Active priorities stay near the top; shipped work is summarized at the bottom for reference.

**Status key**: Active Focus = current priority, Next Slice = recommended near-term implementation, Completed = shipped unless a regression is found  
**Priority key**: P0 = critical path, P1 = high value, P2 = useful follow-on, P3 = future consideration  
**Effort key**: S = small (< 4 hours), M = medium (4–16 hours), L = large (16–40 hours), XL = 40+ hours

## Active Focus

The current focus is sample-driven hardening and broader evidence-bundle intake. The tracked template under `templates/evidence-bundle/` and the PowerShell collector at `scripts/collection/Invoke-CmtraceEvidenceCollection.ps1` now define the working bundle shape, so the next work should prioritize better sample intake, evidence inventory, parser hardening from real samples, registry state capture, curated adjacent evidence sources, and remote collection that feeds the same structure.

## Recommended Next Implementation Slice

1. Make the tracked template and script-produced evidence bundle shape the canonical intake contract for investigations.
2. Add a practical sample-intake flow that records what evidence was provided, what was recognized, and what is still unknown or unsupported.
3. Build an evidence inventory so each local investigation starts with coverage and provenance instead of assumptions.
4. Harden existing parsers and Intune evidence rules from real samples before expanding speculative source coverage.
5. Treat registry snapshots and curated event-log exports as first-class adjacent evidence sources for live-device investigations.
6. Ensure remote collection paths feed the same evidence-bundle shape instead of introducing a separate intake format.

---

## Prioritized Backlog: Next Implementation Slices

### 0.1 Sample Intake Baseline — P0 / M

**Expected outcome**: a dropped local evidence bundle produces a stable intake summary showing recognized artifacts, unsupported artifacts, parse status, and obvious evidence gaps.

- Treat the tracked template under `templates/evidence-bundle/` as the canonical local intake layout.
- Accept the same layout whether it came from a manual local copy workflow or from `scripts/collection/Invoke-CmtraceEvidenceCollection.ps1`.
- Accept a local investigation folder as a mixed evidence bundle, not just a log directory.
- Classify inputs into logs, registry exports, event-log exports, and unknown artifacts.
- Show recognized source families, parse success/failure, and any high-value missing evidence.
- Preserve deterministic ordering so intake results are easy to compare across runs and samples.

### 0.2 Evidence Inventory and Provenance — P0 / M

**Expected outcome**: each diagnostic summary can answer which artifacts were included, which were ignored, and which file or snapshot produced each notable event.

- Use `manifest.json` and `notes.md` as first-class inventory inputs when they are present.
- Add an evidence inventory view with source type, origin path, time coverage, and parse status.
- Surface provenance throughout summaries and timelines instead of collapsing everything into a single implied source.
- Make it obvious when conclusions are based on partial evidence or a narrow subset of the supplied bundle.

### 0.3 Parser Hardening from Real Samples — P1 / M

**Expected outcome**: existing Windows and IME parsers fail less often on real samples and produce fewer generic or misclassified events.

- Use real investigation samples to tighten detection, multiline handling, timestamp parsing, and severity mapping.
- Prioritize the parsers that already unlock common device investigations before adding niche formats.
- Track unsupported line patterns and unknown source families so hardening work stays sample-led.

### 0.4 Registry Snapshot Support — P1 / L

**Expected outcome**: registry evidence is ingested as structured device state that can be queried, compared, and correlated with log timelines.

- Treat registry data as state snapshots, not as another line-log parser.
- Start with exported `.reg` and other practical snapshot inputs that show enrollment, policy, and app-management state.
- Align collector output and manual bundle intake so registry snapshots land under the same `evidence/registry/` shape.
- Normalize keys, values, and hives so policy, enrollment, and health views can reference them directly.
- Support side-by-side comparison of intended state, effective state, and observed failures where that evidence exists.

### 0.5 Curated Event Log Intake — P1 / M

**Expected outcome**: adjacent event evidence can be added to a local investigation in a focused way without requiring a full generic event viewer first.

- Start with curated channels relevant to MDM, Autopilot, enrollment, BitLocker, LAPS, and Defender.
- Prefer practical intake paths such as saved exports or offline investigation artifacts before expanding to a broad live-channel browser.
- Align collector output and manual bundle intake so curated event exports land under the same `evidence/event-logs/` shape.
- Correlate event IDs, levels, and timestamps back into the shared evidence inventory and timelines.

### 0.6 Remote Collection Feeding Shared Bundle Shape — P1 / M

**Expected outcome**: evidence collected remotely still lands in the same reviewable bundle shape as local manual copies and local script runs.

- Keep remote execution focused on producing `manifest.json`, `notes.md`, and the existing `evidence/` folder layout.
- Support Intune or other management delivery only as transport and execution layers, not as a different evidence schema.
- Reuse the same intake, inventory, and provenance logic regardless of whether the bundle was assembled locally or remotely.

### 0.7 Intune Rule Maintenance from New Samples — P2 / S

**Expected outcome**: current Intune diagnostics stays useful without becoming the primary feature track.

- Keep refining IME rules only when new samples expose repeatable gaps.
- Expand remediation guidance only where evidence remains deterministic and reviewable.
- Avoid large new Intune-only UI work unless it directly supports the broader evidence-bundle intake flow.

---

## 1. Parser Expansion

Current state: core CMTrace, simple, plain text, and timestamped parsing are in place. Additional Windows log families remain useful, but parser work should now be driven by real evidence intake and evidence gaps rather than format coverage for its own sake.

### 1.1 CBS/Panther Format Family — P1 / M

**Covers**: `CBS.log`, `dism.log`, `DPX\setupact.log`, `setupact.log`, `setuperr.log`, `WinSetup`, `MoSetup`

Shared line pattern:

```text
YYYY-MM-DD HH:MM:SS, <Level> <Component> <Message>
```

- Supports `Info`, `Error`, `Warning`, `Perf`
- Some lines include an optional hex token such as `[0x0f0082]`
- `[SR]` identifies SFC entries within CSI lines
- Continuation lines have no timestamp and should append to the prior entry
- HRESULTs often appear at the end of the message

**Implementation notes**:

- A single `parser/cbs.rs` module can cover this family.
- Detect with `^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2},\s`.
- Extract HRESULTs for error lookup.
- Map `[SR]` lines to a synthetic `SFC` component if that improves filtering.

### 1.2 SetupAPI Section-Based Format — P2 / M

**Covers**: `setupapi.dev.log`, `setupapi.setup.log`

Section-delimited format using `>>>` and `<<<` markers rather than one entry per line.

```text
>>>  [Device Install (Hardware initiated) - USB\VID_045E&PID_07A5\...]
>>>  Section start 2026/03/09 14:05:57.100
     dvi: {Build Driver List} 14:05:57.115
<<<  Section end 2026/03/09 14:05:58.220
<<<  [Exit status: SUCCESS]
```

- ANSI / system codepage input needs Windows-1252 fallback
- Body prefixes include `ump`, `ndv`, `dvi`, `inf`, `cpy`, `sto`, `sig`, `flq`
- Exit state is usually `SUCCESS` or `FAILURE(0x...)`

**Implementation notes**:

- Model each section as a collapsed logical entry.
- Use the section title as the message and the section type as the component.
- Map `FAILURE` to Error and `SUCCESS` to Info.
- Tree-like expansion is optional follow-on UI work, not a prerequisite for parser support.

### 1.3 MSI Multi-Format Parser — P2 / M

**Covers**: `MSI*.LOG` files from `%TEMP%`

MSI logs mix several line types in a single file:

- `Action start HH:MM:SS: ActionName.`
- `MSI (s) (PID:TID) [HH:MM:SS:mmm]: <message>`
- `Property(S): PropertyName = Value`
- Unprefixed custom action stdout/stderr

**Implementation notes**:

- Classify by prefix, then dispatch to sub-parsers.
- Map `Return value 3` to Error and `Return value 2` to Warning.
- Extract property pairs for a structured detail view later.
- Detect from `=== Verbose logging started` or early `MSI (` lines.

### 1.4 WindowsUpdate.log — P1 / S

**Covers**: generated `WindowsUpdate.log`

```text
YYYY/MM/DD HH:MM:SS.mmmmmmm PID  TID  <Component>  <Message>
```

- Uses 7-digit fractional seconds
- Common markers include `*START*`, `*END*`, `*FAILED*`, and `FATAL:`

**Implementation notes**:

- Extend the timestamped parser or add a dedicated variant.
- Promote `*FAILED*` and `FATAL:` to Error severity.
- Detect with `^\d{4}/\d{2}/\d{2}\s\d{2}:\d{2}:\d{2}\.\d{7}`.

### 1.5 ReportingEvents.log (Tab-Delimited) — P2 / S

**Covers**: `C:\Windows\SoftwareDistribution\ReportingEvents.log`

Tab-delimited rows containing GUID, timestamp, event ID, category, level, update GUID, HRESULT, agent, status, operation, and message.

**Implementation notes**:

- Add `parser/tab_delimited.rs`.
- Split on tabs and map fields positionally.
- Detect when the first data row starts with `{` and includes tab characters.

### 1.6 W3C Extended Log Format — P2 / S

**Covers**: `pfirewall.log`

Self-describing format using a `#Fields:` header.

**Implementation notes**:

- Parse the `#Fields:` header into a dynamic column map.
- Skip comment lines beginning with `#`.
- Map `DROP` to Warning and `ALLOW` to Info.
- Opening firewall logs should still explain that logging is often disabled by default.

### 1.7 XML Log Format — P3 / S

**Covers**: `Diagerr.xml`, `Diagwrn.xml`

**Implementation notes**:

- Use `quick-xml`.
- Map each `<Diagnostic>` element to one log entry.
- Default `Diagerr.xml` to Error and `Diagwrn.xml` to Warning unless the XML payload says otherwise.

### 1.8 UTF-16 Encoded Logs — P3 / S

**Covers**: `SrtTrail.txt`, `PFRO.log`

**Implementation notes**:

- Add UTF-16 LE BOM detection to the encoding path.
- `PFRO.log` should parse operation lines and error codes.
- `SrtTrail.txt` should surface section and key-value content as structured entries.

### 1.9 Auto-Detection Update

Extend `parser/detect.rs` in roughly this priority order:

```text
1. UTF-16 BOM
2. <?xml
3. <![LOG[
4. #Version: or #Fields:
5. >>> at line start
6. === at line start or MSI (
7. {GUID}\t
8. YYYY-MM-DD HH:MM:SS,
9. YYYY/MM/DD HH:MM:SS.NNNNNNN
10. existing timestamped/simple/plain fallback chain
```

---

## 2. Intune Diagnostics

Current state: folder-based IME analysis, source provenance, sidecar-aware event extraction, timeline attribution, deterministic counters, issue clustering, and first-pass suggested fixes are already in place. This area is good enough for now; remaining work should be sample-driven maintenance plus correlation with broader device evidence.

### 2.1 IME Rule Hardening from Real Samples — P1 / M

The core sidecar set is already ingested. The remaining gap is richer extraction and stronger evidence quality from the highest-value files in `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\`, but that work should stay behind real sample demand instead of driving the roadmap on its own.

| Log File | Diagnostic Value | Remaining Gap |
| --- | --- | --- |
| `AppWorkload.log` | Detailed Win32 and WinGet download, staging, and install flow | Better classification of stalled, partial, and retried download/install paths |
| `AppActionProcessor.log` | Assignment decisions, applicability, and workflow transitions | Better evidence for applicability and policy-evaluation failures |
| `AgentExecutor.log` | Script command lines, output, and exit codes | More reliable remediation of script-specific failure patterns |
| `HealthScripts.log` | Proactive remediation scheduling and execution | Better detection vs. remediation separation and recurring failure patterns |
| `ClientHealth.log` | Agent startup and service health | Low-volume but useful health evidence still missing |
| `ClientCertCheck.log` | Certificate validation | Specific certificate-failure signatures still missing |
| `DeviceHealthMonitoring.log` | Readiness and app-crash telemetry | Not yet tied into diagnostics summaries |
| `Sensor.log` | SensorFramework events | Likely lower-value unless sample sets prove otherwise |
| `Win32AppInventory.log` | Inventory scans | Useful for app state context, not yet correlated deeply |
| `ImeUI.log` | End-user notification flow | Nice context, low priority for root-cause diagnostics |

**Implementation notes**:

- Keep `AppWorkload.log` first because service release 2408 shifted more download and install detail there.
- Bias toward explicit rule coverage for retries, stalled content, applicability rejection, timeout loops, and recurring remediation failures.
- Prefer evidence that can be quoted back to the user in the summary panel.

### 2.2 Curated Event Log Channel Integration — P1 / M

Event logs remain the largest adjacent diagnostic gap for MDM, Autopilot, BitLocker, LAPS, and Defender.

**Priority channels**:

| Channel | Use Case |
| --- | --- |
| `DeviceManagement-Enterprise-Diagnostics-Provider/Admin` | Primary MDM failures and CSP operations |
| `DeviceManagement-Enterprise-Diagnostics-Provider/Operational` | Ongoing MDM activity |
| `Microsoft-Windows-AAD/Operational` | Entra registration and token flow |
| `Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot` | Autopilot deployment events |
| `Microsoft-Windows-BitLocker/BitLocker Management` | Encryption and key rotation |
| `Microsoft-Windows-LAPS/Operational` | LAPS events |
| `Microsoft-Windows-SENSE/Operational` | Defender onboarding and connectivity |
| `Intune-Bootstrapper-Agent` | Autopilot Device Preparation |

**Implementation notes**:

- Start with curated exports and focused channel intake before building a broad event-log browser.
- Use the `windows` crate for native EVTX access on Windows where native channel access is needed.
- Map Event ID, Level, and message text into the existing entry model.
- Start with curated channel presets instead of a full generic event viewer.
- Offline `.evtx` file support can follow later.

### 2.3 Autopilot Diagnostics Panel — P1 / L

Build a dedicated Autopilot view that correlates profile files, ESP state, relevant event logs, and setup logs.

**Panel goals**:

- Detect deployment mode
- Show ESP phase progress and failure points
- Summarize profile configuration
- Correlate known event IDs and failure signatures
- Support Autopilot v2 bootstrapper and provisioning hints

### 2.4 Registry-Backed MDM Policy Viewer — P1 / L

Read structured device state from registry paths such as:

- `HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\<Area>\`
- `HKLM\SOFTWARE\Microsoft\PolicyManager\Providers\<GUID>\default\Device\<Area>\`
- `HKLM\SOFTWARE\Microsoft\Enrollments\<GUID>\`

**Features**:

- Compare intended vs. effective values
- Highlight MDM and Group Policy conflicts
- Link CSP paths to documentation
- Export policy snapshots as JSON

**Implementation note**:

- Treat registry intake as structured state and correlation data, not as another log stream.

### 2.5 macOS Intune Log Support — P3 / XL

macOS Intune logs use a pipe-delimited format:

```text
DateTime | Process | LogLevel | PID | Task | TaskInfo
```

**Implementation notes**:

- Add a `parser/pipe_delimited.rs` parser.
- Map `I`, `W`, and `E` to standard severities.
- Add curated macOS predicates only if Windows-focused work no longer dominates.

### 2.6 Diagnostics Coverage and Guided Insight — P1 / M

The current diagnostics panel is useful, but it still needs better confidence and coverage reporting.

**Remaining work**:

- Add per-file counts, oldest/newest timestamps, rotation awareness, and dominant-source reporting.
- Improve repeated-failure grouping for apps, scripts, downloads, and timeout loops.
- Expand rule-based suggested fixes only where known error codes or evidence are strong enough.
- Keep the output auditable with sections such as `Likely Cause`, `Evidence`, `Next Checks`, and `Suggested Fix`.

---

## 3. CMTrace Feature Parity

These are the main gaps relative to the original CMTrace workflow.

### 3.1 Time Delta Calculation (Ctrl+D) — P0 / S

Show elapsed time between log entries.

- Single selection: first entry to selected entry
- Range selection: first selected to last selected
- Status bar format: `Elapsed time is Xh Xm Xs Xms (X.XXX seconds)`

### 3.2 Save As / Export (Ctrl+S) — P0 / S

Export the current filtered view to:

- Plain text matching CMTrace clipboard shape
- CSV with headers
- Visible entries only

**Implementation notes**:

- Reuse the existing clipboard/export path where possible.
- Respect active filters.
- Add save dialog plus format selection.

### 3.3 Preferences / Settings Dialog — P1 / M

Persist application settings such as highlight behavior, column state, window placement, theme, font size, recent files, and find history.

**Implementation notes**:

- Use `tauri-plugin-store` or filesystem-backed persistence.
- Load settings on startup and expose them through the existing state layer.

### 3.4 Multi-File Support — P1 / L

Support both:

1. Tabbed file viewing with per-tab state
2. Merged chronological view with a source column

Memory pressure and timestamp quality are the main constraints.

### 3.5 Print Support (Ctrl+P) — P2 / M

Print the current visible log view with filter and range context.

### 3.6 Regex Support in Find/Filter — P1 / S

Add optional regex matching to Find and Filter with inline validation.

### 3.7 Find History — P2 / S

Persist and expose the last 10 search terms.

### 3.8 Recent Files Menu — P2 / S

Add a recent files menu or toolbar entry backed by persisted file history.

### 3.9 Column Customization — P2 / M

Allow resize, reorder, and show/hide column state with persistence.

---

## 4. UI/UX

### 4.1 Severity Quick-Filter Buttons — P0 / S

Add toolbar toggles for Errors, Warnings, and Info with count badges and keyboard shortcuts.

### 4.2 Dark Theme — P1 / S

Add theme support using CSS custom properties plus System, Light, and Dark selection.

### 4.3 Entry Count and Position Indicator — P1 / S

Show current position, total entries, filtered count, and severity totals in the status bar.

### 4.4 Go-To Line / Go-To Timestamp — P2 / S

Add a `Ctrl+G` dialog for absolute line jumps or nearest timestamp jumps.

### 4.5 Bookmark / Pin Entries — P2 / M

Support session bookmarks, quick navigation, and a visible bookmark indicator.

### 4.6 Log Entry Detail Enhancement — P2 / S

Improve the info pane with structured parsed fields, source metadata, inline error lookup, and clickable URLs.

### 4.7 Tail Mode Indicator — P1 / S

Make live tail state obvious with a `LIVE` badge, jump-to-latest affordance, and entry-rate context.

---

## 5. Error Lookup

### 5.1 Expand Embedded Error Database — P1 / M

Current coverage is still well below CMTrace's embedded set.

**High-value additions**:

- Windows Update Agent errors
- Intune-specific error families
- Standard HRESULT ranges
- NTSTATUS codes
- MDM enrollment errors
- BitLocker, LAPS, Autopilot, WinHTTP, and COM/DCOM errors

**Implementation notes**:

- Consider generating from public Microsoft references where practical.
- Use `FormatMessage` on Windows as a fallback for unknown codes.
- A data file may be easier to maintain than an ever-growing hardcoded Rust table.

### 5.2 Inline Error Detection — P1 / S

Detect common hex and decimal error-code patterns in messages and expose hover or click lookup.

### 5.3 Error Code Hyperlinking — P2 / S

Link recognized codes to inline lookup and, where appropriate, external documentation for that error family.

---

## 6. Performance

### 6.1 Incremental Parsing — P1 / M

Avoid full re-parse on each tail cycle by tracking byte offsets and appending only newly parsed entries.

### 6.2 Background Parsing with Progress — P2 / M

For large files, show parse progress, stream results progressively, and allow cancellation.

### 6.3 Parser Plugin System — P3 / XL

Custom parser definitions remain a long-term architectural option, not a near-term priority.

### 6.4 Memory-Mapped File Reading — P3 / M

Use mapped I/O for very large files only if simpler parsing improvements stop being sufficient.

---

## 7. Integrations

### 7.1 Collect Diagnostics Bundle Support — P1 / L

Open remotely collected diagnostics bundles and expose logs, registry exports, event-log exports, and command output from one entry point, using the same evidence-bundle shape as the tracked template and local PowerShell collector.

### 7.2 MDM Diagnostic Report Viewer — P2 / M

Parse `MDMDiagHtmlReport.html` and `MDMDiagReport.xml` to surface policy values, enrollment variables, certificates, and conflicts.

### 7.3 Graph API GUID Resolution — P2 / L

Optionally resolve extracted Intune app and policy GUIDs to friendly names through Microsoft Graph.

### 7.4 Command-Line Interface — P2 / S

Support startup arguments for opening files, launching Intune analysis, and applying an initial filter.

### 7.5 Log File Health Check — P3 / S

When opening an IME directory, summarize rotation state, time coverage, large gaps, and size vs. configured limits.

---

## 8. Prioritized Implementation Phases

These phases reflect unfinished work only and keep the near-term sequence aligned with the current evidence-bundle-first focus.

### Phase 1 — Evidence Intake Baseline

Target: immediate next slice. Estimated effort: 3–5 days.

1. Sample intake baseline using the tracked template and script-produced bundle shape (0.1)
2. Evidence inventory and provenance foundation (0.2)
3. Remote collection feeding the shared bundle shape (0.6)
4. Collect diagnostics bundle support (7.1)

### Phase 2 — Evidence Quality and Adjacent Evidence

Target: following release. Estimated effort: 1–2 weeks.

1. Parser hardening from real samples (0.3)
2. Registry snapshot support (0.4)
3. Curated event-log intake (0.5)
4. IME rule maintenance from new samples (0.7)
5. Event log channel integration foundation (2.2)

### Phase 3 — Workflow and Investigation UX

Target: after intake and evidence quality land. Estimated effort: 2–3 weeks.

1. Diagnostics coverage and guided insight refinement (2.6)
2. Time Delta calculation (3.1)
3. Save As / Export (3.2)
4. Severity quick-filter buttons (4.1)
5. Entry count and position indicator (4.3)
6. Tail mode indicator (4.7)
7. Incremental parsing (6.1)

### Phase 4 — Parser Expansion and Correlated Views

Target: later follow-on release. Estimated effort: 2–3 weeks.

1. CBS/Panther parser (1.1)
2. WindowsUpdate.log parser (1.4)
3. SetupAPI section parser (1.2)
4. MSI multi-format parser (1.3)
5. ReportingEvents.log parser (1.5)
6. W3C extended log parser (1.6)
7. Autopilot diagnostics panel (2.3)
8. MDM diagnostic report viewer (7.2)

### Phase 5 — Longer-Term Additions

Target: no fixed timeline.

1. MDM policy viewer (2.4)
2. Print support (3.5)
3. Find history (3.7)
4. Recent files menu (3.8)
5. Go-To line / timestamp (4.4)
6. Bookmark / pin entries (4.5)
7. Error code hyperlinking (5.3)
8. Background parsing with progress (6.2)
9. Graph API GUID resolution (7.3)
10. XML log format parser (1.7)
11. UTF-16 encoded logs (1.8)
12. Log file health check (7.5)
13. Memory-mapped file reading (6.4)
14. macOS Intune log support (2.5)
15. Parser plugin system (6.3)

---

## Completed

Shipped work that should no longer appear as active roadmap items:

- The tracked evidence-bundle template lives under `templates/evidence-bundle/` and is intended to be copied to a local working folder outside the repo.
- The PowerShell collector at `scripts/collection/Invoke-CmtraceEvidenceCollection.ps1` produces the same high-level `manifest.json` + `notes.md` + `evidence/` bundle shape for local or remote execution.
- Log sources are first-class inputs: file, folder, and known platform presets.
- Folder open and file browsing are available in the main log workflow, including toolbar access.
- Known source presets include Windows IME logs and route through the shared source-loading flow.
- Intune analysis accepts an IME folder path, not only a single file.
- IME folder discovery includes the documented sidecar bundle instead of narrowing to `IntuneManagementExtension*.log` only.
- Intune results retain and display expanded source-file provenance in the frontend model, summary/header, and event timeline.
- File-aware Intune extraction covers `AppWorkload.log`, `AppActionProcessor.log`, `AgentExecutor.log`, and `HealthScripts.log`.
- Sidecar events use more specific heuristic naming for install phases, policy evaluation, and detection/remediation context.
- Aggregated IME timelines sort by parsed timestamps and collapse duplicate completion events more reliably.
- Intune summary output includes deterministic counters for pending, timed out, failed downloads, successful downloads, and failed scripts.
- Intune diagnostics include evidence-based issue clustering, next checks, and rule-based suggested fixes where evidence is specific enough.
- Parser expansion has been intentionally deprioritized behind sample-driven Intune diagnostics refinement.
