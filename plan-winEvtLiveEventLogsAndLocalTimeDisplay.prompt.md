## Plan: WinEvt Live Event Logs And Local Time Display

Replace the current live Windows Event Log path in the Intune workflow with official WinEvt bindings from the windows crate, while preserving the existing evidence-bundle .evtx path. At the same time, make displayed dates and times resolve in the end user's system timezone instead of relying on naive timestamp strings. The backend change should stay isolated behind the current live-vs-bundle decision point, and the UI should be updated to show live event-log query status and results in the new Intune workspace and left sidebar so users can tell that event channels were actually queried.

**Steps**

1. Phase 1: Lock the live-query boundary. Reuse the existing decision point in c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src-tauri\src\commands\intune.rs inside load_event_log_analysis so only the live path changes. Keep parse_bundle_event_logs and downstream correlation logic unchanged. This step blocks all later backend work.
2. Phase 2: Add WinEvt dependencies and wrapper module. Update c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src-tauri\Cargo.toml to add the windows crate with the minimum required features for Win32 event logging and foundation error handling. Create a focused Windows-only wrapper module, preferably c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src-tauri\src\intune\eventlog_win32.rs, to own UTF-16 conversion, Win32 error mapping, and RAII handle cleanup via EvtClose. This depends on step 1.
3. Phase 3: Implement live channel querying through WinEvt. In the new wrapper module, implement local-machine querying for the existing curated channel list using EvtQuery and EvtNext. Keep the current channel list in c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src-tauri\src\intune\evtx_parser.rs unless there is a deliberate product change. Query each channel independently so access failures or missing channels produce partial results instead of aborting the full live analysis. This depends on step 2.
4. Phase 4: Render event records into the existing EventLogEntry model. Prefer extracting stable system properties through WinEvt rather than regex over shell output. Use EvtCreateRenderContext plus EvtRender for structured system fields such as provider, event id, level, channel, computer, activity id, and timestamp. For message text, use EvtOpenPublisherMetadata and EvtFormatMessage as a best-effort path; if message formatting fails because publisher metadata is unavailable or access is restricted, fall back to a synthesized message built from event data or XML so entries still surface in the UI. This depends on step 3.
5. Phase 5: Normalize timestamps and preserve current correlation behavior. Convert WinEvt timestamps to the same UTC ISO-8601 shape currently expected by EventLogEntry and the correlation code. Keep ordering, severity mapping, and event id assignment stable so c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src-tauri\src\commands\intune.rs and the existing event-log correlation helpers continue to work without schema changes. This depends on step 4.
6. Phase 6: Make frontend display use the viewer's system timezone as the source of truth. Update the display path centered on c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src\lib\date-time-format.ts so UI formatting prefers timezone-aware values or UTC-normalized instants instead of reparsing naive display strings as local dates. The target behavior is that rendered dates and times in the Intune workspace, event-log views, and timeline surfaces show in the current user's system timezone.
7. Phase 7: Normalize timezone handling for Intune and other timeline inputs. Review c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src-tauri\src\intune\timeline.rs and any event serialization paths that still emit naive timestamps, then standardize them to emit timezone-safe values that the frontend can consistently convert into the viewer's local timezone. This depends on steps 5 and 6.
8. Phase 8: Surface live event-log progress and results in the UI. Keep the existing event-log surface in c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src\components\intune\EventLogSurface.tsx and store plumbing in c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src\stores\intune-store.ts, but update c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src\components\layout\FileSidebar.tsx to show live event-log status, queried channel count, and signal counts alongside the IME file list. Also confirm c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src\components\intune\NewIntuneWorkspace.tsx exposes clearer status when live event-log parsing is in progress or when zero accessible entries are returned. This can begin in parallel with step 6 once the returned metadata shape is confirmed.
9. Phase 9: Harden error handling and diagnostics. Distinguish between no entries, inaccessible channel, missing channel, and query failure in backend logs and progress messages. Also distinguish between source timestamps that were timezone-aware and source timestamps that were only local/naive so the display layer does not silently misrepresent time. This depends on steps 6 through 8.
10. Phase 10: Add validation and regression coverage. Add or update Rust tests around severity mapping, timestamp normalization, and partial-channel failure handling. Add frontend validation around local-time rendering in c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src\lib\date-time-format.ts and verify key surfaces such as the Intune timeline and Event Log Evidence use the end user's system timezone consistently. This depends on steps 6 through 9.

**Relevant files**

- c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src-tauri\Cargo.toml — add the windows crate and required Win32 feature flags for event log access and error handling.
- c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src-tauri\src\commands\intune.rs — keep load_event_log_analysis as the stable boundary between bundle and live event-log modes.
- c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src-tauri\src\intune\evtx_parser.rs — retain bundle parsing and shared EventLogAnalysis assembly; replace only the live parser internals.
- c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src-tauri\src\intune\models.rs — preserve EventLogEntry and EventLogAnalysis shapes so frontend/state code does not need schema churn.
- c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src\components\layout\Toolbar.tsx — keep the existing includeLiveEventLogs trigger for the known live Intune source.
- c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src\components\intune\NewIntuneWorkspace.tsx — keep the live-analysis entry point and tighten user-facing status around event-log querying outcomes.
- c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src\components\intune\EventLogSurface.tsx — reuse the existing event-log display surface without changing its contract.
- c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src\lib\date-time-format.ts — make frontend display formatting use timezone-aware or UTC-normalized values and render them in the viewer's local timezone.
- c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src-tauri\src\intune\timeline.rs — remove or isolate naive timestamp parsing so timeline bounds and emitted values can be displayed correctly in the user's system timezone.
- c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src\components\intune\EventTimeline.tsx — confirm timeline rendering consumes the corrected display formatter without reintroducing local-string parsing.
- c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src\components\layout\FileSidebar.tsx — add event-log visibility to the left sidebar for live analysis.
- c:\Users\AdamGell\Documents\GitHub\cmtraceopen\src\stores\intune-store.ts — reuse existing eventLogAnalysis storage and selection/filter state.

**Verification**

1. Build the Rust backend on Windows and confirm the new windows crate features compile cleanly with the existing Tauri target.
2. Run the live Intune analysis flow from the known source and verify that Querying live Windows Event Logs progress is emitted and the resulting eventLogAnalysis is non-null when accessible channels contain matching entries.
3. Confirm that partial failures still produce visible results when some channels are inaccessible or empty.
4. Verify the Event Log Evidence surface renders entries, channel summaries, and correlations without any frontend schema changes.
5. Verify the left sidebar shows event-log query status and event-log counts in the new Intune workspace, not only IME log files.
6. Run the existing frontend build and Rust tests, then add focused backend tests for timestamp conversion, severity mapping, and per-channel error handling.
7. Verify that the Intune timeline, dashboard timestamp summaries, and event-log rows all display in the viewer's system timezone on the machine running CMTrace Open.
8. Verify that UTC-labeled or UTC-normalized backend values are converted for display rather than shown as raw naive strings.

**Decisions**

- In scope: replacing only the live Windows Event Log query path with official WinEvt bindings.
- In scope: preserving the current bundle .evtx parsing path and current EventLogAnalysis schema.
- In scope: exposing live event-log activity in the sidebar and workspace status so the user can see that channels were queried.
- In scope: making user-facing date and time rendering resolve in the system timezone of the machine running the app.
- In scope: replacing naive string-based display parsing with timezone-safe values where available.
- Out of scope: preserving source-machine wall-clock display when it conflicts with the viewer-local requirement, unless a later product decision adds an explicit toggle.
- Out of scope: changing the curated channel list unless validation shows a concrete coverage gap.

**Summary**
Accepted defaults: live event-log queries should return a successful empty result instead of null when nothing matches; the backend should track both channels attempted and channels that produced entries; timestamps should only be converted to viewer-local time when the source instant is timezone-aware or normalized to UTC; timestamps with unknown timezone should remain visible as raw wall-clock values with uncertainty surfaced; and the first WinEvt implementation should preserve the current effective per-channel cap and general correlation behavior. With those decisions locked, the revised scope becomes a focused backend contract change plus a timestamp-normalization cleanup across all consumers, not just a parser swap and formatter tweak.

**Implementation steps**

1. Keep the current live-versus-bundle boundary unchanged at the existing decision point in intune.rs. Only the live event-log implementation changes; the evidence-bundle EVTX path and downstream correlation entry points stay intact.
2. Replace the current live event-log transport in evtx_parser.rs with a Windows-only WinEvt wrapper module that owns query execution, UTF-16 conversion, handle cleanup, structured property rendering, and Win32 error mapping.
3. Extend the live event-log result contract in models.rs and the matching frontend types in event-log.ts to carry live-query metadata. That metadata should include at minimum channelsAttempted, channelsSucceeded, channelsWithResults, channelsEmpty, channelsInaccessible, channelsMissing, channelsFailed, and per-channel outcome details.
4. Change live query semantics so a successful query run with zero matching entries still returns an EventLogAnalysis object. The object should contain zero entries and zero counts plus live-query metadata, allowing the UI to distinguish queried-but-empty from not-run or failed.
5. Preserve the existing curated channel list for the initial WinEvt migration. Query each channel independently, tolerate partial failure, and keep the current effective recent-entry cap per channel so the first migration does not also change product volume or performance characteristics.
6. Build event records from WinEvt system properties using structured rendering rather than XML scraping. The backend should extract provider, event id, level, channel, computer, activity id, and timestamp directly from WinEvt-rendered system properties, then best-effort format the message through publisher metadata with a documented fallback path when formatting fails.
7. Preserve the current EventLogEntry and correlation behavior wherever possible. Event timestamps should remain normalized to UTC ISO-8601 strings, severity mapping should stay stable, and correlation thresholds in evtx_parser.rs should not change in this scope unless normalization exposes a correctness bug.
8. Expand the timezone work beyond the shared formatter in date-time-format.ts. Unify timestamp interpretation across the backend timeline parser in timeline.rs, dashboard filtering in IntuneDashboard.tsx, and timestamp-bound comparison helpers in intune-store.ts.
9. Treat timestamp confidence explicitly. If a timestamp is already UTC or carries an offset, render it in the viewer’s system timezone. If a timestamp is naive and the source timezone is unknown, preserve the raw time string and surface that it is timezone-uncertain rather than silently interpreting it as trustworthy local time.
10. Keep the current UTC-first IME event pipeline intact where it already exists, especially in event_tracker.rs and download_stats.rs, and focus the remaining work on downstream consumers that still parse or compare timestamps naively.
11. Update the UI contract in NewIntuneWorkspace.tsx, FileSidebar.tsx, and EventLogSurface.tsx so the app can show:
    successful live query with entries
    successful live query with zero entries
    partial success with some inaccessible or missing channels
    full failure
12. Add regression coverage for three areas: WinEvt severity and timestamp normalization, partial-channel failure handling with tolerated query errors, and timezone-safe ordering and filtering across timeline, dashboard, and event-log views.

**Edge cases to handle**

- Live query succeeds but every channel returns zero relevant entries.
- Some channels return entries while others are inaccessible, missing, or fail.
- Provider metadata lookup fails and event messages must fall back to synthesized text.
- Viewer-local rendering occurs on a machine in a different timezone from the evidence source.
- Naive timestamps cross daylight saving transitions and cannot be mapped confidently.
- Timeline ordering mixes RFC3339 UTC values with legacy naive strings.
- The sidebar and workspace must still show that querying occurred even when the event-log entry list is empty.
- The Windows-only WinEvt path must not break non-Windows builds or bundle-only workflows.

**Open questions**
None are required to proceed with this scope. Optional later decisions, but not blockers for this revision, are whether to raise the per-channel live-query cap after migration and whether to add a future UI toggle for raw source wall-clock time versus viewer-local display.
