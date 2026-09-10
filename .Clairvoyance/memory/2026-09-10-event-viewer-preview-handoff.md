# 2026-09-10 Event Viewer Preview Badge — Session Handoff

Session date: 2026-09-10. Owner: Adam (moving to the Windows box `labz1-cm01`).
Status: **no production code changed this session** — preflight blocked implementation; this note records verified state, the locked design, and exact unblock actions.

## Goal (Adam's words, 2026-09-10)

Get the Event Viewer tested, validated, and a preview label applied in-app, then push the release.

## Locked design — approved by Adam, NOT yet implemented

**In-app feature badge, two surfaces (Adam selected "Both" → "Filter bar + suffix"):**

1. **Registry suffix** — `src/workspaces/event-log/index.ts`:
   ```diff
   -  label: "Event Log Viewer",
   +  label: "Event Log Viewer (Preview)",
   ```
   Renders automatically in the toolbar workspace dropdown and status bar (`statusLabel` defaults to `${label} workspace`).

2. **Filter-bar ghost badge** — `src/workspaces/event-log/EvtxFilterBar.tsx`:
   Fluent `Badge` (`appearance="ghost"`, small) labeled "Preview", leading the filter bar's first row. This is the workspace's only persistent chrome — it stays visible through file mode, live mode, filtering, grouping, and detail-pane states. The empty-state `SourcePicker` title is deliberately NOT badged (a badge that vanishes on first data load was rejected as not-a-label; a shared-heading alternative was proposed and withdrawn — do not resurrect either without Adam's approval).

**Tests:** focused Vitest + Testing Library, matching `src/workspaces/event-log/EventLogWorkspace.test.tsx` conventions — registry label contract (assert `eventLogWorkspace.label === "Event Log Viewer (Preview)"`) and loaded-state filter-bar badge presence. No QA-tracker row flips to `validated` without exact-SHA Windows evidence; EVTX-002 stays `partial/coverage`.

**Lane target:** epic #539 or an existing child issue if scope fits — do NOT create a new GitHub issue without Adam's explicit authorization.

## The blocker — skillset preflight fails

`python3 .omp/skills/cmtraceopen-dev/scripts/setup_skillset.py --check` exits 1: **9 of 15 approved external skill sources missing** at canonical `~/.hermes/skills/...` paths: `branch-lane-verification`, `cmtrace-scaffold-pipeline`, `cmtraceopen`, `cmtraceopen-code-review`, `contract-scoped-review`, `semantic-reducer-development`, `semantic-reducer-framework`, `windows-lab-workers`, `windows-remote-validation`.

- Root cause: Hermes profile reorganization. The `default-old` profile archive at `~/.hermes/profiles/default-old/skills/` contains directories named for all nine skills; **contents unverified** (only directory existence was checked; the pinned `APPROVED_SKILL_TREE_SHA256` digests must be validated by the check itself once routing is restored).
- Per `.omp/skills/cmtraceopen-dev/SKILL.md`: repair is operator-only ("do not repair it during preflight"); the script resolves canonical `~/.hermes/skills/...` paths hardcoded in `APPROVED_SKILLS`, so repointing only the `~/.omp/agent/skillsets/cmtraceopen/` symlinks will NOT pass — the canonical sources must exist again.
- **Unblock action (Adam):** restore canonical Hermes skill sources/profile routing on the Mac (or wherever OMP runs next), then rerun `setup_skillset.py --check` until green. Only then may feature work start.
- Related, same root cause: the PM execution charter sits at `~/.hermes/profiles/default-old/cmtrace-pm-charter.md` (supplied by Adam this session) rather than canonical `~/.hermes/cmtrace-pm-charter.md`. Read whichever exists; never create or mutate it.

## Windows validation target — verified 2026-09-10

`labz1-cm01` (SSH alias in `~/.ssh/config`) — **online and suitable**:

- Windows Server 2022 x64 (10.0.20348), PowerShell remoting works over SSH
- `Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider` channels present: Operational, Autopilot, Admin
- `git`, `cargo`, `node`, `winget` all resolve; WebView2 runtime `152.0.4191.66` present
- `ring0ivy24-01` and `ring0ivy24-06` timed out from the Mac on 2026-09-10 — connectivity fact only, not proof they are down

**Validation approach decided this session:**

- **Layer 1 (automated, no GUI):** SSH → clone at exact pushed PR head → `cargo test --locked -p cmtrace-open --all-features` + `cargo clippy --all-targets --all-features -- -D warnings` on the box. This compiles and runs the Windows-only code paths (including `event_log::live` wevtapi FFI) natively. Whether specific tests query live channels was not established this session — live-channel behavior is covered only by the Layer-2 RDP acceptance. (CI's `windows-esp` job already runs this per push; the lab run is the native cross-check.)
- **Layer 2 (interactive acceptance): manual RDP is the authority.** Neither OMP GUI control nor Event Viewer IPC bridging is proven. `src-tauri/src/ipc_bridge.rs` (dev-only HTTP bridge on `:1422`) has no Event Viewer commands in its dispatch arm (verified by reading the full `match req.cmd.as_str()` block; it covers log parsing, app config, filesystem, error lookup, and explicit ESP/Graph error arms only) — Event Viewer commands (`evtx_query_channels`, `enumerate_channels`, etc.) hit the unknown-command arm, which returns `{"result":null}` — and the Playwright shim (`e2e/fixtures/tauri-shim.ts`) resolves that null without falling back to defaults, so the browser-driven path cannot validate real wevtapi behavior (exact UI outcome of the null result not traced). Extending bridge dispatch to Event Viewer commands is a separate scoped future lane, explicitly out of scope for the badge task.
- **OMP on the Windows box: optional experiment only** — sensible for agent-driven native fix→test loops, but unproven (GUI control not established). If attempted, start with a disposable smoke session, never against production work.

## Execution sequence (once preflight is green)

1. **Badge lane:** isolated worktree from `main` (never the dirty root checkout — it carries Adam's untracked `.Clairvoyance/report_issues.py` / `report_output.py`, which are Adam's own scratch tooling, unrelated to this task; leave untouched) → RED tests (label + badge assertions) → confirm fail → GREEN (the two edits) → `npx tsc --noEmit` + `npm run test` focused → commit, push, draft PR, CodeRabbit loop to clean.
2. **Windows acceptance pre-merge:** build/install artifact tied to the **pushed PR head SHA** on `labz1-cm01`; native CLI gates; bounded EVTX manual checklist over RDP covering the EVTX-001…010 user stories that can pass; record evidence per row with exact SHA. Native validation is a **pre-merge gate** — only Adam merges.
3. **Review:** CodeRabbit + independent charter review at exact head; complete before presenting ready.
4. **Release (version TBD by Adam):** follows Adam's merge. Changelog (rename `## [Unreleased]`) + the three version files (`package.json`, `src-tauri/tauri.conf.json`, `src-tauri/Cargo.toml` `[package]` — must match exactly) → tag push `vX.Y.Z` fires both `cmtrace-release.yml` (macOS/Linux) and `codesign.yml` (signed Windows). Standard stable flow only — the release workflow hard-rejects non-`MAJOR.MINOR.PATCH` tags and publishes `prerelease: false`; "preview" here is the in-app label, NOT a release channel. Post-tag: verify all eight updater targets in `latest.json` (see `.github/agents/release.agent.md` §6a).

## Facts established this session (verified, not inferred)

- Event Viewer work is **merged to main** (workspace UI `src/workspaces/event-log/` + backend `src-tauri/src/event_log/`, `event-log` feature in `src-tauri/Cargo.toml`). The basic workspace shipped in v1.5.2; main carries ~8.6k added lines since that tag across 41 event_log files (unified timeline, columns chooser, saved filters, grouping, TZ toggle, coverage banner) — those enhancements are post-tag and ship next release.
- Epic #539 has many unchecked items needing real Windows evidence (reference corpus, benchmarks, provider metadata capture, competitive interaction checks) — **preview ≠ epic completion**; frame acceptance as a bounded matrix with explicit coverage gaps.
- CI (`cmtrace-ci.yml`) runs a Windows test/clippy matrix on every push (`windows-esp` job); live-interactive coverage is not part of CI.
- Repo versions checked this session were 1.5.2 (`package.json`, `src-tauri/tauri.conf.json`); latest stable release tag v1.5.2 (2026-08-11); a nightly prerelease channel exists (nightly-signed workflow).
- QA tracker `docs/qa/user-stories.csv`: EVTX-001–010 rows exist; EVTX-002 (live channel browse) is `partial/coverage` pending native evidence — correct as-is.
