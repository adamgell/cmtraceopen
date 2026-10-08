# Fixed-candidate AppImage runtime acceptance

The refreshed candidate is `08d4f19187c0798d9b0175fd60633868f474ebe9`, including named Find bar group and Find results status semantics. The current immutable table below identifies independently verified fresh producer bytes, replacing the old candidate binding. The strict harness requires that unique visible named group and status with exact local `1 of 1` text, query readback, selected BETA and all three rows. It stops at a failed count gate; diagnostic continuation has been removed. Earlier old-source functional/visual results are historical and do not validate refreshed bytes.

This manual harness executes PR #821's unsigned 1.6.3 CI AppImage on a standard Ubuntu 22.04 x64 VM. Ubuntu 24.04 x64 remains a required release gate but is excluded from the current matrix after its unchanged bubblewrap preflight established an environment blocker. Adam removed the voluntary 20-minute job / 40-runner-minute total limit for this task. There is no custom workflow job timeout; normal GitHub platform timeouts apply. The existing 300-second per-case, 660-second supervisor and bounded subprocess/cleanup hang protections remain unchanged. This is not unlimited retry authorization or final signed-release acceptance.

## Dispatch gate

The task-specific dispatch ref is `codex/pr821-ubuntu-runtime`; no main merge is needed. The exact workflow SHA must equal `reviewed_harness_sha`. Repository restriction, first-attempt restriction, max-parallel 2, read-only token permissions and immutable actions remain intact.

The initial authorized allocation was consumed by [run 37808889319, attempt 1](https://github.com/adamgell/cmtraceopen/actions/runs/37808889319), using signed harness `b740b6f5760e64c870bbc4944174d78f8210ae52`:

```sh
gh workflow run cmtrace-appimage-runtime.yml \
  --repo adamgell/cmtraceopen --ref codex/pr821-ubuntu-runtime \
  -f reviewed_harness_sha=b740b6f5760e64c870bbc4944174d78f8210ae52
```

Do not repeat this command as a blind retry. Diagnose a recoverable in-scope failure before any recovery run. Do not change host security policy to make a probe pass. This harness does not publish a release, trigger a catalog retest, or merge a PR.

## Historical old-source diagnosis and recovery

Diagnostic run [37809804187](https://github.com/adamgell/cmtraceopen/actions/runs/37809804187), harness `77a0c399bcc4773fa18ec7dc3ffb923ba9376606`, kept the same artifact and assertions. Ubuntu 22.04 observed a unique, visible Find placeholder with no `entry` role-name objects; the readiness exception was an AT-SPI error. WebKit exposes numeric `GetRole` and `GetRoleName` separately: the latter can follow `rolePlatformString`. Input identification requires declared `tag:input`, editable state; no unobserved role or unused EditableText-interface assumption, preserving uniqueness, visibility, focus/editability and all query/selection/count assertions. The first recovery (run 37810428462, harness e58195c7c0b0df7d069902644b992555acb9b374) showed that numeric Entry alone was still insufficient and exposed a traversal error during readiness. Run 37810968020 (harness d5d08679aa9d3afe0ef3847ad58d059131af2394) reached Find in both cases and proved the unique visible HTML input was editable and focused; only role-enum assumptions rejected it. The current repair uses the declared HTML/state/interface boundary and resamples whole-tree AT-SPI mutation errors instead of discarding children. Bounded polling may resample AT-SPI exceptions within the original deadline; repeated inaccessible samples block, and unrelated exceptions still propagate.

Ubuntu 24.04 diagnostic evidence classified bubblewrap's failure as `id-map-denied`, not an application failure. No policy change is allowed. The current recovery matrix contains only Ubuntu 22.04 to avoid repeating a known environment blocker. Ubuntu 24.04 is still required for release acceptance and needs a separately coordinated compatible disposable x64 environment where the unchanged unprivileged bubblewrap probe succeeds.

## Current immutable candidate

| Binding | Value |
| --- | --- |
| Product candidate | PR #821, unsigned CI 1.6.3; no release tag |
| Artifact / name | `11569479897` / `cmtrace-open-Linux-x64` |
| Producer run / attempt | `37817985168` / `1` |
| Archive SHA256 | `2339771aca4593909dbf9648311f3e9c6701f32fb4eb46937c1b504103494052` |
| Inner AppImage path | `appimage/CMTrace Open_1.6.3_amd64.AppImage` |
| AppImage bytes / SHA256 | `92334584` / `471782dccb2a7f8f7b1f0c6d1a986c332b83c31243699996b089303989c51627` |
| ABI report path | `provenance/appimage-abi.json` |
| ABI report SHA256 | `5786236b89e14002a7081c3e5daca3a98f0e27d93894389bf7c1d141dfc8a163` |
| Product source | `08d4f19187c0798d9b0175fd60633868f474ebe9` |
| Built / producer workflow commit | `75187bc67655e2d34adb55baa50ea749a5573608` |
| Built tree | `f7b17ae264d059e6f24db2a5efcfbdf643d5bcb1` |

The archive and inner AppImage digests were independently verified before dispatch. The runtime receipts bind source, built commit/tree, producer run/attempt and the AppImage digest. Candidate bytes remain fixed; this harness does not rebuild or re-sign them. Recheck artifact availability before any authorized recovery dispatch.

## Historical initial exact-artifact result

Both jobs ended with workflow failure while successfully uploading sanitized evidence. Ubuntu 22.04 passed identity/offline/bubblewrap/FUSE-device preflight. Both cases proved live read-only FUSE mounts and opened all three expected rows. Ordinary failed a UI assertion at `find-open-focus` after 30,167 ms: Close find bar was visible, but the intended input was not unique/focused according to the selector. The screenshot shows the Find bar open; it does not replace the failed accessibility assertion. Renderer-subset blocked with `harness-error` at `ready` after 95 ms. Find/filter/tail/reopen/normal exit acceptance is incomplete.

Ubuntu 24.04 blocked both cases at `preflight` with `bubblewrap-unavailable`: probe return code 1, no signal/timeout/truncation, error category `other`. Read-only observations report AppArmor enabled and `apparmor_restrict_unprivileged_userns=1`, but those values do not prove causation. No app launched there. Do not weaken AppArmor, namespaces, bubblewrap or WebKit sandboxing. A compliant alternate route needs separate coordination before execution.

The current allowlisted evidence does not identify the Ubuntu 22.04 selector mismatch or readiness exception precisely enough to justify changing acceptance assertions. Further recovery should first collect bounded, sanitized selector predicates and an allowlisted exception category, without uploading arbitrary accessibility strings or raw logs and without relaxing assertions.

The supervisor hashes a root-owned copy before execution and checks its producer provenance. It never rebuilds, modifies, extracts, or replaces the candidate.

## Isolation and evidence

Official Ubuntu packages provide Python, AT-SPI, Xvfb, IceWM, D-Bus, bubblewrap and FUSE. Installed package versions and trusted Ubuntu archive origins are recorded before execution. All GUI processes run under a newly allocated temporary account, with no supplementary groups, sudo access, Docker socket access, or inherited credentials. A privileged transient `unshare --net` creates an offline network namespace; `setpriv` then drops UID/GID and inheritable/ambient capabilities. The child verifies zero effective/permitted/inheritable/ambient capabilities, a down loopback-only interface, no IPv4/IPv6 routes, and unchanged outer mount/PID/user namespaces. It probes official bubblewrap before launching the app.

No persistent namespace, host network rule, sysctl, AppArmor policy, device permission, or unrelated mount is changed. Normal FUSE helpers remain usable: the harness does not set `no-new-privs` or drop the capability bounding set. Bubblewrap may create its own nested sandbox. This arrangement is a credential and network boundary on disposable VMs; it is not a claim of full filesystem isolation from a hostile executable.

Both cases launch the actual AppImage runtime under Xvfb:

- `ordinary`: ordinary renderer environment.
- `catalog-renderer-subset`: adds `WEBKIT_DISABLE_DMABUF_RENDERER=1` and `WEBKIT_DISABLE_COMPOSITING_MODE=1`.

The second case covers those catalog renderer settings only. It is not exact catalog sandbox parity: Firejail `--appimage` loop-mounts SquashFS and cannot demonstrate the FUSE runtime path. Neither case is Wayland or physical-GPU acceptance.

For each launch, the controller identifies an application process descended from its own launcher, reads that live process's mountinfo and executable, requires a read-only FUSE mount containing `usr/bin/cmtrace-open`, and stats `AppRun`, `AppRun.wrapped`, and the executable as root-owned regular 0755 files. It records bounded numeric PIDs/mount IDs and filesystem type, not arbitrary mount paths or app output.

UI acceptance uses the actual `Log entries` listbox and option rows:

1. Open three synthetic records and assert their exact messages/count.
2. Wait for the startup overlay to disappear and the active fixture window to be stable. Find BETA through the unique visible, focused, editable `Find...` entry, read back the exact query, and require the selected BETA option and `1 of 1` match count with all three records still present.
3. Filter GAMMA; require it included and ALPHA/BETA excluded.
4. Clear the filter and assert the original three records.
5. Append a unique DELTA record and assert four records within 15 seconds.
6. Fully exit normally, reopen, open the fixture using the native file chooser, and assert all four records again.
7. Fully exit normally again.

Each launch has a dedicated Linux child subreaper whose only child family is the AppImage. It waits for kernel `waitpid` to report `ECHILD`, so late or orphaned helpers cannot escape a process-list snapshot. GUI services remain outside this family. Normal exit additionally requires launcher success and disappearance of the launch's FUSE mount. The host supervisor also adopts orphaned descendants and requires kernel confirmation of no remaining children during final cleanup. These are process-local child-adoption settings, not namespace or host-policy changes.

Fresh home/config/cache/data directories isolate the two cases. Namespace, bubblewrap, FUSE, GUI or accessibility failures are **blocked**. Once accessibility is available, failed functional assertions are **failed**. Both cases must pass for the job to succeed; a blocked case never becomes an application pass.

Readiness checks the splash's HTML ID and exposed subtitle/image semantics even when `STATE_SHOWING` is false, because the overlay fades before removal. Two consecutive samples must contain the expected fixture rows and the same active window geometry within the Xvfb display. The same splash/window gate applies before interacting with the second launch. Find has separate open/focus, query readback, BETA selection and count stages. Selectors follow `index.html` and `src/components/layout/FindBar.tsx`: the live fixed artifact exposes the Find placeholder, declared HTML input and editable/focused state, while role-name/enum/interface assumptions failed. The current selector uses those observed semantics. The original section-based count binding is still not observed and remains failed. Count inspection is bound to the smallest shared section of the unique Find entry and Close button, with exactly the two named toggle buttons (the product uses `aria-pressed`) and three named ordinary buttons and no unrelated inputs, log lists or dialogs. The query, BETA selection and all three rows are rechecked there. Only boundary U+FFFC embedded-object markers and whitespace may be removed from count text; unexpected literal text is not stripped. Nonempty Text takes precedence over the same object's name. Conflicting numeric counts and the product's `No results`/`Invalid regex` statuses fail. See the [WebKit 2.50.4 AT-SPI implementation](https://github.com/WebKit/WebKit/blob/webkitgtk-2.50.4/Source/WebCore/accessibility/atspi/AccessibilityObjectAtspi.cpp). Offline fixtures cover hidden/wrong inputs, duplicate or unrelated controls, wrong roles, query/count mismatches, section/Text representations, global count decoys, and rows visible beneath the splash; actual runner accessibility behavior still requires separately authorized runtime validation.

Each case retains only an allowlisted stage, bounded wait duration and boolean observations. Synthetic timeout, evidence-rejection or cleanup errors use `unobserved` when the last UI stage is unknown; only observed preflight failures claim `preflight`. A failed case may capture its current window into the existing `final.png` slot, explicitly labeled `failure`; a successful case labels that slot `acceptance`. If capture or screenshot cleanup fails, the final image remains unclaimed and is excluded from collection even when stale or partial bytes remain; the original failure and stage are preserved. Capture failure cannot turn a failed assertion into a pass. There are still at most two images per case and the same aggregate byte/retention limits.

The unchanged `/usr/bin/bwrap --ro-bind / / -- /usr/bin/true` gate records its numeric return code, signal, timeout, stderr truncation flag and a fixed error category. If both bounded reap waits expire, the timeout record retains unknown (`null`) return code and signal; the host still requires child-process cleanup before collection. At most 4096 stderr bytes are retained in memory for classification; raw stderr is never written to evidence. Read-only policy observations include available user-namespace sysctls, AppArmor enabled state/current-label classification, and bubblewrap mode, owner and file-capability presence. Missing/unreadable values remain unknown. A namespace denial does not establish AppArmor as its cause. Any failed, timed-out or unspawnable probe still blocks AppImage launch, and collected functional evidence additionally requires a valid successful probe record.

Historical run 37268941550 tested older 1.6.2 bytes, not this candidate. Its failures and consumed approval are not reused as acceptance evidence or runtime authorization.

Application/helper output is discarded. Cleanup terminates only the newly allocated account's processes, using pidfds to avoid PID reuse races, then unmounts any remaining task-owned FUSE mounts under the newly created private temp root using the normal FUSE helper as the task account. This bounded cleanup verifies mount disappearance before deleting the account and files. It preserves a failed or blocked outcome and never substitutes for normal-exit acceptance. Evidence is read after cleanup of child processes, rejecting symlinks, hardlinks, special files, wrong owners and oversized files. Only an allowlisted JSON summary and four decoded/re-encoded PNGs can upload, capped at 10 MiB of screenshots per VM with seven-day retention. No raw logs, environment dump, arbitrary accessibility text, or artifact payload is uploaded.

## Harmless checks before dispatch

```sh
node --test scripts/appimage-runtime-workflow.test.mjs
python3 scripts/appimage_runtime_test.py
actionlint .github/workflows/cmtrace-appimage-runtime.yml
git diff --check
```

The Python tests use stdlib and Pillow. They do not execute the AppImage, create accounts/namespaces, or run the privileged supervisor. Ordinary PR CI runs these checks; runtime allocation remains manual. All existing helper entries in `cmtrace-ci.yml`, including exporter, QA citations and the separately integrated AppImage packaging tests, must be preserved during integration.

Run 37811452969 (harness 0fc631aad268945b77711de8ca50e108d9a895c3) retained the same visible/focused/editable HTML input but did not expose the unused EditableText interface. The harness uses X11 typing and Text readback, so the current selector relies on proven HTML/state identity. Window management commands may resample exit code 1 while IceWM manages a new window, within the existing poll deadline; other command failures propagate. These changes do not infer functional success: exact query, selected BETA, scoped count, filter, tail, reopen and normal exits remain required.

The count-scope diagnostic run 37812414723 (harness 6dcd7a276c7a19591af4fc8f7048eba02bb98905) observed unique entry/Close controls and a visible common ancestor, but that ancestor was neither the expected section nor declared div. The diagnostic continuation retains `find=false`, `status=failed`, the original count-stage diagnostics and a failure-labeled final image even if every later assertion succeeds. It captures the Find state in the existing initial-image slot for independent manual count review, then diagnoses filter/clear/tail/reopen/normal exits. This cannot produce an automated acceptance pass. The immutable candidate is unchanged; a review-only local proposal for an explicitly named FindBar accessibility group is not applied or published.

Continuation run 37813945610, harness 0f96934e2514817f5c7dfcb9b608d5e19506da13, verified filter/clear/tail and the first normal exit/relaunch in both cases (counts 3,1,3,4 and two FUSE proofs). Both stopped at native-chooser reopen. Independent image review of both Find-state initial screenshots confirms visible `1 of 1`, BETA selected and three rows; this does not change the automated count-gate failure. Reopen diagnosis now separates dialog visibility, location focus, path readback and row count. It observes whether a dialog exists on the case-private AT-SPI desktop under the same UID, without acting outside the original app or emitting arbitrary accessible names/text.

Chooser diagnostic run 37814739325 (harness b8f2852ce07f6f9a293cea9553826ee817036500) reached `reopen-count` in both cases, but no four-row reopen was observed. Source uses a multi-file picker. The current repair scopes location focus/path readback and the explicit Open button to the native chooser, rather than treating Return in its location field as dialog submission. The final-image slot may capture an active native modal only after proving its PID belongs to the disposable case UID; no other account's window is captured. All original schema/PNG/aggregate/retention limits remain unchanged.

## Repaired chooser result and remaining decisions

Run [37815694150](https://github.com/adamgell/cmtraceopen/actions/runs/37815694150), executed harness `80b6824573313b2cef8c53c7b8144e29303c6883`, verifies FUSE/open/filter/clear/tail/reopen and both normal exits in both Ubuntu 22.04 cases, with counts `3,1,3,4,4` and two read-only FUSE proofs each. Independent review of this run's two initial screenshots confirms visible `1 of 1`, BETA selected and three rows; both final screenshots show four reopened rows. The workflow still fails, as designed, solely because the automated count-container gate remains `find=false`. This is complete functional/visual evidence with an explicit automated accessibility-count coverage gap, not a fully green automated acceptance claim.

The separate local source proposal `a7efc17377e7a2bfa302b73fc3b9f32d30706bf7`, based on PR #821 source, gives FindBar a named group and polite live results status. Five FindBar tests and TypeScript checking passed on Node 22.23.3. It is not published or included in the tested artifact. Before using that source, the coordinator must decide candidate composition and authorize its publication/fresh CI artifacts; verify new source/build/tree/package digests and rebind the strict semantic selector before acceptance. Old bytes cannot prove the proposal.

Ubuntu 24.04 requires a separately approved disposable x64 route whose unchanged unprivileged bubblewrap UID/GID-map probe succeeds. No AppArmor/sysctl/setuid/capability/sandbox relaxation is proposed or authorized. No further automatic retries are scheduled.
