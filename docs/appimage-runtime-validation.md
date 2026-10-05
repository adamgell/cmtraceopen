# Fixed-candidate AppImage runtime acceptance

This manual harness executes only the signed v1.6.2 draft-release candidate below, using one standard Ubuntu 22.04 VM and one standard Ubuntu 24.04 VM. Each job has a 20-minute limit (40 runner-minutes total). The first workflow attempt is the only accepted attempt. A second dispatch or rerun requires new authorization.

## Dispatch gate

**Do not dispatch from the draft PR.** The sole integration coordinator must first confirm that the reviewed workflow has reached `main`, that the implementation files are unchanged, and that the artifact below is still available. Review the final harness commit independently and record its full SHA/tree in the handoff. A squash merge is supported by checking exact file content against that reviewed commit, rather than assuming ancestry.

After that explicit confirmation and the parent's separate instruction bound to the final candidate and harness, the authorized operator runs this command **once**, replacing the placeholder with the final reviewed harness commit:

```sh
gh workflow run cmtrace-appimage-runtime.yml \
  --repo adamgell/cmtraceopen --ref main \
  -f reviewed_harness_sha=FULL_REVIEWED_HARNESS_COMMIT
```

Monitor that run to a terminal state. Do not retry a blocked or failed job. Do not change host security policy to make a probe pass. This harness does not publish a release, trigger a catalog retest, or merge either PR.

## Immutable candidate

| Binding | Value |
| --- | --- |
| Product tag | `v1.6.2` |
| Signed tag object | `7d7cb1bec8b372fbaf08845c2ac6bab6668ba6c0` |
| Artifact / name | `11324800940` / `appimage-abi-Linux-x64` |
| Producer run / attempt | `37260205745` / `1` |
| Successful Linux job | `111605638405` |
| Archive SHA256 | `b512e643397f886fb6bbdc6f52f1124d9b1457bb3fc58f9a757dbe3d6535e3a7` |
| Inner AppImage path | `appimage/CMTrace Open_1.6.2_amd64.AppImage` |
| AppImage bytes / SHA256 | `92326392` / `4c0a67bdd369f65fa962b8ca91204c0037a0aee058de07d999007d6749fdb9e2` |
| ABI report path | `provenance/appimage-abi.json` |
| ABI report SHA256 | `8f0adfdb637dc41d86cdde426c2c19359738fd664da5517001fa6b0880e6ed59` |
| Product source | `c142b2294b4d686ecba3286cd42812587ca0a334` |
| Built commit | `c142b2294b4d686ecba3286cd42812587ca0a334` |
| Workflow commit | `c142b2294b4d686ecba3286cd42812587ca0a334` |
| Built tree | `ec6daf5654332ad3c31a08b49b4a9e487338b1c4` |
| Draft release / AppImage asset | `403346505` / `611409081` |
| Draft asset name | `CMTrace.Open_1.6.2_amd64.AppImage` |
| Updater signature asset | `611409180` / `CMTrace.Open_1.6.2_amd64.AppImage.sig` |
| Updater signature SHA256 | `a5a9a7119edf7861163ca8e875fd83cf004334b437cc29f18614275ebd1408c1` |

The release owner's receipt verified identical AppImage bytes in the draft asset, archive and ABI report, the updater signature's trusted `version:1.6.2` comment, and provenance for producer attempt 1. The successful Linux job does not establish acceptance of the whole release: remaining producer/platform gates and draft publication belong to the release owner. The product tag and candidate bytes remain fixed; this harness does not rebuild or re-sign them. Recheck artifact availability before dispatch.

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

Readiness checks the splash's HTML ID and exposed subtitle/image semantics even when `STATE_SHOWING` is false, because the overlay fades before removal. Two consecutive samples must contain the expected fixture rows and the same active window geometry within the Xvfb display. The same splash/window gate applies before interacting with the second launch. Find has separate open/focus, query readback, BETA selection and count stages. Selectors follow `index.html` and `src/components/layout/FindBar.tsx`: WebKit maps text inputs to AT-SPI `entry` with `placeholder-text`, and suppresses ordinary spans/StaticText objects while exposing their Text on containing sections. Count inspection is bound to the smallest shared section of the unique Find entry and Close button, with exactly the two named toggle buttons (the product uses `aria-pressed`) and three named ordinary buttons and no unrelated inputs, log lists or dialogs. The query, BETA selection and all three rows are rechecked there. Only boundary U+FFFC embedded-object markers and whitespace may be removed from count text; unexpected literal text is not stripped. Nonempty Text takes precedence over the same object's name. Conflicting numeric counts and the product's `No results`/`Invalid regex` statuses fail. See the [WebKit 2.50.4 AT-SPI implementation](https://github.com/WebKit/WebKit/blob/webkitgtk-2.50.4/Source/WebCore/accessibility/atspi/AccessibilityObjectAtspi.cpp). Offline fixtures cover hidden/wrong inputs, duplicate or unrelated controls, wrong roles, query/count mismatches, section/Text representations, global count decoys, and rows visible beneath the splash; actual runner accessibility behavior still requires separately authorized runtime validation.

Each case retains only an allowlisted stage, bounded wait duration and boolean observations. A failed case may capture its current window into the existing `final.png` slot, explicitly labeled `failure`; a successful case labels that slot `acceptance`. Capture failure cannot turn a failed assertion into a pass. There are still at most two images per case and the same aggregate byte/retention limits.

The unchanged `/usr/bin/bwrap --ro-bind / / -- /usr/bin/true` gate records its numeric return code, signal, timeout, stderr truncation flag and a fixed error category. At most 4096 stderr bytes are retained in memory for classification; raw stderr is never written to evidence. Read-only policy observations include available user-namespace sysctls, AppArmor enabled state/current-label classification, and bubblewrap mode, owner and file-capability presence. Missing/unreadable values remain unknown. A namespace denial does not establish AppArmor as its cause. Any failed, timed-out or unspawnable probe still blocks AppImage launch, and collected functional evidence additionally requires a valid successful probe record.

The first approved allocation was consumed by [run 37268941550, attempt 1](https://github.com/adamgell/cmtraceopen/actions/runs/37268941550): Ubuntu 22.04 failed UI assertions and Ubuntu 24.04 blocked at the bubblewrap gate. This diagnostic correction does not authorize another dispatch or change host policy. A second run requires Adam's new approval bound to the reviewed harness.

Application/helper output is discarded. Cleanup terminates only the newly allocated account's processes, using pidfds to avoid PID reuse races, then unmounts any remaining task-owned FUSE mounts under the newly created private temp root using the normal FUSE helper as the task account. This bounded cleanup verifies mount disappearance before deleting the account and files. It preserves a failed or blocked outcome and never substitutes for normal-exit acceptance. Evidence is read after cleanup of child processes, rejecting symlinks, hardlinks, special files, wrong owners and oversized files. Only an allowlisted JSON summary and four decoded/re-encoded PNGs can upload, capped at 10 MiB of screenshots per VM with seven-day retention. No raw logs, environment dump, arbitrary accessibility text, or artifact payload is uploaded.

## Harmless checks before dispatch

```sh
node --test scripts/appimage-runtime-workflow.test.mjs
python3 scripts/appimage_runtime_test.py
actionlint .github/workflows/cmtrace-appimage-runtime.yml
git diff --check
```

The Python tests use stdlib and Pillow. They do not execute the AppImage, create accounts/namespaces, or run the privileged supervisor. Ordinary PR CI runs these checks; runtime allocation remains manual. All existing helper entries in `cmtrace-ci.yml`, including exporter, QA citations and the separately integrated AppImage packaging tests, must be preserved during integration.
