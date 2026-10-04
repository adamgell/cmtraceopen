# Fixed-candidate AppImage runtime acceptance

This manual harness is a separate review surface from product PR #786. It executes only the candidate below, using one standard Ubuntu 22.04 VM and one standard Ubuntu 24.04 VM. Each job has a 20-minute limit (40 runner-minutes total). The first workflow attempt is the only accepted attempt. A second dispatch or rerun requires new authorization.

## Dispatch gate

**Do not dispatch from the draft PR.** The sole integration coordinator must first confirm that the reviewed workflow has reached `main`, that the implementation files are unchanged, and that the artifact below is still available. Review the final harness commit independently and record its full SHA/tree in the handoff. A squash merge is supported by checking exact file content against that reviewed commit, rather than assuming ancestry.

After that explicit confirmation, the authorized operator runs this command **once**, replacing the placeholder with the final reviewed harness commit:

```sh
gh workflow run cmtrace-appimage-runtime.yml \
  --repo adamgell/cmtraceopen --ref main \
  -f reviewed_harness_sha=FULL_REVIEWED_HARNESS_COMMIT
```

Monitor that run to a terminal state. Do not retry a blocked or failed job. Do not change host security policy to make a probe pass. This harness does not publish a release, trigger a catalog retest, or merge either PR.

## Immutable candidate

| Binding | Value |
| --- | --- |
| Artifact | `11311507149` |
| Producer run / attempt | `37222916777` / `1` |
| AppImage SHA256 | `fe80fa10c11b0dbd16198579169a08e4f2ed5ab5e72da876c3ec0197153b9873` |
| Product source | `0a1bb21add1e7d331d4f4e2a00be8c317240bebf` |
| Built merge | `9433d28d28db986c0a2204b22cf20a7643d7f3df` |
| Built tree | `5481bee5fc7f503b075ed6501bc9556db65de76e` |

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
2. Find BETA through the focused editable and require the selected BETA option and `1 of 1` match count.
3. Filter GAMMA; require it included and ALPHA/BETA excluded.
4. Clear the filter and assert the original three records.
5. Append a unique DELTA record and assert four records within 15 seconds.
6. Fully exit normally, reopen, open the fixture using the native file chooser, and assert all four records again.
7. Fully exit normally again.

A per-controller Linux child subreaper adopts orphaned app helpers, including helpers forked between shutdown observations. Exit checks bind PIDs to process start times, exclude pre-existing GUI services, and require the launch's FUSE mount to disappear before reopening. This changes only process-local child adoption, not a namespace or host policy.

Fresh home/config/cache/data directories isolate the two cases. Namespace, bubblewrap, FUSE, GUI or accessibility failures are **blocked**. Once accessibility is available, failed functional assertions are **failed**. Both cases must pass for the job to succeed; a blocked case never becomes an application pass.

Application/helper output is discarded. Cleanup terminates only the newly allocated account's processes, using pidfds to avoid PID reuse races, then unmounts any remaining task-owned FUSE mounts under the newly created private temp root using the normal FUSE helper as the task account. This bounded cleanup verifies mount disappearance before deleting the account and files. It preserves a failed or blocked outcome and never substitutes for normal-exit acceptance. Evidence is read after cleanup of child processes, rejecting symlinks, hardlinks, special files, wrong owners and oversized files. Only an allowlisted JSON summary and four decoded/re-encoded PNGs can upload, capped at 10 MiB of screenshots per VM with seven-day retention. No raw logs, environment dump, arbitrary accessibility text, or artifact payload is uploaded.

## Harmless checks before dispatch

```sh
node --test scripts/appimage-runtime-workflow.test.mjs
python3 scripts/appimage_runtime_test.py
actionlint .github/workflows/cmtrace-appimage-runtime.yml
git diff --check
```

The Python tests use stdlib and Pillow. They do not execute the AppImage, create accounts/namespaces, or run the privileged supervisor. Ordinary PR CI runs these checks; runtime allocation remains manual. All existing helper entries in `cmtrace-ci.yml`, including exporter, QA citations and the separately integrated AppImage packaging tests, must be preserved during integration.
