# Homebrew cask

`Casks/cmtrace-open.rb` is the source of truth for the CMTrace Open Homebrew cask. It is a
submission artifact, not a tap: Homebrew only recognises taps in repositories named
`homebrew-*`, so `adamgell/cmtraceopen` cannot be tapped directly. The file is kept here so
version bumps and metadata edits are reviewed in this repository, then copied into a
`Homebrew/homebrew-cask` fork when submitting.

Once accepted upstream, the cask lives at `Casks/c/cmtrace-open.rb` in `Homebrew/homebrew-cask`
(that repository shards `Casks/` by first letter; this repository does not need to).

## Install (users)

```bash
brew install --cask cmtrace-open
```

Apple Silicon only. The macOS release ships a single `aarch64` DMG with an arm64-thin binary,
so the cask declares `depends_on arch: :arm64`. On an Intel Mac, Homebrew refuses the install
with a hard error naming the unsatisfied architecture requirement. It will not fall back to
Rosetta, because there is no x86_64 or universal artifact to translate. Intel users have to
build from source. If a universal or x86_64 DMG is ever published, replace the single `url`
with an `arch`/`on_arm`/`on_intel` block and drop the `depends_on arch:` line.

## Staying current

The cask has a `livecheck` block and needs no release automation. Homebrew's autobump is
opt-out: every cask in `Homebrew/homebrew-cask` is autobumped unless it is deprecated, calls
`no_autobump!`, or has a `livecheck` block containing `skip`. None of those apply here. A
GitHub Action in the Homebrew organisation re-checks the autobump list every few hours and
opens the version-bump pull request itself, recomputing `sha256` from the new asset.

`strategy :github_latest` queries the GitHub `releases/latest` endpoint, which excludes drafts
and pre-releases. That matters for this repository: the rolling `nightly` tag is published as a
pre-release, and `strategy :github_releases` would enumerate it. `github_latest` also strips
the `v` prefix from the `v1.5.0` tag on its own, so no `regex` is needed.

A `brew bump-cask-pr` workflow in this repository was considered and rejected. It would need a
`HOMEBREW_GITHUB_API_TOKEN` with push access to a personal `homebrew-cask` fork, would race
Homebrew's own bumping action, and would duplicate work Homebrew already does for free. Revisit
only if autobump is observed skipping this cask.

## Submitting a new version manually

Only needed for the initial submission, or if autobump ever stalls. Requires a fork of
`Homebrew/homebrew-cask`.

Verify locally first. `brew style` and `brew audit` reject a cask that is not in a tap, so put
it in a throwaway one:

```bash
brew tap-new adamgell/casktest --no-git
cp Casks/cmtrace-open.rb "$(brew --repository adamgell/casktest)/Casks/"
brew style --cask adamgell/casktest/cmtrace-open
brew audit --new --cask adamgell/casktest/cmtrace-open
brew livecheck --cask adamgell/casktest/cmtrace-open
```

`brew audit --new` downloads the DMG, so it verifies the `sha256`, mounts it, and checks the
`app` stanza against the real bundle name. Then exercise the install path end to end and
confirm the app launches:

```bash
HOMEBREW_NO_INSTALL_FROM_API=1 brew install --cask adamgell/casktest/cmtrace-open
brew uninstall --cask adamgell/casktest/cmtrace-open
brew zap --cask adamgell/casktest/cmtrace-open
```

`brew zap` deletes the paths in the `zap trash:` stanza, which are the real user data
directories: markers, recent files, window state, logs, and WebKit local storage. Do not run
it on a machine whose CMTrace Open data you want to keep. `brew install --cask` also fails if
`/Applications/CMTrace Open.app` already exists from a manual DMG install; remove it first.

Clean up the scratch tap when done:

```bash
brew untap adamgell/casktest
```

To open the pull request, copy the file into a fork of `Homebrew/homebrew-cask` at
`Casks/c/cmtrace-open.rb`, then either commit it by hand or let Homebrew do it:

```bash
brew bump-cask-pr --version 1.5.0 cmtrace-open
```

`bump-cask-pr` only works against a cask that already exists upstream, so the first submission
is a hand-written pull request titled `cmtrace-open 1.5.0 (new cask)`. Homebrew's package
acceptance policy gates new casks on notability; the 75-star threshold is met
(`adamgell/cmtraceopen` is well above it). Disclose AI assistance in the pull request template
if any was used.

## Facts the cask depends on

Re-verify these whenever the macOS bundle changes, because the cask is wrong in a
silent-until-runtime way if any of them drift:

| Fact | Value | How to check |
|------|-------|--------------|
| App bundle name | `CMTrace Open.app` | `hdiutil attach -nobrowse -readonly <dmg>` then `ls /Volumes/CMTrace\ Open/` |
| Bundle identifier | `com.cmtrace.open` | `plutil -p "<app>/Contents/Info.plist"`, also `src-tauri/tauri.conf.json` `identifier` |
| Architecture | arm64 thin | `codesign -dv --verbose=4 "<app>"` reports `Mach-O thin (arm64)` |
| Notarization | stapled | `spctl -a -vvv -t install "<app>"` reports `Notarized Developer ID` |
| `zap` paths | see stanza | `find ~/Library -maxdepth 2 -iname '*com.cmtrace.open*'` after running the app |

The `zap trash:` list is derived from the verified bundle identifier: Tauri's `app_config_dir`
and `app_data_dir` both resolve to `~/Library/Application Support/com.cmtrace.open` on macOS
(window state, markers, recent entries, file-association prefs), `tauri-plugin-log` writes to
`~/Library/Logs/com.cmtrace.open`, `NSUserDefaults` writes
`~/Library/Preferences/com.cmtrace.open.plist`, and the Zustand `persist` stores land in
WKWebView local storage under `~/Library/WebKit/com.cmtrace.open`. All four were confirmed
present on a machine that had run the release build. `~/Library/WebKit/cmtrace-open` and
`~/Library/WebKit/cmtrace_open-<hash>` also exist on developer machines; those come from
`npm run app:dev`, not from the cask, so they are deliberately not zapped.
