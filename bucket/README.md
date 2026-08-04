# Scoop bucket

This directory is a [Scoop](https://scoop.sh) bucket, so this repository can be
added to Scoop directly:

```powershell
scoop bucket add cmtraceopen https://github.com/adamgell/cmtraceopen
scoop install cmtrace
```

| Manifest | Installs | Command |
|----------|----------|---------|
| [`cmtrace.json`](cmtrace.json) | Full edition, the default build | `cmtrace` |
| [`cmtrace-lite.json`](cmtrace-lite.json) | Lite edition, the core log viewer only | `cmtrace-lite` |

Both are the portable single-file executables, x64 and arm64. Nothing is written
to Program Files and no installer runs, so `scoop uninstall` leaves nothing
behind except the settings the app keeps in its own WebView2 profile.

## Staying current

`.github/workflows/scoop-publish.yml` runs on `release: published`, bumps the
manifests, validates them with real Scoop on a Windows runner, and commits the
result. `workflow_dispatch` with a `tag` input does the same for a release that
was published before the workflow existed.

The bump itself is `.github/scripts/Update-ScoopManifest.ps1`, which can be run
by hand from a clone:

```powershell
./.github/scripts/Update-ScoopManifest.ps1 -Version 1.5.1
```

It derives every URL from the manifests' own `autoupdate` templates and takes
each `sha256` from the GitHub release asset digest, falling back to downloading
the asset. If a release ever renames an asset, only the `autoupdate` template
needs editing. To check a hash independently:

```powershell
(Get-FileHash .\CMTrace-Open_1.5.1_x64.exe -Algorithm SHA256).Hash.ToLower()
```

## Submitting to ScoopInstaller/Extras

The manifests here already carry `checkver` and `autoupdate`, so once they are in
[ScoopInstaller/Extras](https://github.com/ScoopInstaller/Extras) the Excavator
bot bumps them on its own and users can `scoop install cmtrace` without adding
this bucket first. That submission is a one-time manual step, and Scoop's
[contributing guide](https://github.com/ScoopInstaller/.github/blob/main/.github/CONTRIBUTING.md)
requires an issue before the pull request:

1. Open an issue on `ScoopInstaller/Extras` proposing the package. Pull requests
   without a related issue are explicitly discouraged.
2. Once a maintainer approves it, fork `ScoopInstaller/Extras` and branch from
   `master`.
3. Copy `cmtrace.json` (and `cmtrace-lite.json`, if both are wanted) into the
   fork's `bucket/` directory unchanged. The field order, four-space indentation,
   and SPDX license identifier already match what Extras requires.
4. Test locally on Windows: `scoop install .\bucket\cmtrace.json`, confirm the
   app launches and the shim works, then `scoop uninstall cmtrace`.
5. Confirm autoupdate resolves. From a clone of `ScoopInstaller/Scoop`:
   `.\bin\checkver.ps1 -App <path>\bucket\cmtrace.json -ForceUpdate`. Use
   `-ForceUpdate` rather than `-Update`, which is a no-op while the manifest is
   already at the latest version and so proves nothing.
6. Open the pull request titled `cmtrace: Add version 1.5.1`, then comment
   `/verify` on it to trigger the manifest verifier.

Extras is a copy, not a mirror. After it lands, this bucket and the Extras copy
are bumped independently: the workflow here, Excavator there. Divergence beyond
`version`/`url`/`hash` means a manual pull request to Extras.

The Extras guide says nothing about package naming or trademarks, but `cmtrace`
is also the name of the Microsoft tool this project replaces, so a reviewer may
raise it. The manifests state the MIT license, link `homepage` to
cmtraceopen.com, and carry a "Not affiliated with or endorsed by Microsoft" note
that Scoop shows after install.
