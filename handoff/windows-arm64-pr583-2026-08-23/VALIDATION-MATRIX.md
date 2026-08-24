# Windows 11 ARM64 validation matrix

`Invoke-CMTraceOpenArm64Validation.ps1 -PlanOnly` is the exact 33-gate automatic plan. `manual-results.template.json` is the exact 68-gate native/manual contract. This document is the operator runbook for interpreting and exercising those gates.

## Evidence and status contract

Every manual gate has a fixed ID, requirement, and `requiredForFullAcceptance` flag. Do not add, remove, reorder, rename, or rewrite them.

For an exercised `PASS`, `FAIL`, or `BLOCKED` gate, choose a unique lowercase `evidenceId` and retain exactly one new regular, non-reparse proof file at `raw-artifacts/manual-evidence/<evidenceId>.proof`. Do not reuse an ID or proof across gates. The exporter resolves only that derived path, recomputes its hash, and leaves it on the target. Record only:

- allowed status and disposition code;
- UTC timestamp ending in `Z`;
- the unique safe lowercase `evidenceId` slug;
- lowercase SHA-256 of the private proof file;
- truthful native-observation and independent-readback booleans (`true` is mandatory for `PASS`/`FAIL`; a pre-observation `BLOCKED` row keeps them `false`);
- artifact SHA-256 for every `PASS`/`FAIL` when the gate is artifact-bound, and for `BLOCKED` only if the artifact was actually reached;
- defined bounded numeric measurements.

`PASS` uses `CONFIRMED`; `FAIL` uses `OBSERVED_FAILURE`. `BLOCKED` uses one bounded blocker code and still requires an evidence anchor. `NOT_EXERCISED` contains no timestamp, evidence, artifact, or observation/readback claim.

For every `PASS`/`FAIL` that observes the application or installer, set `artifactSha256` to the exact artifact kind defined by the gate map below. A `BLOCKED` row leaves it null unless execution actually reached that artifact. Source/harness-only rows leave it null. The exporter rejects a supplied hash that is not one of the automatic Full, Lite, NSIS, or provenance-derived installed-executable hashes, and enforces the mapped kind where one is defined.

| Gate set | Required artifact kind for `PASS`/`FAIL` |
|---|---|
| `lite-portable-launch` | `lite-portable` |
| `nsis-clean-install`, `provider-packaged-resource` | `nsis-installer` |
| `nsis-installed-arm64-payload`, `default-apps-file-associations`, `nsis-uninstall-cleanup`, `elevation-same-account`, `elevation-over-the-shoulder`, `genuine-upgrade-lifecycle` | provenance-derived `installed-executable` |
| `clean-snapshot-version-isolation`, `real-evtx-nonvacuous`, `provider-native-capture`, `provider-retained-db-tests`, all three known impossible advanced-surface gates, `performance-host-profile`, `performance-all-channels-seven-day`, `production-signing-and-msi-boundary` | none; `artifactSha256` must remain null |
| Every other manual gate, including all seven recovery rows | `full-portable` |

All native/manual commands that can emit target content use the bounded `Invoke-PrivateProcess` procedure in README. Capture stdout and stderr under `raw-artifacts/private-command-output`, do not echo `--nocapture`, EVTX/provider/MDMDiag/remote/performance output to the shared terminal, and kill only the owned process tree at the documented timeout. A timeout is never PASS.

The exporter derives:

- `MANUAL_FAILED` if any gate is `FAIL`;
- `MANUAL_COMPLETE` only when every required gate is `PASS`;
- otherwise `MANUAL_INCOMPLETE`.

The three exact-head product-surface gaps below can never be marked PASS:

- `eventlog-filter-library-advanced-surface`: no operator UI for import/export/favorites/tags/recents management;
- `eventlog-grouping-drag-pivot-surface`: ordered dropdown grouping is not drag-to-group or pivot;
- `eventlog-filter-rule-color-surface`: quick-filter term highlighting is not rule-specific saved-filter coloring.

## Snapshot and exact portable artifacts

The automatic lane publishes only these target-private launch candidates. `full-portable` and `lite-portable` are executable-only records; neither record contains or authenticates an external resource directory:

| Kind | Exact path |
|---|---|
| `full-portable` | `raw-artifacts/full/cmtrace-open.exe` |
| `lite-portable` | `raw-artifacts/lite/cmtrace-open.exe` |
| `nsis-installer` | `raw-artifacts/nsis/cmtrace-open-setup.exe` |

Before every launch, re-read `artifacts.json` and require that the exact regular non-reparse file's byte length and lowercase SHA-256 match its unique kind record. Never substitute a source-tree, installed, downloaded, or prior-run executable. Keep `CMTRACEOPEN_DISABLE_UPDATE_CHECKS=1` in the process environment for both portable launches. Installed and shell-launched activation instead requires the independently read-back HKCU installer policy described below. NSIS execution still requires separate approval.

| Gate | Pass boundary |
|---|---|
| `clean-snapshot-version-isolation` | Fresh snapshot; no stable/nightly install or prior CMTrace Open/WebView2 profile; both portable processes inherit `CMTRACEOPEN_DISABLE_UPDATE_CHECKS=1` |
| `full-portable-launch` | Exact `full-portable` bytes/hash verified immediately before launch; native ARM64/WebView2 UI renders and remains responsive |
| `lite-portable-launch` | Exact `lite-portable` bytes/hash verified immediately before launch; native UI works and Event Log is intentionally absent |

## Automatic lane

All automatic gates are required. A failed dependency blocks only downstream gates; any failure or block prevents automatic PASS.

| Area | Automatic evidence | Pass boundary |
|---|---|---|
| Source | commit, tree, lockfile blobs, fetch/push URLs, detached state, public signature, no submodules, clean before/after | All immutable coordinates match; push is disabled; status empty |
| Frontend | npm ci, TypeScript, production build, Vitest, release contracts, npm audit | Direct Node invocation of bundled npm/npx CLI exits 0 |
| Browser | Playwright Chromium install and E2E | Exits 0; mocked backend remains explicitly non-native |
| PowerShell | installer and collector Pester | Pester result Passed; encoded path is never returned |
| Parser | format, native ARM64 tests/Clippy, wasm check | Every command exits 0 |
| Windows Rust | native ESP, Graph, all-feature build/test/Clippy, Lite test/Clippy, Rust 1.88 | Every native command targets `aarch64-pc-windows-msvc` and exits 0 |
| Supply chain | cargo-deny, cargo-audit | Current advisory/policy data exits 0 |
| Artifacts | Full, Lite, NSIS, bundle verification, schema-v2 provenance | Full/Lite are unsigned `0xAA64`; NSIS is unsigned bootstrapper `0x014C`; hashes and expected installed executable bind to exact source |

Automatic success does not prove live Event Log behavior, installed behavior, signed output, updater signatures, protected MSI, or native accessibility.

## Local Event Log service

| Gate | Pass boundary |
|---|---|
| `local-channel-enumeration` | Full UI enumerates local channels; bounded independent OS readback includes Application and System |
| `local-unfiltered-nonzero` | Controlled local query returns a nonzero count and source provenance |
| `local-time-filter-strict` | `localNarrowRecordCount < localWideRecordCount`; the ignored assertion alone is insufficient |
| `local-level-filter-nonzero` | `localLevelRecordCount > 0` and every checked record has the requested level |
| `local-impossible-filter-zero` | Impossible filter returns zero, never widened results |
| `local-system-fields` | Timestamp, channel, provider, event ID, record ID, and source fields agree with private OS readback |

Run the five exact ignored selectors from README individually. Never use the aggregate local/remote module selector.

## Real EVTX and recovery

`New-CMTraceOpenPrivateEvtxFixtures.ps1` creates seven target-private copies under `raw-artifacts\private-evtx\recovery-copies` and refuses other output paths.

| Gate | Pass boundary |
|---|---|
| `real-evtx-nonvacuous` | Existing target-local fixture; exactly seven integration tests execute; `realEvtxTestsExecuted=7` |
| `recovery-clean-baseline` | Nonzero CLI/GUI records; no false damage coverage |
| `recovery-tail-truncation` | Visible incomplete/truncation coverage; no crash or false complete result |
| `recovery-internal-missing-chunk` | Missing clean IDs, later recovered IDs, nonzero records, nonzero damage coverage |
| `recovery-malformed-file-header` | Bounded visible file-header failure; no crash/hang/false clean result |
| `recovery-malformed-chunk-header` | Bounded chunk damage; no crash/hang/false clean result |
| `recovery-malformed-record-size` | Bounded record failure; no unbounded allocation or crash |
| `recovery-malformed-binxml` | Bounded XML failure; no fabricated content or crash |

Keep CLI TSV/JSON, coverage-gap text, and record-ID sets private. For the internal gap, require at least one clean ID missing from the damaged result and at least one damaged-result ID greater than the maximum missing ID. Return only the proof-file hash and bounded counts.

## Provider capture and descriptions

The ignored capture test deletes its temporary database. Use `New-CMTraceOpenPrivateProviderDatabase.ps1`; it executes that smoke test, builds the provided helper only in a target-private exact-source archive, captures an all-or-nothing database, isolates it from other `.db` files, and runs these exact retained selectors:

```text
event_log::provider_db::real_database_tests::opens_a_real_database_and_reports_its_size
event_log::provider_db::real_database_tests::renders_a_real_mdm_description_end_to_end
event_log::provider_db::real_database_tests::every_payload_in_a_sample_of_providers_inflates
event_log::parser::description_tests::an_unknown_event_id_falls_back_rather_than_inventing_a_description
event_log::parser::description_tests::a_loaded_database_renders_a_real_provider_description
event_log::parser::description_tests::an_event_the_database_does_not_cover_still_falls_back
```

| Gate | Pass boundary |
|---|---|
| `provider-native-capture` | Native smoke and exact helper pass; private all-or-nothing DB published |
| `provider-retained-db-tests` | All six tests pass against one isolated DB and `providerCount > 100` |
| `provider-packaged-resource` | Approved current-user NSIS lane only: exact source and installed `provider-db` regular non-reparse file inventories, bytes, and hashes agree; the installed manifest and both curated databases load; covered descriptions render; uncovered descriptions remain explicit |

Packaged curated DBs with 1 and 9 rows are not substitutes for the retained machine-wide DB. The executable-only Full portable artifact cannot satisfy `provider-packaged-resource`; defer that gate to the installed-lane procedure below and bind its manual `artifactSha256` to the exact `nsis-installer` hash.

## Live subscription, polling, and source composition

| Gate | Pass boundary |
|---|---|
| `live-subscription-delivery` | Purpose-created safe events arrive exactly once, in order, with sequence and visible subscription mode |
| `live-subscription-stop` | Stop/cancel releases resources; a later independently created event is not appended |
| `live-polling-fallback` | Only a naturally observed approved error 1, 50, 120, or 127 followed by visible polling delivery; there is no force-fallback seam |
| `folder-wildcard-rotation-deduplication` | File, folder, recursion, wildcard, rotation, overlap, provenance, ordering, and deduplication all agree |
| `unified-timeline-provenance` | Existing authorized lab text plus Event Log remains chronologically truthful and source-distinct; do not generate plausible logs |

## Recovered folder child errors and archive structure

Create the exact structural fixtures:

```powershell
$SourceFixtureScript = Join-Path $Handoff 'scripts\New-CMTraceOpenPrivateSourceFixtures.ps1'
$SourceFixtureBinding = Get-CMTraceContentBinding -Path $SourceFixtureScript -Label 'Sealed private source fixture helper'
$SourceFixtureResult = Invoke-PrivateProcess -Id 'private-source-fixtures' `
  -FilePath (Get-Command pwsh.exe).Source -WorkingDirectory $Handoff -TimeoutMinutes 10 `
  -ContentBindings @($SourceFixtureBinding) `
  -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'RemoteSigned', '-File', $SourceFixtureScript, '-EvidenceRoot', $Evidence)
if ($SourceFixtureResult.ExitCode -ne 0) { throw 'Private source fixture generation failed.' }
```

Revalidate the complete generated structure immediately before a contained Full UI launch. The two regular ZIP inputs and manifest are held by expected bytes for the complete process. Junction metadata cannot use a regular-file content guard, so the exact five names, link type, and common target are re-read immediately before the owned Full child starts; this lane requires the already-established clean, exclusive validation account boundary.

```powershell
$SourceFixtureRoot = Join-Path $Evidence 'raw-artifacts\private-source-fixtures'
$FolderChildFixture = Join-Path $SourceFixtureRoot 'folder-child-errors'
$JunctionTarget = Join-Path $SourceFixtureRoot 'junction-target'
$UnsafeStructuralZip = Join-Path $SourceFixtureRoot 'unsafe-duplicate.zip'
$MemberLimitStructuralZip = Join-Path $SourceFixtureRoot 'member-limit-513.zip'
$SourceFixtureManifestPath = Join-Path $SourceFixtureRoot 'fixture-manifest.json'

$ExpectedFixtureRootNames = @(
  'fixture-manifest.json',
  'folder-child-errors',
  'junction-target',
  'member-limit-513.zip',
  'unsafe-duplicate.zip'
)
$ActualFixtureRootNames = @(Get-ChildItem -LiteralPath $SourceFixtureRoot -Force |
  Sort-Object -Property Name -CaseSensitive | ForEach-Object Name)
if (($ActualFixtureRootNames -join "`n") -cne ($ExpectedFixtureRootNames -join "`n")) {
  throw 'Private structural fixture root inventory changed after generation.'
}

$ExpectedJunctionTarget = (Resolve-Path -LiteralPath $JunctionTarget).Path
$Junctions = @(Get-ChildItem -LiteralPath $FolderChildFixture -Force |
  Sort-Object -Property Name -CaseSensitive)
if ($Junctions.Count -ne 5) { throw 'Expected exactly five structural child-error junctions.' }
for ($Index = 0; $Index -lt $Junctions.Count; $Index++) {
  $Junction = $Junctions[$Index]
  $ExpectedName = 'blocked-{0}.evtx' -f ($Index + 1)
  $Targets = @($Junction.Target)
  if ($Junction.Name -cne $ExpectedName -or $Junction.LinkType -cne 'Junction' -or
      -not ($Junction.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $Targets.Count -ne 1 -or
      -not [string]::Equals((Resolve-Path -LiteralPath ([string]$Targets[0])).Path,
        $ExpectedJunctionTarget, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Structural child-error junction changed after generation: $ExpectedName"
  }
}

$SourceFixtureManifest = Get-Content -LiteralPath $SourceFixtureManifestPath -Raw | ConvertFrom-Json
if (($SourceFixtureManifest.schemaVersion -isnot [int32] -and $SourceFixtureManifest.schemaVersion -isnot [int64]) -or
    $SourceFixtureManifest.schemaVersion -ne 1 -or
    [string]$SourceFixtureManifest.sourceCommit -cne $script:CMTraceExpectedSourceCommit -or
    [int64]$SourceFixtureManifest.folderRejectedChildCount -ne 5 -or
    [int64]$SourceFixtureManifest.folderDisplayExpectedCount -ne 3 -or
    [int64]$SourceFixtureManifest.folderHiddenExpectedCount -ne 2 -or
    [int64]$SourceFixtureManifest.unsafeArchiveMembers -ne 3 -or
    [int64]$SourceFixtureManifest.memberLimitArchiveMembers -ne 513 -or
    [string]$SourceFixtureManifest.unsafeArchiveSha256 -cne (Get-CMTraceSha256 -Path $UnsafeStructuralZip) -or
    [string]$SourceFixtureManifest.memberLimitArchiveSha256 -cne (Get-CMTraceSha256 -Path $MemberLimitStructuralZip)) {
  throw 'Private structural fixture manifest does not bind the expected generated structure.'
}

$StructuralFixtureBindings = @(
  Get-CMTraceContentBinding -Path $SourceFixtureManifestPath -Label 'Private structural fixture manifest'
  Get-CMTraceContentBinding -Path $UnsafeStructuralZip -Label 'Private unsafe duplicate structural ZIP'
  Get-CMTraceContentBinding -Path $MemberLimitStructuralZip -Label 'Private 513-member structural ZIP'
)
$FullArtifact = Get-VerifiedPrivateArtifact -Kind 'full-portable'
$StructuralGuiResult = Invoke-PrivateProcess -Id 'private-structural-full-ui' `
  -FilePath $FullArtifact.Path -ExpectedSha256 $FullArtifact.Sha256 -ExpectedBytes $FullArtifact.Bytes `
  -WorkingDirectory (Split-Path -Parent $FullArtifact.Path) -TimeoutMinutes 60 `
  -Environment @{ CMTRACEOPEN_DISABLE_UPDATE_CHECKS = '1' } -ContentBindings $StructuralFixtureBindings `
  -ArgumentList @()
if ($StructuralGuiResult.ExitCode -ne 0) { throw 'Private structural Full UI observation failed.' }
```

While that owned Full process is open, recursively open `$FolderChildFixture`, then open `$UnsafeStructuralZip` and `$MemberLimitStructuralZip` through the native UI. Record all three exact observations below, close Full cleanly, and keep paths/screenshots private.

| Gate | Pass boundary |
|---|---|
| `folder-child-errors-visible` | Exact no-valid-EVTX fixture with five sorted reparse-point children retains the first rejected child and exact reason `symbolic link or reparse point is not followed during wildcard expansion`; no traversal/elevation/crash |
| `folder-child-errors-display-bound` | `folderChildErrorCount=5`; shows sorted blocked-1/2/3 plus `2 more`; does not expose blocked-4/5; each path/reason is bounded to 160 characters |
| `mdmdiag-structural-bounds` | Unsafe relative path is explicit, second case-insensitive duplicate is `duplicate`, and 513 members are rejected at the 512-member bound |

Structural binary placeholders are parser mechanics, not investigation evidence.

## Real MDMDiagReport archive

Stage an authorized target-local real `MDMDiagReport.zip` as a regular, non-reparse file at `cmtraceopen-input\MDMDiagReport.zip` on the same fixed local NTFS volume as `$Source`. Never generate plausible Event Log/text members. The following derives that reserved input root from the authenticated source volume, requires the exact approved staging path, creates the exact private destination, binds the source and copy hashes, keeps a private `System.IO.Compression` inventory, and enforces the native declared member, compressed, and uncompressed bounds before the CLI or UI opens it:

```powershell
$InputRoot = Join-Path ([IO.Path]::GetPathRoot($Source)) 'cmtraceopen-input'
$AuthorizedMdmBundle = Join-Path $InputRoot 'MDMDiagReport.zip'
if (-not (Test-Path -LiteralPath $AuthorizedMdmBundle -PathType Leaf)) {
  throw "Stage the approved MDMDiagReport.zip at $AuthorizedMdmBundle."
}
$AuthorizedMdmPath = Assert-CMTraceFixedLocalNtfsPath -Path $AuthorizedMdmBundle `
  -Label 'Authorized MDMDiagReport.zip' -ForbiddenRoots @($Handoff, $Source, $Evidence)
$AuthorizedMdmPath = Assert-CMTracePathWithinRoot -Path $AuthorizedMdmPath `
  -Root $InputRoot -Label 'Authorized MDMDiagReport.zip'
$AuthorizedMdmEntry = Get-Item -LiteralPath $AuthorizedMdmPath -Force
if ($AuthorizedMdmEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
  throw 'Authorized MDMDiagReport.zip cannot be a reparse point.'
}
if ($AuthorizedMdmEntry.Length -le 0 -or $AuthorizedMdmEntry.Length -gt 536870912L) {
  throw 'Authorized MDMDiagReport.zip is empty or exceeds the 512 MiB compressed-file bound.'
}

$PrivateMdmRoot = Join-Path $Evidence 'raw-artifacts\private-mdmdiag'
if (Test-Path -LiteralPath $PrivateMdmRoot) { throw 'Private MDMDiag destination already exists.' }
New-Item -ItemType Directory -Path $PrivateMdmRoot | Out-Null
$PrivateMdmRootEntry = Get-Item -LiteralPath $PrivateMdmRoot -Force
if ($PrivateMdmRootEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
  throw 'Private MDMDiag destination cannot be a reparse point.'
}

$Bundle = Join-Path $PrivateMdmRoot 'MDMDiagReport.zip'
$AuthorizedMdmSha256 = (Get-FileHash -LiteralPath $AuthorizedMdmEntry.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::Copy($AuthorizedMdmEntry.FullName, $Bundle, $false)
if ((Get-FileHash -LiteralPath $Bundle -Algorithm SHA256).Hash.ToLowerInvariant() -cne $AuthorizedMdmSha256) {
  throw 'Private MDMDiag copy hash mismatch.'
}

$MdmArchive = [IO.Compression.ZipFile]::OpenRead($Bundle)
try {
  if ($MdmArchive.Entries.Count -le 0 -or $MdmArchive.Entries.Count -gt 512) {
    throw 'MDMDiag archive member count is empty or exceeds 512.'
  }
  $TotalBytes = 0L
  $TotalCompressedBytes = 0L
  $Inventory = @()
  for ($Index = 0; $Index -lt $MdmArchive.Entries.Count; $Index++) {
    $Entry = $MdmArchive.Entries[$Index]
    if ($Entry.Length -gt 134217728L) { throw "MDMDiag member $Index exceeds 128 MiB." }
    if ($TotalBytes -gt (536870912L - $Entry.Length)) { throw 'MDMDiag aggregate bytes exceed 512 MiB.' }
    if ($TotalCompressedBytes -gt (536870912L - $Entry.CompressedLength)) { throw 'MDMDiag compressed aggregate exceeds 512 MiB.' }
    $TotalBytes += $Entry.Length
    $TotalCompressedBytes += $Entry.CompressedLength
    $Inventory += [ordered]@{
      index = $Index
      name = $Entry.FullName
      bytes = [int64]$Entry.Length
      compressedBytes = [int64]$Entry.CompressedLength
    }
  }
  [ordered]@{
    archiveSha256 = $AuthorizedMdmSha256
    memberCount = $Inventory.Count
    totalBytes = $TotalBytes
    totalCompressedBytes = $TotalCompressedBytes
    members = $Inventory
  } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $PrivateMdmRoot 'inventory.json') -Encoding utf8NoBOM
}
finally {
  $MdmArchive.Dispose()
}
```

Run the exact native CLI privately. Define `Invoke-PrivateProcess` from the README manual-helper section first, then complete the new private-target build in README section 8. Reuse its `$PrivateEventLogExport` binding and `$PrivateCliRoot`; do not rebuild, reconstruct a default source-tree target path, or capture a replacement hash.

```powershell
if (@(Get-Variable -Name PrivateEventLogExport, PrivateCliRoot -ErrorAction SilentlyContinue).Count -ne 2) {
  throw 'Complete the private event-log-export build and binding in README section 8 first.'
}
$ExpectedPrivateCliRoot = [IO.Path]::GetFullPath((Join-Path $Evidence 'raw-artifacts\private-event-log-export'))
$ResolvedPrivateCliRoot = (Resolve-Path -LiteralPath $PrivateCliRoot).Path
if (-not $ResolvedPrivateCliRoot.Equals($ExpectedPrivateCliRoot, [StringComparison]::OrdinalIgnoreCase)) {
  throw 'The private event-log-export binding belongs to a different evidence session.'
}
$ResolvedPrivateCliPath = (Resolve-Path -LiteralPath $PrivateEventLogExport.Path).Path
[void](Assert-CMTracePathWithinRoot -Path $ResolvedPrivateCliPath -Root $ResolvedPrivateCliRoot `
  -Label 'Current-evidence private event-log-export binding')
$MdmCliBinding = Get-CMTraceVerifiedArm64Executable -Path $ResolvedPrivateCliPath -Root $ResolvedPrivateCliRoot `
  -ExpectedSha256 $PrivateEventLogExport.Sha256 -ExpectedBytes $PrivateEventLogExport.Bytes
$CliOutput = Join-Path $PrivateMdmRoot 'cli-output.json'
$MdmBundleBinding = Get-CMTraceContentBinding -Path $Bundle -Label 'Private MDMDiagReport copy'
$MdmResult = Invoke-PrivateProcess -Id 'private-mdmdiag-cli' `
  -FilePath $MdmCliBinding.Path -ExpectedSha256 $MdmCliBinding.Sha256 -ExpectedBytes $MdmCliBinding.Bytes `
  -WorkingDirectory $Source -TimeoutMinutes 30 -ContentBindings @($MdmBundleBinding) `
  -ArgumentList @('--source', $Bundle, '--format', 'json', '--output', $CliOutput)
if ($MdmResult.ExitCode -ne 0) { throw 'MDMDiag CLI parse failed.' }
```

Reauthenticate the native Full artifact and hold the verified private archive for its complete GUI observation. This command blocks until Full exits. While it is open, use only the native file-open UI to open `$Bundle`, inspect archive/member provenance and counts, compare them with the private CLI output, and then close Full cleanly:

```powershell
$FullArtifact = Get-VerifiedPrivateArtifact -Kind 'full-portable'
$MdmGuiResult = Invoke-PrivateProcess -Id 'private-mdmdiag-full-ui' `
  -FilePath $FullArtifact.Path -ExpectedSha256 $FullArtifact.Sha256 -ExpectedBytes $FullArtifact.Bytes `
  -WorkingDirectory (Split-Path -Parent $FullArtifact.Path) -TimeoutMinutes 60 `
  -Environment @{ CMTRACEOPEN_DISABLE_UPDATE_CHECKS = '1' } -ContentBindings @($MdmBundleBinding) `
  -ArgumentList @()
if ($MdmGuiResult.ExitCode -ne 0) { throw 'Private MDMDiag Full UI observation failed.' }
```

`$CliOutput`, captured stdout/stderr, archive, full member manifest, and GUI observations remain private.

| Gate | Pass boundary |
|---|---|
| `mdmdiag-real-nonvacuous` | `mdmArchiveMemberCount > 0`, at least one parsed EVTX member, nonzero records; text/registry/binary inventory remains visible as applicable |
| `mdmdiag-member-accounting` | Every ZIP entry agrees with normalized member provenance, kind, outcome, present hash, and bounded omission accounting |
| `mdmdiag-record-provenance` | Archive/member provenance remains visible; missing time is unplaced, not guessed/dropped; CLI and GUI counts agree |

The `mdmdiag-structural-bounds` acceptance boundary is defined once under **Recovered folder child errors and archive structure** above; apply that same gate to this archive without redefining it here.

## Archive, VSS, remote, and clear boundaries

| Gate | Required observation |
|---|---|
| `archive-source-elevation-cancel` | Cancel reports cancellation and original process remains usable |
| `archive-source-elevation-success` | After approval, private Archive source loads and original process remains usable |
| `vss-source` | Already approved snapshot loads or precise denied/unavailable outcome; creating/deleting a snapshot needs separate approval |
| `remote-source-success` | Second authorized host succeeds with current OS credentials; no endpoint/credential is returned |
| `remote-source-denied-empty-unavailable` | Denied, empty, and unavailable remain distinct |
| `remote-handle-cleanup` | Measured baseline/after handle counts remain stable across meaningful repeated open/query/close; three loops alone are insufficient |
| `clear-typed-confirmation-cancel` | Owned canary unchanged by independent `Get-WinEvent` readback |
| `clear-non-elevated-denial` | Visible denial; canary unchanged |
| `clear-uac-cancel` | Truthful cancel; canary unchanged |
| `clear-owned-canary-success` | Snapshot and explicit approval; only owned canary cleared; independent readback and post-clear tail recovery pass |

Never clear Application, System, Security, Setup, remote, production, or customer logs.

## Installed application and artifact readback

The automatic artifact evidence contains the NSIS package hash/bytes and provenance-derived expected installed executable hash/bytes. Do not use the top-level standalone executable hash as the installed NSIS expectation.

Before installer execution, privately bind the exact raw NSIS file to returned evidence:

```powershell
$ArtifactEvidence = Get-Content -LiteralPath (Join-Path $Evidence 'artifacts.json') -Raw | ConvertFrom-Json
$ProvenanceRecords = @($ArtifactEvidence.items | Where-Object { $_.kind -ceq 'windows-build-provenance' })
$NsisRecords = @($ArtifactEvidence.items | Where-Object { $_.kind -ceq 'nsis-installer' })
if ($ProvenanceRecords.Count -ne 1 -or $NsisRecords.Count -ne 1) {
  throw 'Expected unique provenance and NSIS artifact records.'
}
$Provenance = $ProvenanceRecords[0]
$NsisSummary = $NsisRecords[0]
$SelectedInstallers = @($Provenance.installers | Where-Object { $_.bundleType -ceq 'nsis' })
if ($SelectedInstallers.Count -ne 1) { throw 'Expected one NSIS provenance record.' }
$SelectedInstaller = $SelectedInstallers[0]
$PrivateNsis = Join-Path $Evidence 'raw-artifacts\nsis\cmtrace-open-setup.exe'
$PrivateNsisEntry = Get-Item -LiteralPath $PrivateNsis -Force
if ($PrivateNsisEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
  throw 'Private NSIS file cannot be a reparse point.'
}

$PrivateNsisSha256 = (Get-FileHash -LiteralPath $PrivateNsis -Algorithm SHA256).Hash.ToLowerInvariant()
if ($PrivateNsisSha256 -cne $NsisSummary.sha256 -or $PrivateNsisSha256 -cne $SelectedInstaller.sha256) {
  throw 'Private NSIS file hash mismatch.'
}
if ($PrivateNsisEntry.Length -ne [int64]$NsisSummary.bytes -or $PrivateNsisEntry.Length -ne [int64]$SelectedInstaller.bytes) {
  throw 'Private NSIS size mismatch.'
}
```

Use the current-user branch of the sealed `installMode: both` package for this clean lifecycle. A per-machine lane is a separate approved observation; do not let installer auto-selection decide the scope. The exact source installer hook accepts `/DisableUpdateChecks` and writes a DWORD policy for the selected scope. On this fresh snapshot the HKCU value and every `cmtrace-open` process must be absent before install. Initialize the lifecycle state and baseline before requesting installer approval:

```powershell
$UpdatePolicyPath = 'HKCU:\Software\CMTrace Open'
$NsisLifecycleFailures = [Collections.Generic.List[string]]::new()
$NsisLifecycleReady = $true
$NsisInstallAttempted = $false
$InstalledExecutableVerified = $false
$UnexpectedInstalledProcessObserved = $false
$DefaultAppsBefore = $null
$DefaultAppRestorationMatched = $false
$DefaultAppsApproved = $false
$UninstallApproved = $false
function Test-PrivateRegistryValue {
  param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
  if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) { return $false }
  $Key = Get-Item -LiteralPath $Path -ErrorAction Stop
  foreach ($ValueName in $Key.GetValueNames()) {
    if ([string]::Equals($ValueName, $Name, [StringComparison]::OrdinalIgnoreCase)) { return $true }
  }
  return $false
}
$StartMenuShortcut = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\CMTrace Open.lnk'
$DesktopShortcut = Join-Path ([Environment]::GetFolderPath('Desktop')) 'CMTrace Open.lnk'
$ExpectedInstallDirectory = Join-Path $env:LOCALAPPDATA 'Programs\CMTrace Open'
$ExpectedInstalledPath = Join-Path $ExpectedInstallDirectory 'cmtrace-open.exe'
$ArpPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\CMTrace Open'

function Get-PrivateDefaultAppChoices {
  $Choices = [ordered]@{}
  foreach ($Extension in @('.log', '.log_', '.lo_', '.cmtlog')) {
    $UserChoicePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
    if (-not (Test-Path -LiteralPath $UserChoicePath -ErrorAction Stop) -or
        -not (Test-PrivateRegistryValue -Path $UserChoicePath -Name 'ProgId')) {
      $Choices[$Extension] = [pscustomobject][ordered]@{ present = $false; progId = $null }
    }
    else {
      $Choices[$Extension] = [pscustomobject][ordered]@{
        present = $true
        progId = [string](Get-ItemPropertyValue -LiteralPath $UserChoicePath -Name ProgId -ErrorAction Stop)
      }
    }
  }
  return $Choices
}
function Test-PrivateDefaultAppChoiceEqual {
  param([Parameter(Mandatory)][object]$Expected, [Parameter(Mandatory)][object]$Actual)
  if ($Expected.present -isnot [bool] -or $Actual.present -isnot [bool]) {
    throw 'Default-app choice snapshot has an invalid presence discriminator.'
  }
  if ($Expected.present -ne $Actual.present) { return $false }
  if (-not $Expected.present) { return $true }
  return [string]::Equals([string]$Expected.progId, [string]$Actual.progId, [StringComparison]::OrdinalIgnoreCase)
}
function Get-PrivateRegularFileInventory {
  param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$Label
  )

  $ResolvedRoot = (Resolve-Path -LiteralPath $Root).Path
  $RootEntry = Get-Item -LiteralPath $ResolvedRoot -Force
  if (-not $RootEntry.PSIsContainer -or ($RootEntry.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw "$Label must be a regular, non-reparse directory."
  }
  $VolumeRoot = [IO.Path]::GetPathRoot($RootEntry.FullName)
  $Volume = Get-Volume -DriveLetter $VolumeRoot.Substring(0, 1) -ErrorAction Stop
  if ($Volume.DriveType -ne 'Fixed' -or $Volume.FileSystem -ne 'NTFS') {
    throw "$Label must be on fixed NTFS."
  }
  $Cursor = $RootEntry.FullName
  while (-not [string]::IsNullOrWhiteSpace($Cursor)) {
    $CursorEntry = Get-Item -LiteralPath $Cursor -Force
    if ($CursorEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
      throw "$Label cannot traverse a reparse point."
    }
    if ($Cursor -eq $VolumeRoot.TrimEnd([IO.Path]::DirectorySeparatorChar)) { break }
    $Parent = Split-Path -Parent $Cursor
    if ([string]::IsNullOrWhiteSpace($Parent) -or $Parent -eq $Cursor) { break }
    $Cursor = $Parent
  }

  $Prefix = $RootEntry.FullName.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
  $Inventory = @()
  foreach ($Entry in Get-ChildItem -LiteralPath $RootEntry.FullName -Recurse -Force) {
    if ($Entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
      throw "$Label contains a reparse entry."
    }
    if ($Entry.PSIsContainer) { continue }
    $RelativePath = $Entry.FullName.Substring($Prefix.Length).Replace([IO.Path]::DirectorySeparatorChar, [char]'/')
    $Inventory += [pscustomobject]@{
      relativePath = $RelativePath
      bytes = [int64]$Entry.Length
      sha256 = (Get-FileHash -LiteralPath $Entry.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
  }
  return @($Inventory | Sort-Object -Property relativePath -CaseSensitive)
}
try {
  $UpdatePolicyKeyExisted = Test-Path -LiteralPath $UpdatePolicyPath -ErrorAction Stop
  if (Test-PrivateRegistryValue -Path $UpdatePolicyPath -Name 'DisableUpdateChecks') {
    throw 'Fresh-snapshot lane requires the HKCU DisableUpdateChecks value to be absent.'
  }
  if (Test-Path -LiteralPath $StartMenuShortcut -PathType Any) { throw 'Fresh lane already has the owned start-menu shortcut.' }
  if (Test-Path -LiteralPath $DesktopShortcut -PathType Any) { throw 'Fresh lane already has the owned desktop shortcut.' }
  if (Test-Path -LiteralPath $ExpectedInstallDirectory -PathType Any) { throw 'Fresh lane already has the owned install directory.' }
  if (Test-Path -LiteralPath $ArpPath) { throw 'Fresh lane already has the owned Add/Remove Programs record.' }
  if (@(Get-Process -Name 'cmtrace-open' -ErrorAction SilentlyContinue).Count -ne 0) {
    throw 'A CMTrace Open process exists before install. Do not stop it.'
  }
  $DefaultAppsBefore = Get-PrivateDefaultAppChoices
}
catch {
  $NsisLifecycleFailures.Add($_.Exception.Message)
  $NsisLifecycleReady = $false
}
```

If `$NsisLifecycleReady` is false, do not execute the installer and do not stop any unexpected process. Create unique proofs for the blocked installed-lifecycle gates, finish any remaining safe non-installed gates, seal and transport the privacy-bounded return, and obtain acceptance. Only then request separate approval to revert the disposable snapshot.

After installer approval, run the exact hash-bound installer with a 15-minute owned-process timeout. On its final page, explicitly clear `Run CMTrace Open` before selecting Finish. If the option cannot be confirmed unchecked, cancel the installer. After the command returns, the prompt accepts the fixed phrase only when the option was visibly unchecked; enter any other text after a cancellation or uncertain observation. Any cancellation, exception, nonzero exit, unexpected launched process, policy-readback error, or missing shortcut records a target-private lifecycle failure and blocks dependent installed observations. It never authorizes killing a process or reverting before the return is accepted:

```powershell
if (-not $NsisLifecycleReady) { throw 'The fresh-snapshot baseline failed; do not execute the installer.' }
$InstallResult = $null
$NsisInstallAttempted = $true
try {
  # On the interactive finish page, clear "Run CMTrace Open" before selecting Finish.
  $InstallResult = Invoke-PrivateProcess -Id 'nsis-current-user-install' `
    -FilePath $PrivateNsis -ExpectedSha256 $PrivateNsisSha256 -ExpectedBytes $PrivateNsisEntry.Length `
    -WorkingDirectory $Handoff -TimeoutMinutes 15 `
    -ArgumentList @('/CurrentUser', '/DisableUpdateChecks')
}
catch {
  $NsisLifecycleFailures.Add($_.Exception.Message)
  $NsisLifecycleReady = $false
}
$RunOptionConfirmation = Read-Host 'Type RUN-OPTION-UNCHECKED only if that option was visibly unchecked before Finish'
$RunOptionConfirmedUnchecked = [string]::Equals($RunOptionConfirmation, 'RUN-OPTION-UNCHECKED', [StringComparison]::Ordinal)
if (-not $RunOptionConfirmedUnchecked) {
  $NsisLifecycleFailures.Add('Run CMTrace Open was not directly confirmed unchecked before installer completion.')
  $NsisLifecycleReady = $false
}
if ($null -eq $InstallResult -or $InstallResult.ExitCode -ne 0) {
  $NsisLifecycleFailures.Add('The approved current-user installer did not return a trustworthy zero exit code.')
  $NsisLifecycleReady = $false
}
if (@(Get-Process -Name 'cmtrace-open' -ErrorAction SilentlyContinue).Count -ne 0) {
  $UnexpectedInstalledProcessObserved = $true
  $NsisLifecycleFailures.Add('The installer launched CMTrace Open before independent policy readback. The process was not stopped.')
  $NsisLifecycleReady = $false
}
$InstalledProviderContentBindings = @()
if ($NsisLifecycleReady) {
  try {
    $PolicyValue = Get-ItemPropertyValue -LiteralPath $UpdatePolicyPath -Name DisableUpdateChecks -ErrorAction Stop
    if ([int64]$PolicyValue -ne 1) { throw 'Installed and shell-launched update isolation policy was not established.' }
    if (-not (Test-Path -LiteralPath $StartMenuShortcut -PathType Leaf)) {
      throw 'Current-user install did not create the expected owned start-menu shortcut.'
    }
  }
  catch {
    $NsisLifecycleFailures.Add($_.Exception.Message)
    $NsisLifecycleReady = $false
  }
}

if ($NsisLifecycleReady) { 'NSIS_POST_INSTALL_ISOLATION_READY' } else { 'NSIS_POST_INSTALL_ISOLATION_FAILED' }
```

Keep that value in place for every installed launch, including Explorer/Default Apps activation that cannot inherit the calling PowerShell process environment. In the target-private `nsis-clean-install` proof, record that `Run CMTrace Open` was visibly unchecked, no `cmtrace-open` process existed immediately before policy readback, and the independently read HKCU DWORD equaled `1`. Then locate the installed Full executable privately and require:

```powershell
if ($NsisLifecycleReady) {
  try {
    if (-not (Test-Path -LiteralPath $ExpectedInstalledPath -PathType Leaf)) {
      throw 'The /CurrentUser payload is absent from the exact User Program Files location.'
    }
    $InstalledExe = (Resolve-Path -LiteralPath $ExpectedInstalledPath).Path
    $InstalledEntry = Get-Item -LiteralPath $InstalledExe -Force
    if ($InstalledEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
      throw 'Installed executable cannot be a reparse point.'
    }

    $Expected = $SelectedInstaller.expectedInstalledExecutable
    $Installed = $InstalledEntry
    if ($Installed.Length -ne [int64]$Expected.bytes) { throw 'Installed size mismatch.' }
    if ((Get-FileHash -LiteralPath $InstalledExe -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Expected.sha256) {
      throw 'Installed hash mismatch.'
    }
    $ArpRecord = Get-ItemProperty -LiteralPath $ArpPath -ErrorAction Stop
    if ([string]$ArpRecord.DisplayName -cne 'CMTrace Open' -or [string]$ArpRecord.DisplayVersion -cne '1.5.1') {
      throw 'Current-user Add/Remove Programs identity or version is wrong.'
    }
    $ArpInstallLocation = ([string]$ArpRecord.InstallLocation).Trim('"')
    if (-not [string]::Equals(
        (Resolve-Path -LiteralPath $ArpInstallLocation).Path,
        (Resolve-Path -LiteralPath $ExpectedInstallDirectory).Path,
        [StringComparison]::OrdinalIgnoreCase)) {
      throw 'Add/Remove Programs install location does not bind to the verified payload.'
    }

    $PeStream = $null
    $PeReader = $null
    try {
      $PeStream = [IO.File]::Open($InstalledExe, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
      $PeReader = [IO.BinaryReader]::new($PeStream)
      if ($PeReader.ReadUInt16() -ne 0x5A4D) { throw 'Installed executable has no MZ header.' }
      $PeStream.Position = 0x3C
      $PeOffset = $PeReader.ReadInt32()
      if ($PeOffset -lt 64 -or $PeOffset -gt ($PeStream.Length - 6)) { throw 'Installed PE offset is invalid.' }
      $PeStream.Position = $PeOffset
      if ($PeReader.ReadUInt32() -ne 0x00004550) { throw 'Installed executable has no PE signature.' }
      if ($PeReader.ReadUInt16() -ne 0xAA64) { throw 'Installed executable is not ARM64.' }
    }
    finally {
      if ($null -ne $PeReader) { $PeReader.Dispose() }
      elseif ($null -ne $PeStream) { $PeStream.Dispose() }
    }
    $InstalledExecutableVerified = $true

    $SourceProviderDirectory = Join-Path $Source 'src-tauri\resources\provider-db'
    $InstalledProviderDirectory = Join-Path $ExpectedInstallDirectory 'provider-db'
    $SourceProviderInventory = @(Get-PrivateRegularFileInventory -Root $SourceProviderDirectory -Label 'Exact-source provider-db')
    $InstalledProviderInventory = @(Get-PrivateRegularFileInventory -Root $InstalledProviderDirectory -Label 'Installed provider-db')

    $RequiredProviderFiles = @(
      'provider-manifest.json',
      'cmtraceopen-provider-windows-20348.db',
      'cmtraceopen-provider-windows-26200.db'
    )
    if ($SourceProviderInventory.Count -eq 0 -or
        @($SourceProviderInventory | Where-Object { $_.relativePath -clike '*.db' }).Count -ne 2 -or
        @($RequiredProviderFiles | Where-Object { $_ -cnotin $SourceProviderInventory.relativePath }).Count -ne 0) {
      throw 'Exact source does not contain the expected manifest and exactly two curated provider databases.'
    }
    if ($InstalledProviderInventory.Count -ne $SourceProviderInventory.Count) {
      throw 'Installed provider-db regular-file inventory count differs from exact source.'
    }
    for ($Index = 0; $Index -lt $SourceProviderInventory.Count; $Index++) {
      $SourceResource = $SourceProviderInventory[$Index]
      $InstalledResource = $InstalledProviderInventory[$Index]
      if ($InstalledResource.relativePath -cne $SourceResource.relativePath -or
          $InstalledResource.bytes -ne $SourceResource.bytes -or
          $InstalledResource.sha256 -cne $SourceResource.sha256) {
        throw "Installed provider-db resource differs from exact source at inventory index $Index."
      }
    }
    $InstalledProviderContentBindings = @(
      foreach ($InstalledResource in $InstalledProviderInventory) {
        [pscustomobject][ordered]@{
          Path = Join-Path $InstalledProviderDirectory $InstalledResource.relativePath
          Sha256 = $InstalledResource.sha256
          Bytes = [int64]$InstalledResource.bytes
          Label = "Installed provider resource $($InstalledResource.relativePath)"
        }
      }
    )

    $ProviderResourceInventoryProofLines = @(
      "nsisSha256=$PrivateNsisSha256"
      "installedExecutableSha256=$($Expected.sha256)"
      "providerResourceFileCount=$($SourceProviderInventory.Count)"
      for ($Index = 0; $Index -lt $SourceProviderInventory.Count; $Index++) {
        $SourceResource = $SourceProviderInventory[$Index]
        $InstalledResource = $InstalledProviderInventory[$Index]
        "sourceResource=$($SourceResource.relativePath);bytes=$($SourceResource.bytes);sha256=$($SourceResource.sha256)"
        "installedResource=$($InstalledResource.relativePath);bytes=$($InstalledResource.bytes);sha256=$($InstalledResource.sha256)"
      }
    )
  }
  catch {
    $NsisLifecycleFailures.Add($_.Exception.Message)
    $NsisLifecycleReady = $false
  }
}
```

The next command blocks until the installed Full process exits. While it is open, observe the packaged-provider load outcome plus one covered and one uncovered description, then close it cleanly so the command can return:

```powershell
if ($NsisLifecycleReady) {
  try {
    $ProviderResourceResult = Invoke-PrivateProcess -Id 'installed-provider-packaged-resource' `
      -FilePath $InstalledExe -ExpectedSha256 $Expected.sha256 -ExpectedBytes $Expected.bytes `
      -ContentBindings $InstalledProviderContentBindings -ArgumentList @() `
      -WorkingDirectory $ExpectedInstallDirectory -TimeoutMinutes 30
    if ($ProviderResourceResult.ExitCode -ne 0) { throw 'Installed provider-resource observation launch failed.' }
  }
  catch {
    $NsisLifecycleFailures.Add($_.Exception.Message)
    $NsisLifecycleReady = $false
  }
}
```

Replace the placeholder with that actual target-private observation before running the proof block:

```powershell
$ProviderResourceObservation = '<replace with actual installed manifest/two-database load and covered/uncovered description observation>'
if ($NsisLifecycleReady) {
  try {
    if ($ProviderResourceObservation.StartsWith('<')) {
      throw 'Record the actual installed provider-resource observation before creating proof.'
    }
    $ProviderResourceProof = Save-PrivateManualProof -EvidenceId 'provider-packaged-resource-001' `
      -Lines @(
        'gate=provider-packaged-resource'
        "executedAtUtc=$((Get-Date).ToUniversalTime().ToString('o'))"
        $ProviderResourceInventoryProofLines
        "nativeObservation=$ProviderResourceObservation"
      )
  }
  catch {
    $NsisLifecycleFailures.Add($_.Exception.Message)
    $NsisLifecycleReady = $false
  }
}
# Use $PrivateNsisSha256 as artifactSha256 and copy only the two $ProviderResourceProof binding fields into this gate's JSON row.
```

Stop and obtain separate human approval before changing any file association or default-app choice. After that decision, run this approval-recording block. Only the exact fixed phrase records approval; an empty or different response records `APPROVAL_NOT_GRANTED`, blocks this gate, and authorizes no Default Apps action:

```powershell
if ($NsisLifecycleReady) {
  $DefaultAppsApprovalToken = Read-Host 'Type APPROVE-DEFAULT-APPS only after separate human approval; otherwise press Enter'
  $DefaultAppsApproved = [string]::Equals(
    $DefaultAppsApprovalToken,
    'APPROVE-DEFAULT-APPS',
    [StringComparison]::Ordinal)
  if (-not $DefaultAppsApproved) {
    $NsisLifecycleFailures.Add('APPROVAL_NOT_GRANTED: default-apps-file-associations was not authorized and no Default Apps action was performed.')
    $NsisLifecycleReady = $false
  }
}
```

Only when both `$DefaultAppsApproved` and `$NsisLifecycleReady` are true, privately exercise `.log`, `.log_`, `.lo_`, and `.cmtlog` through Explorer while the policy readback is `1`, restore the pre-install choices through Windows Settings, and independently read back each choice before uninstall:

```powershell
if ($DefaultAppsApproved -and $NsisLifecycleReady) {
  try {
    $DefaultAppsExerciseToken = Read-Host 'Type DEFAULT-APPS-EXERCISED-AND-RESTORED only after all four Explorer actions and Windows Settings restorations are complete'
    if (-not [string]::Equals(
        $DefaultAppsExerciseToken,
        'DEFAULT-APPS-EXERCISED-AND-RESTORED',
        [StringComparison]::Ordinal)) {
      throw 'Default Apps activation and restoration were not directly confirmed; no restoration readback was accepted.'
    }
    $DefaultAppsRestoredBeforeUninstall = Get-PrivateDefaultAppChoices
    $DefaultAppRestorationMatched = $true
    foreach ($Extension in $DefaultAppsBefore.Keys) {
      if (-not (Test-PrivateDefaultAppChoiceEqual -Expected $DefaultAppsBefore[$Extension] `
          -Actual $DefaultAppsRestoredBeforeUninstall[$Extension])) {
        $DefaultAppRestorationMatched = $false
      }
    }
  }
  catch {
    $NsisLifecycleFailures.Add($_.Exception.Message)
    $NsisLifecycleReady = $false
  }
}
```

Record only the bounded `restorationMatched` boolean in the target-private proof. If it is false, mark `default-apps-file-associations` `BLOCKED` and continue the ordinary uninstall and policy cleanup below. Do not turn the anticipated Windows restoration limitation into a cleanup-stopping exception. Any `$NsisLifecycleFailures` similarly block the affected and dependent installed gates: retain unique proof anchors, run only the safe cleanup path below, finish other safe gates, create and transport the return, obtain acceptance, and only then request approval to revert.

Stop and obtain separate human approval before uninstall. After that decision, run this approval-recording block. Only the exact fixed phrase records approval; an empty or different response leaves the installed files in place for later approved snapshot reversion:

```powershell
if ($NsisInstallAttempted) {
  $UninstallApprovalToken = Read-Host 'Type APPROVE-UNINSTALL only after separate human approval; otherwise press Enter'
  $UninstallApproved = [string]::Equals(
    $UninstallApprovalToken,
    'APPROVE-UNINSTALL',
    [StringComparison]::Ordinal)
}
```

After every attempted install, run this cleanup block even when an earlier installed validation failed or uninstall approval was not granted. It invokes only the uninstaller beside an independently verified executable, only when `$UninstallApproved` is true, and only when no unexpected `cmtrace-open` process is active. Otherwise it preserves the installed state for the later approved snapshot revert. It always attempts policy restoration when no unexpected process remains, records every cleanup problem target-privately, and deliberately does not throw at the end so failure evidence can still be sealed and accepted:

```powershell
$InstallDirectory = $ExpectedInstallDirectory
$Uninstaller = Join-Path $InstallDirectory 'uninstall.exe'
$CleanupFailures = [Collections.Generic.List[string]]::new()
if ($NsisInstallAttempted) {
  try {
    $ActiveInstalledProcesses = @(Get-Process -Name 'cmtrace-open' -ErrorAction SilentlyContinue)
    if (-not $UninstallApproved) {
      $CleanupFailures.Add('APPROVAL_NOT_GRANTED: ordinary uninstall was not authorized and was not run.')
    }
    elseif ($UnexpectedInstalledProcessObserved -or $ActiveInstalledProcesses.Count -ne 0) {
      $CleanupFailures.Add('Ordinary uninstall was not run because an unexpected CMTrace Open process remains; it was not stopped.')
    }
    elseif (-not $InstalledExecutableVerified) {
      $CleanupFailures.Add('Ordinary uninstall was not run because the installed executable was not independently verified.')
    }
    elseif (-not (Test-Path -LiteralPath $ArpPath)) {
      $CleanupFailures.Add('Current-user Add/Remove Programs record is missing before uninstall.')
    }
    elseif (-not (Test-Path -LiteralPath $Uninstaller -PathType Leaf)) {
      $CleanupFailures.Add('Installed uninstaller is missing before uninstall.')
    }
    else {
      $UninstallerEntry = Get-Item -LiteralPath $Uninstaller -Force
      if ($UninstallerEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        $CleanupFailures.Add('Installed uninstaller cannot be a reparse point.')
      }
      else {
        $UninstallResult = $null
        $UninstallResult = Invoke-PrivateProcess -Id 'nsis-current-user-uninstall' `
          -FilePath $Uninstaller -WorkingDirectory $Handoff -TimeoutMinutes 15 `
          -ArgumentList @('/CurrentUser')
        if ($UninstallResult.ExitCode -ne 0) {
          $CleanupFailures.Add("NSIS current-user uninstall exited with code $($UninstallResult.ExitCode).")
        }
      }
    }

    $RemainingArtifactCounts = [ordered]@{
      installDirectory = [int](Test-Path -LiteralPath $InstallDirectory -PathType Any)
      arpRecord = [int](Test-Path -LiteralPath $ArpPath -PathType Any)
      startMenuShortcut = [int](Test-Path -LiteralPath $StartMenuShortcut -PathType Any)
      desktopShortcut = [int](Test-Path -LiteralPath $DesktopShortcut -PathType Any)
    }
    $RemainingArtifactGroups = @($RemainingArtifactCounts.GetEnumerator() | Where-Object Value -gt 0 | ForEach-Object {
      "$($_.Key)=$($_.Value)"
    })
    if ($RemainingArtifactGroups.Count -gt 0) {
      $CleanupFailures.Add("Owned Full artifacts remain after ordinary uninstall by kind and count: $($RemainingArtifactGroups -join ', ').")
    }

    if (Test-PrivateRegistryValue -Path 'HKCU:\Software\RegisteredApplications' -Name 'CMTrace Open') {
      $CleanupFailures.Add('CMTrace Open remains registered as an available application after uninstall.')
    }
    if (@(@('HKCU:\Software\CMTraceOpen\Capabilities', 'HKCU:\Software\Classes\CMTraceOpen.LogFile') | Where-Object {
        Test-Path -LiteralPath $_
      }).Count -gt 0) {
      $CleanupFailures.Add('A Full runtime file-association key remains after uninstall.')
    }
    foreach ($Extension in @('.log', '.log_', '.lo_', '.cmtlog')) {
      $OpenWithPath = "HKCU:\Software\Classes\$Extension\OpenWithProgids"
      if (Test-PrivateRegistryValue -Path $OpenWithPath -Name 'CMTraceOpen.LogFile') {
        $CleanupFailures.Add("The Full runtime ProgID remains attached to $Extension after uninstall.")
      }
    }

    if ($null -ne $DefaultAppsBefore) {
      $DefaultAppsAfter = Get-PrivateDefaultAppChoices
      $DefaultAppsRemainRestored = $true
      foreach ($Extension in $DefaultAppsBefore.Keys) {
        if (-not (Test-PrivateDefaultAppChoiceEqual -Expected $DefaultAppsBefore[$Extension] -Actual $DefaultAppsAfter[$Extension])) {
          $DefaultAppsRemainRestored = $false
        }
      }
      if ($DefaultAppRestorationMatched -and -not $DefaultAppsRemainRestored) {
        $CleanupFailures.Add('Ordinary uninstall disturbed default-app choices that had been restored successfully.')
      }
    }
  }
  catch {
    $CleanupFailures.Add($_.Exception.Message)
  }
  finally {
    try {
      if (@(Get-Process -Name 'cmtrace-open' -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'Update-policy restoration was deferred because an unexpected CMTrace Open process remains active.'
      }
      if (Test-PrivateRegistryValue -Path $UpdatePolicyPath -Name 'DisableUpdateChecks') {
        Remove-ItemProperty -LiteralPath $UpdatePolicyPath -Name DisableUpdateChecks -ErrorAction Stop
      }
      if (Test-PrivateRegistryValue -Path $UpdatePolicyPath -Name 'DisableUpdateChecks') {
        throw 'Handoff-owned update policy was not removed.'
      }
      if (-not $UpdatePolicyKeyExisted -and (Test-Path -LiteralPath $UpdatePolicyPath)) {
        $CreatedPolicyKey = Get-Item -LiteralPath $UpdatePolicyPath
        if ($CreatedPolicyKey.GetValueNames().Count -ne 0 -or @(Get-ChildItem -LiteralPath $UpdatePolicyPath).Count -ne 0) {
          throw 'The handoff-created policy key contains unexpected state and cannot be removed safely.'
        }
        Remove-Item -LiteralPath $UpdatePolicyPath
      }
      if ((Test-Path -LiteralPath $UpdatePolicyPath) -ne $UpdatePolicyKeyExisted) {
        throw 'The update-policy key existence state was not restored exactly.'
      }
    }
    catch {
      $CleanupFailures.Add($_.Exception.Message)
    }
  }
  foreach ($Failure in $CleanupFailures) {
    $NsisLifecycleFailures.Add($Failure)
  }
}

if ($NsisLifecycleFailures.Count -eq 0) { 'NSIS_LIFECYCLE_COMPLETE' } else { "NSIS_LIFECYCLE_INCOMPLETE failureCount=$($NsisLifecycleFailures.Count)" }
```

| Gate | Pass boundary |
|---|---|
| `nsis-clean-install` | Snapshot/approval; exact `nsis-installer` hash executes via `/CurrentUser /DisableUpdateChecks`, exits 0, and version 1.5.1 installs |
| `nsis-installed-arm64-payload` | Installed file is `0xAA64` and matches provenance-derived bytes/hash |
| `default-apps-file-associations` | Activation and `.log`, `.log_`, `.lo_`, `.cmtlog` open installed app; before/after state restored |
| `nsis-uninstall-cleanup` | Ordinary uninstall removes the one emitted Full package's owned files and Full stable identity; it does not claim removal of the separately portable Lite edition or unrelated choices |
| `elevation-same-account` | Approved owned action succeeds with bounded status |
| `elevation-over-the-shoulder` | Initiating context remains truthful without returned identity data |
| `genuine-upgrade-lifecycle` | Older authorized ARM64 install upgrades to exact-head ARM64 with owned state preserved; reinstalling 1.5.1 is not proof |
| `production-signing-and-msi-boundary` | Never PASS from local unsigned output; protected Azure signing/mpdev MSI remain separate and no workflow is dispatched |

## Export, timeline, markers, interaction, and accessibility

| Gate | Pass boundary |
|---|---|
| `exports-and-cli-gui-equivalence` | CSV/TSV/JSON/XML/HTML/raw XML, redaction, formula defense, parseability, atomic replace, unwritable/empty/large streaming, CLI/GUI counts |
| `marker-persistence-source-isolation` | Tag/Bookmark buttons and T/B shortcuts persist across reorder/filter/group/refetch/restart and isolate equal record IDs by source |
| `eventlog-layered-filtering` | Before-load, on-load, quick-filter, and grouping stages compose without widening/drop |
| `eventlog-six-quick-filter-modes` | oneString, multipleWords, multipleStrings, allWords, allStrings, eventIds; all/visible scope; show/hide; case; ranges; highlight; invalid input |
| `eventlog-nested-grouping-keyboard` | Child counts sum to parent; no loss; grid/tree roles/counts and Arrow/Home/End/Enter/Space/focus/hidden selection pass |
| `eventlog-saved-filter-persistence` | Full staged state survives restart; case-insensitive re-save updates instead of duplicates |
| `eventlog-filter-library-advanced-surface` | Known exact-head gap; cannot PASS |
| `eventlog-grouping-drag-pivot-surface` | Known exact-head gap; cannot PASS |
| `eventlog-highlight-accessibility-precedence` | Match text/mark/Narrator/toggle and selected > marker > severity > match > default precedence; not color-only |
| `eventlog-filter-rule-color-surface` | Known exact-head gap; cannot PASS |
| `eventlog-columns-time-font` | Visibility/reorder/width/reset, UTC/local/day grouping, min/max sizes align and persist |
| `accessibility-interaction` | Keyboard, focus, Narrator, high contrast, 100/200%, min size, resize, touch, reduced motion, no color-only state |

The `unified-timeline-provenance` acceptance boundary is defined once under **Live subscription, polling, and source composition** above; use that authoritative chronology-and-provenance gate for this section.

## Performance and competitor evidence

No numeric performance threshold exists at this SHA. PASS means complete truthful measurement on fixed evidence plus no crash/hang; it does not authorize a relative performance claim.

`machine.json` supplies bounded host profile. For the native seven-day backend harness:

```powershell
$PrivateScanRoot = Join-Path $Evidence 'raw-artifacts\private-evtx-scan'
$PrivateScanRoot = Assert-CMTraceFixedLocalNtfsPath -Path $PrivateScanRoot `
  -Label 'Private evtx_scan build root' -ForbiddenRoots @($Handoff, $Source) -MustNotExist
$PrivateScanRoot = Assert-CMTracePathWithinRoot -Path $PrivateScanRoot `
  -Root (Join-Path $Evidence 'raw-artifacts') -Label 'Private evtx_scan build root'
[void](Assert-CMTraceNoReparseAncestor -Path $PrivateScanRoot -Label 'Private evtx_scan build root')
New-Item -ItemType Directory -Path $PrivateScanRoot -ErrorAction Stop | Out-Null
[void](Assert-CMTraceNoReparseAncestor -Path $PrivateScanRoot -Label 'Private evtx_scan build root')

$ScanTargetDir = Join-Path $PrivateScanRoot 'cargo-target'
if (Test-Path -LiteralPath $ScanTargetDir -PathType Any) {
  throw 'Private evtx_scan target directory already exists; use a new evidence root.'
}
New-Item -ItemType Directory -Path $ScanTargetDir -ErrorAction Stop | Out-Null
[void](Assert-CMTraceNoReparseAncestor -Path $ScanTargetDir -Label 'Private evtx_scan target directory')
if (@(Get-ChildItem -LiteralPath $ScanTargetDir -Force).Count -ne 0) {
  throw 'Private evtx_scan target directory was not created empty.'
}

[void](Assert-CMTraceSourceIntegrity -RepositoryPath $Source)
$ScanBuild = Invoke-PrivateProcess -Id 'evtx-scan-build' `
  -FilePath (Get-Command cargo.exe).Source -WorkingDirectory $Source -TimeoutMinutes 60 `
  -ArgumentList @('build', '--locked', '--release', '--target', $Target, '--target-dir', $ScanTargetDir, '--manifest-path', 'src-tauri\Cargo.toml', '--example', 'evtx_scan', '--features', 'event-log')
if ($ScanBuild.ExitCode -ne 0) { throw 'evtx_scan build failed.' }
[void](Assert-CMTraceSourceIntegrity -RepositoryPath $Source)
$ScanPath = Join-Path $ScanTargetDir 'aarch64-pc-windows-msvc\release\examples\evtx_scan.exe'
$PrivateEvtxScan = Get-CMTraceVerifiedArm64Executable -Path $ScanPath -Root $PrivateScanRoot
```

The new private Cargo target directory is never reused. Run and parse three target-private samples, rebinding the native ARM64 executable immediately before each launch. Raw output exposes channel names and stays under `raw-artifacts/private-command-output`; never print it to the shared terminal:

```powershell
function Get-PrivateMedianInt64 {
  param([Parameter(Mandatory)][int64[]]$Values)
  if ($Values.Count -ne 3) { throw 'Exactly three values are required for this median.' }
  return [int64](@($Values | Sort-Object)[1])
}

$SevenDayRuns = @()
for ($Run = 1; $Run -le 3; $Run++) {
  $ScanBinding = Get-CMTraceVerifiedArm64Executable -Path $PrivateEvtxScan.Path -Root $PrivateScanRoot `
    -ExpectedSha256 $PrivateEvtxScan.Sha256 -ExpectedBytes $PrivateEvtxScan.Bytes
  $Result = Invoke-PrivateProcess -Id "evtx-scan-seven-day-$Run" `
    -FilePath $ScanBinding.Path -ExpectedSha256 $ScanBinding.Sha256 -ExpectedBytes $ScanBinding.Bytes `
    -WorkingDirectory $Source -TimeoutMinutes 30 `
    -ArgumentList @('--days', '7')
  if ($Result.ExitCode -ne 0 -or $Result.PeakWorkingSetBytes -le 0) {
    throw "Seven-day scan $Run failed or lacks a positive process-tree peak."
  }

  $Values = @{}
  foreach ($Line in Get-Content -LiteralPath $Result.StdoutPath) {
    if ($Line -cmatch '^(days|channels_scanned|channels_failed|channels_with_gaps|gap_entries|events|enumerate_ms|scan_ms)=([0-9]+)$') {
      if ($Values.ContainsKey($Matches[1])) { throw "Duplicate seven-day field: $($Matches[1])" }
      $Values[$Matches[1]] = [int64]$Matches[2]
    }
    elseif ($Line -cmatch '^per_event_us=([0-9]+(?:\.[0-9]+)?)$') {
      if ($Values.ContainsKey('per_event_us')) { throw 'Duplicate seven-day field: per_event_us' }
      $Values['per_event_us'] = [decimal]$Matches[1]
    }
  }
  $Required = @('days', 'channels_scanned', 'channels_failed', 'channels_with_gaps', 'gap_entries', 'events', 'enumerate_ms', 'scan_ms', 'per_event_us')
  if (@($Required | Where-Object { -not $Values.ContainsKey($_) }).Count -ne 0) {
    throw "Seven-day scan $Run omitted a required bounded field."
  }
  if ($Values.days -ne 7 -or $Values.channels_scanned -le 0 -or $Values.events -le 0 -or
      $Values.scan_ms -le 0 -or $Values.per_event_us -le 0) {
    throw "Seven-day scan $Run is vacuous or not the exact seven-day scenario."
  }
  $SevenDayRuns += [pscustomobject]@{
    ChannelsScanned = $Values.channels_scanned
    ChannelsFailed = $Values.channels_failed
    ChannelsWithGaps = $Values.channels_with_gaps
    GapEntries = $Values.gap_entries
    ScanMilliseconds = $Values.scan_ms
    RecordCount = $Values.events
    PeakWorkingSetBytes = [int64]$Result.PeakWorkingSetBytes
  }
}

if (@($SevenDayRuns | Where-Object {
      $_.ChannelsFailed -ne 0 -or $_.ChannelsWithGaps -ne 0 -or $_.GapEntries -ne 0
    }).Count -ne 0) {
  throw 'At least one seven-day run contains a channel failure or coverage gap.'
}

$SevenDayMeasurements = [ordered]@{
  sevenDayChannelsScanned = Get-PrivateMedianInt64 @($SevenDayRuns.ChannelsScanned)
  sevenDayChannelsFailed = Get-PrivateMedianInt64 @($SevenDayRuns.ChannelsFailed)
  sevenDayChannelsWithGaps = Get-PrivateMedianInt64 @($SevenDayRuns.ChannelsWithGaps)
  sevenDayGapEntries = Get-PrivateMedianInt64 @($SevenDayRuns.GapEntries)
  sevenDayAllChannelScanMilliseconds = Get-PrivateMedianInt64 @($SevenDayRuns.ScanMilliseconds)
  sevenDayAllChannelRecordCount = Get-PrivateMedianInt64 @($SevenDayRuns.RecordCount)
  sevenDayPeakWorkingSetBytes = Get-PrivateMedianInt64 @($SevenDayRuns.PeakWorkingSetBytes)
}
```

Copy only those seven numeric values into `manual-results.json`. PASS additionally requires every one of the three private runs, not merely each median, to have zero `channels_failed`, `channels_with_gaps`, and `gap_entries`. Retain all three run details and private output hashes together inside the gate's one target-local proof file and return only that one evidence ID/hash binding.

Measure cold Full window launch with three controlled, quiescent runs. This procedure re-reads and rehashes the exact artifact immediately before each launch, starts the clock immediately before releasing the pre-assigned ownership wrapper, requires a visible responsive window within 30 seconds, samples only the requested command/descendant working set, requests an ordinary close, and keeps the two-minute owned-tree deadline active until the Job is empty. It does not clear or reset application/WebView2 profile data between runs, so the result is a cold-process measurement on one frozen profile, not a first-install or first-row claim.

```powershell
$ColdLaunchRuns = @()
$PortableEnvironment = @{ CMTRACEOPEN_DISABLE_UPDATE_CHECKS = '1' }
foreach ($Run in 1..3) {
  if (@(Get-Process -Name 'cmtrace-open' -ErrorAction SilentlyContinue).Count -ne 0) {
    throw "A CMTrace Open process is already running before cold-window run $Run."
  }
  Start-Sleep -Seconds 5
  $FullArtifact = Get-VerifiedPrivateArtifact -Kind 'full-portable'
  $Result = Invoke-PrivateProcess -Id "cold-window-launch-$Run" `
    -FilePath $FullArtifact.Path -WorkingDirectory (Split-Path -Parent $FullArtifact.Path) `
    -ExpectedSha256 $FullArtifact.Sha256 -ExpectedBytes $FullArtifact.Bytes `
    -ArgumentList @() -Environment $PortableEnvironment -TimeoutMinutes 2 -MeasureInputIdle -CloseAfterInputIdle
  if ($Result.ExitCode -ne 0 -or $Result.InputIdleMilliseconds -le 0 -or $Result.PeakWorkingSetBytes -le 0) {
    throw "Cold-window run $Run failed or returned vacuous timing/memory evidence."
  }
  if (@(Get-Process -Name 'cmtrace-open' -ErrorAction SilentlyContinue).Count -ne 0) {
    throw "Cold-window run $Run left a CMTrace Open process behind."
  }
  $ColdLaunchRuns += [pscustomobject]@{
    Milliseconds = [int64]$Result.InputIdleMilliseconds
    PeakWorkingSetBytes = [int64]$Result.PeakWorkingSetBytes
    StdoutSha256 = (Get-FileHash -LiteralPath $Result.StdoutPath -Algorithm SHA256).Hash.ToLowerInvariant()
    StderrSha256 = (Get-FileHash -LiteralPath $Result.StderrPath -Algorithm SHA256).Hash.ToLowerInvariant()
  }
}

$ColdLaunchMeasurements = [ordered]@{
  coldLaunchRun1Milliseconds = $ColdLaunchRuns[0].Milliseconds
  coldLaunchRun2Milliseconds = $ColdLaunchRuns[1].Milliseconds
  coldLaunchRun3Milliseconds = $ColdLaunchRuns[2].Milliseconds
  coldLaunchMilliseconds = Get-PrivateMedianInt64 @($ColdLaunchRuns.Milliseconds)
  coldLaunchRun1PeakWorkingSetBytes = $ColdLaunchRuns[0].PeakWorkingSetBytes
  coldLaunchRun2PeakWorkingSetBytes = $ColdLaunchRuns[1].PeakWorkingSetBytes
  coldLaunchRun3PeakWorkingSetBytes = $ColdLaunchRuns[2].PeakWorkingSetBytes
  coldLaunchPeakWorkingSetBytes = Get-PrivateMedianInt64 @($ColdLaunchRuns.PeakWorkingSetBytes)
}
$ColdLaunchProof = Save-PrivateManualProof -EvidenceId 'performance-cold-window-launch-001' -Lines @(
  foreach ($Index in 0..2) {
    "run$($Index + 1)Milliseconds=$($ColdLaunchRuns[$Index].Milliseconds)"
    "run$($Index + 1)PeakWorkingSetBytes=$($ColdLaunchRuns[$Index].PeakWorkingSetBytes)"
    "run$($Index + 1)StdoutSha256=$($ColdLaunchRuns[$Index].StdoutSha256)"
    "run$($Index + 1)StderrSha256=$($ColdLaunchRuns[$Index].StderrSha256)"
  }
)
```

Copy all eight `$ColdLaunchMeasurements` integers into `manual-results.json` and use the one `$ColdLaunchProof` binding for `performance-cold-window-launch`. First visible row remains a distinct manual target-local visual observation on three separate frozen-source runs: record the three positive integers in `firstRowRun1Milliseconds` through `firstRowRun3Milliseconds`, set `firstRowMilliseconds` to their exact median, and retain all three timestamped observations inside that gate's one proof file. Recordings never return. A 100,000-row gate requires an authorized real corpus, its private hash/count, responsive navigation/filter/grouping, settled time, and peak memory; never generated plausible records.

Intune timing is a composite load measurement on authorized nonzero records; there is no isolated provider timer. Run exactly three frozen-source measurements. Every run must have positive elapsed time, peak working set, and resolved-description count; its missing-description count may be zero. Set `intuneDescriptionResolutionMilliseconds`, `intunePeakWorkingSetBytes`, `intuneDescriptionsResolved`, and `intuneDescriptionsMissing` to the exact median of each corresponding three-value series. Retain all three per-run values and private output hashes in the gate's one target-local proof; only the four medians return.

| Gate | Pass boundary |
|---|---|
| `performance-host-profile` | Machine contract proves build, native architecture, CPU class/count, memory, fixed NTFS, no identity fields |
| `performance-cold-window-launch` | Three run values + median + peak process-tree working set; distinct from first row |
| `performance-cold-first-visible-row` | Three manually observed first-row values + median; private visual proof |
| `performance-all-channels-seven-day` | Three complete no-cap harness runs; bounded counts/timing/gaps plus positive `sevenDayPeakWorkingSetBytes`; no omission/timeout |
| `performance-100k-render` | Authorized `renderRecordCount >= 100000`; responsive render/interaction and bounded timing/peak |
| `performance-intune-description-resolution` | Exactly three nonzero authorized composite runs; four exact medians return and all per-run values plus private output hashes remain target-local |
| `performance-competitor-same-corpus` | Named available tools use same frozen corpus/hardware/scenario; versions and emulation/manual/uncontrolled limits labeled |

Unavailable competitors, corpus, Intune source, remote host, or nondeterministic polling remain `NOT_EXERCISED`/`BLOCKED`; never infer comparative or feature PASS.

## Completion rule

Create a return only with `New-CMTraceOpenArm64ValidationReturn.ps1 -RepositoryPath $Source -EvidenceRoot $Evidence -OutputPath $ReturnZip`. The exporter performs the final live-PR and exact clean-source check after manual work, resolves each exercised gate's unique `.proof` file, and verifies its recorded hash before packaging. Any source change invalidates affected evidence.

Transport the return ZIP and adjacent sidecar only after recording the ZIP's lowercase outer SHA-256. Send that literal through a trusted out-of-band channel; the receiver must compare the trusted value with both received files before extraction. The adjacent sidecar and internal checksum inventory are not independent trust roots.

Full PR acceptance requires automatic `PASSED`, manual `MANUAL_COMPLETE`, exact source/tree/lock/artifact hashes, native ARM64 observation, private evidence hash, independent readback, and PASS for every required row. The three known exact-head advanced UI gaps currently prevent that conclusion.
