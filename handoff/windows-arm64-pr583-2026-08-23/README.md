# CMTrace Open PR 583: Windows 11 ARM64 validation handoff

Start here. This is a sealed, connected validation package for PR 583 at application source commit `39ee0b4f6f2e42e5845c6d86f5f9b03fa06e0c84` and tree `251c7ccaea9e4195cde986b45971dd56d9e861d6`.

The package is ready to transfer. It is not evidence that PR 583 passed Windows 11 ARM64 acceptance. That requires execution on the target and truthful completion of the separate native/manual contract.

## Hard boundaries

- Use a disposable, non-customer Windows 11 ARM64 VM from a fresh snapshot. A physical device is outside this handoff because it has no defined snapshot/revert boundary.
- Use an exclusive clean disposable validation account and session. Before handling trusted bytes, confirm there is no unexpected same-account process, scheduled task, startup item, injected tool, sync client, or observed path mutation. If any appears, stop without executing further package or source bytes, preserve only the privacy-safe state required by this handoff, and revert only after the separate approval gate.
- Use native ARM64 PowerShell 7.5 or later, native ARM64 Node 22, rustup 1.28.1 or later, and a native ARM64 Rust host. An x64-emulated shell is a hard failure.
- Keep this package, source, evidence, return, input, and temporary directories disjoint on fixed local NTFS volumes. Use only the reserved top-level roots `CMTraceOpen-Handoff`, `CMTraceOpen-Return`, `cmtraceopen-input`, `cmtraceopen-validation`, and `src`; the scripts reject other roots, common sync-product path names, mapped drives, junctions, and reparse paths.
- Clone only the public repository into a new path. Never reset, clean, rebase, merge, push, sign, publish, or modify another checkout.
- Use a disposable lab account without proxy credentials, SSH-agent state, Git credential helpers or URL rewrites, registry tokens, signing values, or package-manager credentials.
- Never transfer credentials, signing keys, raw Event Logs, provider databases, registry exports, screenshots, recordings, private URLs, customer data, or private source/member paths.
- Do not run `scripts/Launch-CMTraceOpen.ps1`; it can stop processes and free a port.
- Do not run the Event Log collector bootstrap; its pinned bootstrap is x64-oriented and unrelated to this validation.
- Stop for human approval before VM snapshot/revert, prerequisite installation or elevation, installer execution, file-association changes, custom-channel creation, VSS mutation, remote-machine access, or Event Log clearing.
- Clear only an owned disposable lab channel. Never clear Application, System, Security, Setup, a remote channel, or customer logs.

Read `SECURITY-NOTES.md` before moving any bytes.

## Sealed coordinate

`MANIFEST.json` binds this package to:

- PR `https://github.com/adamgell/cmtraceopen/pull/583`
- branch `orchestration/event-viewer-epic`
- source commit `39ee0b4f6f2e42e5845c6d86f5f9b03fa06e0c84`
- source tree `251c7ccaea9e4195cde986b45971dd56d9e861d6`
- base commit `59679c06b5dd1f5d59849a14d527f4b262b30a1c`
- Cargo.lock blob `9a7e7c287e695a975658a253eac9576cc491e033`
- package-lock.json blob `42eed8fc692efb0fdf3ebf2e2ed0d240d6c96f31`
- Rust target `aarch64-pc-windows-msvc`
- application version `1.5.1`

`PUBLIC_ALLOWED_SIGNERS` contains exactly one public key. It verifies the signed application source commit; it does not authenticate this helper ZIP.

## 1. Bootstrap native PowerShell, authenticate, and extract the transfer ZIP

Installing PowerShell mutates the lab machine and needs approval. From the inbox Windows shell, install the ARM64 package from the named WinGet source, open a new `pwsh.exe` session, and hard-fail unless the new process is native ARM64:

```powershell
winget install --id Microsoft.PowerShell --exact --source winget --architecture arm64
```

```powershell
if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'Arm64' -or
    [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'Arm64' -or
    $PSVersionTable.PSVersion -lt [version]'7.5') {
  throw 'Native ARM64 PowerShell 7.5 or later is required before package verification.'
}
```

Obtain the outer ZIP SHA-256 through a trusted out-of-band channel from the handoff sender. The adjacent sidecar is a transport convenience, not an independent trust root. Compare the trusted literal before executing anything from the ZIP:

```powershell
function Assert-BootstrapPathBoundary {
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$MustExist,
    [ValidateSet('Any', 'Leaf', 'Container')][string]$RequiredType = 'Any'
  )

  $FullPath = [IO.Path]::GetFullPath($Path)
  if ($FullPath.StartsWith('\\') -or
      $FullPath -match '(?i)[\\/](?:OneDrive|Dropbox|Google Drive|My Drive|iCloudDrive|Box|Creative Cloud Files|Nextcloud|Syncthing)(?:[\\/]|$)') {
    throw "Bootstrap path must be local and nonsynchronized: $FullPath"
  }
  $Root = [IO.Path]::GetPathRoot($FullPath)
  if ($Root -notmatch '^[A-Za-z]:\\$' -or $Root -eq $FullPath) {
    throw "Bootstrap path must be a non-root local drive path: $FullPath"
  }
  $Volume = Get-Volume -DriveLetter $Root.Substring(0, 1) -ErrorAction Stop
  if ($Volume.DriveType -ne 'Fixed' -or $Volume.FileSystem -ne 'NTFS') {
    throw "Bootstrap path volume must be fixed NTFS: $FullPath"
  }
  $Relative = [IO.Path]::GetRelativePath($Root, $FullPath).Replace('/', '\')
  $TopLevel = @($Relative.Split('\', [StringSplitOptions]::RemoveEmptyEntries))[0]
  if ($TopLevel -ine 'CMTraceOpen-Handoff') {
    throw "Bootstrap path must remain under the CMTraceOpen-Handoff top-level directory on its fixed NTFS volume: $FullPath"
  }
  foreach ($OneDriveName in @('OneDrive', 'OneDriveCommercial', 'OneDriveConsumer')) {
    $OneDriveRoot = [Environment]::GetEnvironmentVariable($OneDriveName)
    if (-not [string]::IsNullOrWhiteSpace($OneDriveRoot)) {
      $FullOneDrive = [IO.Path]::GetFullPath($OneDriveRoot).TrimEnd([char]'\', [char]'/')
      if ($FullPath.Equals($FullOneDrive, [StringComparison]::OrdinalIgnoreCase) -or
          $FullPath.StartsWith(($FullOneDrive + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) {
        throw "Bootstrap path cannot be inside OneDrive: $FullPath"
      }
    }
  }
  if ($MustExist -and -not (Test-Path -LiteralPath $FullPath -PathType $RequiredType)) {
    throw "Required bootstrap $RequiredType path is missing: $FullPath"
  }

  $Existing = $FullPath
  while (-not (Test-Path -LiteralPath $Existing -PathType Any)) {
    $Parent = Split-Path -Parent $Existing
    if ([string]::IsNullOrWhiteSpace($Parent) -or $Parent -eq $Existing) {
      throw "Bootstrap path has no existing safe parent: $FullPath"
    }
    $Existing = $Parent
  }
  $Cursor = $Existing
  while (-not [string]::IsNullOrWhiteSpace($Cursor)) {
    $Entry = Get-Item -LiteralPath $Cursor -Force
    if ($Entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
      throw "Bootstrap path traverses a reparse point: $Cursor"
    }
    $Parent = Split-Path -Parent $Cursor
    if ([string]::IsNullOrWhiteSpace($Parent) -or $Parent -eq $Cursor) { break }
    $Cursor = $Parent
  }
  return $FullPath
}

$Zip = 'C:\CMTraceOpen-Handoff\cmtraceopen-pr583-windows11-arm64-validation-20260823-r6.zip'
$Zip = Assert-BootstrapPathBoundary -Path $Zip -MustExist -RequiredType Leaf
$SidecarPath = Assert-BootstrapPathBoundary -Path "$Zip.sha256" -MustExist -RequiredType Leaf
$TrustedSha256 = '<trusted out-of-band lowercase SHA-256>'
if ($TrustedSha256.StartsWith('<') -or $TrustedSha256 -cnotmatch '\A[0-9a-f]{64}\z') {
  throw 'Set $TrustedSha256 to the lowercase SHA-256 received out of band before continuing.'
}
$ZipGuard = $null
try {
  # FileShare.Read denies replacement, deletion, and writes while the same file
  # object is hashed and consumed by Expand-Archive.
  $ZipGuard = [IO.File]::Open($Zip, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  $Zip = Assert-BootstrapPathBoundary -Path $Zip -MustExist -RequiredType Leaf
  $Actual = (Get-FileHash -InputStream $ZipGuard -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($Actual -cne $TrustedSha256) { throw "Outer ZIP checksum mismatch: $Actual" }

  $Sidecar = ((Get-Content -LiteralPath $SidecarPath -Raw).Trim() -split '\s+')[0]
  if ($Sidecar -cne $TrustedSha256) { throw 'Adjacent checksum does not match the trusted value.' }

  $Handoff = 'C:\CMTraceOpen-Handoff\pr583-arm64'
  $Handoff = Assert-BootstrapPathBoundary -Path $Handoff
  if (Test-Path -LiteralPath $Handoff) { throw "Extraction destination exists: $Handoff" }
  New-Item -ItemType Directory -Path $Handoff -ErrorAction Stop | Out-Null
  $Handoff = Assert-BootstrapPathBoundary -Path $Handoff -MustExist -RequiredType Container
  $ZipGuard.Position = 0
  [IO.Compression.ZipFile]::ExtractToDirectory($ZipGuard, $Handoff, $false)
  $Handoff = Assert-BootstrapPathBoundary -Path $Handoff -MustExist -RequiredType Container
  if (@(Get-ChildItem -LiteralPath $Handoff -Recurse -Force | Where-Object {
        $_.Attributes -band [IO.FileAttributes]::ReparsePoint
      }).Count -ne 0) {
    throw 'Extracted handoff contains a reparse point.'
  }

  # The trusted outer hash is established before removing Internet-zone marks.
  Get-ChildItem -LiteralPath $Handoff -File -Recurse | Unblock-File
}
finally {
  if ($null -ne $ZipGuard) { $ZipGuard.Dispose() }
}

Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
if ((Get-ExecutionPolicy) -notin @('RemoteSigned', 'Unrestricted', 'Bypass')) {
  throw 'Effective Group Policy prevents this unsigned, hash-authenticated handoff from running.'
}
$Handoff = Assert-BootstrapPathBoundary -Path $Handoff -MustExist -RequiredType Container
pwsh.exe -NoProfile -ExecutionPolicy RemoteSigned -File "$Handoff\scripts\Test-CMTraceOpenArm64Handoff.ps1" -HandoffRoot $Handoff
```

Expected final line: `HANDOFF_INTEGRITY_OK`.

## 2. Freeze the target

1. Confirm this is a disposable, non-customer Windows 11 ARM64 VM using an exclusive clean validation account/session, with no unexpected same-account process, scheduled task, startup item, injected tool, sync client, or path mutation. Any such observation is a hard stop; do not execute more package/source bytes, and do not revert without the separate approval.
2. Take a VM snapshot.
3. Confirm no stable or nightly CMTrace Open install and no prior CMTrace Open/WebView2 application profile is present. If either exists, revert to a clean snapshot. Exact source version 1.5.1 can be contaminated by a newer installed build, stored profile state, or updater.
4. Launch portable artifacts with process environment `CMTRACEOPEN_DISABLE_UPDATE_CHECKS=1`. Use the captured/read-back HKCU policy procedure below before any installed or shell-launched activation; a UI preference alone is not the isolation boundary.
5. Create the reserved fixed-local-NTFS parents `C:\src`, `C:\cmtraceopen-input`, `C:\cmtraceopen-validation\runs`, and `C:\cmtraceopen-validation\temp`. Set both process `TEMP` and `TMP` to that exact temp directory before source initialization and keep them unchanged for the entire validation. Confirm these roots are not configured in any sync client.
6. Remove authentication, signing, SSH-agent, proxy, global Git credential/rewrite, every repository/user/global npmrc, and every user Cargo config or credential file from the disposable lab account. Ensure `.cargo\config` and `.cargo\config.toml` are absent from every source/evidence working-directory ancestor outside the authenticated source copy, including `C:\src\.cargo` and `C:\.cargo`. Unset `HOME` and `PREFIX` environment overrides. The preflight rejects every variable outside its explicit ordinary-session allowlist; every child process then receives a smaller toolchain allowlist plus only sealed per-gate overrides.

```powershell
$ValidationTemp = 'C:\cmtraceopen-validation\temp'
if (Test-Path -LiteralPath $ValidationTemp -PathType Leaf) {
  throw "Validation temp path is a file: $ValidationTemp"
}
if (-not (Test-Path -LiteralPath $ValidationTemp -PathType Container)) {
  New-Item -ItemType Directory -Path $ValidationTemp | Out-Null
}
$env:TEMP = $ValidationTemp
$env:TMP = $ValidationTemp
```

If Git is absent, stop for approval before installing it: any prerequisite installation mutates the VM even when it does not elevate. After approval, install Git from the named WinGet source and then open a new native `pwsh.exe` session:

```powershell
winget install --id Git.Git --exact --source winget
```

Microsoft documents WinGet as the recommended PowerShell installation route on Windows clients and a ZIP fallback for Arm systems: `https://learn.microsoft.com/powershell/scripting/install/install-powershell-on-windows`.

Hard-fail unless these are `Arm64`, `Arm64`, `ARM64`, and PowerShell 7.5 or later:

```powershell
[System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
[System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
$env:PROCESSOR_ARCHITECTURE
$PSVersionTable.PSVersion
```

## 3. Initialize the exact source

The initializer refuses an existing destination before mutation; rejects non-fixed, non-NTFS, synchronized, and reparse paths; isolates Git with a guarded zero-byte regular global config, an impossible absolute hook path beneath that locked file, an empty command-scope template setting, and a command-scope credential reset; creates a complete-content, depth-one clone without checkout; fixes line-ending behavior before checkout; verifies that the advertised branch still equals the sealed commit; checks out detached without a later promisor fetch; disables the push URL; verifies the public SSH commit signature; and validates the tree, lockfile blobs, remote, and clean status.

```powershell
$Handoff = 'C:\CMTraceOpen-Handoff\pr583-arm64'
$Source = 'C:\src\cmtraceopen-pr583-arm64'
$env:TEMP = 'C:\cmtraceopen-validation\temp'
$env:TMP = $env:TEMP
pwsh.exe -NoProfile -ExecutionPolicy RemoteSigned -File "$Handoff\scripts\Initialize-CMTraceOpenArm64Source.ps1" `
  -DestinationPath $Source
```

Expected: `SOURCE_READY 39ee0b4f6f2e42e5845c6d86f5f9b03fa06e0c84`.

Once the initializer creates the destination, every later failure preserves that directory for inspection. Do not delete or reuse it for a retry. Correct the environment, choose a new nonexisting attempt-suffixed destination such as `C:\src\cmtraceopen-pr583-arm64-002`, rerun the initializer, and use that new path as `$Source` for every later step. This follows the same new-output-per-attempt rule used by preflight reports.

If the branch moved, stop. Never silently validate another head.

## 4. Install prerequisites after approval

This mutates the lab machine and needs administrator approval. Take another snapshot afterward.

Do not run the repository prerequisite script as-is: it installs the moving Node LTS package, while this handoff reproduces CI with Node 22. Install and independently verify:

- native ARM64 Node 22, including its bundled `npm-cli.js` and `npx-cli.js`;
- Visual Studio 2022 Build Tools components `Microsoft.VisualStudio.Workload.VCTools`, `Microsoft.VisualStudio.Component.VC.Tools.x86.x64`, `Microsoft.VisualStudio.Component.VC.Tools.ARM64`, and `Microsoft.VisualStudio.Component.Windows11SDK.26100`;
- Microsoft Edge WebView2 Runtime;
- Rustup with default `stable-aarch64-pc-windows-msvc`;
- LLVM/Clang under `C:\Program Files\LLVM\bin`;
- Pester exactly 5.7.1 from canonical PSGallery;
- `cargo-deny` and `cargo-audit`.

The runner deliberately enters Visual Studio with `-Arch arm64 -HostArch amd64`, matching the repository's supported Windows ARM64 build path. Windows may emulate those x64-hosted compiler tools; that does not relax the native-target boundary. PowerShell, Node, and the Rust host must remain native ARM64, every Rust build targets `aarch64-pc-windows-msvc`, and the produced Full/Lite executables must independently report PE machine `0xAA64`.

Typical approved package installs are:

```powershell
winget show --id OpenJS.NodeJS.22 --exact --source winget
winget install --id OpenJS.NodeJS.22 --exact --source winget --architecture arm64

winget install --id Microsoft.VisualStudio.2022.BuildTools --exact --source winget `
  --override "--passive --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.VC.Tools.ARM64 --add Microsoft.VisualStudio.Component.Windows11SDK.26100 --includeRecommended --norestart"
winget install --id Microsoft.EdgeWebView2Runtime --exact --source winget
winget install --id Rustlang.Rustup --exact --source winget
winget install --id LLVM.LLVM --exact --source winget
```

From a new native ARM64 PowerShell 7.5+ session:

```powershell
$env:TEMP = 'C:\cmtraceopen-validation\temp'
$env:TMP = $env:TEMP
$Handoff = 'C:\CMTraceOpen-Handoff\pr583-arm64'
. "$Handoff\scripts\CMTraceOpenArm64Handoff.Common.ps1"
[void](Assert-CMTraceHandoffIntegrity -HandoffRoot $Handoff)
$NodeArchitecture = (& node.exe -p 'process.arch').Trim()
if ($LASTEXITCODE -ne 0 -or $NodeArchitecture -cne 'arm64') {
  throw "Node.js must be native ARM64; observed: $NodeArchitecture"
}
if ((& node.exe --version).Trim() -notmatch '^v22\.') { throw 'Node.js 22 is required.' }

rustup default stable-aarch64-pc-windows-msvc
rustup target add aarch64-pc-windows-msvc
rustup target add wasm32-unknown-unknown
rustup component add clippy rustfmt
rustup toolchain install 1.88 --profile minimal --target aarch64-pc-windows-msvc

$PowerShellRepositories = @(Get-PSRepository -ErrorAction Stop)
if ($PowerShellRepositories.Count -ne 1 -or $PowerShellRepositories[0].Name -cne 'PSGallery' -or
    -not ([string]$PowerShellRepositories[0].SourceLocation).TrimEnd([char]'/').Equals(
      'https://www.powershellgallery.com/api/v2', [StringComparison]::OrdinalIgnoreCase)) {
  throw 'The disposable account must have exactly canonical PSGallery registered before Pester retrieval.'
}

$PesterToolsRoot = Assert-CMTraceFixedLocalNtfsPath `
  -Path 'C:\cmtraceopen-validation\tools' -Label 'Isolated prerequisite tools root' `
  -ForbiddenRoots @($Handoff) -MustNotExist
New-Item -ItemType Directory -Path $PesterToolsRoot -ErrorAction Stop | Out-Null
$PesterPackage = Join-Path $PesterToolsRoot 'Pester.5.7.1.nupkg'
Invoke-WebRequest -Uri 'https://www.powershellgallery.com/api/v2/package/Pester/5.7.1' `
  -OutFile $PesterPackage -MaximumRedirection 5 -ErrorAction Stop
$PesterPackageGuard = [IO.File]::Open(
  $PesterPackage, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
try {
  if ($PesterPackageGuard.Length -ne 325233) { throw 'Pinned Pester package length mismatch.' }
  $PesterPackageSha256 = (Get-FileHash -InputStream $PesterPackageGuard -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($PesterPackageSha256 -cne '4a27904c6814a5fbe4758f8e49861f6a1994aee77b71165a5c43c0371ba6c580') {
    throw "Pinned Pester package SHA-256 mismatch: $PesterPackageSha256"
  }
  $PesterModuleRoot = 'C:\cmtraceopen-validation\tools\PowerShell\Modules\Pester\5.7.1'
  New-Item -ItemType Directory -Path $PesterModuleRoot -ErrorAction Stop | Out-Null
  $PesterPackageGuard.Position = 0
  [IO.Compression.ZipFile]::ExtractToDirectory($PesterPackageGuard, $PesterModuleRoot, $false)
}
finally {
  $PesterPackageGuard.Dispose()
}
$PesterBinding = Get-CMTraceTrustedPesterModule
if ($PesterBinding.Version -cne '5.7.1' -or $PesterBinding.Repository -cne 'PSGallery') {
  throw 'Pinned isolated Pester readback failed.'
}

cargo install cargo-deny --locked
cargo install cargo-audit --locked
```

Do not install Pester into a shared module path, add another PowerShell repository, or use `-SkipPublisherCheck`. The isolated package byte binding avoids the inbox-Pester publisher conflict without weakening provenance. Stop and correct or revert the disposable prerequisite state if retrieval, extraction, or readback fails.

The runner returns only bounded normalized tool version tokens in `machine.json`. Full banners, installation paths, environment variables, and configuration remain private.

## 5. Run preflight

The preflight output file and evidence root must be disjoint. Their required parents must already exist on fixed local NTFS outside synchronized/reparse paths.

```powershell
$Handoff = 'C:\CMTraceOpen-Handoff\pr583-arm64'
$Source = 'C:\src\cmtraceopen-pr583-arm64'
$Evidence = 'C:\cmtraceopen-validation\runs\pr583-arm64-001'
$Preflight = 'C:\cmtraceopen-validation\preflight-pr583-arm64-001.json'
$env:TEMP = 'C:\cmtraceopen-validation\temp'
$env:TMP = $env:TEMP

Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
if ((Get-ExecutionPolicy) -notin @('RemoteSigned', 'Unrestricted', 'Bypass')) {
  throw 'Effective Group Policy prevents the authenticated handoff scripts from running.'
}

pwsh.exe -NoProfile -ExecutionPolicy RemoteSigned -File "$Handoff\scripts\Test-CMTraceOpenArm64Preflight.ps1" `
  -RepositoryPath $Source `
  -OutputPath $Preflight
```

Expected: `PREFLIGHT_OK`. Resolve every failure without editing the source. Preserve each failed report and use a new nonexisting attempt-suffixed output such as `preflight-pr583-arm64-002.json` for the next run; the preflight intentionally refuses to overwrite. Preflight also runs exactly fourteen Windows-only owned-Job regressions and requires `14 passed, 0 failed, 0 skipped`. These prove native child stdout and stderr capture, simultaneous drain without deadlock, exact nonzero exit propagation, aggregate output limiting, timeout/descendant cleanup, and native ARM64 Git with the guarded isolated configuration. They also prove that a descendant retaining inherited output handles cannot outlive successful command completion, wrapper startup failure is never misreported as a native child exit, both the documented private helper and provider Cargo helper drain and classify that failure, bounded standard input reaches the owned native child used for exhaustive tracked-byte hashing, the Windows file guard denies target replacement until the wrapper confirms child start, and verified content bindings remain write/delete guarded until their consuming child exits.

## 6. Run the automatic plan

Plan-only mode is platform-neutral and does not mutate source:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy RemoteSigned -File "$Handoff\scripts\Invoke-CMTraceOpenArm64Validation.ps1" `
  -PlanOnly `
  -PlanOutputPath 'C:\cmtraceopen-validation\automatic-plan.json'
```

Run as an ordinary user. The runner executes 33 exact gates, prints bounded gate start/end progress, gives each gate a default 180-minute timeout, constructs every child environment from an explicit ordinary/toolchain allowlist plus sealed per-gate overrides, isolates npm, and gives every direct or transitive Git invocation the guarded zero-byte global config, its impossible locked-file-descendant hook path, and the empty command-scope template setting. Before every automatic process gate it reauthenticates the exact source, rejects nonordinary Git index visibility flags, unsealed `.env*`/toolchain controls, active local Git exclude/attribute rules, Cargo configuration outside the authenticated source boundary, Cargo-home config/credentials, and any Rustup active-toolchain override. Each stdout and stderr capture is limited to exactly 16 MiB; exceeding either limit kills the owned process tree and fails the gate. Sanitization is capped at 262,144 input and output characters; an oversized log is withheld wholesale from the return while its complete raw bytes remain target-private. The lane builds unsigned Full/Lite/NSIS output, requires Full/Lite PE `0xAA64`, requires the expected unsigned x86 NSIS bootstrapper `0x014C`, emits schema-v2 installed-executable provenance, and rechecks the live PR coordinate plus clean exact source.

This lane writes ignored checkout output such as `node_modules`, frontend output, and `src-tauri\target`; npm, Cargo registry/Git/advisory, and Playwright account caches; and the new evidence root. Those are expected lab mutations, not returnable evidence. The approved prerequisite phase also writes machine/account package state, toolchains, modules, installed binaries, and installer caches. Preserve the disposable target until evidence is accepted, then revert it.

```powershell
$env:TEMP = 'C:\cmtraceopen-validation\temp'
$env:TMP = $env:TEMP
pwsh.exe -NoProfile -ExecutionPolicy RemoteSigned -File "$Handoff\scripts\Invoke-CMTraceOpenArm64Validation.ps1" `
  -RepositoryPath $Source `
  -EvidenceRoot $Evidence `
  -GateTimeoutMinutes 180
```

Expected: `AUTOMATIC_VALIDATION_PASSED_MANUAL_PENDING`.

Automatic success is not native acceptance. Playwright uses a mocked Tauri backend, local packages are intentionally unsigned, and environment-gated Event Log work remains manual.

Before any portable or installer launch, bind the exact target-private files to `artifacts.json`. Never launch a similarly named file from the source tree, Downloads, a prior run, or an installed copy. The Full and Lite portable records below intentionally bind standalone executables only; they do not contain or prove the external `provider-db` resource tree. Exercise `provider-packaged-resource` only in the approved NSIS current-user lane, where the matrix independently compares every regular non-reparse source resource with the installed tree before the first installed launch:

```powershell
. "$Handoff\scripts\CMTraceOpenArm64Handoff.Common.ps1"
[void](Assert-CMTraceHandoffIntegrity -HandoffRoot $Handoff)

$PrivateArtifacts = [ordered]@{
  'full-portable' = Join-Path $Evidence 'raw-artifacts\full\cmtrace-open.exe'
  'lite-portable' = Join-Path $Evidence 'raw-artifacts\lite\cmtrace-open.exe'
  'nsis-installer' = Join-Path $Evidence 'raw-artifacts\nsis\cmtrace-open-setup.exe'
}
$VerifiedArtifactSha = [ordered]@{}

function Get-VerifiedPrivateArtifact {
  param([Parameter(Mandatory)][ValidateSet('full-portable', 'lite-portable', 'nsis-installer')][string]$Kind)

  $ArtifactEvidence = Get-Content -LiteralPath (Join-Path $Evidence 'artifacts.json') -Raw | ConvertFrom-Json
  $ExpectedArtifact = @($ArtifactEvidence.items | Where-Object { $_.kind -ceq $Kind })
  if ($ExpectedArtifact.Count -ne 1) { throw "Missing unique artifact record: $Kind" }
  $VerifiedPath = Assert-CMTraceFixedLocalNtfsPath -Path $PrivateArtifacts[$Kind] -Label "Private artifact $Kind" -ForbiddenRoots @($Handoff)
  $PrivateArtifact = Get-Item -LiteralPath $VerifiedPath -Force
  if ($PrivateArtifact.PSIsContainer -or ($PrivateArtifact.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw "Artifact is not a regular file: $Kind"
  }
  if ($PrivateArtifact.Length -ne [int64]$ExpectedArtifact[0].bytes) {
    throw "Artifact size mismatch: $Kind"
  }
  $ActualArtifactSha = (Get-FileHash -LiteralPath $PrivateArtifact.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($ActualArtifactSha -cne $ExpectedArtifact[0].sha256) {
    throw "Artifact SHA-256 mismatch: $Kind"
  }
  $VerifiedArtifactSha[$Kind] = $ActualArtifactSha
  return [pscustomobject]@{
    Path = $PrivateArtifact.FullName
    Sha256 = $ActualArtifactSha
    Bytes = [int64]$PrivateArtifact.Length
  }
}
```

Initialize the proof writer before the first manual observation. It uses create-new semantics, writes the detailed observation only to the target-private proof file, reads back its hash, and returns only the safe ID/hash binding:

```powershell
$ManualEvidence = Join-Path $Evidence 'raw-artifacts\manual-evidence'
if (-not (Test-Path -LiteralPath $ManualEvidence -PathType Container)) {
  New-Item -ItemType Directory -Path $ManualEvidence | Out-Null
}
$ManualEvidenceEntry = Get-Item -LiteralPath $ManualEvidence -Force
if ($ManualEvidenceEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
  throw 'Manual evidence directory cannot be a reparse point.'
}

function Save-PrivateManualProof {
  param(
    [Parameter(Mandatory)][ValidatePattern('^[a-z0-9][a-z0-9._-]{0,63}$')][string]$EvidenceId,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$Lines
  )

  if (@($Lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -eq 0) {
    throw "Manual proof cannot be empty: $EvidenceId"
  }
  $ProofPath = Join-Path $ManualEvidence "$EvidenceId.proof"
  $Stream = [IO.File]::Open($ProofPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  $Writer = $null
  try {
    $Writer = [IO.StreamWriter]::new($Stream, [Text.UTF8Encoding]::new($false))
    foreach ($Line in $Lines) { $Writer.WriteLine($Line) }
    $Writer.Flush()
  }
  finally {
    if ($null -ne $Writer) { $Writer.Dispose() } else { $Stream.Dispose() }
  }
  return [pscustomobject]@{
    evidenceId = $EvidenceId
    evidenceSha256 = (Get-FileHash -LiteralPath $ProofPath -Algorithm SHA256).Hash.ToLowerInvariant()
  }
}
```

Do not launch Full, Lite, or NSIS yet. Define the bounded private-process helper in the next section first. Full and Lite are then launched through that helper; NSIS still requires separate installer approval.

## 7. Run local native Event Log tests

Keep all raw records, fixture output, member inventories, provider material, screenshots, recordings, and private paths under the target evidence root.

Every manual native command that can emit target data must capture both output streams beneath the evidence root and use a bounded timeout. Do not run `--nocapture`, EVTX, provider, MDMDiag, remote, or performance commands directly into the shared terminal. Define this target-local helper once. Before every launch it reauthenticates all tracked source bytes, source/Cargo controls, and the active stable ARM64 Rust toolchain. It then writes through a strict 32 MiB aggregate byte cap, kills only its owned process tree on timeout or cap, samples exact Job membership working set at 100 ms intervals, and returns only an exit code, private file locations, and the peak byte count. A timeout or cap is a failed command; a capped file is never complete evidence and never qualifies for PASS.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
if ((Get-ExecutionPolicy) -notin @('RemoteSigned', 'Unrestricted', 'Bypass')) {
  throw 'Effective Group Policy prevents the authenticated handoff scripts from running.'
}
. "$Handoff\scripts\CMTraceOpenArm64Handoff.Common.ps1"
[void](Assert-CMTraceHandoffIntegrity -HandoffRoot $Handoff)
$InputRoot = Join-Path ([IO.Path]::GetPathRoot($Source)) 'cmtraceopen-input'
[void](Assert-CMTraceSafeTemporaryRoot -ForbiddenRoots @($Handoff, $Source, $Evidence, $InputRoot))
$GitIsolation = Get-CMTraceGitIsolationContext -ForbiddenRoots @($Handoff, $Source, $Evidence, $InputRoot)
$GitEnvironment = $GitIsolation.Environment

$PrivateCommandOutput = Join-Path $Evidence 'raw-artifacts\private-command-output'
if (-not (Test-Path -LiteralPath $PrivateCommandOutput -PathType Container)) {
  New-Item -ItemType Directory -Path $PrivateCommandOutput | Out-Null
}
$PrivateCommandOutputEntry = Get-Item -LiteralPath $PrivateCommandOutput -Force
if ($PrivateCommandOutputEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
  throw 'Private command output directory cannot be a reparse point.'
}

Initialize-CMTraceOwnedProcessType

function Get-PrivateJobWorkingSetBytes {
  param(
    [Parameter(Mandatory)][CMTraceOpen.Validation.OwnedProcessJob]$Job,
    [Parameter(Mandatory)][int]$WrapperProcessId
  )

  $WorkingSetBytes = 0L
  foreach ($ProcessId in @($Job.ActiveProcessIds | Where-Object { $_ -ne $WrapperProcessId })) {
    $Member = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($null -ne $Member) {
      try { $WorkingSetBytes += [int64]$Member.WorkingSet64 }
      finally { $Member.Dispose() }
    }
  }
  return $WorkingSetBytes
}

function Invoke-PrivateProcess {
  param(
    [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]+$')][string]$Id,
    [Parameter(Mandatory)][string]$FilePath,
    [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ArgumentList,
    [Parameter(Mandatory)][string]$WorkingDirectory,
    [System.Collections.IDictionary]$Environment = @{},
    [AllowEmptyString()][string]$ExpectedSha256 = '',
    [int64]$ExpectedBytes = -1,
    [AllowEmptyCollection()][object[]]$ContentBindings = @(),
    [ValidateRange(1, 180)][int]$TimeoutMinutes = 30,
    [switch]$MeasureInputIdle,
    [switch]$CloseAfterInputIdle
  )

  if ($CloseAfterInputIdle -and -not $MeasureInputIdle) {
    throw 'CloseAfterInputIdle requires MeasureInputIdle.'
  }
  $HasExpectedBinding = -not [string]::IsNullOrWhiteSpace($ExpectedSha256)
  if ($HasExpectedBinding -ne ($ExpectedBytes -ge 0)) {
    throw 'Expected executable SHA-256 and byte length must be supplied together.'
  }

  [void](Assert-CMTraceHandoffIntegrity -HandoffRoot $Handoff)
  [void](Assert-CMTraceSourceIntegrity -RepositoryPath $Source)
  [void](Assert-CMTraceCargoConfigurationBoundary -WorkingDirectory $Source `
    -AllowedConfigurationPaths @((Join-Path $Source '.cargo\config.toml')))
  [void](Assert-CMTraceActiveRustToolchain -WorkingDirectory $Source)

  $StdoutPath = Join-Path $PrivateCommandOutput "$Id.stdout.log"
  $StderrPath = Join-Path $PrivateCommandOutput "$Id.stderr.log"
  foreach ($Path in @($StdoutPath, $StderrPath)) {
    if (Test-Path -LiteralPath $Path) { throw "Private command output already exists: $Id" }
  }

  $StartInfo = [Diagnostics.ProcessStartInfo]::new()
  $StartInfo.WorkingDirectory = $WorkingDirectory
  $StartInfo.UseShellExecute = $false
  $StartInfo.CreateNoWindow = $true
  $StartInfo.RedirectStandardOutput = $true
  $StartInfo.RedirectStandardError = $true
  foreach ($Argument in $ArgumentList) { [void]$StartInfo.ArgumentList.Add($Argument) }
  $ChildEnvironment = [ordered]@{}
  foreach ($Entry in $GitEnvironment.GetEnumerator()) {
    $ChildEnvironment[[string]$Entry.Key] = [string]$Entry.Value
  }
  foreach ($Entry in $Environment.GetEnumerator()) {
    if (@($GitEnvironment.Keys) -icontains [string]$Entry.Key) {
      throw "Private command environment cannot override sealed Git isolation entry: $($Entry.Key)"
    }
    $ChildEnvironment[[string]$Entry.Key] = [string]$Entry.Value
  }
  Initialize-CMTraceChildEnvironment -StartInfo $StartInfo -Environment $ChildEnvironment

  $Process = [Diagnostics.Process]::new()
  $OwnedLaunch = $null
  $StdoutStream = $null
  $StderrStream = $null
  $StdoutReadTask = $null
  $StderrReadTask = $null
  $StdoutComplete = $false
  $StderrComplete = $false
  $Started = $false
  $JobAssigned = $false
  $TimedOut = $false
  $InputIdleTimedOut = $false
  $OutputLimitExceeded = $false
  $TerminationDrainExceeded = $false
  $MaximumOutputBytes = 33554432L
  $CapturedBytes = 0L
  $PeakWorkingSetBytes = 0L
  $InputIdleMilliseconds = $null
  $RequestedProcess = $null
  $InputIdleCloseRequested = $false
  $ExitCode = $null
  $TargetStartFailure = $null
  $PrivateJob = $null
  $TargetGuard = $null
  $GuardedTargetPath = $null
  $ContentGuards = [Collections.Generic.List[IO.FileStream]]::new()
  try {
    $ContentGuards.Add((Open-CMTraceGitIsolationGuard -Context $GitIsolation `
      -ForbiddenRoots @($Handoff, $Source, $Evidence, $InputRoot)))
    $TargetGuard = Open-CMTraceGuardedReadFile -Path $FilePath -Label "Private command target $Id" `
      -ExpectedSha256 $ExpectedSha256 -ExpectedBytes $ExpectedBytes
    $GuardedTargetPath = $TargetGuard.Path
    $StartInfo.FileName = $GuardedTargetPath
    foreach ($Binding in @($ContentBindings)) {
      if ($null -eq $Binding -or
          @($Binding.PSObject.Properties.Name | Where-Object { $_ -cin @('Path', 'Sha256', 'Bytes', 'Label') }).Count -ne 4 -or
          @($Binding.PSObject.Properties.Name).Count -ne 4) {
        throw 'Each private content binding must contain exactly Path, Sha256, Bytes, and Label.'
      }
      $ContentGuard = Open-CMTraceGuardedReadFile -Path ([string]$Binding.Path) -Label ([string]$Binding.Label) `
        -ExpectedSha256 ([string]$Binding.Sha256) -ExpectedBytes ([int64]$Binding.Bytes)
      $ContentGuards.Add($ContentGuard.Stream)
    }
    $OwnedLaunch = Get-CMTraceOwnedProcessLaunch -TargetStartInfo $StartInfo
    $Process.StartInfo = $OwnedLaunch.StartInfo
    $PrivateJob = [CMTraceOpen.Validation.OwnedProcessJob]::new()
    $StdoutStream = [IO.File]::Open($StdoutPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    $StderrStream = [IO.File]::Open($StderrPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    if (-not $Process.Start()) { throw "Could not start private command: $Id" }
    $Started = $true
    $PrivateJob.Assign($Process)
    $JobAssigned = $true
    $Timer = [Diagnostics.Stopwatch]::StartNew()
    $Timeout = [TimeSpan]::FromMinutes($TimeoutMinutes)
    $StdoutBuffer = [byte[]]::new(8192)
    $StderrBuffer = [byte[]]::new(8192)
    $StdoutReadTask = $Process.StandardOutput.BaseStream.ReadAsync($StdoutBuffer, 0, $StdoutBuffer.Length)
    $StderrReadTask = $Process.StandardError.BaseStream.ReadAsync($StderrBuffer, 0, $StderrBuffer.Length)
    $TerminationRequested = $false
    $TerminationDrainDeadline = [DateTimeOffset]::MaxValue
    [void]$OwnedLaunch.ReadyEvent.Set()
    try {
      Wait-CMTraceOwnedTargetStarted -OwnedLaunch $OwnedLaunch -WrapperProcess $Process
      $TargetGuard.Stream.Dispose()
      $TargetGuard = $null
    }
    catch {
      $TargetStartFailure = $_.Exception.Message
      $TerminationRequested = $true
      $TerminationDrainDeadline = [DateTimeOffset]::UtcNow.AddSeconds(5)
      try { $PrivateJob.Terminate(1) } catch { $TerminationDrainExceeded = $true }
    }

    while ($PrivateJob.ActiveProcessCount -gt 0 -or -not $Process.HasExited -or -not $StdoutComplete -or -not $StderrComplete) {
      $Now = [DateTimeOffset]::UtcNow
      if (-not $TerminationRequested) {
        $WorkingSetBytes = Get-PrivateJobWorkingSetBytes -Job $PrivateJob -WrapperProcessId $Process.Id
        if ($WorkingSetBytes -gt $PeakWorkingSetBytes) { $PeakWorkingSetBytes = $WorkingSetBytes }

        if ($MeasureInputIdle -and $null -eq $InputIdleMilliseconds) {
          if ($null -eq $RequestedProcess) {
            $RequestedCandidates = @($PrivateJob.ActiveProcessIds | Where-Object { $_ -ne $Process.Id } | ForEach-Object {
              $Candidate = Get-Process -Id $_ -ErrorAction SilentlyContinue
              if ($null -ne $Candidate) {
                try {
                  if ([IO.Path]::GetFullPath($Candidate.Path).Equals([IO.Path]::GetFullPath($GuardedTargetPath), [StringComparison]::OrdinalIgnoreCase)) {
                    $Candidate
                  }
                  else {
                    $Candidate.Dispose()
                  }
                }
                catch { $Candidate.Dispose() }
              }
            })
            if ($RequestedCandidates.Count -gt 1) {
              foreach ($Candidate in $RequestedCandidates) { $Candidate.Dispose() }
              throw "Private UI command launched multiple matching Job members before identity was bound: $Id"
            }
            if ($RequestedCandidates.Count -eq 1) {
              $RequestedProcess = $RequestedCandidates[0]
            }
          }
          if ($null -ne $RequestedProcess) {
            $RequestedProcess.Refresh()
            if ($RequestedProcess.HasExited) {
              throw "Private UI command exited before a responsive window was observed: $Id"
            }
            $IsInputIdle = $false
            try { $IsInputIdle = $RequestedProcess.WaitForInputIdle(0) } catch [InvalidOperationException] { }
            $RequestedProcess.Refresh()
            if ($IsInputIdle -and $RequestedProcess.MainWindowHandle -ne [IntPtr]::Zero -and $RequestedProcess.Responding) {
              $InputIdleMilliseconds = [Math]::Max(1L, $Timer.ElapsedMilliseconds)
              if ($CloseAfterInputIdle) {
                if (-not $RequestedProcess.CloseMainWindow()) {
                  throw "Private UI command did not accept an ordinary close request: $Id"
                }
                $InputIdleCloseRequested = $true
              }
            }
          }
          if ($null -eq $InputIdleMilliseconds -and $Timer.Elapsed -ge [TimeSpan]::FromSeconds(30)) {
            $InputIdleTimedOut = $true
            $TerminationRequested = $true
            $TerminationDrainDeadline = $Now.AddSeconds(5)
            $PrivateJob.Terminate(1)
          }
        }
      }

      if (-not $TerminationRequested -and $Timer.Elapsed -ge $Timeout) {
        $TimedOut = $true
        $TerminationRequested = $true
        $TerminationDrainDeadline = $Now.AddSeconds(5)
        $PrivateJob.Terminate(1)
      }
      if ($TerminationRequested -and $Now -ge $TerminationDrainDeadline -and
          ($PrivateJob.ActiveProcessCount -gt 0 -or -not $Process.HasExited -or
           -not $StdoutComplete -or -not $StderrComplete)) {
        $TerminationDrainExceeded = $true
        break
      }

      $PendingTasks = @()
      $PendingStreams = @()
      if (-not $StdoutComplete) {
        $PendingTasks += $StdoutReadTask
        $PendingStreams += 'stdout'
      }
      if (-not $StderrComplete) {
        $PendingTasks += $StderrReadTask
        $PendingStreams += 'stderr'
      }
      if ($PendingTasks.Count -eq 0) {
        if ($Process.HasExited) { Start-Sleep -Milliseconds 100 }
        else { [void]$Process.WaitForExit(100) }
        continue
      }

      $CompletedIndex = [Threading.Tasks.Task]::WaitAny([Threading.Tasks.Task[]]$PendingTasks, 100)
      if ($CompletedIndex -lt 0) { continue }
      $StreamName = $PendingStreams[$CompletedIndex]
      if ($StreamName -eq 'stdout') {
        $ReadBytes = $StdoutReadTask.GetAwaiter().GetResult()
        if ($ReadBytes -eq 0) {
          $StdoutComplete = $true
        }
        else {
          $RemainingBytes = [Math]::Max(0L, $MaximumOutputBytes - $CapturedBytes)
          $WriteBytes = [int][Math]::Min([long]$ReadBytes, $RemainingBytes)
          if ($WriteBytes -gt 0) {
            $StdoutStream.Write($StdoutBuffer, 0, $WriteBytes)
            $CapturedBytes += $WriteBytes
          }
          if ($WriteBytes -lt $ReadBytes) {
            if (-not $OutputLimitExceeded) {
              $OutputLimitExceeded = $true
              $TerminationRequested = $true
              $TerminationDrainDeadline = [DateTimeOffset]::UtcNow.AddSeconds(5)
              $PrivateJob.Terminate(1)
            }
          }
          $StdoutReadTask = $Process.StandardOutput.BaseStream.ReadAsync($StdoutBuffer, 0, $StdoutBuffer.Length)
        }
      }
      else {
        $ReadBytes = $StderrReadTask.GetAwaiter().GetResult()
        if ($ReadBytes -eq 0) {
          $StderrComplete = $true
        }
        else {
          $RemainingBytes = [Math]::Max(0L, $MaximumOutputBytes - $CapturedBytes)
          $WriteBytes = [int][Math]::Min([long]$ReadBytes, $RemainingBytes)
          if ($WriteBytes -gt 0) {
            $StderrStream.Write($StderrBuffer, 0, $WriteBytes)
            $CapturedBytes += $WriteBytes
          }
          if ($WriteBytes -lt $ReadBytes) {
            if (-not $OutputLimitExceeded) {
              $OutputLimitExceeded = $true
              $TerminationRequested = $true
              $TerminationDrainDeadline = [DateTimeOffset]::UtcNow.AddSeconds(5)
              $PrivateJob.Terminate(1)
            }
          }
          $StderrReadTask = $Process.StandardError.BaseStream.ReadAsync($StderrBuffer, 0, $StderrBuffer.Length)
        }
      }
    }

    $Timer.Stop()
    $StdoutStream.Flush($true)
    $StderrStream.Flush($true)
    if ($Process.HasExited) { $ExitCode = $Process.ExitCode }
  }
  finally {
    if ($Started -and -not $JobAssigned -and -not $Process.HasExited) {
      try { $Process.Kill($true) } catch { $TerminationDrainExceeded = $true }
    }
    if ($null -ne $PrivateJob -and $Started -and
        ($PrivateJob.ActiveProcessCount -gt 0 -or -not $Process.HasExited -or
         ($null -ne $StdoutReadTask -and -not $StdoutReadTask.IsCompleted) -or
         ($null -ne $StderrReadTask -and -not $StderrReadTask.IsCompleted))) {
      try { $PrivateJob.Terminate(1) } catch { $TerminationDrainExceeded = $true }
    }
    if ($null -ne $PrivateJob) { $PrivateJob.Dispose() }
    if ($null -ne $OwnedLaunch) {
      $OwnedLaunch.TargetStartedEvent.Dispose()
      $OwnedLaunch.ReadyEvent.Dispose()
    }
    if ($Started -and -not $Process.HasExited) {
      try { [void]$Process.WaitForExit(5000) } catch { $TerminationDrainExceeded = $true }
    }
    $PendingReadTasks = @(@($StdoutReadTask, $StderrReadTask) | Where-Object { $null -ne $_ -and -not $_.IsCompleted })
    if ($PendingReadTasks.Count -gt 0) {
      try { $Process.StandardOutput.BaseStream.Dispose() } catch { $TerminationDrainExceeded = $true }
      try { $Process.StandardError.BaseStream.Dispose() } catch { $TerminationDrainExceeded = $true }
      try {
        if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$PendingReadTasks, 5000)) {
          $TerminationDrainExceeded = $true
        }
      }
      catch { $TerminationDrainExceeded = $true }
    }
    if ($null -ne $StdoutStream) { $StdoutStream.Dispose() }
    if ($null -ne $StderrStream) { $StderrStream.Dispose() }
    if ($null -ne $RequestedProcess) { $RequestedProcess.Dispose() }
    $Process.Dispose()
    if ($null -ne $TargetGuard) { $TargetGuard.Stream.Dispose() }
    foreach ($ContentGuard in $ContentGuards) { $ContentGuard.Dispose() }
  }
  if (-not [string]::IsNullOrWhiteSpace($TargetStartFailure) -or
      (Test-CMTraceOwnedProcessWrapperFailureExitCode -ExitCode $ExitCode)) {
    throw "Owned-process wrapper failed before a trustworthy native child result: $Id. Record the affected gate BLOCKED with dispositionCode ENVIRONMENT_UNAVAILABLE; never record FAIL or OBSERVED_FAILURE."
  }
  if ($InputIdleTimedOut) { throw "Private UI command did not produce a visible responsive window within 30 seconds: $Id" }
  if ($TimedOut) { throw "Private command timed out after $TimeoutMinutes minutes: $Id" }
  if ($OutputLimitExceeded) { throw "Private command output reached the exact $MaximumOutputBytes-byte aggregate cap: $Id" }
  if ($TerminationDrainExceeded) { throw "Private command streams did not close within the bounded five-second termination drain: $Id" }
  if ($null -eq $ExitCode) { throw "Private command ended without an exit code: $Id" }
  if ($MeasureInputIdle -and ($null -eq $InputIdleMilliseconds -or ($CloseAfterInputIdle -and -not $InputIdleCloseRequested))) {
    throw "Private UI command did not complete the responsive-window measurement: $Id"
  }
  return [pscustomobject]@{
    ExitCode = $ExitCode
    StdoutPath = $StdoutPath
    StderrPath = $StderrPath
    PeakWorkingSetBytes = $PeakWorkingSetBytes
    InputIdleMilliseconds = $InputIdleMilliseconds
  }
}
```

Exit code `253` is reserved for owned-process wrapper infrastructure failure. A real child that returns `253` is deliberately treated as untrustworthy rather than claimed as native evidence; retain the private diagnostic and record the affected manual gate as `BLOCKED` / `ENVIRONMENT_UNAVAILABLE`, never `FAIL` / `OBSERVED_FAILURE`.

Keep `CMTRACEOPEN_DISABLE_UPDATE_CHECKS=1` in the process environment for both portable launches. Re-read and verify `artifacts.json` immediately before each launch, observe Full and Lite separately, close each cleanly, and record native behavior in the matching manual rows. The helper keeps both output streams private, enforces the aggregate cap and timeout, and does not treat wrapper exit as process-tree completion:

```powershell
$PortableEnvironment = @{ CMTRACEOPEN_DISABLE_UPDATE_CHECKS = '1' }

$FullArtifact = Get-VerifiedPrivateArtifact -Kind 'full-portable'
$FullResult = Invoke-PrivateProcess -Id 'full-portable-manual' `
  -FilePath $FullArtifact.Path -ArgumentList @() -Environment $PortableEnvironment `
  -ExpectedSha256 $FullArtifact.Sha256 -ExpectedBytes $FullArtifact.Bytes `
  -WorkingDirectory (Split-Path -Parent $FullArtifact.Path) -TimeoutMinutes 30
if ($FullResult.ExitCode -ne 0) { throw 'Full portable launch failed.' }

$LiteArtifact = Get-VerifiedPrivateArtifact -Kind 'lite-portable'
$LiteResult = Invoke-PrivateProcess -Id 'lite-portable-manual' `
  -FilePath $LiteArtifact.Path -ArgumentList @() -Environment $PortableEnvironment `
  -ExpectedSha256 $LiteArtifact.Sha256 -ExpectedBytes $LiteArtifact.Bytes `
  -WorkingDirectory (Split-Path -Parent $LiteArtifact.Path) -TimeoutMinutes 30
if ($LiteResult.ExitCode -ne 0) { throw 'Lite portable launch failed.' }
```

Do not run the aggregate ignored live module; it also selects remote-only tests. Run these five individually:

```powershell
$Target = 'aarch64-pc-windows-msvc'
$Tests = @(
  'event_log::live::live_service_tests::an_unfiltered_query_returns_records',
  'event_log::live::live_service_tests::a_time_filter_is_applied_by_the_service_and_narrows_the_result',
  'event_log::live::live_service_tests::a_level_filter_returns_only_that_level',
  'event_log::live::live_service_tests::an_impossible_filter_returns_nothing_rather_than_everything',
  'event_log::live::live_service_tests::system_fields_are_populated_from_real_events'
)

Push-Location $Source
try {
  for ($Index = 0; $Index -lt $Tests.Count; $Index++) {
    $Result = Invoke-PrivateProcess -Id ('local-eventlog-{0}' -f ($Index + 1)) `
      -FilePath (Get-Command cargo.exe).Source -WorkingDirectory $Source -TimeoutMinutes 30 `
      -ArgumentList @('test', '--locked', '-p', 'cmtrace-open', '--all-features', '--target', $Target, '--lib', $Tests[$Index], '--', '--exact', '--ignored', '--nocapture', '--test-threads=1')
    if ($Result.ExitCode -ne 0) { throw "Failed: $($Tests[$Index])" }
  }
}
finally { Pop-Location }
```

The level test can pass with zero records and the time test accepts equality. Manual PASS additionally requires a nonzero requested level and measured strict narrowing; record only bounded counts in `manual-results.json`.

## 8. Create and exercise private recovery fixtures

Export a lab-only EVTX beneath the evidence root. It can contain identity and event content and must never leave the target:

```powershell
$PrivateEvtx = Join-Path $Evidence 'raw-artifacts\private-evtx'
if (Test-Path -LiteralPath $PrivateEvtx -PathType Any) {
  throw 'Private EVTX evidence directory already exists; use a new evidence root and do not overwrite prior evidence.'
}
[void](Assert-CMTraceFixedLocalNtfsPath -Path $PrivateEvtx -Label 'Private EVTX evidence' -ForbiddenRoots @($Handoff, $Source) -MustNotExist)
New-Item -ItemType Directory -Path $PrivateEvtx | Out-Null
$Export = Join-Path $PrivateEvtx 'application-export.evtx'
$ExportResult = Invoke-PrivateProcess -Id 'application-evtx-export' `
  -FilePath (Get-Command wevtutil.exe).Source -WorkingDirectory $Source -TimeoutMinutes 10 `
  -ArgumentList @('epl', 'Application', $Export, '/ow:false')
if ($ExportResult.ExitCode -ne 0) { throw 'Private EVTX export command failed.' }
if (-not (Test-Path -LiteralPath $Export -PathType Leaf)) { throw 'Private EVTX export failed.' }

$FixtureScript = Join-Path $Handoff 'scripts\New-CMTraceOpenPrivateEvtxFixtures.ps1'
$FixtureBindings = @(
  Get-CMTraceContentBinding -Path $FixtureScript -Label 'Sealed private EVTX fixture helper'
  Get-CMTraceContentBinding -Path $Export -Label 'Private clean EVTX export'
)
$FixtureResult = Invoke-PrivateProcess -Id 'private-evtx-fixtures' `
  -FilePath (Get-Command pwsh.exe).Source -WorkingDirectory $Handoff -TimeoutMinutes 10 `
  -ContentBindings $FixtureBindings `
  -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'RemoteSigned', '-File', $FixtureScript, '-CleanEvtxPath', $Export, '-EvidenceRoot', $Evidence)
if ($FixtureResult.ExitCode -ne 0) { throw 'Private EVTX fixture generation failed.' }
$Recovery = Join-Path $PrivateEvtx 'recovery-copies'
```

The helper refuses an arbitrary output location and creates seven copies: clean, tail-truncated, internal missing chunk, malformed file header, malformed chunk header, malformed record size, and malformed BinXML. It verifies canonical signatures and never edits the export.

Prove the seven real-EVTX integration tests are non-vacuous:

```powershell
$CleanEvtx = Join-Path $Recovery 'clean.evtx'
$CleanEvtxBinding = Get-CMTraceContentBinding -Path $CleanEvtx -Label 'Private clean recovery EVTX'
$RealEvtxResult = Invoke-PrivateProcess -Id 'real-evtx-suite' `
  -FilePath (Get-Command cargo.exe).Source -WorkingDirectory $Source -TimeoutMinutes 30 `
  -Environment @{ CMTRACE_EVTX_FIXTURE = $CleanEvtx } -ContentBindings @($CleanEvtxBinding) `
  -ArgumentList @('test', '--locked', '-p', 'cmtrace-open', '--all-features', '--target', $Target, '--test', 'event_log_real_evtx', '--', '--nocapture', '--test-threads=1')
if ($RealEvtxResult.ExitCode -ne 0) { throw 'Real-EVTX suite failed.' }
```

An unset/missing fixture or skipped suite is not PASS. Build the exact native CLI and exercise every copy privately:

```powershell
$PrivateCliRoot = Join-Path $Evidence 'raw-artifacts\private-event-log-export'
$PrivateCliRoot = Assert-CMTraceFixedLocalNtfsPath -Path $PrivateCliRoot `
  -Label 'Private event-log-export build root' -ForbiddenRoots @($Handoff, $Source) -MustNotExist
$PrivateCliRoot = Assert-CMTracePathWithinRoot -Path $PrivateCliRoot `
  -Root (Join-Path $Evidence 'raw-artifacts') -Label 'Private event-log-export build root'
[void](Assert-CMTraceNoReparseAncestor -Path $PrivateCliRoot -Label 'Private event-log-export build root')
New-Item -ItemType Directory -Path $PrivateCliRoot -ErrorAction Stop | Out-Null
[void](Assert-CMTraceNoReparseAncestor -Path $PrivateCliRoot -Label 'Private event-log-export build root')

$CliTargetDir = Join-Path $PrivateCliRoot 'cargo-target'
if (Test-Path -LiteralPath $CliTargetDir -PathType Any) {
  throw 'Private event-log-export target directory already exists; use a new evidence root.'
}
New-Item -ItemType Directory -Path $CliTargetDir -ErrorAction Stop | Out-Null
[void](Assert-CMTraceNoReparseAncestor -Path $CliTargetDir -Label 'Private event-log-export target directory')
if (@(Get-ChildItem -LiteralPath $CliTargetDir -Force).Count -ne 0) {
  throw 'Private event-log-export target directory was not created empty.'
}

[void](Assert-CMTraceSourceIntegrity -RepositoryPath $Source)
$CliBuild = Invoke-PrivateProcess -Id 'event-log-export-build' `
  -FilePath (Get-Command cargo.exe).Source -WorkingDirectory $Source -TimeoutMinutes 60 `
  -ArgumentList @('build', '--locked', '-p', 'cmtrace-open', '--no-default-features', '--features', 'event-log', '--target', $Target, '--target-dir', $CliTargetDir, '--bin', 'event-log-export')
if ($CliBuild.ExitCode -ne 0) { throw 'ARM64 event-log-export build failed.' }
[void](Assert-CMTraceSourceIntegrity -RepositoryPath $Source)

$CliPath = Join-Path $CliTargetDir 'aarch64-pc-windows-msvc\debug\event-log-export.exe'
$PrivateEventLogExport = Get-CMTraceVerifiedArm64Executable -Path $CliPath -Root $PrivateCliRoot
foreach ($Fixture in Get-ChildItem -LiteralPath $Recovery -Filter '*.evtx') {
  $Name = $Fixture.BaseName
  $Output = Join-Path $PrivateEvtx "cli-$Name.tsv"
  $CliBinding = Get-CMTraceVerifiedArm64Executable -Path $PrivateEventLogExport.Path -Root $PrivateCliRoot `
    -ExpectedSha256 $PrivateEventLogExport.Sha256 -ExpectedBytes $PrivateEventLogExport.Bytes
  $FixtureBinding = Get-CMTraceContentBinding -Path $Fixture.FullName -Label "Private recovery EVTX $Name"
  $CliResult = Invoke-PrivateProcess -Id "recovery-$Name" `
    -FilePath $CliBinding.Path -ExpectedSha256 $CliBinding.Sha256 -ExpectedBytes $CliBinding.Bytes `
    -WorkingDirectory $Source -TimeoutMinutes 10 -ContentBindings @($FixtureBinding) `
    -ArgumentList @('--source', $Fixture.FullName, '--format', 'tsv', '--output', $Output)
  if ($CliResult.ExitCode -ne 0 -and $Name -notmatch '^malformed-') { throw "Unexpected CLI failure for $Name" }
}
```

The new private Cargo target directory is never reused. `$PrivateEventLogExport` binds the just-built non-reparse native ARM64 executable by byte length and SHA-256, and every invocation rechecks containment, all path ancestors, PE machine `0xAA64`, bytes, and hash. TSV still contains private event text. Compare only target-local record-ID sets and bounded coverage. Internal-gap PASS requires missing clean IDs, at least one returned ID later than the maximum missing ID, nonzero exported records, and visible nonzero damage coverage. Malformed variants require bounded visible failure/coverage with no crash, hang, false clean result, or fabricated content.

Reauthenticate and hold all seven verified EVTX files for the complete native Full UI observation. The command blocks until Full exits. While it is open, use only its file-open UI to exercise every recovery copy, record the bounded recovery observations, and then close it cleanly:

```powershell
$RecoveryEntries = @(Get-ChildItem -LiteralPath $Recovery -Filter '*.evtx' -File |
  Sort-Object -Property Name -CaseSensitive)
if ($RecoveryEntries.Count -ne 7) { throw 'Expected exactly seven private recovery EVTX files.' }
$RecoveryBindings = @(
  foreach ($RecoveryEntry in $RecoveryEntries) {
    Get-CMTraceContentBinding -Path $RecoveryEntry.FullName -Label "Private Full UI recovery EVTX $($RecoveryEntry.BaseName)"
  }
)
$FullArtifact = Get-VerifiedPrivateArtifact -Kind 'full-portable'
$RecoveryGuiResult = Invoke-PrivateProcess -Id 'private-recovery-full-ui' `
  -FilePath $FullArtifact.Path -ExpectedSha256 $FullArtifact.Sha256 -ExpectedBytes $FullArtifact.Bytes `
  -WorkingDirectory (Split-Path -Parent $FullArtifact.Path) -TimeoutMinutes 60 `
  -Environment @{ CMTRACEOPEN_DISABLE_UPDATE_CHECKS = '1' } -ContentBindings $RecoveryBindings `
  -ArgumentList @()
if ($RecoveryGuiResult.ExitCode -ne 0) { throw 'Private recovery Full UI observation failed.' }
```

## 9. Capture and validate a real provider database

The source ignored capture test deletes its temporary database. It cannot supply the six retained-database tests. This handoff therefore includes a small public Rust helper and a fail-closed PowerShell wrapper. The wrapper:

- runs the exact ignored native capture smoke test;
- creates a target-private `git archive` of the sealed source;
- adds the helper only to that private copy;
- calls the exact public `capture_providers_to_db` seam;
- keeps the all-or-nothing database isolated from other `.db` files;
- runs all six exact real-database/description selectors with `CMTRACEOPEN_PROVIDER_DB`;
- rechecks the immutable source.

```powershell
$ProviderScript = Join-Path $Handoff 'scripts\New-CMTraceOpenPrivateProviderDatabase.ps1'
$ProviderScriptBinding = Get-CMTraceContentBinding -Path $ProviderScript -Label 'Sealed private provider validation helper'
$ProviderResult = Invoke-PrivateProcess -Id 'private-provider-validation' `
  -FilePath (Get-Command pwsh.exe).Source -WorkingDirectory $Handoff -TimeoutMinutes 180 `
  -ContentBindings @($ProviderScriptBinding) `
  -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'RemoteSigned', '-File', $ProviderScript, '-RepositoryPath', $Source, '-EvidenceRoot', $Evidence)
if ($ProviderResult.ExitCode -ne 0) { throw 'Private provider validation failed.' }
```

The captured private stdout must end with `PRIVATE_PROVIDER_VALIDATION_PASSED`. The first retained test is the authoritative `provider_count > 100` gate. Never substitute the packaged curated databases, which contain only small curated sets. A partial capture is failure, not usable evidence.

## 10. Complete the 68 native/manual gates

`VALIDATION-MATRIX.md` is the operator runbook. It separately covers live subscription and polling, folders and the recovered `childErrors` behavior, real MDMDiagReport accounting, Archive/VSS, remote outcomes and handle stability, destructive clear boundaries, install/uninstall/default apps, interaction/accessibility, saved filters/grouping/highlighting/markers/columns, exact performance measurements, competitor parity, genuine upgrade, and protected release boundaries.

For the NSIS lifecycle, follow the matrix's exact `/CurrentUser /DisableUpdateChecks` invocation, explicitly clear `Run CMTrace Open` before selecting Finish, prove no `cmtrace-open` process exists before the HKCU policy readback, and never kill an unexpected process. Any precondition, installer, readback, payload, provider, or restoration failure stays target-private, blocks its dependent installed gates, and enters the matrix's safe cleanup path; it does not authorize an immediate revert. Only after a successful policy readback may the matrix verify the installed payload hash/PE, bind the complete installed `provider-db` tree to exact source bytes/hashes, and perform the first installed launch. Seal, transport, verify, and obtain acceptance for the privacy-bounded return before separately requesting approval to revert the snapshot. The process-scoped variable used for portable launches does not isolate an application started later by Explorer or Windows Settings.

Three #539 UI requirements are known exact-head product gaps and cannot be marked PASS: saved-filter import/export/favorites/tags/recents management, drag-to-group/pivot, and rule-specific saved-filter row colors. Do not relabel adjacent capabilities as proof.

The returned manual document has no freeform observation field. For each exercised gate, choose a unique safe `evidenceId` and use the already-defined `Save-PrivateManualProof` helper to keep its complete target-local proof in exactly one regular, non-reparse file named `raw-artifacts\manual-evidence\<evidenceId>.proof`. Do not reuse an ID or proof file across gates. The exporter resolves that exact derived path and recomputes its hash; it never returns the file.

```powershell
$EvidenceId = 'full-portable-launch-001'
$NativeObservation = '<replace with the actual native window and responsiveness observation>'
$IndependentReadback = '<replace with the actual independent PE/process/readback result>'
if ($NativeObservation.StartsWith('<') -or $IndependentReadback.StartsWith('<')) {
  throw 'Record the actual target-private observation and independent readback before creating proof.'
}
$ObservationLines = @(
  'gate=full-portable-launch'
  "executedAtUtc=$((Get-Date).ToUniversalTime().ToString('o'))"
  "artifactSha256=$($VerifiedArtifactSha['full-portable'])"
  'nativeArm64Observed=true'
  'independentReadback=true'
  "nativeObservation=$NativeObservation"
  "independentReadbackDetail=$IndependentReadback"
)
$ProofBinding = Save-PrivateManualProof -EvidenceId $EvidenceId -Lines $ObservationLines
# Copy only $ProofBinding.evidenceId and $ProofBinding.evidenceSha256 into this gate's JSON row.
```

For each exercised gate, record only:

- exact gate ID and allowed status/disposition;
- UTC execution time;
- its unique lowercase `evidenceId` slug, which names the exact `.proof` file;
- SHA-256 of the target-local proof file;
- truthful observation/readback booleans (`true` for `PASS`/`FAIL`; a pre-observation `BLOCKED` row may remain `false`);
- exact mapped artifact SHA for `PASS`/`FAIL`, and for `BLOCKED` only if that artifact was reached;
- fixed bounded numeric measurements where the template defines them.

For `PASS`, use disposition `CONFIRMED`. For `FAIL`, use `OBSERVED_FAILURE`. A `BLOCKED` row also requires a target-local proof of the actual blocker and a bounded blocker code, but a blocker reached before native feature observation keeps both observation/readback booleans false and leaves `artifactSha256` null. `NOT_EXERCISED` retains null evidence fields and false observation/readback booleans. Overall status is derived as `MANUAL_FAILED`, `MANUAL_COMPLETE`, or `MANUAL_INCOMPLETE`; the exporter rejects inconsistency.

Remote, polling fallback, Archive/VSS, destructive clear, genuine upgrade, and protected workflows may remain blocked or unexercised, but required gaps prevent full acceptance. Never infer PASS from availability, a skipped test, or a neighboring feature.

## 11. Create the privacy-bounded return

Human-review all 33 sanitized logs and the four returned JSON files. Do not add anything. Create the return parent outside the evidence root, then invoke the exporter:

```powershell
$ReturnParent = 'C:\cmtraceopen-validation\returns'
if (-not (Test-Path -LiteralPath $ReturnParent)) {
  New-Item -ItemType Directory -Path $ReturnParent | Out-Null
}
$ReturnZip = Join-Path $ReturnParent 'pr583-arm64-001.zip'

pwsh.exe -NoProfile -ExecutionPolicy RemoteSigned -File "$Handoff\scripts\New-CMTraceOpenArm64ValidationReturn.ps1" `
  -RepositoryPath $Source `
  -EvidenceRoot $Evidence `
  -OutputPath $ReturnZip
```

The exporter first rechecks the live PR coordinate and the exact detached source/tree/lockfiles/signature/remote/clean state after all manual work. It resolves every exercised manual proof as the unique target-local `raw-artifacts/manual-evidence/<evidenceId>.proof` file and recomputes its SHA-256 without returning it. It then allows exactly four schema-validated JSON documents plus one strict UTF-8 `.log` for each of the 33 automatic gates and an internal checksum. It rejects missing/extra/reordered/duplicate gates, wrong coordinates or architecture, inconsistent derived statuses, partial artifact evidence, provenance/hash disagreement, arbitrary `.txt`, renamed binary data, invalid UTF-8/control bytes, oversized logs, reparse points, unsafe paths, exact target-private literals, and common identity/secret/IP/GUID/UNC/private-domain patterns. It copies to fixed-local-NTFS temporary staging, constructs an unpublished candidate beneath an atomically owned directory in the return parent, reopens the central directory, fresh-extracts it, and rechecks exact inventory, every internal hash, the exact source, and the live PR coordinate. Only then does it publish the ZIP and sidecar with atomic fail-no-overwrite moves and read both public paths back. It never deletes a public return path after publication; if a late conflict or readback fails, preserve the files for inspection and retry with a new `NNN` basename.

The script's `-ContractOnly` parameter is a package-development structural check. It can run off-target, cannot accept an output path, never writes a return ZIP or sidecar, and emits only `RETURN_CONTRACT_OK`; it is not target validation evidence and must never be used for transport.

No pattern scanner can prove arbitrary text private. Human review remains mandatory. Raw logs, binaries, EVTX, provider databases, recordings, screenshots, inventories, and detailed manual proof remain on the target.

Expected: `RETURN_BUNDLE_OK ...`.

Before transport, verify the just-created ZIP against its sidecar, then send the literal outer hash through a trusted out-of-band channel separate from the ZIP and sidecar:

```powershell
$ReturnOuterSha256 = (Get-FileHash -LiteralPath $ReturnZip -Algorithm SHA256).Hash.ToLowerInvariant()
$ReturnSidecarSha256 = ((Get-Content -LiteralPath "$ReturnZip.sha256" -Raw).Trim() -split '\s+')[0]
if ($ReturnSidecarSha256 -cne $ReturnOuterSha256) { throw 'Return ZIP sidecar mismatch.' }
$ReturnOuterSha256
```

The receiver must obtain that trusted literal independently and compare it with both received files before extraction. The adjacent sidecar and the ZIP's internal hashes cannot authenticate one another:

```powershell
$ReceivedReturnZip = 'C:\CMTraceOpen-Return\pr583-arm64-001.zip'
$TrustedReturnSha256 = '<trusted out-of-band lowercase SHA-256 from the target operator>'
$ReceivedReturnSha256 = (Get-FileHash -LiteralPath $ReceivedReturnZip -Algorithm SHA256).Hash.ToLowerInvariant()
$ReceivedSidecarSha256 = ((Get-Content -LiteralPath "$ReceivedReturnZip.sha256" -Raw).Trim() -split '\s+')[0]
if ($ReceivedReturnSha256 -cne $TrustedReturnSha256) { throw 'Return ZIP transport hash mismatch.' }
if ($ReceivedSidecarSha256 -cne $TrustedReturnSha256) { throw 'Return sidecar does not match the trusted hash.' }
```

## Acceptance language

Use only the strongest statement supported by the returned evidence:

- Package only: `Ready for Windows 11 ARM64 target validation.`
- Automatic lane only: `Exact-head automatic ARM64 build/test lane passed; native manual acceptance remains pending.`
- Partial lane: enumerate PASS, FAIL, BLOCKED, and NOT_EXERCISED gate IDs.
- Full acceptance: only when every `requiredForFullAcceptance` row is `PASS`, the manual status is `MANUAL_COMPLETE`, automatic status is `PASSED`, all exact coordinates/hashes agree, and independent target-local evidence remains available.

Any source change invalidates affected evidence. Start a new checkout and evidence root for a new head.
