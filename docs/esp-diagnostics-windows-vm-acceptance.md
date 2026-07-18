# ESP Diagnostics Windows VM Acceptance

This is the release gate for the Full Windows build of CMTrace Open ESP Diagnostics. It is read-only with respect to Windows enrollment and Intune. Run synthetic log, MSI-help, archive, and module-shadow canaries only after real enrollment finishes and only on a disposable VM snapshot.

Do not use an installer unless every build field below identifies the same commit. Do not install an application, initiate MDM sync, retry a deployment, change tenant consent, induce throttling, force PID reuse, or interrupt networking solely to satisfy this checklist.

Mask or crop tenant, user, device, app, policy, script, profile, session, request, and correlation identifiers before evidence leaves the restricted test location. Never capture, decode, paste, or export an access token.

## Acceptance record

### Build under test

Fill this table from the exact-head GitHub workflow and transferred package. A blank or mismatched field blocks testing.

| Field | Recorded value |
| --- | --- |
| Source branch commit (40 characters) | `TBD` |
| CI build commit (PR merge SHA or source SHA) | `TBD` |
| Branch | `codex/esp-diagnostics` |
| Pull request | `266` |
| Workflow name and run ID | `TBD` |
| Artifact ID and name | `TBD` |
| GitHub artifact digest | `TBD` |
| Downloaded archive SHA-256 | `TBD` |
| Installer filename and SHA-256 | `TBD` |
| Installer Authenticode status and signer | `TBD` |
| MSI ProductVersion, ProductCode, and UpgradeCode, or NSIS ProductVersion | `TBD` |
| Expected installed executable bytes and SHA-256 from the selected installer provenance entry | `TBD` |
| Installed executable path and actual SHA-256 | `TBD` |
| This runbook commit | `TBD` |
| Tester, VM, Windows build, and UTC start | `TBD` |

On the VM:

```powershell
$Installer = '<transferred exact-head MSI or NSIS package>'
$ExpectedInstallerSha256 = '<value from exact-head CI evidence>'
$ProvenancePath = '<transferred provenance/windows-build-provenance.json>'
$InstallerItem = Get-Item -LiteralPath $Installer
$ActualInstallerSha256 = (Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash
if ($ActualInstallerSha256 -ne $ExpectedInstallerSha256) {
    throw "Installer hash mismatch: $ActualInstallerSha256"
}

$Provenance = Get-Content -LiteralPath $ProvenancePath -Raw |
    ConvertFrom-Json
if ($Provenance.schemaVersion -ne 2) {
    throw "Unsupported Windows provenance schema: $($Provenance.schemaVersion)"
}
$InstallerMatches = @($Provenance.installers | Where-Object {
    $_.sha256 -eq $ActualInstallerSha256.ToLowerInvariant()
})
if ($InstallerMatches.Count -ne 1) {
    throw "Expected exactly one provenance installer match; found $($InstallerMatches.Count)"
}
$SelectedInstaller = $InstallerMatches[0]
if ([int64]$SelectedInstaller.bytes -ne $InstallerItem.Length) {
    throw 'Installer size does not match its provenance entry.'
}
$ExpectedBundleType = if ($InstallerItem.Extension -ieq '.msi') {
    'msi'
}
elseif ($InstallerItem.Extension -ieq '.exe') {
    'nsis'
}
else {
    throw "Unsupported installer extension: $($InstallerItem.Extension)"
}
if ($SelectedInstaller.bundleType -ne $ExpectedBundleType) {
    throw "Installer bundle type mismatch: $($SelectedInstaller.bundleType)"
}
if ($SelectedInstaller.expectedInstalledExecutable.derivation -ne 'tauriBundleTypeMarkerV1') {
    throw 'Unsupported installed-executable provenance derivation.'
}

Get-AuthenticodeSignature -LiteralPath $Installer |
    Select-Object Status, StatusMessage,
        @{Name='Signer';Expression={$_.SignerCertificate.Subject}}

if ($InstallerItem.Extension -ieq '.msi') {
    $WindowsInstaller = New-Object -ComObject WindowsInstaller.Installer
    $Database = $WindowsInstaller.GetType().InvokeMember(
        'OpenDatabase', 'InvokeMethod', $null, $WindowsInstaller, @($Installer, 0)
    )
    function Get-MsiProperty {
        param([object]$Database, [string]$Name)
        $Query = 'SELECT `Value` FROM `Property` WHERE `Property`=''{0}''' -f $Name
        $View = $null
        $Record = $null
        try {
            $View = $Database.GetType().InvokeMember(
                'OpenView', 'InvokeMethod', $null, $Database, @($Query)
            )
            $null = $View.GetType().InvokeMember(
                'Execute', 'InvokeMethod', $null, $View, $null
            )
            $Record = $View.GetType().InvokeMember(
                'Fetch', 'InvokeMethod', $null, $View, $null
            )
            if ($null -eq $Record) { throw "MSI property missing: $Name" }
            $Record.GetType().InvokeMember(
                'StringData', 'GetProperty', $null, $Record, 1
            )
        }
        finally {
            if ($null -ne $Record) {
                [void][Runtime.InteropServices.Marshal]::ReleaseComObject($Record)
            }
            if ($null -ne $View) {
                [void][Runtime.InteropServices.Marshal]::ReleaseComObject($View)
            }
        }
    }
    [pscustomobject]@{
        ProductVersion = Get-MsiProperty $Database 'ProductVersion'
        ProductCode = Get-MsiProperty $Database 'ProductCode'
        UpgradeCode = Get-MsiProperty $Database 'UpgradeCode'
    } | Format-List
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($Database)
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($WindowsInstaller)
}
else {
    $InstallerItem.VersionInfo | Select-Object FileVersion, ProductVersion
}

# Set after installation.
$Exe = '<installed Full CMTrace Open executable>'
$ExpectedExeSha256 = [string]$SelectedInstaller.expectedInstalledExecutable.sha256
$ExpectedExeBytes = [int64]$SelectedInstaller.expectedInstalledExecutable.bytes
$ExeItem = Get-Item -LiteralPath $Exe
if ($ExeItem.Length -ne $ExpectedExeBytes) {
    throw "Installed executable size mismatch: $($ExeItem.Length)"
}
$ActualExeSha256 = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash
if ($ActualExeSha256 -ne $ExpectedExeSha256) {
    throw "Installed executable hash mismatch: $ActualExeSha256"
}
$ExeItem.VersionInfo |
    Select-Object FileVersion, ProductVersion
```

Record an unsigned CI package as unsigned; never describe it as signed. The artifact must include `provenance/windows-build-provenance.json`. On a pull request, `sourceCommit` is the exact pushed branch head while `buildCommit` is GitHub's tested synthetic merge commit; on a main-branch push they are the same. Record both and verify that the workflow run belongs to that source head. Select exactly one `installers[]` entry by the already-verified installer SHA-256, require its size and `bundleType` to match the transferred package, and compare the installed executable with that same entry's `expectedInstalledExecutable` size and SHA-256. That expectation is derived fail-closed from the exact standalone executable by applying Tauri's installer-specific bundle marker and is labeled `tauriBundleTypeMarkerV1`. The top-level `releaseExecutable` describes the standalone `UNK`-stamped Tauri build output; it intentionally differs from the MSI (`MSI`) and NSIS (`NSS`) installed executables and must not be used as their expected installed-file hash. Separately record the MSI/NSIS properties from the transferred package and confirm its ProductVersion matches the manifest's `packageVersion`; ProductCode and UpgradeCode are local package metadata, not fields claimed by the provenance manifest. A missing, schema-v1, or ambiguous provenance file blocks acceptance even if the displayed product version is correct.

### Tools under test

Use Microsoft Sysinternals Process Monitor obtained from its official distribution. Record the archive and executable hashes, file version, Authenticode status, and signer. Accept the EULA before the enrollment snapshot so the dialog cannot obstruct OOBE.

| Tool field | Recorded value |
| --- | --- |
| ProcMon source URL and retrieval UTC | `TBD` |
| ProcMon archive SHA-256 | `TBD` |
| `Procmon64.exe` SHA-256 and file version | `TBD` |
| Authenticode status and signer | `TBD` |
| ProcMon backing PML and exported CSV paths | `TBD` |

```powershell
$ProcMon = '<path to Procmon64.exe>'
Get-FileHash -LiteralPath $ProcMon -Algorithm SHA256
(Get-Item -LiteralPath $ProcMon).VersionInfo |
    Select-Object FileVersion, ProductVersion
Get-AuthenticodeSignature -LiteralPath $ProcMon |
    Select-Object Status, StatusMessage,
        @{Name='Signer';Expression={$_.SignerCertificate.Subject}}
```

### Snapshot sequence

Use separate snapshots so synthetic evidence cannot contaminate the enrollment observation.

1. `ESP-00-clean`: Windows installed, not enrolled, no CMTrace Open.
2. `ESP-01-staged`: exact installer and verified ProcMon staged; EULA accepted; no canaries.
3. `ESP-02-live-complete`: real OOBE/ESP observation complete, before post-enrollment canaries.
4. `ESP-03-post-enrollment`: disposable canary, Graph, accessibility, and cleanup work.

Retain the clean and staged snapshots until all evidence is accepted. Revert rather than trying to undo enrollment or network changes.

## Phase A: pre-OOBE staging

1. Verify every build/tool field above.
2. Install the Full build. Lite is not an acceptable substitute.
3. Confirm CMTrace Open starts and ESP Diagnostics is a single workspace page with no left sidebar.
4. Confirm **Live evidence and logs** is collapsed by default and the prominent **Open live logs** action is visible.
5. Close CMTrace Open. Configure ProcMon to use UTC display and a named PML backing file in the restricted evidence folder.
6. Save snapshot `ESP-01-staged`.

Prepare the path/operation filters before OOBE, but start capture only when the VM is ready for the real observation. Add exact process IDs immediately after CMTrace Open and its children launch. Include:

- the exact CMTrace Open PID after launch;
- its observed child PIDs, especially the inbox Windows PowerShell child used for Delivery Optimization;
- registry and file activity under the Intune Management Extension, MDM/Provisioning, Autopilot, CloudExperienceHost, DeviceManagement-Enterprise-Diagnostics-Provider, Windows Installer, and approved temporary evidence roots;
- process create/exit activity needed to bind each child to the app.

Do not filter only for writes. The evidence must show both the expected reads and the absence of mutation. WebView2/runtime writes under CMTrace Open's own application-data location are expected and must be labeled separately from diagnostic-source access.

## Phase B: real OOBE and ESP observation

### Start and elevation

1. Launch normally, open **ESP Diagnostics**, and confirm **Administrator access recommended**, **Coverage impact**, **Restart as administrator**, and **Not elevated**.
2. Start live diagnostics. The UI must enter **Starting** promptly and offer **Stop live diagnostics** while providers initialize.
3. Stop during **Starting** once. No later provider or live update may resurrect the stopped session.
4. Start normally again and record every restricted or permission-denied source in **Local coverage**.
5. Select **Restart as administrator**, accept same-account UAC, and verify the original process exits.
6. The elevated process must open directly in ESP Diagnostics without accepting an arbitrary evidence path. Confirm **Elevated**, then start live diagnostics.
7. Compare coverage by source. Protected registry, event log, process-command-line, SYSTEM-temp, or TPM coverage may improve when those sources exist; no hard-coded source count is required.

Fail if denied reads disappear instead of becoming coverage gaps, the restart opens another workspace, the original process remains alive, or any remediation is performed.

### Observe enrollment

Start the elevated session before assigned applications begin and leave it running through ESP.

- Keep logs collapsed initially. The **Open live logs** badge must gain unread evidence while collection continues.
- Navigate away and back; the same live session must remain active.
- Exercise **Open live logs**, resize the dock, **Expand live logs**, **Restore docked live logs**, and **Close live logs**.
- Closing by button and Escape must return focus to **Open live logs**. A programmatic close must not steal focus.
- Confirm IME and deployment logs attach and append without restarting.
- Confirm newly created installer logs under curated deployment roots, approved shallow temp roots, or an exact path observed in a trusted installer command attach without a drive-wide scan.
- Record any rejected path, source cap, partial coverage, rotation, truncation, or reset boundary.
- Confirm the rest of the page—phase, blockers, workload table, MSI status, evidence sections, Graph panel, and live activity—continues to update while the dock is collapsed.

For **What MSIEXEC is doing now**:

- no process: **No active MSI installer process observed** plus the warning that this is not proof of completion;
- one or more processes: one row per `{ PID, startTimeUtc }`, with parent, sanitized command line, active log path, evidence links, and correlation confidence;
- when a real assigned MSI exists, verify exact PID/log/product/app correlation;
- if there is no real MSI, record `not exercised`; do not install one for the test;
- if Windows naturally reuses a PID, the new start time must prevent inherited correlation. Never force PID reuse.

Capture the real failure or success state, coverage gaps, action recommendations, and raw local identifiers. The workspace must not retry an install, sync MDM, alter enrollment, start a service, or write to diagnostic roots.

Stop diagnostics at the end of ESP. Ten seconds later ProcMon must show no new discovery, tail, process-sampling, WMI, event-log, or Delivery Optimization acquisition. Idle reusable worker threads are acceptable only when they perform no query.

Save the restricted PML and a UTC CSV export, then save snapshot `ESP-02-live-complete`.

## Phase C: post-enrollment canaries

With CMTrace Open and capture tools stopped, create a new VM snapshot or full clone named `ESP-03-post-enrollment` from the accepted post-enrollment state. Boot that disposable state and record its snapshot/clone ID before creating any synthetic evidence. Run this entire phase only from `ESP-03-post-enrollment`. Each block uses `try/finally`; cleanup is part of the gate.

### Live tail, resets, MSI identity, and redaction

The sentinel is intentionally visible in the PowerShell command history and OS process tools. Its required absence applies only to CMTrace Open-produced UI, snapshots, application logs, copy, and export surfaces. Do not use an OS-level capture containing the canary command as proof of an app leak.

```powershell
$Tail = Join-Path $env:TEMP 'msi-cmtraceopen-tail-canary.log'
$Rotated = "$Tail.old"
$Sentinel = 'CMTRACEOPEN_REDACTION_CANARY'
$CanaryProcesses = [System.Collections.Generic.List[object]]::new()

try {
    if ((Test-Path -LiteralPath $Tail) -or (Test-Path -LiteralPath $Rotated)) {
        throw 'Canary paths already exist; aborting without overwrite.'
    }

    Set-Content -LiteralPath $Tail -Encoding UTF8 -Value "$(Get-Date -Format o) CANARY_INITIAL"
    $Process = Start-Process -FilePath "$env:WINDIR\System32\msiexec.exe" `
        -ArgumentList "/? /L*V `"$Tail`" --token $Sentinel" -PassThru
    try {
        $Identity = [pscustomobject]@{
            Pid = $Process.Id
            StartTimeUtc = $Process.StartTime.ToUniversalTime()
            LogPath = $Tail
        }
        $CanaryProcesses.Add($Identity)
        $Identity | Format-List
    }
    catch {
        try {
            $Process.Refresh()
            if (-not $Process.HasExited) {
                $Process.Kill()
                if (-not $Process.WaitForExit(5000)) {
                    throw 'owned MSI help process did not exit within five seconds'
                }
            }
        }
        catch {
            throw "Could not secure the owned MSI help process after identity capture failed: $($_.Exception.Message)"
        }
        Write-Warning 'MSI help exited before a safe PID/start-time identity could be saved; active-process canary is not exercised.'
    }

    # Perform the UI checks below before continuing.
    Read-Host 'Press Enter after the initial attach/redaction checks'

    Add-Content -LiteralPath $Tail -Value "$(Get-Date -Format o) CANARY_APPEND_WHILE_COLLAPSED"
    Read-Host 'Press Enter after unread/search checks'

    Move-Item -LiteralPath $Tail -Destination $Rotated
    Set-Content -LiteralPath $Tail -Encoding UTF8 -Value "$(Get-Date -Format o) CANARY_ROTATED_GENERATION"
    Read-Host 'Press Enter after the rotation reset boundary appears'

    1..200 | ForEach-Object { Add-Content -LiteralPath $Tail -Value "CANARY_PADDING_$_" }
    Start-Sleep -Seconds 3
    Set-Content -LiteralPath $Tail -Encoding UTF8 -Value "$(Get-Date -Format o) CANARY_TRUNCATED_GENERATION"
    Read-Host 'Press Enter after the truncation reset boundary appears'

    Read-Host 'Select Stop live diagnostics, then press Enter'
    Add-Content -LiteralPath $Tail -Value "$(Get-Date -Format o) CANARY_AFTER_STOP_MUST_NOT_APPEAR"
    Start-Sleep -Seconds 10
    Read-Host 'Confirm the post-stop line is absent in CMTrace Open and ProcMon shows no new source read, then press Enter'
    Read-Host 'Start and stop live diagnostics once more; after confirming no ownership conflict, press Enter'
}
finally {
    $CleanupFailures = [System.Collections.Generic.List[string]]::new()
    foreach ($Identity in $CanaryProcesses) {
        try {
            $Candidate = Get-Process -Id $Identity.Pid -ErrorAction SilentlyContinue
            if ($Candidate -and $Candidate.ProcessName -ieq 'msiexec' -and
                $Candidate.StartTime.ToUniversalTime() -eq $Identity.StartTimeUtc) {
                Stop-Process -Id $Identity.Pid -ErrorAction Stop
                $Candidate.WaitForExit(5000)
            }
            $Remaining = Get-Process -Id $Identity.Pid -ErrorAction SilentlyContinue
            if ($Remaining -and $Remaining.ProcessName -ieq 'msiexec' -and
                $Remaining.StartTime.ToUniversalTime() -eq $Identity.StartTimeUtc) {
                $CleanupFailures.Add("canary process $($Identity.Pid) is still running")
            }
        }
        catch {
            $CleanupFailures.Add("canary process $($Identity.Pid): $($_.Exception.Message)")
        }
    }
    foreach ($CanaryPath in @($Tail, $Rotated)) {
        try {
            Remove-Item -LiteralPath $CanaryPath -Force -ErrorAction Stop
        }
        catch {
            if (Test-Path -LiteralPath $CanaryPath) {
                $CleanupFailures.Add("canary path remains: $CanaryPath")
            }
        }
    }
    if ($CleanupFailures.Count -ne 0) {
        throw "Canary cleanup incomplete: $($CleanupFailures -join '; ')"
    }
}
```

If `msiexec /?` exits immediately, record the active-process canary as `not exercised`; do not substitute an installation. Pass criteria:

- the active card is bound to the saved `{ PID, startTimeUtc, logPath }` when the process remains active;
- the sentinel is `[REDACTED]` everywhere CMTrace Open produces output; record copy/export as `not exposed` if the shipping UI offers no such action;
- the temp log attaches after session start;
- append while collapsed increases unread count and is searchable;
- rotation and truncation each produce **Source reset boundary observed; exact source unavailable** with distinct provenance;
- after **Stop live diagnostics**, an appended `CANARY_AFTER_STOP_MUST_NOT_APPEAR` line never enters the UI and no new source read occurs;
- a second start/stop has no ownership conflict.

For a multiple-process state, make a separate copy of the complete script and add two help-only launches with unique log names inside the same `try` block, before the UI prompts. Add each `{ PID, startTimeUtc, logPath }` to that run's `$CanaryProcesses` list so its single `finally` owns every cleanup. Do not try to reuse the list after the script exits. Never stop a PID by number alone.

### Delivery Optimization module-shadow defense

Use one local-administrator account throughout: launch CMTrace Open non-elevated, then elevate that same account through the app. Do not use an alternate administrator credential. Abort if a CurrentUser `DeliveryOptimization` module already exists.

```powershell
$CurrentUserModuleBase = $env:PSModulePath -split ';' |
    Where-Object {
        $_ -and [IO.Path]::GetFullPath($_).StartsWith(
            [IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\') + '\',
            [StringComparison]::OrdinalIgnoreCase
        )
    } | Select-Object -First 1

if (-not $CurrentUserModuleBase) { throw 'No CurrentUser module path is present.' }

$ShadowRoot = Join-Path $CurrentUserModuleBase 'DeliveryOptimization'
$Marker = Join-Path $env:TEMP 'cmtraceopen-do-shadow-imported.txt'
if ((Test-Path -LiteralPath $ShadowRoot) -or (Test-Path -LiteralPath $Marker)) {
    throw 'A shadow root or prior marker already exists; abort without deleting either artifact.'
}
$ExistingInstances = @(Get-Process -Name 'cmtrace-open' -ErrorAction SilentlyContinue)
if ($ExistingInstances.Count -ne 0) {
    throw 'Close every existing CMTrace Open process before the module-shadow test.'
}

try {
    New-Item -ItemType Directory -Path $ShadowRoot | Out-Null
    @'
$marker = Join-Path $env:TEMP 'cmtraceopen-do-shadow-imported.txt'
Set-Content -LiteralPath $marker -Value 'CURRENT_USER_SHADOW_IMPORTED'
function Get-DeliveryOptimizationPerfSnapThisMonth { throw 'CURRENT_USER_SHADOW_EXECUTED' }
function Get-DeliveryOptimizationLog { throw 'CURRENT_USER_SHADOW_EXECUTED' }
Export-ModuleMember -Function Get-DeliveryOptimizationPerfSnapThisMonth,Get-DeliveryOptimizationLog
'@ | Set-Content -LiteralPath (Join-Path $ShadowRoot 'DeliveryOptimization.psm1') -Encoding UTF8

    New-ModuleManifest -Path (Join-Path $ShadowRoot 'DeliveryOptimization.psd1') `
        -RootModule 'DeliveryOptimization.psm1' -ModuleVersion '99.0.0' `
        -FunctionsToExport @(
            'Get-DeliveryOptimizationPerfSnapThisMonth',
            'Get-DeliveryOptimizationLog'
        )
    $App = Start-Process -FilePath $Exe -ArgumentList '--workspace=esp-diagnostics' -PassThru
    Start-Sleep -Seconds 2
    $App.Refresh()
    if ($App.HasExited) {
        throw 'The launched instance exited before testing; possible single-instance routing invalidates this run.'
    }
    $AppIdentity = [pscustomobject]@{
        Pid = $App.Id
        StartTimeUtc = $App.StartTime.ToUniversalTime()
        Executable = $Exe
    }
    $AppIdentity | Format-List
    Read-Host 'Use Restart as administrator, start diagnostics, then press Enter'

    if (Test-Path -LiteralPath $Marker) {
        throw 'CurrentUser shadow module was imported.'
    }
}
finally {
    Remove-Item -LiteralPath $ShadowRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Marker -Force -ErrorAction SilentlyContinue
}
```

ProcMon and process evidence must prove the child is the inbox Windows PowerShell executable and that the command:

- resets `PSModulePath` to `$PSHOME\Modules`;
- imports only `$PSHOME\Modules\DeliveryOptimization\DeliveryOptimization.psd1`;
- invokes module-qualified Delivery Optimization commands;
- never reads the CurrentUser shadow path.

The process tree must begin with the saved non-elevated `$AppIdentity`, show that exact process exiting during **Restart as administrator**, and identify the replacement elevated CMTrace Open PID/start time. If another instance receives a single-instance message or the saved launch identity is not the process that performed the relaunch, discard the run.

Delivery Optimization must return evidence or an explicit coverage result without `CURRENT_USER_SHADOW_EXECUTED`.

### Captured bundle staging and cleanup

Use a tenant-sanitized fixture whose recipe and SHA-256 are stored with the restricted test evidence. Record the source hash and never modify the fixture in place. Exercise:

1. a valid manifest folder or archive;
2. a malformed/truncated copy that must fail closed;
3. a cancellation path when exposed by the exact build or native acceptance harness.

Before and after each case, search the process temp directory for both prefixes:

```powershell
Get-ChildItem -LiteralPath $env:TEMP -Force -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -like 'cmtrace-open-esp-archive-*' -or
        $_.Name -like 'cmtraceopen-esp-intake-*'
    } | Select-Object FullName, CreationTimeUtc, LastWriteTimeUtc
```

No new directory may remain after success, failure, or cancellation. The truncated copy must never be parsed as the complete original. If cancellation is not reachable in the shipping UI, mark the live case `not exposed` and attach the exact automated cancellation-test result; do not simulate it by killing Windows during enrollment.

## Optional Graph/WAM acceptance

Local diagnostics are mandatory. Graph enrichment is conditional on the existing option being enabled and an explicit user sign-in. An authenticated partial connection may also use the explicit **Request missing permissions** action in Settings; that action may open WAM for the fixed declared permission union, but ESP startup and refresh never invoke it. When Graph is disabled or unavailable, raw local logs and identifiers must remain usable as-is.

### Prerequisites

- public client ID: `14d82eec-204b-4c2f-b7e8-296a70dab67e`;
- delegated read scopes only:
  - `DeviceManagementManagedDevices.Read.All`;
  - `DeviceManagementServiceConfig.Read.All`;
  - `DeviceManagementApps.Read.All`;
  - `DeviceManagementConfiguration.Read.All`;
  - `DeviceManagementScripts.Read.All`;
- written authorization for an isolated, non-production test tenant and disposable test account before exercising consent, denial, or administrator-consent paths; production tenants and real customer accounts are out of scope, and unavailable cases must be recorded as `not exercised`;
- tenant consent and the signed-in account's Intune read roles must be sufficient for the sections being tested;
- the native five-scope union is the only permission input: neither the frontend command nor any IPC caller may provide scope names;
- capability display may infer short names from the `scp` claim, but the token itself must remain memory-only and must never appear in evidence;
- Graph 401/403 responses, not decoded claims, are authoritative.

Record live results only from the authorized isolated tenant. Automated or static evidence may support a row, but it must not be reported as live Windows acceptance.

### State matrix

| State | Required result |
| --- | --- |
| Graph option off, current session and cold start | Local evidence only; no WAM prompt, Graph request, warning, or loss of raw IDs. |
| Enable option in the current Settings session | The confirmation enables Graph and reads cached status; opening ESP or starting/refreshing local diagnostics does not itself initiate WAM. |
| Explicit **Sign in with Windows** | HWND-parented WAM interaction; five capability rows; no token display. |
| Authenticated partial status in Settings | The missing declared permissions are listed and **Request missing permissions** is visible. The button is absent for disconnected or complete status. Merely opening or refreshing Settings does not invoke it. |
| Click **Request missing permissions** | Exactly one zero-argument `graph_request_missing_permissions` call; other Graph actions remain locked while it runs; any WAM window is parented to CMTrace Open; no ESP fetch is started. |
| WAM permission request remains pending | Settings stays responsive for the full wait: switch to another Settings tab and back, interact with the Graph enable/disable control, and confirm the rest of the window continues repainting. Returning to the Graph tab shows the same pending action rather than starting a status refresh or second WAM request. Disabling Graph invalidates the pending result without freezing the UI. |
| Permission upgrade succeeds | Returned capabilities are a strict superset, every previously working capability remains available, the capability rows update without sign-out, and the button disappears only when no declared permission remains missing. |
| Permission result is unchanged or administrator consent is required | The partial connection and all previously working capabilities remain active. Settings explains that no permission changed and that tenant administrator consent may be required; it does not claim to grant administrator consent. |
| Permission request is cancelled, denied, or fails | The partial connection and all previously working capabilities remain active; the inline outcome is sanitized, no automatic retry or second WAM interaction occurs, and status is not changed to disconnected. Denial guidance states: `Consent was not granted. Your existing Graph permissions remain available. A tenant administrator may need to approve the missing permissions.` |
| Permission result is stale | The newer authoritative Graph state wins. The stale completion never restores an older connection, removes a newer one, or changes the active action; Settings shows the status returned for the winning generation without exposing rejected provider text. |
| Any consent, denial, or administrator-consent exercise | Use only the pre-authorized isolated test tenant and disposable account. If that boundary or required consent setup is unavailable, record `not exercised`; do not use a production tenant or customer identity. |
| ESP Graph refresh while permissions are partial | ESP invokes only its fetch/cancel commands as needed. It never invokes `graph_request_missing_permissions`, never opens WAM, and preserves local evidence plus the sections allowed by the retained capabilities. |
| Cold start with the option already persisted on | The existing application startup flow may call WAM before ESP opens. Record whether cached credentials complete silently or WAM becomes interactive; attribute this to startup, not ESP. |
| Restart after an upgraded, unchanged, cancelled, denied, failed, or stale outcome | With otherwise valid cached credentials, no permission-upgrade prompt appears. The new action never runs automatically on restart; any separate interaction from the pre-existing startup authentication path must be recorded and attributed separately. |
| Startup authentication unavailable or cancelled | ESP shows `GraphNotConnected`; it does not queue enrichment or open a second WAM interaction. |
| Connected, before refresh | Existing local session remains unchanged; enrichment does not start automatically. |
| Explicit refresh | Progress followed by complete or section-level partial result; local evidence remains. |
| Cancel refresh | Remote request stops; local evidence remains. |
| Disable during refresh | Overlay cancels/clears; local evidence remains; WAM is not signed out. |
| 401/403, if naturally observed | 401 invalidates once; 403 is isolated to its section. |
| Missing scope, offline, throttled, ambiguous device, beta unknown | Record only if naturally observed or exercised in an isolated test tenant; otherwise `not exercised`. |
| Permission-upgrade IPC and log inspection | IPC exposes only the structured outcome, sanitized message, and projected status. Application logs, IPC payloads, evidence, screenshots, and exports contain no access token, authorization header, raw provider payload, or account-object internals. |
| Caller attempts to supply `scopes` or another permission list | The production command has no caller-supplied permission argument and builds the complete five-scope union natively with `resource=https://graph.microsoft.com`; the development bridge rejects the protected command instead of forwarding input. |

Static review evidence must additionally distinguish the existing persisted-option startup connection, the Settings-only permission action, and ESP behavior. It must show the fixed five short delegated-scope union with the required `resource=https://graph.microsoft.com` WAM property, no caller-controlled scope input, direct ESP Graph operations using GET, bounded `$batch` operations using a POST envelope whose subrequests are GET-only, bounded retry/pagination/body limits, zero upgrade calls from startup/ESP refresh, and token/authorization-header redaction.

Compare enriched values read-only with the Intune portal and record `match`, `mismatch`, `not found`, or `not exercised` for managed device, Autopilot identity/group tag, profile, declared assignments and filters, Autopilot events, ESP configuration, apps, scripts, and policy state. Declared targeting must never be presented as effective group membership or proof that an app blocks ESP.

## Read-only ProcMon and optional network evidence

For Graph-off collection, one explicit Graph refresh, archive success/failure, and stop, retain the native PML and a UTC CSV export. Pass requires:

- diagnostic registry activity is query/open/enumerate only;
- evidence roots are read/metadata only, with no create, write, rename, set, or delete;
- no MDM sync, service-control, installer, remediation, or enrollment process is started;
- Delivery Optimization uses the trusted inbox PowerShell/module path;
- app writes are limited to its own logs/settings/WebView2 data, explicit user export, and bounded archive staging;
- archive/intake staging is removed;
- no acquisition continues ten seconds after Stop.

Optional bounded packet-header capture is allowed only from an isolated disposable snapshot and must remain in the restricted evidence location. `--pkt-size 0` is forbidden because it captures complete packets. Record `pktmon status` and `pktmon filter list` before capture; do not run `pktmon filter remove` or modify shared filters. If another capture is active or existing filters make the result ambiguous, skip the live packet gate and revert to a clean snapshot instead of stopping or altering work you do not own.

```powershell
$Evidence = '<approved restricted evidence folder>'
$CaptureId = Get-Date -Format 'yyyyMMdd-HHmmss'
$Etl = Join-Path $Evidence "graph-$CaptureId.etl"
$Pcap = Join-Path $Evidence "graph-$CaptureId.pcapng"
$StatusBeforePath = Join-Path $Evidence "pktmon-status-before-$CaptureId.txt"
$StatusAfterPath = Join-Path $Evidence "pktmon-status-after-$CaptureId.txt"
$StatusRetryPath = Join-Path $Evidence "pktmon-status-after-retry-$CaptureId.txt"
$FiltersBeforePath = Join-Path $Evidence "pktmon-filters-before-$CaptureId.txt"
$FiltersAfterPath = Join-Path $Evidence "pktmon-filters-after-$CaptureId.txt"
$StopAttemptPath = Join-Path $Evidence "pktmon-stop-attempt-$CaptureId.txt"
$StopRetryPath = Join-Path $Evidence "pktmon-stop-retry-$CaptureId.txt"
$CaptureStartedByThisRun = $false
$EvidenceWriteFailures = @()

if (-not (Test-Path -LiteralPath $Evidence -PathType Container)) {
    throw "Restricted evidence directory does not exist: $Evidence"
}
foreach ($OutputPath in @(
    $Etl, $Pcap, $StatusBeforePath, $StatusAfterPath, $StatusRetryPath,
    $FiltersBeforePath, $FiltersAfterPath, $StopAttemptPath, $StopRetryPath
)) {
    if (Test-Path -LiteralPath $OutputPath) {
        throw "Packet evidence output already exists: $OutputPath"
    }
}

$StatusBefore = & pktmon status 2>&1
$StatusExit = $LASTEXITCODE
$StatusBefore | Set-Content -LiteralPath $StatusBeforePath -ErrorAction Stop
if ($StatusExit -ne 0) { throw "pktmon status failed: $StatusExit" }

$FiltersBefore = & pktmon filter list 2>&1
$FilterExit = $LASTEXITCODE
$FiltersBefore | Set-Content -LiteralPath $FiltersBeforePath -ErrorAction Stop
if ($FilterExit -ne 0) { throw "pktmon filter list failed: $FilterExit" }

$OwnershipConfirmation = Read-Host 'After reviewing status, type INACTIVE only if no capture is running'
if ($OwnershipConfirmation -cne 'INACTIVE') {
    throw 'Packet capture ownership was not established; do not stop another capture.'
}

try {
    & pktmon start --capture --comp nics --pkt-size 128 --file-size 128 `
        --log-mode circular --file-name $Etl
    if ($LASTEXITCODE -ne 0) { throw "pktmon start failed: $LASTEXITCODE" }
    $CaptureStartedByThisRun = $true

    Read-Host 'Run one Graph-off session and one explicit Graph refresh, then press Enter'
}
finally {
    if ($CaptureStartedByThisRun) {
        $StopOutput = & pktmon stop 2>&1
        $StopExit = $LASTEXITCODE
        $StopOutput | Out-Host
        try {
            $StopOutput | Set-Content -LiteralPath $StopAttemptPath -ErrorAction Stop
        }
        catch {
            $EvidenceWriteFailures += "initial stop output: $($_.Exception.Message)"
        }

        # Status verification remains inside finally so an error in the capture body cannot
        # bypass termination checks and leave sensitive acquisition running.
        $StatusAfter = & pktmon status 2>&1
        $StatusAfterExit = $LASTEXITCODE
        $StatusAfter | Out-Host
        try {
            $StatusAfter | Set-Content -LiteralPath $StatusAfterPath -ErrorAction Stop
        }
        catch {
            $EvidenceWriteFailures += "post-stop status: $($_.Exception.Message)"
        }
        if ($StatusAfterExit -ne 0) {
            throw "Capture state is unknown because pktmon status failed after stop ($StatusAfterExit). Immediately shut down or revert this disposable VM; do not continue and do not issue an unverified stop."
        }

        $StoppedConfirmation = Read-Host 'Review the displayed post-stop status. Type INACTIVE only if capture is stopped'
        if ($StoppedConfirmation -cne 'INACTIVE') {
            $RetryConfirmation = Read-Host 'Type RETRY-OWNED only if this runbook capture is still active and no other operator or tool could have replaced it; otherwise immediately shut down or revert the VM'
            if ($RetryConfirmation -cne 'RETRY-OWNED') {
                throw 'Runbook-owned capture termination was not established. Immediately shut down or revert this disposable VM; do not continue or issue a later generic pktmon stop.'
            }

            $RetryOutput = & pktmon stop 2>&1
            $RetryExit = $LASTEXITCODE
            $RetryOutput | Out-Host
            try {
                $RetryOutput | Set-Content -LiteralPath $StopRetryPath -ErrorAction Stop
            }
            catch {
                $EvidenceWriteFailures += "retry stop output: $($_.Exception.Message)"
            }

            $StatusRetry = & pktmon status 2>&1
            $StatusRetryExit = $LASTEXITCODE
            $StatusRetry | Out-Host
            try {
                $StatusRetry | Set-Content -LiteralPath $StatusRetryPath -ErrorAction Stop
            }
            catch {
                $EvidenceWriteFailures += "post-retry status: $($_.Exception.Message)"
            }
            if ($StatusRetryExit -ne 0) {
                throw "Capture state is unknown because pktmon status failed after the ownership-safe retry ($StatusRetryExit). Immediately shut down or revert this disposable VM."
            }
            $RetryStoppedConfirmation = Read-Host 'Review the displayed post-retry status. Type INACTIVE only if capture is stopped'
            if ($RetryStoppedConfirmation -cne 'INACTIVE') {
                throw 'Capture remains active or ambiguous after the ownership-safe retry. Immediately shut down or revert this disposable VM; do not continue or issue another stop.'
            }
            if ($RetryExit -ne 0) {
                Write-Warning "pktmon retry returned $RetryExit, but the displayed status was independently confirmed inactive. Record the command failure in the acceptance result."
            }
        }
        if ($StopExit -ne 0) {
            Write-Warning "pktmon stop returned $StopExit. The workflow continued only after displayed status was independently confirmed inactive. Record the command failure in the acceptance result."
        }
        if ($EvidenceWriteFailures.Count -ne 0) {
            throw "Capture is confirmed inactive, but required packet evidence could not be saved: $($EvidenceWriteFailures -join '; ')"
        }
    }
}

& pktmon etl2pcap $Etl --out $Pcap
if ($LASTEXITCODE -ne 0) { throw "pktmon etl2pcap failed: $LASTEXITCODE" }

$FiltersAfter = & pktmon filter list 2>&1
$FiltersAfterExit = $LASTEXITCODE
$FiltersAfter | Set-Content -LiteralPath $FiltersAfterPath -ErrorAction Stop
if ($FiltersAfterExit -ne 0) { throw "pktmon filter list failed after capture: $FiltersAfterExit" }
```

The 128-byte packet limit and 128 MB circular file cap bound the capture but do not make it non-sensitive. Graph-off must produce no Graph connection. Identity traffic is expected only during the existing startup flow or explicit sign-in; Graph traffic is expected only during explicit enrichment. TLS evidence proves destination and timing, not the HTTP verb; use static review to prove direct GET operations and the bounded `$batch` POST envelope with GET-only subrequests.

## Native accessibility and responsive layout

Use the real Tauri app at 1200×800 and 1440×900 with Windows animation effects both enabled and disabled. Mask identifiers in captures.

- Tab through the workspace header, Graph, phase, actions, workloads, MSI state, evidence, and live-log controls; focus is always visible.
- Settings traps focus; Left/Right arrows, Home, and End move tabs; Escape closes and restores focus.
- Closing live logs restores focus to **Open live logs**.
- On **Resize live evidence and logs**, Arrow Up/Down changes height, Home selects minimum, End selects maximum, and Narrator announces the separator value.
- A virtualized evidence row is keyboard reachable; Enter/Space selects it and exposes **Raw evidence provenance**.
- Status and correlation confidence are understandable without color.
- With animations disabled, no function or state is lost.
- At both sizes, the no-sidebar single-page workspace remains usable without clipped primary actions.

Capture at least: elevated/collapsed, docked logs, full-page logs, non-elevated recommendation, active MSI when naturally present, and Device Preparation only when real evidence exists.

## Final cleanup and decision

1. Stop live diagnostics and any Graph request.
2. Start/stop once more to prove session ownership was released.
3. Close only canary processes whose name and start time match the saved identity.
4. Remove canary logs, rotated files, sanitized fixture copies, shadow module, and marker.
5. Confirm no `cmtrace-open-esp-archive-*` or `cmtraceopen-esp-intake-*` directory remains.
6. Close CMTrace Open and verify the process and its acquisition children exit.
7. Stop only a ProcMon capture owned by this test. The packet block must have ended with a displayed and saved `INACTIVE` confirmation. If it did not, stop acceptance and immediately shut down or revert the disposable VM; do not proceed through generic cleanup. After confirmed termination, never issue a later `pktmon stop`, because that could stop an unrelated capture. Retain restricted evidence according to policy.
8. Revert the disposable post-enrollment snapshot.

Any remediation, tenant write, installer retry, MDM sync, unexpected diagnostic-root write, token disclosure, unrelated process-command-line capture, unsafe path traversal, or post-stop acquisition is an immediate acceptance failure.

Final result: `PASS / FAIL / BLOCKED`

Open items and evidence locations: `TBD`
