# ESP Diagnostics Windows VM Acceptance

This is the release gate for the Full Windows build of CMTrace Open ESP Diagnostics. It is read-only with respect to Windows enrollment and Intune. Run synthetic log, MSI-help, archive, and module-shadow canaries only after real enrollment finishes and only on a disposable VM snapshot.

Do not use an installer unless every build field below identifies the same commit. Do not install an application, initiate MDM sync, retry a deployment, change tenant consent, induce throttling, force PID reuse, or interrupt networking solely to satisfy this checklist.

Mask or crop tenant, user, device, app, policy, script, profile, session, request, and correlation identifiers before evidence leaves the restricted test location. Never capture, decode, paste, or export an access token.

## Acceptance record

### Build under test

Fill this table from the exact-head GitHub workflow and transferred package. A blank or mismatched field blocks testing.

| Field | Recorded value |
| --- | --- |
| Source commit (40 characters) | `TBD` |
| Branch | `codex/esp-diagnostics` |
| Pull request | `266` |
| Workflow name and run ID | `TBD` |
| Artifact ID and name | `TBD` |
| GitHub artifact digest | `TBD` |
| Downloaded archive SHA-256 | `TBD` |
| Installer filename and SHA-256 | `TBD` |
| Installer Authenticode status and signer | `TBD` |
| Package version | `TBD` |
| Installed executable path and SHA-256 | `TBD` |
| This runbook commit | `TBD` |
| Tester, VM, Windows build, and UTC start | `TBD` |

On the VM:

```powershell
$Installer = '<transferred exact-head MSI or NSIS package>'
$ExpectedInstallerSha256 = '<value from exact-head CI evidence>'
$ActualInstallerSha256 = (Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash
if ($ActualInstallerSha256 -ne $ExpectedInstallerSha256) {
    throw "Installer hash mismatch: $ActualInstallerSha256"
}

Get-AuthenticodeSignature -LiteralPath $Installer |
    Select-Object Status, StatusMessage,
        @{Name='Signer';Expression={$_.SignerCertificate.Subject}}

$InstallerVersion = (Get-Item -LiteralPath $Installer).VersionInfo.ProductVersion
$InstallerVersion

# Set after installation.
$Exe = '<installed Full CMTrace Open executable>'
Get-FileHash -LiteralPath $Exe -Algorithm SHA256
(Get-Item -LiteralPath $Exe).VersionInfo |
    Select-Object FileVersion, ProductVersion
```

Record an unsigned CI package as unsigned; never describe it as signed. The artifact provenance, hashes, package version, installed executable hash, and source commit must still agree.

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

Run this entire phase from `ESP-03-post-enrollment`. Each block uses `try/finally`; cleanup is part of the gate.

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
    $Identity = [pscustomobject]@{
        Pid = $Process.Id
        StartTimeUtc = $Process.StartTime.ToUniversalTime()
        LogPath = $Tail
    }
    $CanaryProcesses.Add($Identity)
    $Identity | Format-List

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
}
finally {
    foreach ($Identity in $CanaryProcesses) {
        $Candidate = Get-Process -Id $Identity.Pid -ErrorAction SilentlyContinue
        if ($Candidate -and $Candidate.ProcessName -ieq 'msiexec' -and
            $Candidate.StartTime.ToUniversalTime() -eq $Identity.StartTimeUtc) {
            Stop-Process -Id $Identity.Pid -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -LiteralPath $Tail,$Rotated -Force -ErrorAction SilentlyContinue
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

For a multiple-process state, repeat the help-only launch with two unique log names, store all three identities, and use the same identity check in `finally`. Never stop a PID by number alone.

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
if (Test-Path -LiteralPath $ShadowRoot) {
    throw 'CurrentUser DeliveryOptimization already exists; aborting.'
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
    Remove-Item -LiteralPath $Marker -Force -ErrorAction SilentlyContinue

    Start-Process -FilePath $Exe -ArgumentList '--workspace=esp-diagnostics'
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

Local diagnostics are mandatory. Graph enrichment is conditional on the existing option being enabled and an explicit user sign-in. When Graph is disabled or unavailable, raw local logs and identifiers must remain usable as-is.

### Prerequisites

- public client ID: `14d82eec-204b-4c2f-b7e8-296a70dab67e`;
- delegated read scopes only:
  - `DeviceManagementManagedDevices.Read.All`;
  - `DeviceManagementServiceConfig.Read.All`;
  - `DeviceManagementApps.Read.All`;
  - `DeviceManagementConfiguration.Read.All`;
  - `DeviceManagementScripts.Read.All`;
- tenant consent and the signed-in account's Intune read roles must be sufficient for the sections being tested;
- capability display may infer short names from the `scp` claim, but the token itself must remain memory-only and must never appear in evidence;
- Graph 401/403 responses, not decoded claims, are authoritative.

### State matrix

| State | Required result |
| --- | --- |
| Graph option off | Local evidence only; no WAM prompt, Graph request, warning, or loss of raw IDs. |
| Option on, disconnected | `GraphNotConnected`; no silent WAM prompt or queued query. |
| Explicit **Sign in with Windows** | HWND-parented WAM interaction; five capability rows; no token display. |
| Connected, before refresh | Existing local session remains unchanged; enrichment does not start automatically. |
| Explicit refresh | Progress followed by complete or section-level partial result; local evidence remains. |
| Cancel refresh | Remote request stops; local evidence remains. |
| Disable during refresh | Overlay cancels/clears; local evidence remains; WAM is not signed out. |
| 401/403, if naturally observed | 401 invalidates once; 403 is isolated to its section. |
| Missing scope, offline, throttled, ambiguous device, beta unknown | Record only if naturally observed or exercised in an isolated test tenant; otherwise `not exercised`. |

Static review evidence must additionally show five fully qualified v2 scopes, no WAM resource property, GET-only ESP Graph operations, bounded retry/pagination/body limits, and token/authorization-header redaction.

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

Optional packet metadata capture is allowed only from an isolated disposable snapshot. Record `pktmon filter list` before capture and do not run `pktmon filter remove` or modify shared filters. If existing filters make the capture ambiguous, skip the live packet gate and revert to a clean snapshot instead of altering them.

```powershell
$Evidence = '<approved restricted evidence folder>'
pktmon filter list | Out-File -LiteralPath "$Evidence\pktmon-filters-before.txt"
pktmon start --capture --comp nics --pkt-size 0 --file-name "$Evidence\graph.etl"

# Run one Graph-off session and one explicit Graph refresh, then:
pktmon stop
pktmon etl2pcap "$Evidence\graph.etl" --out "$Evidence\graph.pcapng"
pktmon filter list | Out-File -LiteralPath "$Evidence\pktmon-filters-after.txt"
```

Graph-off must produce no Graph connection. Identity traffic is expected only during explicit sign-in; Graph traffic is expected only during explicit enrichment. TLS metadata proves destination and timing, not the HTTP verb; use static review for GET-only proof.

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
7. Stop ProcMon/pktmon and retain restricted evidence according to policy.
8. Revert the disposable post-enrollment snapshot.

Any remediation, tenant write, installer retry, MDM sync, unexpected diagnostic-root write, token disclosure, unrelated process-command-line capture, unsafe path traversal, or post-stop acquisition is an immediate acceptance failure.

Final result: `PASS / FAIL / BLOCKED`

Open items and evidence locations: `TBD`
