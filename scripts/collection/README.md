# Evidence Collection

This folder contains a dependency-light PowerShell collector for building a local evidence bundle that matches the tracked cmtrace-open evidence template as closely as practical.

## Files

- `Invoke-CmtraceEvidenceCollection.ps1`: collects curated logs, registry exports, event-log exports, and command output into a bundle, writes `manifest.json` and `notes.md`, compresses the bundle, and can optionally upload the zip to Azure Blob Storage with a SAS URL.
- `Invoke-CmtraceEvidenceBootstrap.ps1`: stages the collector and profile locally, accepts a direct SAS URL for upload, and registers a one-time `SYSTEM` scheduled task to run the collector outside the assignment process.
- `Detect-CmtraceEvidenceBootstrap.ps1`: Intune Remediations detection script that checks the bootstrap throttle state, removes only stale, invalid, or task-orphaned state, and exits `1` when remediation should restage the bootstrap.
- `Remediate-CmtraceEvidenceBootstrap.ps1`: Intune Remediations entrypoint that mirrors the bootstrap behavior in a self-contained script so the upload does not depend on a sibling file being present on the endpoint.
- `intune-evidence-profile.json`: curated collection profile consumed by the script.

## Intended execution model

- Windows endpoint execution under Intune or another local management runner.
- No Azure PowerShell modules.
- No external dependencies beyond built-in PowerShell cmdlets and native Windows tools such as `reg.exe`, `wevtutil.exe`, and `dsregcmd.exe`.

## Pre-requirments

- The detection, bootstrap, and remediation path is compatible with Windows PowerShell 5.1 and can run before PowerShell 7 is installed.
- The collector still runs through the resolved PowerShell 7.5.4 `pwsh.exe` path after bootstrap.
- `Invoke-CmtraceEvidenceBootstrap.ps1` enforces that collector prerequisite by downloading and installing the pinned PowerShell 7.5.4 x64 MSI when `pwsh.exe` is missing or older than required.

## Examples

Local-only collection:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-CmtraceEvidenceCollection.ps1
```

Local-only collection to a custom root:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-CmtraceEvidenceCollection.ps1 -OutputRoot 'C:\ProgramData\CmtraceOpen\Evidence' -CaseReference 'INC-12345'
```

Upload to a blob SAS URL that already includes the target zip name:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-CmtraceEvidenceCollection.ps1 -SasUrl 'https://account.blob.core.windows.net/evidence/cmtrace-case.zip?<sas>'
```

Upload to a container or virtual-folder SAS URL and let the script append a blob name:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-CmtraceEvidenceCollection.ps1 -SasUrl 'https://account.blob.core.windows.net/evidence/intune?<sas>' -BlobName 'collections/cmtrace-case.zip'
```

Force local-only behavior even if a SAS URL is supplied:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-CmtraceEvidenceCollection.ps1 -SasUrl 'https://account.blob.core.windows.net/evidence?<sas>' -LocalOnly
```

Bootstrap a one-time scheduled collection using explicit HTTPS payload URLs and a direct upload SAS URL:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-CmtraceEvidenceBootstrap.ps1 -CollectorScriptUrl 'https://raw.githubusercontent.com/<owner>/<repo>/<ref>/cmtrace-open/scripts/collection/Invoke-CmtraceEvidenceCollection.ps1' -CollectorProfileUrl 'https://raw.githubusercontent.com/<owner>/<repo>/<ref>/cmtrace-open/scripts/collection/intune-evidence-profile.json' -SasUrl 'https://account.blob.core.windows.net/evidence/container-or-blob?<sas>'
```

For Intune Remediations, upload `Detect-CmtraceEvidenceBootstrap.ps1` as the detection script and `Remediate-CmtraceEvidenceBootstrap.ps1` as the remediation script.

## Output shape

The script creates a bundle root like this:

```text
CMTRACE-20260311-153000-DEVICE/
├── manifest.json
├── notes.md
└── evidence/
    ├── logs/
    ├── registry/
    ├── event-logs/
    ├── exports/
    ├── screenshots/
    └── command-output/
```

The resulting zip is created beside the bundle root.

## Upload behavior

- If `-SasUrl` is omitted, the script stays in local-only mode.
- Uploads use HTTPS with `Invoke-WebRequest` and `x-ms-blob-type: BlockBlob`.
- The script does not require storage account keys, Azure CLI, or Azure PowerShell.
- The manifest records the intended upload destination without exposing the SAS query string.
- If upload fails, the local bundle and zip still remain available and the script returns the upload error in its final output object.

## Bootstrap behavior

- `Invoke-CmtraceEvidenceBootstrap.ps1` is intended for assignment-side or other bootstrap execution where you do not want the full collector to run inline.
- `Detect-CmtraceEvidenceBootstrap.ps1` is the Intune Remediations detection-side companion. It returns `0` while the existing throttle window is still valid, and it returns `1` only after clearing stale, invalid, expired, or task-orphaned throttle state so remediation can run.
- `Remediate-CmtraceEvidenceBootstrap.ps1` intentionally mirrors the bootstrap logic in a self-contained file because Intune Remediations stores uploaded script content instead of a reference to the repo-side bootstrap path.
- In the Intune Remediations pairing, detection only cleans up stale or orphaned throttle state and signals remediation with exit `1`; remediation then uploads and runs the self-contained `Remediate-CmtraceEvidenceBootstrap.ps1` payload to restage the collector bootstrap flow.
- The detection, bootstrap, and remediation entrypoints are written to run under Windows PowerShell 5.1 before PowerShell 7 is present on the endpoint.
- Each bootstrap or remediation run downloads the collector and profile from HTTPS URLs into `C:\ProgramData\CmtraceOpen\Staging` and resolves run-scoped staged paths for that specific run.
- The staged collector remains generic. Runtime values such as the SAS URL, bundle metadata, and local-only mode are still passed at execution time through the scheduled task arguments rather than being baked into the staged collector file.
- The one-time `SYSTEM` scheduled task is registered with those exact staged collector and profile paths for that run.
- The bootstrap resolves the PowerShell 7.5.4 `pwsh.exe` path for the collector and enforces that prerequisite by staging and installing the pinned PowerShell 7.5.4 x64 MSI when `pwsh.exe` is missing or below the required version.
- Runtime resolution treats a missing or off-`PATH` `pwsh.exe` as a normal fallback case and continues to the pinned PowerShell 7.5.4 MSI install path instead of failing during command discovery.
- The bootstrap accepts a direct upload SAS URL and passes it to the collector scheduled task when not running in local-only mode.
- The bootstrap validates that the staged collector payload parses as PowerShell and that the staged profile parses as JSON before it registers the scheduled task.
- `CollectorProfileUrl` must return raw JSON content. Do not point it at an HTML landing page, portal download page, or any URL that wraps the JSON in another response format.
- If Intune or IME logs appear to show a space inserted into `intune-evidence-profile.json`, that is typically log line wrapping or copied-output formatting rather than a different filename on disk.
- The bootstrap registers a one-time `SYSTEM` scheduled task and writes state to `C:\ProgramData\CmtraceOpen\State\collection-bootstrap.json` so repeated execution can be throttled.
- Bootstrap and remediation status output now include a content-derived payload identifier, and the saved throttle state records the same identifier so operators can confirm which uploaded script content actually ran on a device.
- That payload identifier is especially useful with Intune Remediations because it helps catch stale remediation uploads where the device is still running older uploaded script content than expected.
- The remediation entrypoint self-relaunches into 64-bit PowerShell when needed before it starts the remediation transcript or registers the scheduled task.
- The remediation entrypoint starts a transcript under `C:\ProgramData\CmtraceOpen\Logs` for the remediation bootstrap run itself; that transcript does not cover the later collector scheduled task.
- If the log folder exists but the transcript file is missing, treat that as transcript startup failure rather than a successful transcript run; the remediation now emits compact status output for that condition.
- The remediation entrypoint keeps the same parameter flow and compact status-style output, but normal output now includes the transcript path and more troubleshooting context even without `-Verbose`.
- The bootstrap ships with placeholder URLs on `example.invalid`; pass real HTTPS payload URLs at execution time.
- Use commit-pinned raw GitHub URLs instead of `main` if you want deployment-time payload pinning.

## Collection behavior

- Missing or failed artifacts are recorded in `manifest.json` instead of aborting the whole run.
- The collector now starts a durable transcript under `C:\ProgramData\CmtraceOpen\Logs\Collection` and reports the resolved log path in normal status output, `notes.md`, and the final result object.
- Nested profile destinations such as `evidence/logs/panther` and `evidence/exports/autopilot` are created automatically before copy, export, or write operations.
- Current profile coverage includes curated IME logs; narrow Panther setup logs; MDM, IME, and Autopilot registry exports; curated event channels; targeted supporting files under `evidence/exports`; `dsregcmd /status`; and Delivery Optimization snapshots.
- Autopilot and enrollment-adjacent registry coverage includes these roots when present:
  - `HKLM\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot`
  - `HKLM\SOFTWARE\Microsoft\Provisioning\AutopilotSettings`
  - `HKLM\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics`
  - `HKLM\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps`
  - `HKLM\SOFTWARE\Microsoft\Provisioning\NodeCache\CSP`
  - `HKLM\SOFTWARE\Microsoft\Provisioning\OMADM\SyncML\ODJApplied`
- The curated event channel set currently includes:
  - `Microsoft-Windows-AAD/Operational`
  - `Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin`
  - `Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational`
  - `Microsoft-Windows-DeliveryOptimization/Operational`
  - `Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot`
  - `Microsoft-Windows-ModernDeployment-Diagnostics-Provider/ManagementService`
  - `Microsoft-Windows-Provisioning-Diagnostics-Provider/Admin`
  - `Microsoft-Windows-Shell-Core/Operational`
  - `Microsoft-Windows-Time-Service/Operational`
  - `Microsoft-Windows-User Device Registration/Admin`
- Targeted file exports include `AutoPilotConfigurationFile.json`, JSON staged under `C:\Windows\ServiceState\Autopilot`, existing `C:\Users\Public\Documents\MDMDiagnostics` output, and `AutopilotDDSZTDFile.json` when present.
- The collector runs `MdmDiagnosticsTool.exe` during collection and harvests the generated `MDMDiagReport.zip` back into the same bundle so fresh diagnostics land beside any pre-existing `MDMDiagnostics` output.
- Delivery Optimization command capture currently includes `Get-DeliveryOptimizationStatus` and `Get-DeliveryOptimizationPerfSnap` snapshots.
- Enrollment `FirstSync` is not exported separately because the `Enrollments` export already covers that state, and `EstablishedCorrelations` is not duplicated because the Autopilot diagnostics export already includes it.
- The profile can be adjusted later without changing app code.

## Operational notes

- Run under a context that can read the targeted logs, registry paths, and event channels. Intune `SYSTEM` is the primary target.
- Missing Autopilot-only or scenario-specific artifacts are normal on devices that are not in an Autopilot flow, never staged the related JSON, did not produce local `MDMDiagnostics` output yet, or simply do not have the targeted Panther/setup traces. Those cases are recorded in `manifest.json` and do not fail the collection run.
- `Compress-Archive` uses the built-in ZIP implementation and is sufficient for typical evidence bundles. Very large bundles should still be sized with care.
- Use short-lived SAS URLs with write permissions scoped only to the target container or blob path.
- If you use the bootstrap flow, keep the upload SAS short-lived and do not commit live SAS values into repo-tracked bootstrap or profile files.
- If profile download validation fails, the bootstrap now reports the staged path, the source URL with query redacted, and a short payload preview so it is easier to spot non-JSON responses.
