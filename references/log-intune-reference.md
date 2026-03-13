# Complete Intune diagnostic log reference for Windows and macOS

**Every diagnostic log, event channel, registry key, and unified log predicate used for troubleshooting Microsoft Intune on Windows and macOS** — organized for programmatic quick-access in a log viewer tool. Each entry includes exact file name, path, format, diagnostic purpose, and the scenario where it's most valuable.

---

## Windows: Intune Management Extension (IME) logs

All IME logs reside in **`C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\`** and use **CMTrace-compatible format** (structured plain text with timestamp, component, severity fields parseable by CMTrace, OneTrace, or any regex-aware viewer). Log rotation occurs at **3 MB per file** by default; rotated files are renamed with a creation timestamp suffix (e.g., `IntuneManagementExtension-20260310-143022.log`). Three rotated copies are retained by default.

| File name | Format | Diagnostic purpose | Most useful scenario |
|---|---|---|---|
| `IntuneManagementExtension.log` | .log (CMTrace) | Primary IME log — check-ins, policy processing, Win32 app detection/install, graph communication, content download (pre-2408) | Always the first log to check for any IME issue |
| `AppWorkload.log` | .log (CMTrace) | Dedicated Win32/WinGet app workload log (introduced 2408) — download bytes, DO progress, staging, install execution, toast notifications | App install failures, content download problems |
| `AppActionProcessor.log` | .log (CMTrace) | High-level app action decisions, assignment workflow, applicability checks, detection across subgraphs | App detection failures, assignment/targeting issues |
| `AgentExecutor.log` | .log (CMTrace) | PowerShell script execution, remediation script execution, WinGet install actions — records command line, stdout, stderr, exit codes | Script execution failures, proactive remediation debugging |
| `HealthScripts.log` | .log (CMTrace) | Proactive Remediations (Health Scripts) — detection and remediation scheduling, output, errors | Remediation script troubleshooting |
| `ClientHealth.log` | .log (CMTrace) | IME agent health evaluation — service startup, connectivity checks | IME service issues, agent connectivity |
| `ClientCertCheck.log` | .log (CMTrace) | MDM client certificate validation (introduced 2408) — checks LocalMachine\My store for correct OID and private key | Certificate-related management failures |
| `DeviceHealthMonitoring.log` | .log (CMTrace) | Hardware readiness, device inventory, app crash telemetry via 1DS SDK | Endpoint analytics, inventory discrepancies |
| `Sensor.log` | .log (CMTrace) | SensorFramework component — subscribes to device events for usage data collection | Endpoint analytics data collection |
| `Win32AppInventory.log` | .log (CMTrace) | Scans installed Win32 apps via WMI, reports inventory to Intune | Incorrect detection state in portal |
| `ImeUI.log` | .log (CMTrace) | Toast notification UI events shown to end users by ImeUI component | User-facing notification issues |

**IME log configuration registry** at `HKLM\SOFTWARE\Microsoft\IntuneWindowsAgent\Logging` accepts `LogMaxSize` (bytes as string, e.g., `5000000`), `LogMaxHistory` (count of rotated files), and `LogDirectory` (custom path).

### Win32 app content staging paths

| Stage | Path | Notes |
|---|---|---|
| Download (incoming) | `C:\Program Files (x86)\Microsoft Intune Management Extension\Content\Incoming\` | .intunewin packages arrive here via BITS/DO |
| Integrity verification | `C:\Program Files (x86)\Microsoft Intune Management Extension\Content\Staging\` | Decryption and hash verification |
| Execution cache | `C:\Windows\IMECache\` | Final decrypted content; install commands execute from here; cleaned post-detection |
| Health script cache | `C:\Windows\IMECache\HealthScripts\` | Cached remediation detection/remediation scripts |

### Win32 app registry keys

| Registry path | Purpose |
|---|---|
| `HKLM\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\{SID}\{AppID}\` | Per-app installation state, result codes, detection outcomes |
| `HKLM\SOFTWARE\Microsoft\IntuneManagementExtension\SideCarPolicies\StatusServiceReports\` | Status service reports (install results, error codes) |
| `HKLM\SOFTWARE\Microsoft\IntuneManagementExtension\SideCarPolicies\Scripts\Execution\` | Script execution tracking |
| `HKLM\SOFTWARE\Microsoft\IntuneManagementExtension\SideCarPolicies\Scripts\Reports\` | Script reports with JSON containing detection output and exit codes |

**Note on "GH" and "SidecarProductionLog"**: These are not separate files. "Sidecar" is the internal IME codename; Graph Helper operations log within `IntuneManagementExtension.log`. Search for `[Win32App]`, `ProcessDetection`, `ApplicationDetected`, `ExitCode`, `[Win32App][WinGetApp]`, or `ContentManager` to isolate relevant entries.

---

## Windows: MDM diagnostics and DMClient logs

### MDM Diagnostic Tool output

Generated via `C:\Windows\System32\MdmDiagnosticsTool.exe`. Default output goes to `C:\Users\Public\Documents\MDMDiagnostics\`. Extended collection: `mdmdiagnosticstool.exe -area DeviceEnrollment;DeviceProvisioning;Autopilot;TPM -cab C:\temp\Autopilot.cab`.

| File name | Format | Purpose |
|---|---|---|
| `MDMDiagHtmlReport.html` | HTML | Human-readable snapshot — management URL, MDM server device ID, certificates, applied Policy CSP values (current vs. default) |
| `MDMDiagReport.xml` | XML | Detailed MDM config — enrollment variables, provisioning packages, multivariant conditions |
| `MdmDiagReport_RegistryDump.reg` | .reg (text) | Registry export of Autopilot, PolicyManager, Provisioning, Enrollments keys |
| `MdmDiagLogMetadata.json` | JSON | Metadata about the diagnostic collection command |
| `MdmLogCollectorFootPrint.txt` | Plain text | Tool execution log |
| `DiagnosticLogCSP_Collector_DeviceEnrollment.etl` | ETL (binary) | Device enrollment ETW traces |
| `DiagnosticLogCSP_Collector_Autopilot_*.etl` | ETL (binary) | Autopilot ETW traces |
| `DiagnosticLogCSP_Collector_DeviceProvisioning_*.etl` | ETL (binary) | Provisioning ETW traces |
| `TpmHliInfo_Output.txt` | Plain text | TPM hardware info including EK cert status |
| Multiple `.evtx` files | EVTX (binary) | Exported copies of all MDM-related event logs |

### DMClient flat logs

| File path | Format | Purpose | Scenario |
|---|---|---|---|
| `C:\Windows\System32\config\systemprofile\AppData\Local\mdm\*.log` | Plain text .log | DMClient internal operation logs, MDM sync communication | MDM sync troubleshooting, enrollment communication |

### DiagnosticLog CSP collector files

| Path | Format | Contents |
|---|---|---|
| `C:\ProgramData\Microsoft\DiagnosticLogCSP\Collectors\*.etl` | ETL (binary) | ETL traces collected via DiagnosticLog CSP — Autopilot, provisioning, enrollment |

**ETL conversion methods**: `tracerpt.exe <file.etl> -o output.xml -of XML` | `netsh trace convert input=<file.etl> output=<file.txt>` | `Get-WinEvent -Path <file.etl> -Oldest` | Windows Performance Analyzer (WPA from Windows ADK).

---

## Windows: MDM event log channels

All event logs stored as EVTX binary files under `C:\Windows\System32\winevt\Logs\`. File names use `%4` in place of `/` for the channel hierarchy.

| Event log channel | EVTX file name | Default state | Purpose | Key event IDs |
|---|---|---|---|---|
| Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin | `…Enterprise-Diagnostics-Provider%4Admin.evtx` | Enabled | **Primary MDM log** — OMA-DM sessions, policy errors, CSP operations, enrollment | 16 (OMA-DM config succeeded), 58 (provisioning succeeded), 75/76 (auto-enroll success/fail), 208 (session started), 404 (command failure), 813/814 (CSP policy applied) |
| …/Operational | `…%4Operational.evtx` | Enabled | Day-to-day MDM operational events | Varies |
| …/Debug | `…%4Debug.evtx` | **Disabled** — enable via View > Show Analytic and Debug Logs | Verbose SyncML processing, detailed CSP traces | Detailed OMA-DM protocol data |
| Microsoft-Windows-AAD/Operational | `…AAD%4Operational.evtx` | Enabled | Entra ID device registration, token requests, SSO, device join | AAD join/registration events |
| Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot | `…ModernDeployment-Diagnostics-Provider%4Autopilot.evtx` | Enabled | Autopilot deployment events — profile download, OOBE, TPM attestation | 100–172 series, 807–908 series |
| Microsoft-Windows-Provisioning-Diagnostics-Provider/Admin | `…Provisioning-Diagnostics-Provider%4Admin.evtx` | Enabled | Provisioning package application events | Provisioning status |
| Microsoft-Windows-AppXDeploymentServer/Operational | `…AppXDeploymentServer%4Operational.evtx` | Enabled | Modern app deployment/packaging | Store app deployment |
| Microsoft-Windows-User Device Registration/Admin | Standard winevt path | Enabled | Device registration events during OOBE | Registration status |
| Microsoft-Windows-HelloForBusiness/Operational | Standard winevt path | Enabled | WHfB provisioning, authentication | PIN provisioning, cert enrollment |
| Microsoft-Windows-AssignedAccess/Admin | Standard winevt path | Enabled | Kiosk mode events | Assigned access |

---

## Windows: MDM registry keys for diagnostics

| Registry path | Type | Diagnostic purpose |
|---|---|---|
| `HKLM\SOFTWARE\Microsoft\Enrollments\<GUID>\` | Key per enrollment | Enrollment state — `DiscoveryServiceFullURL`, `EnrollmentType`, `ProviderID`, `EnrollmentState` |
| `HKLM\SOFTWARE\Microsoft\Enrollments\<GUID>\FirstSync\` | Subkey | ESP state — `SkipDeviceStatusPage`, `SkipUserStatusPage`, `SyncFailureTimeout`, `BlockInStatusPage` |
| `HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\<Area>\` | Values | Currently effective device policies (merged result from all sources) |
| `HKLM\SOFTWARE\Microsoft\PolicyManager\Providers\<GUID>\default\Device\<Area>\` | Values | Policies delivered by specific provider (Intune) before CSP implementation — compare with `current` to detect application failures |
| `HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\ControlPolicyConflict\` | DWORD | `MDMWinsOverGP` — 0=GP wins (default), 1=MDM wins |
| `HKLM\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\<GUID>\` | Subkey | OMA-DM account config — server URL, credentials reference |
| `HKLM\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\<GUID>\` | Subkey | OMA-DM session state — last sync time, session history |
| `HKLM\SOFTWARE\Microsoft\Provisioning\Diagnostics\AutoPilot\` | Values | Autopilot profile settings — `AadTenantId`, `CloudAssignedOobeConfig` (bitmask), `IsAutopilotDisabled` |
| `HKLM\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\<GUID>\` | Key | Confirms active enrollment GUID |
| `HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\<TenantID>\` | Values | MDM enrollment URLs — `MdmEnrollmentUrl`, `MdmTermsOfUseUrl`, `MdmComplianceUrl` |
| `HKLM\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement\<SID>\MSI\<ProductID>\` | Values | LOB MSI tracking — `Status`, `LastError`, `CurrentDownloadUrl` |

---

## Windows: Autopilot v1 (classic) logs

### Panther setup logs

| File name | Path | Format | Scenario |
|---|---|---|---|
| `setupact.log` | `C:\Windows\Panther\setupact.log` | Plain text (CMTrace-compatible) | OOBE actions, feature updates, Autopilot provisioning |
| `setuperr.log` | `C:\Windows\Panther\setuperr.log` | Plain text (CMTrace-compatible) | Error-only entries during setup — quick error scanning |
| `setupact.log` | `C:\$Windows.~BT\Sources\Panther\setupact.log` | Plain text | Feature update pre-completion phase |
| `setuperr.log` | `C:\$Windows.~BT\Sources\Panther\setuperr.log` | Plain text | Errors during feature update pre-completion |
| `setupact.log` | `C:\$Windows.~BT\Sources\Rollback\setupact.log` | Plain text | Rollback phase after failed upgrade |
| `setupact.log` | `C:\Windows\Panther\UnattendGC\setupact.log` | Plain text | Generalize/cleanup pass (Sysprep) |
| `setupact.log` | `C:\Windows\Panther\NewOS\setupact.log` | Plain text | New OS environment during feature updates |

### Autopilot profile JSON files

| File name | Path | Format | Purpose |
|---|---|---|---|
| `AutopilotDDSZTDFile.json` | `C:\Windows\Provisioning\Diagnostics\AutopilotDDSZTDFile.json` | JSON | ZTD profile — drives OOBE behavior (Win10 1903+) |
| `AutopilotConciergeFile.json` | `C:\Windows\ServiceState\Autopilot\AutopilotConciergeFile.json` | JSON | Self-deploying mode OOBE customization (language/region) |
| `AutopilotConfigurationFile.json` | `C:\Windows\Provisioning\AutoPilot\AutopilotConfigurationFile.json` | JSON | Classic profile config (≤1809, existing device scenarios) |

### ESP tracking

| Source | Path | Format | Purpose |
|---|---|---|---|
| ESP tracking registry | `HKLM\Software\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\` | Registry | Tracks device/user ESP phases (1=NotInstalled, 2=InProgress, 3=Completed, 4=Error) |
| AutopilotSettings registry | `HKLM\Software\Microsoft\Provisioning\AutopilotSettings\` | Registry | Sub-category status: notStarted, inProgress, succeeded, failed |

---

## Windows: Autopilot v2 (device preparation) logs

Autopilot Device Preparation does **not** use the traditional ESP. The **Bootstrapper Agent** within IME is the core orchestrator. `Get-AutopilotDiagnostics.ps1` does NOT work for AP-DP.

| Log source | Path/channel | Format | Purpose |
|---|---|---|---|
| Bootstrapper event log | `Applications and Services Logs > Microsoft > Windows > Intune-Bootstrapper-Agent` | .evtx | Primary AP-DP log — provisioning flow, batch workload progress, app/script status, state changes |
| DevicePreparation registry | `HKLM\SOFTWARE\Microsoft\Provisioning\AutopilotSettings\AutopilotDevicePrepHint` | DWORD | 0=not in APv2, 2=bootstrapping, 3=executing workloads, 4=complete |
| InitialProvisioning registry | `HKLM\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\Provisioning\InitialProvisioning` | JSON in registry | Workload progress — OrchestrationContext, previous progress, current phase |
| IME logs | `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log` | .log (CMTrace) | Granular app install details during AP-DP |
| MDM event log | DeviceManagement-Enterprise-Diagnostics-Provider/Admin | .evtx | CSP policy application during AP-DP |

---

## Windows: Windows Update for Business (WUfB) logs

**`WindowsUpdate.log`** no longer exists as a live file on Windows 10+. It must be generated from ETL traces using `Get-WindowsUpdateLog` in PowerShell, which outputs to `C:\Users\<user>\Desktop\WindowsUpdate.log` by default. Source ETLs reside at `C:\Windows\Logs\WindowsUpdate\WindowsUpdate.*.etl`.

| File name | Path | Format | Purpose | Scenario |
|---|---|---|---|---|
| `WindowsUpdate.log` | Generated to Desktop | Plain text | Merged/decoded WU ETL traces — scan, download, install events | All Windows Update troubleshooting |
| `CBS.log` | `C:\Windows\Logs\CBS\CBS.log` | Plain text | Component-Based Servicing — TrustedInstaller operations, SFC results (search `[SR]`), update installation detail | Update installation failures, component corruption |
| `CbsPersist_*.cab` | `C:\Windows\Logs\CBS\` | .cab (compressed) | Archived CBS.log when file grows too large | Historical CBS analysis |
| `dism.log` | `C:\Windows\Logs\DISM\dism.log` | Plain text | DISM operations — image servicing, repair, feature management | DISM command failures, image repair |
| `ReportingEvents.log` | `C:\Windows\SoftwareDistribution\ReportingEvents.log` | Plain text | Quick summary of all WU scan/download/install transactions with result codes | Overview of WU activity |
| WU source ETLs | `C:\Windows\Logs\WindowsUpdate\WindowsUpdate.*.etl` | ETL (binary) | Raw WU diagnostic traces | Deep WU analysis when Get-WindowsUpdateLog is insufficient |
| USO ETLs | `C:\ProgramData\USOShared\Logs\UpdateSessionOrchestration.etl` | ETL (binary) | Update Session Orchestrator — download/install sequencing | Updates downloaded but not installing |
| WaaSMedic ETLs | `C:\Windows\Logs\waasmedic\waasmedic*.etl` | ETL (binary) | WU Medic Service — remediation of WU components (~60 files/day, ~12KB each, ~57-day retention) | WU service recovery failures |
| Expedited update ETLs | `C:\Program Files\Microsoft Update Health Tools\Logs\*.etl` | ETL (binary) | Expedited quality update policy execution | Expedited update troubleshooting |

### WUfB event log channels

| Channel | Purpose |
|---|---|
| `Microsoft-Windows-WindowsUpdateClient/Operational` | Client-side update events — scan, download, install status |
| `Microsoft-Windows-UpdateOrchestrator/Operational` | Update scheduling and sequencing |
| `Microsoft-Windows-Update/Operational` | Generic update operations |

WUfB ring policy values are visible in `MDMDiagHtmlReport.html` under Update CSP and in the registry at `HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Update\`.

---

## Windows: Delivery Optimization logs

| File/source | Path | Format | Purpose |
|---|---|---|---|
| `dosvc.*.etl` | `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs\` | ETL (binary) | Primary DO service logs — download/peering, bandwidth metrics, content sources |
| `domgmt.*.etl` | Same directory | ETL (binary) | DO management events |
| DO event log | `Microsoft-Windows-DeliveryOptimization/Operational` | .evtx | DO operational events — download mode, peer discovery, transfer stats |

**Decode DO ETLs** via `Get-DeliveryOptimizationLog` PowerShell cmdlet. Enable verbose logging with `Enable-DeliveryOptimizationVerboseLogs`. Additional cmdlets: `Get-DeliveryOptimizationStatus`, `Get-DeliveryOptimizationPerfSnap`, `Get-DeliveryOptimizationLogAnalysis`. ETL retention is approximately **57–58 days**.

---

## Windows: Company Portal logs

| Source | Path | Format | Purpose |
|---|---|---|---|
| CP app logs | `C:\Users\<user>\AppData\Local\Packages\Microsoft.CompanyPortal_8wekyb3d8bbwe\LocalState\Log_<n>.log` | Plain text | Per-user CP events, errors, enrollment state |
| MDM diagnostic export | `C:\Users\Public\Public Documents\MDMDiagnostics\` | .cab + .html | Exported via Settings > Accounts > Access work or school > Export management log files |

Collect diagnostics from the Company Portal app via **Help & support > Upload logs** or navigate directly to the LocalState folder.

---

## Windows: Microsoft Edge management logs

| Source | Path | Format | Purpose |
|---|---|---|---|
| `MicrosoftEdgeUpdate.log` | `C:\ProgramData\Microsoft\EdgeUpdate\Log\MicrosoftEdgeUpdate.log` | Plain text .log | Edge update checks, downloads, installations — channel, version, success/failure |
| Edge policy page | `edge://policy` in browser | Interactive | View all applied policies with source (GPO/MDM/Platform) and status |
| Edge policy registry (machine) | `HKLM\SOFTWARE\Policies\Microsoft\Edge\` | Registry | Machine-wide Edge browser policies from Intune Settings Catalog/ADMX |
| Edge policy registry (user) | `HKCU\SOFTWARE\Policies\Microsoft\Edge\` | Registry | User-scope Edge policies |
| Edge update policy registry | `HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate\` | Registry | Auto-update period, target version, channel |

Edge CSP policy delivery events appear in the `DeviceManagement-Enterprise-Diagnostics-Provider/Admin` event log (filter Event ID **814** for string policy confirmations).

---

## Windows: Microsoft Defender and Defender for Endpoint logs

### Defender Antivirus

| File/source | Path | Format | Purpose |
|---|---|---|---|
| `MPLog-<datetime>.log` | `C:\ProgramData\Microsoft\Windows Defender\Support\` | Plain text .log | Comprehensive AV operational log — scan results, threat detections, real-time protection, process metrics | 
| `MpCmdRun.log` | `C:\Windows\Temp\MpCmdRun.log` (also per-user in `%TEMP%`) | Plain text .log | MpCmdRun.exe command output — scans, signature updates, MAPS tests |
| `MpSupportFiles.cab` | `C:\ProgramData\Microsoft\Windows Defender\Support\MpSupportFiles.cab` | .cab archive | Full diagnostic bundle from `MpCmdRun.exe -GetFiles` — all Defender logs, registry, config |
| Defender Operational event log | `Microsoft-Windows-Windows Defender/Operational` | .evtx | All AV events — detections, scans, exclusions, config changes |
| Defender WHC event log | `Microsoft-Windows-Windows Defender/WHC` | .evtx | Windows Security Center integration |

### Defender for Endpoint (EDR / SENSE)

| Source | Path/channel | Format | Purpose |
|---|---|---|---|
| SENSE event log | `Microsoft-Windows-SENSE/Operational` | .evtx | EDR sensor onboarding, connectivity, errors |
| SenseIR event log | `Microsoft-Windows-SenseIR/Operational` | .evtx | Live Response session events, incident response actions |
| `SenseIR.log` | `C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Logs\SenseIR.log` | Plain text .log | IR and Live Response action logs |
| `Telemetry.log` | `C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Logs\Telemetry.log` | Plain text .log | Telemetry upload status/errors |
| Onboarding registry | `HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status` | Registry | `OnboardingState` = 1 (onboarded) or 0 (not onboarded) |

---

## Windows: BitLocker logs

| Event log channel | Purpose | Key details |
|---|---|---|
| `Microsoft-Windows-BitLocker/BitLocker Management` | Encryption/decryption operations, key rotation triggered by Intune | Primary channel for Intune-managed BitLocker |
| `Microsoft-Windows-BitLocker/BitLocker Operational` | Day-to-day operational events | Ongoing monitoring |
| `Microsoft-Windows-BitLocker-API/Management` | API-level calls; Event IDs 853+ for errors | Silent encryption failures, prerequisite checks (TPM, Secure Boot) |
| `Microsoft-Windows-BitLocker-DrivePreparationTool/Admin` | Drive preparation events | Partition-related failures preventing encryption |
| `Microsoft-Windows-BitLocker-DrivePreparationTool/Operational` | Operational preparation events | Disk layout issues |

Recovery key escrow to Entra ID is logged in the **DeviceManagement-Enterprise-Diagnostics-Provider/Admin** event log (filter for `./Device/Vendor/MSFT/BitLocker/`). Server-side verification uses Microsoft Entra ID Audit Logs under `KeyManagement`. BitLocker CSP policy status is visible in `MDMDiagHtmlReport.html` and at `HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker\`.

---

## Windows: LAPS logs

| Source | Path | Format | Key event IDs |
|---|---|---|---|
| LAPS Operational event log | `Microsoft-Windows-LAPS/Operational` | .evtx | **10003** (cycle start), **10004** (success), **10005** (failure), **10020** (password updated in Entra ID), **10022** (policy config from CSP — shows source, backup directory, account, complexity) |
| LAPS policy registry | `HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\LAPS\` | Registry | Intune/CSP-configured LAPS settings |
| GPO LAPS policy registry | `HKLM\SOFTWARE\Microsoft\Policies\LAPS\` | Registry | GP-configured LAPS settings (if applicable) |

LAPS events are **exclusively** in the dedicated LAPS > Operational channel — they do **not** appear in the DeviceManagement-Enterprise-Diagnostics-Provider channel. Use `Get-LapsDiagnostics` for a full diagnostic package and `Get-LapsPolicy` to verify applied policy.

---

## Windows: Certificate / SCEP / PKCS logs

### Client-side

| Event source | Location | Purpose |
|---|---|---|
| DeviceManagement-Enterprise-Diagnostics-Provider/Admin | Event Viewer | MDM cert profile delivery — Event 306 (SCEP CspExecute), Event 39 (cert installed) |
| CertificateServicesClient-CertEnroll | Application event log | Certificate enrollment operations — Event 86 (failures) |
| CertificateServicesClient-Lifecycle-System/Operational | Event Viewer | System certificate lifecycle — expiration/renewal |
| CertificateServicesClient-Lifecycle-User/Operational | Event Viewer | User certificate lifecycle |

### NDES / Connector server-side

| Source | Path | Format |
|---|---|---|
| Intune Certificate Connector | `Applications and Services Logs > Microsoft > Intune > CertificateConnectors > Admin` and `Operational` | .evtx |
| NDESConnector svclog | `C:\Program Files\Microsoft Intune\NDESConnectorSvc\Logs\Logs\NDESConnector_*.svclog` | .svclog (XML) |
| CertificateRegistrationPoint | Same Logs directory, `CertificateRegistrationPoint_*.svclog` | .svclog (XML) |
| IIS Logs | `C:\inetpub\logs\LogFiles\W3SVC1\` | W3C .log |
| NDES config registry | `HKLM\Software\Microsoft\Cryptography\MSCEP\` and `HKLM\Software\Microsoft\MicrosoftIntune\NDESConnector\` | Registry |

---

## Windows: Group Policy vs. MDM conflict diagnostics

| Source | Path/command | Format | Purpose |
|---|---|---|---|
| GPResult | `gpresult /h C:\temp\gpresult.html` | HTML | All applied GPOs, RSoP — identifies GP settings conflicting with MDM |
| MDMDiagReport | `C:\Users\Public\Documents\MDMDiagnostics\MDMDiagReport.html` | HTML | All applied MDM policies, ControlPolicyConflict status, MDMWinsOverGP |
| ControlPolicyConflict registry | `HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\ControlPolicyConflict\` | Registry DWORD | `MDMWinsOverGP` — 1 = MDM wins over GP |
| Debug event log | DeviceManagement-Enterprise-Diagnostics-Provider/Debug | .evtx | Shows `MdmWinsOverGp Policy value` confirmation, GP value deleted → MDM value applied sequences |

---

## Windows: SetupDiag logs

SetupDiag runs **automatically** after failed feature updates (Windows 10 2004+).

| File | Path | Format | Trigger |
|---|---|---|---|
| `SetupDiagResults.xml` | `C:\Windows\Logs\SetupDiag\SetupDiagResults.xml` | XML | Automatic after failed upgrade — contains ProfileName, FailureData, Remediation |
| `SetupDiagResults.log` | Same directory as SetupDiag.exe (manual runs) | Plain text | Manual execution |
| Results registry | `HKLM\SYSTEM\Setup\SetupDiag\Results` | Registry | Automatic run results |

---

## Windows: Microsoft 365 Apps deployment logs

| Source | Path | Format |
|---|---|---|
| Click-to-Run logs | `C:\Windows\Temp\<MachineName>-<Date>-<Number>.log` | Office telemetry/JSON structured .log |
| User-context C2R logs | `%TEMP%\<MachineName>-<Date>-<Number>.log` | Same format |
| Office config registry | `HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration\` | Registry — version, update channel, CDN URL |

Enable verbose C2R logging: `reg add HKLM\SOFTWARE\Microsoft\ClickToRun\OverRide /v LogLevel /t REG_DWORD /d 3`.

---

## Windows: Health monitoring and Collect Diagnostics

The **Collect Diagnostics** remote action (Intune admin center > Devices > Collect diagnostics) uploads a ZIP to Azure Blob Storage, available for **28 days** (max 10 collections per device, **250 MB** or 25 files). It collects:

- All files from `%ProgramData%\Microsoft\IntuneManagementExtension\Logs\*.*`
- `%windir%\System32\config\systemprofile\AppData\Local\mdm\*.log`
- `%ProgramData%\Microsoft\DiagnosticLogCSP\Collectors\*.etl`
- `%windir%\logs\CBS\cbs.log` and `%windir%\logs\WindowsUpdate\*.etl`
- `%ProgramData%\Microsoft\Windows Defender\Support\MpSupportFiles.cab`
- `%windir%\logs\measuredboot\*.*` (TCG logs for health attestation)
- Registry dumps from IntuneManagementExtension, PolicyManager, Windows Advanced Threat Protection, EPMAgent, Policies
- Event logs: Application, System, Setup, BitLocker Management, SENSE, SenseIR, HelloForBusiness, AppLocker, Firewall, WMI-Activity
- Command output: `dsregcmd /status`, `certutil -store`, `ipconfig /all`, `netsh` commands

---

## Windows: WinGet / Microsoft Store app logs

| Source | Path | Format |
|---|---|---|
| WinGet native logs (SYSTEM) | `C:\Windows\System32\config\systemprofile\AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\DiagOutputDir\WinGet-*.log` | Plain text .log |
| WinGet native logs (user) | `%LOCALAPPDATA%\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\DiagOutputDir\WinGet-*.log` | Plain text .log |

WinGet logs have **no max file size**; the directory auto-cleans after exceeding 100 files. Store app processing is also logged in `AppWorkload.log` (search `[WinGetApp]`) and `IntuneManagementExtension.log` (search `[Win32App][WinGetApp]`).

---

## Windows: LOB MSI app deployment logs

LOB MSI packages delivered via MDM are tracked in the **DeviceManagement-Enterprise-Diagnostics-Provider/Admin** event log with Event IDs **1901** (node creation), **1904** (installer started), **1905** (download started), **1906** (download completed), **1907** (install started), **1910** (install completed). Packages are staged at `C:\Windows\System32\config\systemprofile\AppData\Local\mdm\`.

For verbose MSI logs when wrapping as Win32 apps, include in the install command: `msiexec /i app.msi /qn /l*v "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\AppName.log"` — this ensures the log is captured by Collect Diagnostics.

---

## macOS: Core MDM enrollment and profile management

### mdmclient

The `mdmclient` binary (`/usr/libexec/mdmclient`) logs **exclusively via macOS Unified Logging** — no standalone flat log file exists. To enable debug persistence: `sudo log config --subsystem com.apple.ManagedClient --mode="level:debug,persist:debug"`. Reset with `sudo log config --subsystem com.apple.ManagedClient --reset`. Alternatively, create a debug flag: `sudo touch /var/db/MDM_EnableDebug`.

### Profile and enrollment state files

| Path | Format | Purpose |
|---|---|---|
| `/private/var/db/ConfigurationProfiles/Store/ConfigProfiles.binary` | Encrypted binary (CoreData) | All installed configuration profiles — **never manually edit** |
| `/private/var/db/ConfigurationProfiles/Settings/.profilesAreInstalled` | Marker file | Indicates profiles are installed |
| `/private/var/db/ConfigurationProfiles/Settings/.cloudConfigProfileInstalled` | Marker file | ADE cloud config installed (macOS 14+) |
| `/private/var/db/ConfigurationProfiles/Settings/.cloudConfigRecordFound` | Marker file | ADE activation record cached |
| `/Library/Managed Preferences/` | .plist (XML property list) | Per-domain managed preference files deployed via MDM — e.g., `com.apple.loginwindow.plist`, `com.microsoft.Edge.plist` |
| `/Library/Logs/ManagedClient/ManagedClient.log` | Plain text .log | Legacy MCX debug log (enable via `sudo defaults write /Library/Preferences/com.apple.MCXDebug debugOutput -2`) |

**Profile commands**: `sudo profiles show` (text), `sudo profiles show -output stdout-xml` (XML), `sudo profiles status -type enrollment` (MDM/DEP/user-approved status), `sudo profiles validate -type enrollment` (validate against Apple servers).

---

## macOS: Intune Company Portal logs

| Source | Path | Format | Purpose |
|---|---|---|---|
| Company Portal log | `~/Library/Logs/CompanyPortal/` (also bundled in diagnostic ZIP export) | .log (text) | Enrollment, sign-in, compliance checks, device details |

Collect via **Company Portal > Help > Save Diagnostic Report** (local ZIP) or **Send Diagnostic Report** (uploads to Microsoft, returns incident ID). Enable verbose logging via Company Portal **Preferences > Turn on advanced logging** — captures MSAL certificate/network detail.

---

## macOS: Intune Management Agent logs

The Intune Management Agent installs at **`/Library/Intune/Microsoft Intune Agent.app`** and does not appear in Finder > Applications. It runs two processes: **`IntuneMdmDaemon`** (root-level — PKG/DMG installs, root scripts) and **`IntuneMdmAgent`** (user-context scripts).

### System-level logs

| File pattern | Path | Format | Purpose |
|---|---|---|---|
| `IntuneMDMDaemon <date>-<time>.log` | `/Library/Logs/Microsoft/Intune/` | Pipe-delimited .log (Date-Time \| Process \| LogLevel \| PID \| Task \| TaskInfo) | Primary daemon log — app installs, root script execution, policy assignments |
| `IntuneMDMAgent <date>-<time>.log` | `/Library/Logs/Microsoft/Intune/` | Same pipe-delimited format | Agent operations |
| `LogCollectionInfo.txt` | `/Library/Logs/Microsoft/Intune/` | Plain text | Generated during remote log collection — lists missing files |

### User-level logs

| File pattern | Path | Format |
|---|---|---|
| `IntuneMDMAgent <date>-<time>.log` | `~/Library/Logs/Microsoft/Intune/` | Same pipe-delimited format |

Log levels: **I** (Information), **W** (Warning), **E** (Error). New files are created on agent restart. Monitor in real time: `tail -f /Library/Logs/Microsoft/Intune/*IntuneMDMDaemon*.log`.

### Script execution logs

Shell scripts deployed via Intune are logged in `IntuneMDMDaemon*.log` (root context) and `IntuneMDMAgent*.log` (user context). Custom per-script logging (from Microsoft's `shell-intune-samples` repo) goes to `/Library/Logs/Microsoft/IntuneScripts/<ScriptName>/<ScriptName>.log`.

---

## macOS: Unified Logging predicates — the complete reference

All predicates below use `log show`. Add `--info` for info-level, `--debug` for debug-level. Time filters: `--last 10m`, `--last 1h`, `--last 1d`, or `--start "YYYY-MM-DD HH:MM:SS" --end "..."`. Export archive: `sudo log collect --output ~/Desktop/logs.logarchive --last 1d`.

### MDM client and profile management

```bash
# Broad MDM/profile management
log show --predicate 'subsystem == "com.apple.ManagedClient"' --info --last 1h

# mdmclient process specifically
log show --predicate 'process == "mdmclient"' --info --last 1h

# Profile installations only
log show --predicate 'subsystem == "com.apple.ManagedClient" AND category == "MDMDaemon"' --info --last 1h

# Profile installed events
log show --predicate 'subsystem == "com.apple.ManagedClient" AND eventMessage CONTAINS "Installed configuration profile:"' --last 1h

# Profile removed events
log show --predicate 'subsystem == "com.apple.ManagedClient" AND eventMessage CONTAINS "Removed configuration profile:"' --last 1h

# MDM command processing
log show --predicate 'process == "mdmclient" AND eventMessage CONTAINS "Processing server request"' --info --last 10m

# Real-time MDM streaming
log stream --predicate 'process == "mdmclient" OR process == "apsd" OR process == "dasd"' --info
```

### Intune agent processes

```bash
# IntuneMdmDaemon in unified log (some system events)
log show --predicate 'process == "IntuneMdmDaemon"' --info --last 1h

# IntuneMdmAgent in unified log
log show --predicate 'process == "IntuneMdmAgent"' --info --last 1h

# Company Portal
log show --predicate 'process == "Company Portal"' --info --last 1h
```

**Note**: The Intune agent primarily writes to **file-based logs** at `/Library/Logs/Microsoft/Intune/`, not the unified logging system. Use file-based logs as the primary source; unified log filtering captures only system-level interactions.

### Declarative Device Management (DDM) — macOS 14+

```bash
# DDM general
log show --predicate 'process == "remotemanagementd" OR subsystem == "com.apple.remotemanagementd"' --info --last 10m

# DDM status sync
log show --predicate 'process == "remotemanagementd" AND eventMessage CONTAINS "Syncing only if needed"' --info --last 10m

# DDM mdmConduit category
log show --predicate 'subsystem == "com.apple.remotemanagementd" AND category == "mdmConduit"' --info --last 10m

# Cloud configuration daemon (DEP/ADE)
log stream --info --debug --predicate 'subsystem CONTAINS "com.apple.ManagedClient.cloudconfigurationd"'
```

### Certificate / SCEP operations

```bash
# SCEP enrollment (critical for cert troubleshooting)
log show --info --debug --predicate 'subsystem == "com.apple.SCEP"' --last 1h

# SCEP network requests only
log show --predicate 'category == "SCEP.fw"' --info --last 1h

# Certificate payload via ManagedClient
log show --predicate 'subsystem == "com.apple.ManagedClient" AND library == "Certificate"' --info --last 1h

# Keychain/security daemon
log show --predicate 'subsystem == "com.apple.securityd"' --info --last 1h

# Trust evaluation
log show --predicate 'subsystem == "com.apple.securityd" AND eventMessage CONTAINS "trust"' --info --last 1h
```

### Software updates

```bash
# Software Update subsystem
log show --predicate 'subsystem == "com.apple.SoftwareUpdate"' --info --last 1d

# softwareupdated daemon
log show --predicate 'process == "softwareupdated"' --info --last 1d

# MDM-managed OS update mapping
log show --predicate 'subsystem == "com.apple.ManagedClient" AND category == "OSUpdate"' --info --last 1d

# MDM push for updates
log show --predicate 'process == "mdmclient" AND eventMessage CONTAINS "ScheduleOSUpdate"' --info --last 1d
```

### DEP/ADE enrollment and Setup Assistant

```bash
# Setup Assistant
log show --predicate 'process == "Setup Assistant"' --info --debug --last 1h

# Cloud configuration daemon (ADE profile fetch from iprofiles.apple.com)
log show --predicate 'subsystem CONTAINS "com.apple.ManagedClient.cloudconfigurationd"' --info --debug --last 1h

# Combined DEP troubleshooting (real-time)
log stream --info --debug --predicate 'process == "mdmclient" OR process == "Setup Assistant" OR process == "cloudconfigurationd"'

# Await Configuration (macOS 14+)
log show --predicate 'process == "remotemanagementd" AND eventMessage CONTAINS "await"' --info --last 1h
```

### APNs (push notifications)

```bash
log show --predicate 'process == "apsd"' --info --last 1h
```

### Process name reference for filtering

| Process | Purpose |
|---|---|
| `mdmclient` | Apple MDM client — profile installs, MDM commands |
| `IntuneMdmDaemon` | Intune agent daemon — app/script deployment as root |
| `IntuneMdmAgent` | Intune agent — user-context scripts |
| `Company Portal` | Intune Company Portal app |
| `remotemanagementd` | Declarative Device Management (macOS 14+) |
| `cloudconfigurationd` | DEP/ADE cloud configuration |
| `Setup Assistant` | OOBE/initial setup |
| `softwareupdated` | Software update daemon |
| `apsd` | Apple Push Notification Service |
| `securityd` | Security/keychain daemon |
| `storedownloadd` | App Store downloads |

---

## macOS: Microsoft Defender for Endpoint logs

| Source | Path | Format | Purpose |
|---|---|---|---|
| `install.log` | `/Library/Logs/Microsoft/mdatp/install.log` | Plain text .log | Installation details — specifics not in the installer UI |
| `microsoft_defender_core_err.log` | `/Library/Logs/Microsoft/mdatp/microsoft_defender_core_err.log` | Plain text .log | Core errors — config loading, bad JSON properties, startup failures |
| Diagnostic bundle | Output of `sudo mdatp diagnostic create` → `/Library/Application Support/Microsoft/Defender/wdavdiag/<UUID>.zip` | .zip archive | Comprehensive diagnostic package |
| Quarantine files | `/Library/Application Support/Microsoft/Defender/quarantine/` | Binary | Quarantined threats (list with `mdatp threat list`) |

Key commands: `mdatp health` (overall status), `mdatp health --field edr_machine_id`, `mdatp connectivity test` (cloud connectivity), `mdatp log level set --level debug` (increase logging). Client analyzer: `sudo ./MDESupportTool -d --mdatp-log debug`.

---

## macOS: Microsoft Edge logs

| Source | Path | Format |
|---|---|---|
| Mandatory policies plist | `/Library/Managed Preferences/com.microsoft.Edge.plist` | .plist (XML) |
| Recommended policies plist | `/Library/Preferences/com.microsoft.Edge.plist` | .plist (XML) |
| EdgeUpdater policy plist | `/Library/Managed Preferences/com.microsoft.EdgeUpdater.plist` | .plist (XML) |
| Policy verification | `edge://policy/` in browser | Interactive |

No dedicated flat log file for Edge on macOS. Edge updates (EdgeUpdater, which replaced Microsoft AutoUpdate from Edge v113+) can be checked via unified logging by filtering process `EdgeUpdater`.

---

## macOS: Software update logs

| Source | Path | Format | Purpose |
|---|---|---|---|
| `install.log` | `/var/log/install.log` | Plain text .log | **All** pkg installations and macOS software updates — persists across reboots; one of the few remaining useful flat log files |

For unified logging predicates, see the Software Updates section under unified logging above. Force a state dump: `sudo softwareupdate --dump-state`.

---

## macOS: ADE/DEP enrollment files

| Path | Purpose |
|---|---|
| `/var/db/ConfigurationProfiles/Settings/.cloudConfigProfileInstalled` | ADE profile installed marker |
| `/var/db/ConfigurationProfiles/Settings/.cloudConfigRecordFound` | Activation record found marker |
| `/var/db/ConfigurationProfiles/Settings/.cloudConfigRecordNotFound` | No DEP record marker |
| `/var/db/.AppleSetupDone` | Setup Assistant completed |
| `/Library/Keychains/apsd.keychain` | APNs keychain |

During ADE enrollment, `cloudconfigurationd` fetches the activation record from `iprofiles.apple.com`. During enrollment, track installations via `/var/log/install.log`. During Setup Assistant, use keyboard shortcuts **Cmd+Opt+Ctrl+T** (Terminal) and **Cmd+Opt+Ctrl+C** (Console) for live debugging.

---

## macOS: Additional log locations

| Path | Contents | Format |
|---|---|---|
| `/Library/Logs/Microsoft/Intune/` | IntuneMDMDaemon/Agent logs | Pipe-delimited .log |
| `/Library/Logs/Microsoft/mdatp/` | Defender install and error logs | Plain text .log |
| `/Library/Logs/Microsoft/IntuneScripts/` | Custom per-script logs (shell-intune-samples) | Plain text .log |
| `/Library/Logs/ManagedClient/` | MCX debug log | Plain text .log |
| `~/Library/Logs/Microsoft/Intune/` | User-context agent logs | Pipe-delimited .log |
| `~/Library/Logs/CompanyPortal/` | Company Portal logs | Plain text .log |
| `~/Library/Logs/DiagnosticReports/` | User crash logs (`.crash`, `.ips`) | JSON-based |
| `/Library/Logs/DiagnosticReports/` | System crash logs | JSON-based |
| `/var/log/system.log` | Legacy system log (largely deprecated since Sierra) | Plain text |
| `/var/log/install.log` | Package installations and updates | Plain text |

**Unified log retention**: approximately **30 days**. File-based log retention for Intune agent: indefinite (new file per restart, not auto-cleaned). Collect a full system diagnostic via `sudo sysdiagnose` (output to `/var/tmp/sysdiagnose_*.tar.gz`), then view the unified log archive inside with `log show --archive <path>`.

---

## Parsing format summary for tool implementation

| Format | File types | Recommended parser | Platform |
|---|---|---|---|
| CMTrace (.log) | All IME logs, Panther setup logs | Regex: `<![LOG[<message>]LOG]!><time="HH:MM:SS.mmm" date="MM-DD-YYYY" component="<comp>" context="" type="<1\|2\|3>" thread="<tid>" file="">` | Windows |
| Plain text (.log) | CBS.log, DISM.log, ReportingEvents.log, MicrosoftEdgeUpdate.log, DMClient logs, WinGet logs | Line-by-line timestamp parsing | Windows |
| EVTX (binary) | All Windows Event Logs | `Get-WinEvent`, Event Viewer, EvtxECmd | Windows |
| ETL (binary) | WU ETLs, DO ETLs, WaaSMedic, DiagnosticLogCSP collectors | `tracerpt.exe`, WPA, `Get-WinEvent`, PerfView | Windows |
| HTML | MDMDiagHtmlReport, GPResult | Browser rendering or HTML parser | Windows |
| XML | MDMDiagReport.xml, SetupDiagResults.xml | XML parser | Windows |
| JSON | Autopilot profile JSONs, MdmDiagLogMetadata.json | JSON parser | Windows |
| Registry | PolicyManager, Enrollments, Win32Apps, LAPS, BitLocker, Edge policies | `reg query`, PowerShell `Get-ItemProperty` | Windows |
| Pipe-delimited (.log) | IntuneMDMDaemon, IntuneMDMAgent logs | Split on `\|` delimiter: DateTime \| Process \| Level \| PID \| Task \| TaskInfo | macOS |
| Unified log | mdmclient, remotemanagementd, SCEP, SoftwareUpdate, securityd | `log show --predicate` with subsystem/process filters | macOS |
| .plist (XML) | Managed Preferences, Edge policies | `plutil`, `defaults read`, plist parser | macOS |
| .crash / .ips | Crash reports | JSON parser (modern macOS) | macOS |

## Conclusion

This reference covers **over 80 distinct log sources** across both platforms. For the log viewer's quick-access menu, the most impactful organizational structure groups logs by troubleshooting workflow rather than alphabetically: enrollment first (MDM event logs, Autopilot JSONs, AAD operational), then policy sync (PolicyManager registry, DeviceManagement-Enterprise-Diagnostics-Provider), then app deployment (IME logs, AppWorkload, WinGet), then security/compliance (Defender, BitLocker, LAPS, certificates). On macOS, the unified log predicate library is the single most powerful diagnostic mechanism — building a predicate picker with the exact subsystem and process filters above eliminates the need for users to remember complex `log show` syntax. Two critical implementation details to note: Windows ETL files require conversion before display (consider shelling out to `tracerpt.exe` or `Get-WinEvent`), and macOS unified logs require `sudo` for system-level entries and have an approximate 30-day retention window that cannot be extended.