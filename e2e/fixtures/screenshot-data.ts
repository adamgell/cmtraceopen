/**
 * Curated mock data for the repository screenshot harness (`e2e/screenshots/`).
 *
 * These objects are injected into the running frontend so each workspace renders
 * a realistic, populated state without a real backend or real device data:
 *
 *  - `MOCK_LOG_PARSE_RESULT` — a `ParseResult` mirroring `demo/ConfigMgr_AppEnforce_demo.log`.
 *    Used only as the fallback when the real Rust IPC bridge (`:1422`) is NOT running;
 *    when it is, the real parser parses the demo log on disk instead.
 *  - `MOCK_INTUNE` — arguments for the Intune store's `setResults(...)`.
 *  - `MOCK_DSREGCMD` — arguments for the DSRegCmd store's `setResults(...)`. Always synthetic:
 *    a real `dsregcmd /status` capture would leak the host's device/tenant identifiers into a
 *    committed public screenshot, so this workspace never uses live data.
 *
 * The data is intentionally fictional (Contoso, placeholder GUIDs) so nothing here identifies
 * a real device, tenant, or user.
 */
import { fileURLToPath } from "node:url";
import path from "node:path";

import type { LogEntry, ParseResult } from "../../src/types/log";

const HERE = path.dirname(fileURLToPath(import.meta.url));

/** Absolute path to the committed demo CCM log parsed in live (bridge) mode. */
export const DEMO_LOG_ABS_PATH = path.resolve(HERE, "demo", "ConfigMgr_AppEnforce_demo.log");

// ---------------------------------------------------------------------------
// Log Viewer — a ConfigMgr (CCM) app-deployment log with a fail → retry → success
// story arc, so the screenshot shows Info / Warning / Error / Success coloring plus
// recognized Windows error codes.
// ---------------------------------------------------------------------------

interface LogSeed {
  message: string;
  severity: LogEntry["severity"];
  component: string;
  /** Windows error code appearing verbatim in `message`, highlighted + looked up. */
  errorCode?: { hex: string; decimal: string; description: string; category: string };
}

const LOG_SEEDS: LogSeed[] = [
  { message: 'Performing detection of app deployment type "Contoso VPN Client 4.2 (x64)" for system.', severity: "Info", component: "AppDiscovery" },
  { message: "+++ Application not discovered. [AppDT Id: ScopeId_A1/DeploymentType_9f3, Revision: 3]", severity: "Info", component: "AppDiscovery" },
  { message: 'The user clicked to install "Contoso VPN Client 4.2 (x64)".', severity: "Info", component: "AppEnforce" },
  { message: 'Executing Command line: "C:\\WINDOWS\\system32\\msiexec.exe" /i "ContosoVPN.msi" /q /l*v "C:\\WINDOWS\\ccm\\logs\\ContosoVPN_install.log"', severity: "Info", component: "AppEnforce" },
  { message: "Existing anti-malware scan already in progress, deferring content download by 30 seconds.", severity: "Warning", component: "AppEnforce" },
  { message: "Process 6132 terminated with exitcode: 1603", severity: "Error", component: "AppEnforce" },
  { message: "Matched exit code 1603 to a Failure entry in exit codes table.", severity: "Info", component: "AppEnforce" },
  {
    message: "CMsiHandler::EnforceApp failed with error 0x80070643 (The installation package could not be opened).",
    severity: "Error",
    component: "AppEnforce",
    errorCode: { hex: "0x80070643", decimal: "-2147023293", description: "Fatal error during installation.", category: "Windows" },
  },
  {
    message: "Method CBaseProvider::EnforceApp failed with error code 0x87D00269",
    severity: "Error",
    component: "AppEnforce",
    errorCode: { hex: "0x87D00269", decimal: "-2016410007", description: "Application requirement evaluation or detection failed.", category: "ConfigMgr" },
  },
  { message: "Retrying install after 10 minute back-off. Attempt 2 of 3.", severity: "Warning", component: "AppEnforce" },
  { message: 'Executing Command line: "C:\\WINDOWS\\system32\\msiexec.exe" /i "ContosoVPN.msi" /q /l*v "C:\\WINDOWS\\ccm\\logs\\ContosoVPN_install.log"', severity: "Info", component: "AppEnforce" },
  { message: "Process 8044 terminated with exitcode: 0", severity: "Info", component: "AppEnforce" },
  { message: "Matched exit code 0 to a Success entry in exit codes table.", severity: "Info", component: "AppEnforce" },
  { message: "+++ Discovered application [AppDT Id: ScopeId_A1/DeploymentType_9f3, Revision: 3]", severity: "Info", component: "AppEnforce" },
  { message: '++++++ App enforcement completed (successfully) for App DT "Contoso VPN Client 4.2 (x64)" ++++++', severity: "Success", component: "AppEnforce" },
];

// Deterministic, wall-clock-independent timestamps starting 2026-07-13 09:14:02.331 UTC.
const LOG_BASE_EPOCH_MS = Date.UTC(2026, 6, 13, 9, 14, 2, 331);
const THREAD = 4820;

function two(n: number): string {
  return String(n).padStart(2, "0");
}
function three(n: number): string {
  return String(n).padStart(3, "0");
}

function buildLogEntries(): LogEntry[] {
  return LOG_SEEDS.map((seed, index) => {
    // Space entries a few seconds apart; jump forward across the back-off retry.
    const offsetMs = (index < 10 ? index * 3200 : 600_000 + index * 3200);
    const epoch = LOG_BASE_EPOCH_MS + offsetMs;
    const d = new Date(epoch);
    const display = `${two(d.getUTCMonth() + 1)}-${two(d.getUTCDate())}-${d.getUTCFullYear()} ${two(d.getUTCHours())}:${two(d.getUTCMinutes())}:${two(d.getUTCSeconds())}.${three(d.getUTCMilliseconds())}`;

    const entry: LogEntry = {
      id: index,
      lineNumber: index + 1,
      message: seed.message,
      component: seed.component,
      timestamp: epoch,
      timestampDisplay: display,
      severity: seed.severity,
      thread: THREAD,
      threadDisplay: String(THREAD),
      sourceFile: "appexcnlib.cpp",
      format: "Ccm",
      filePath: DEMO_LOG_ABS_PATH,
      timezoneOffset: 0,
    };

    if (seed.errorCode) {
      const start = seed.message.indexOf(seed.errorCode.hex);
      if (start >= 0) {
        entry.errorCodeSpans = [
          {
            start,
            end: start + seed.errorCode.hex.length,
            codeHex: seed.errorCode.hex,
            codeDecimal: seed.errorCode.decimal,
            description: seed.errorCode.description,
            category: seed.errorCode.category,
          },
        ];
      }
    }

    return entry;
  });
}

const LOG_ENTRIES = buildLogEntries();

export const MOCK_LOG_PARSE_RESULT: ParseResult = {
  entries: LOG_ENTRIES,
  formatDetected: "Ccm",
  parserSelection: {
    parser: "ccm",
    implementation: "ccm",
    provenance: "dedicated",
    parseQuality: "structured",
    recordFraming: "logicalRecord",
    dateOrder: "monthFirst",
  },
  totalLines: LOG_ENTRIES.length,
  parseErrors: 0,
  filePath: DEMO_LOG_ABS_PATH,
  fileSize: 6144,
  byteOffset: 6144,
};

// ---------------------------------------------------------------------------
// Intune Diagnostics — arguments for `useIntuneStore.getState().setResults(...)`.
// Coverage / confidence / repeated-failure clusters are auto-derived when the
// optional metadata argument is omitted.
// ---------------------------------------------------------------------------

const IME_LOG = "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\IntuneManagementExtension.log";
const APPWORKLOAD_LOG = "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\AppWorkload.log";
const AGENTEXEC_LOG = "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\AgentExecutor.log";

export const MOCK_INTUNE = {
  sourceFile: IME_LOG,
  sourceFiles: [IME_LOG, APPWORKLOAD_LOG, AGENTEXEC_LOG],
  events: [
    {
      id: 1, eventType: "Win32App", name: "Company Portal", guid: "3f2b1a90-1111-4a2b-9c3d-aaaaaaaaaaaa",
      status: "Success", startTime: "2026-07-13 09:15:22.101", endTime: "2026-07-13 09:16:04.550",
      durationSecs: 42, errorCode: null, detail: "Install succeeded (exit code 0).",
      sourceFile: "AppWorkload.log", lineNumber: 812, startTimeEpoch: null, endTimeEpoch: null,
    },
    {
      id: 2, eventType: "Win32App", name: "7-Zip 23.01 (x64)", guid: "7a1c2b90-2222-4b3c-8d4e-bbbbbbbbbbbb",
      status: "Failed", startTime: "2026-07-13 09:22:10.300", endTime: "2026-07-13 09:22:59.900",
      durationSecs: 49, errorCode: "0x87D1041C", detail: "Detection rule failed after install; app not detected.",
      sourceFile: "AppWorkload.log", lineNumber: 1044, startTimeEpoch: null, endTimeEpoch: null,
    },
    {
      id: 3, eventType: "PowerShellScript", name: "Detect-DiskSpace.ps1", guid: null,
      status: "Failed", startTime: "2026-07-13 09:31:05.000", endTime: "2026-07-13 09:31:06.240",
      durationSecs: 1, errorCode: "0x80070005", detail: "Access is denied while writing remediation state.",
      sourceFile: "AgentExecutor.log", lineNumber: 205, startTimeEpoch: null, endTimeEpoch: null,
    },
    {
      id: 4, eventType: "ContentDownload", name: "Adobe Acrobat Reader DC", guid: "c0ffee90-3333-4c4d-9e5f-cccccccccccc",
      status: "Success", startTime: "2026-07-13 09:40:00.000", endTime: "2026-07-13 09:41:12.000",
      durationSecs: 72, errorCode: null, detail: "Downloaded 512.0 MB via Delivery Optimization (peer: 38%).",
      sourceFile: "IntuneManagementExtension.log", lineNumber: 1590, startTimeEpoch: null, endTimeEpoch: null,
    },
    {
      id: 5, eventType: "Win32App", name: "Adobe Acrobat Reader DC", guid: "c0ffee90-3333-4c4d-9e5f-cccccccccccc",
      status: "Success", startTime: "2026-07-13 09:41:20.000", endTime: "2026-07-13 09:43:02.000",
      durationSecs: 102, errorCode: null, detail: "Install succeeded (exit code 0).",
      sourceFile: "AppWorkload.log", lineNumber: 1655, startTimeEpoch: null, endTimeEpoch: null,
    },
    {
      id: 6, eventType: "PolicyEvaluation", name: "Windows Compliance Baseline", guid: null,
      status: "Success", startTime: "2026-07-13 09:46:33.000", endTime: "2026-07-13 09:47:10.000",
      durationSecs: 37, errorCode: null, detail: "All 14 settings evaluated compliant.",
      sourceFile: "IntuneManagementExtension.log", lineNumber: 1702, startTimeEpoch: null, endTimeEpoch: null,
    },
  ],
  downloads: [
    {
      contentId: "app-adobe-reader-dc", name: "Adobe Acrobat Reader DC", sizeBytes: 536870912,
      speedBps: 7340032, doPercentage: 38, durationSecs: 72, success: true,
      timestamp: "2026-07-13 09:41:12.000", timestampEpoch: null,
    },
    {
      contentId: "app-company-portal", name: "Company Portal", sizeBytes: 78643200,
      speedBps: 12582912, doPercentage: 61, durationSecs: 6, success: true,
      timestamp: "2026-07-13 09:15:19.000", timestampEpoch: null,
    },
    {
      contentId: "app-7zip-2301", name: "7-Zip 23.01 (x64)", sizeBytes: 1887436,
      speedBps: 0, doPercentage: 0, durationSecs: 5, success: false,
      timestamp: "2026-07-13 09:22:15.000", timestampEpoch: null,
    },
  ],
  summary: {
    totalEvents: 6, win32Apps: 3, wingetApps: 0, scripts: 1, remediations: 0,
    succeeded: 4, failed: 2, inProgress: 0, pending: 0, timedOut: 0,
    totalDownloads: 3, successfulDownloads: 2, failedDownloads: 1, failedScripts: 1,
    logTimeSpan: "09:15:22 - 09:47:10 (31m 48s)",
  },
  diagnostics: [
    {
      id: "diag-win32-detect-fail", severity: "Error", category: "Install", remediationPriority: "High",
      title: "Win32 app installed but failed detection",
      summary: "7-Zip 23.01 exited 0 but the detection rule did not match, so Intune reports the install as failed.",
      likelyCause: "The detection rule points at a version or path that the installer does not produce.",
      evidence: ["AppWorkload.log:1044 - detection failed (0x87D1041C)"],
      nextChecks: ["Confirm the detection rule file/version", "Re-run detection manually on the device"],
      suggestedFixes: ["Update the detection rule to match the installed build"],
      focusAreas: ["Detection"], affectedSourceFiles: ["AppWorkload.log"], relatedErrorCodes: ["0x87D1041C"],
    },
    {
      id: "diag-script-access-denied", severity: "Warning", category: "Script", remediationPriority: "Medium",
      title: "Remediation script blocked by permissions",
      summary: "Detect-DiskSpace.ps1 failed with Access Denied while writing its state file.",
      likelyCause: "The script runs in the user context but writes to a protected location.",
      evidence: ["AgentExecutor.log:205 - 0x80070005 Access is denied"],
      nextChecks: ["Verify the script run-as context"],
      suggestedFixes: ["Run the script in system context"],
      focusAreas: ["Permissions"], affectedSourceFiles: ["AgentExecutor.log"], relatedErrorCodes: ["0x80070005"],
    },
  ],
};

// ---------------------------------------------------------------------------
// DSRegCmd — arguments for `useDsregcmdStore.getState().setResults(rawInput, result, context)`.
// A fictional Microsoft Entra joined device with one Warning and one Info finding.
// ---------------------------------------------------------------------------

const DSREGCMD_RAW = [
  "+----------------------------------------------------------------------+",
  "| Device State                                                         |",
  "+----------------------------------------------------------------------+",
  "",
  "             AzureAdJoined : YES",
  "          EnterpriseJoined : NO",
  "              DomainJoined : NO",
  "               Device Name : WORKSTATION",
  "",
  "+----------------------------------------------------------------------+",
  "| SSO State                                                            |",
  "+----------------------------------------------------------------------+",
  "",
  "                AzureAdPrt : YES",
  "      AzureAdPrtUpdateTime : 2026-07-13 06:02:11.000 UTC",
  "             EnterprisePrt : NO",
  "",
].join("\n");

const DSREGCMD_RESULT = {
  facts: {
    joinState: { azureAdJoined: true, domainJoined: false, workplaceJoined: false, enterpriseJoined: false },
    deviceDetails: {
      deviceId: "2b8f1e44-9c7a-4d21-9f6e-1a2b3c4d5e6f",
      thumbprint: "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
      deviceCertificateValidity: "[ 2025-01-10 09:14:02.000 UTC -- 2035-01-08 09:14:02.000 UTC ]",
      keyContainerId: "0f6c1d2e-3a4b-5c6d-7e8f-9012a3b4c5d6",
      keyProvider: "Microsoft Platform Crypto Provider", tpmProtected: true, deviceAuthStatus: "SUCCESS",
    },
    tenantDetails: { tenantId: "9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d", tenantName: "Contoso", domainName: "contoso.onmicrosoft.com", idp: "login.microsoftonline.com" },
    managementDetails: {
      mdmUrl: "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc",
      mdmComplianceUrl: "https://portal.manage.microsoft.com/?portalAction=Compliance",
      mdmTouUrl: "https://portal.manage.microsoft.com/TermsofUse.aspx",
      settingsUrl: null, deviceManagementSrvVer: "1.0", deviceManagementSrvUrl: null, deviceManagementSrvId: "0000000a-0000-0000-c000-000000000000",
    },
    serviceEndpoints: {
      authCodeUrl: "https://login.microsoftonline.com/common/oauth2/authorize",
      accessTokenUrl: "https://login.microsoftonline.com/common/oauth2/token",
      joinSrvVersion: "1.0", joinSrvUrl: "https://enterpriseregistration.windows.net/EnrollmentServer/device/", joinSrvId: "urn:ms-drs:enterpriseregistration.windows.net",
      keySrvVersion: "1.0", keySrvUrl: "https://enterpriseregistration.windows.net/EnrollmentServer/key/", keySrvId: "urn:ms-drs:enterpriseregistration.windows.net",
      webAuthnSrvVersion: "1.0", webAuthnSrvUrl: "https://enterpriseregistration.windows.net/webauthn/", webAuthnSrvId: "urn:ms-drs:enterpriseregistration.windows.net",
    },
    userState: {
      ngcSet: true, ngcKeyId: "c3d4e5f6-1234-4a5b-8c9d-0e1f2a3b4c5d", canReset: "DestructiveOnly",
      wamDefaultSet: true, wamDefaultAuthority: "organizations", wamDefaultId: "https://login.microsoft.com", wamDefaultGuid: "9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d",
      isDeviceJoined: true, isUserAzureAd: true, policyEnabled: true, postLogonEnabled: true, deviceEligible: true, sessionIsNotRemote: true,
    },
    ssoState: {
      azureAdPrt: true, azureAdPrtAuthority: "https://login.microsoftonline.com/9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d",
      azureAdPrtUpdateTime: "2026-07-13 06:02:11.000 UTC", acquirePrtDiagnostics: "PRESENT",
      enterprisePrt: false, enterprisePrtUpdateTime: null, enterprisePrtExpiryTime: null, enterprisePrtAuthority: null,
      onPremTgt: false, cloudTgt: true, adfsRefreshToken: false, adfsRaIsReady: false, kerbTopLevelNames: ".contoso.com,.windows.net",
    },
    diagnostics: {
      previousPrtAttempt: "2026-07-13 06:02:11.000 UTC", attemptStatus: "0x0", userIdentity: "alice@contoso.com",
      credentialType: "Password", correlationId: "7f3a1b2c-8d9e-4f01-a2b3-c4d5e6f70819", endpointUri: "https://login.microsoftonline.com/common/oauth2/token",
      httpMethod: "POST", httpError: null, httpStatus: 200, requestId: "b1c2d3e4-f5a6-7890-1234-56789abcdef0",
      diagnosticsReference: null, userContext: null, clientTime: "2026-07-13 06:02:10.000 UTC",
    },
    preJoinTests: {
      adConnectivityTest: null, adConfigurationTest: null, drsDiscoveryTest: "SUCCESS",
      drsConnectivityTest: "SUCCESS", tokenAcquisitionTest: "SUCCESS", fallbackToSyncJoin: null,
    },
    registration: {
      previousRegistration: null, errorPhase: null, certEnrollment: "none", logonCertTemplateReady: "NotApplicable",
      preReqResult: "Will Provision", clientErrorCode: "0x0", serverErrorCode: null, serverMessage: null, serverErrorDescription: null,
    },
    postJoinDiagnostics: { aadRecoveryEnabled: false, keySignTest: "PASSED" },
  },
  derived: {
    joinType: "EntraIdJoined", joinTypeLabel: "Microsoft Entra joined",
    dominantPhase: "post_join", phaseSummary: "Device is Entra joined and past registration; token and policy health are being evaluated.",
    captureConfidence: "high", captureConfidenceReason: "Capture ran in the signed-in user context with a full SSO State section present.",
    mdmEnrolled: false, missingMdm: true, complianceUrlPresent: true, missingComplianceUrl: false,
    azureAdPrtPresent: true, stalePrt: false, prtLastUpdate: "2026-07-13 06:02:11.000 UTC", prtReferenceTime: "2026-07-13 08:40:00.000 UTC", prtAgeHours: 2.6,
    tpmProtected: true,
    certificateValidFrom: "2025-01-10 09:14:02.000 UTC", certificateValidTo: "2035-01-08 09:14:02.000 UTC",
    certificateExpiringSoon: false, certificateDaysRemaining: 3101,
    networkErrorCode: null, hasNetworkError: false, remoteSessionSystem: false,
  },
  diagnostics: [
    {
      id: "mdm-not-enrolled", severity: "Warning", category: "Management",
      title: "Device is Entra joined but not MDM enrolled",
      summary: "No MDM enrollment URLs resolved to an active enrollment, so Intune compliance and policy may not apply.",
      evidence: ["MdmUrl present but enrollment state not detected", "DeviceManagementSrvUrl is empty"],
      nextChecks: ["Confirm the auto-enrollment GPO / CSP is scoped to this device", "Check the DeviceManagement section on the endpoint"],
      suggestedFixes: ["Trigger enrollment via Settings > Access work or school", "Verify the user has an Intune license assigned"],
    },
    {
      id: "on-prem-sso-missing", severity: "Info", category: "SSO",
      title: "No on-premises SSO artifacts present",
      summary: "OnPremTgt and EnterprisePrt are not set. Expected for a cloud-only Entra joined device without Hybrid configuration.",
      evidence: ["EnterprisePrt : NO", "OnPremTgt : NO"],
      nextChecks: ["Confirm whether on-prem resource access is required for this user"],
      suggestedFixes: ["If on-prem SSO is needed, configure Entra Connect / Cloud Kerberos Trust"],
    },
  ],
  policyEvidence: {
    policyEnabled: { displayValue: true, currentValue: true, providerValue: null, source: "dsregcmd", note: null },
    postLogonEnabled: { displayValue: true, currentValue: true, providerValue: null, source: "dsregcmd", note: null },
    pinRecoveryEnabled: { displayValue: false, currentValue: false, providerValue: null, source: "windows_policy_machine", note: null },
    requireSecurityDevice: { displayValue: true, currentValue: true, providerValue: null, source: "windows_policy_machine", note: null },
    useCertificateForOnPremAuth: { displayValue: false, currentValue: false, providerValue: null, source: null, note: null },
    useCloudTrustForOnPremAuth: { displayValue: false, currentValue: false, providerValue: null, source: null, note: null },
    artifactPaths: ["HKLM\\SOFTWARE\\Policies\\Microsoft\\PassportForWork"],
  },
  osVersion: { currentBuild: "26100", displayVersion: "24H2", productName: "Windows 11 Enterprise", ubr: 1742, editionId: "Enterprise" },
  proxyEvidence: null,
  enrollmentEvidence: null,
  activeEvidence: null,
  scheduledTaskEvidence: null,
  eventLogAnalysis: null,
};

export const MOCK_DSREGCMD = {
  rawInput: DSREGCMD_RAW,
  result: DSREGCMD_RESULT,
  context: {
    source: { kind: "capture" as const },
    requestedPath: null,
    resolvedPath: null,
    bundlePath: null,
    displayLabel: "Sample capture (Contoso)",
    evidenceFilePath: null,
    rawLineCount: DSREGCMD_RAW.split("\n").length,
    rawCharCount: DSREGCMD_RAW.length,
  },
};
