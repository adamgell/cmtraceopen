/**
 * JAMF workspace fixtures for `e2e/jamf.spec.ts`.
 *
 * The E2E job runs without a Rust build (`.github/workflows/cmtrace-ci.yml`), so
 * the six `jamf_*` commands are answered through the Tauri IPC shim's per-test
 * overrides. Nothing here is invented from scratch — each payload is what the
 * committed JAMF corpus produces:
 *
 *  - `JAMF_ENVIRONMENT` follows `jamf::detect`, including the summary wording
 *    from `build_summary` and the version string shape documented in
 *    `src-tauri/src/jamf/detect.rs`.
 *  - `JAMF_LOG_SCAN` lists the files `jamf_scan_logs` resolves — the standalone
 *    `paths::JAMF_LOG` / `paths::JAMF_CONNECT_LOG_SYSTEM` files and the
 *    per-user log directory — with the sizes of the fixture logs they stand in
 *    for.
 *  - `JAMF_POLICY_LOG` is the parse of
 *    `src-tauri/tests/fixtures/jamf_policy_log_basic.log`: one event per line,
 *    classified exactly as `jamf::policy_log::classify` does, with the elapsed
 *    times (and the `None` for a policy with nothing to measure against)
 *    pinned by `tests/jamf_policy_log_parsing.rs`.
 *  - `JAMF_SELF_SERVICE_EVENTS` and `JAMF_CONNECT_EVENTS` are the parses of
 *    `jamf_self_service_basic.log` and `jamf_connect_basic.log` as pinned by
 *    their own parser tests.
 *  - `JAMF_PROFILES` mirrors the shape `jamf_filter_profiles` returns for a
 *    JAMF-deployed profile. The PPPC payload is the documented real case where
 *    the Apple payload type carries no JAMF identity and the
 *    `com.jamfsoftware.` payload *identifier* does.
 *
 * Identifiers are placeholders (Contoso, `MAC-EXAMPLE0001`, `jdoe`) matching
 * the fixture logs, so nothing here points at a real device or organization.
 */
import type {
  JamfConnectEvent,
  JamfEnvironment,
  JamfLogScanResult,
  JamfPolicyLogResult,
  JamfProfilesResult,
  JamfSelfServiceEvent,
} from "../../src/workspaces/macos-jamf/types";

/**
 * Workspace allowlist reported by a macOS build. `macos-diag` and `macos-jamf`
 * are pushed together by the `macos-diag` feature in
 * `src-tauri/src/commands/app_config.rs`; the remaining ids match the IPC
 * shim's default list so only the macOS entries differ.
 */
export const MACOS_JAMF_WORKSPACES = [
  "log",
  "intune",
  "new-intune",
  "dsregcmd",
  "deployment",
  "event-log",
  "sysmon",
  "secureboot",
  "esp-diagnostics",
  "macos-diag",
  "macos-jamf",
];

export const JAMF_ENVIRONMENT: JamfEnvironment = {
  jamfInstalled: true,
  // Real `jamf version` output shape: `version=11.26.1-t1774880441315`.
  jamfVersion: "11.26.1-t1774880441315",
  jssUrl: "https://contoso.jamfcloud.com",
  lastCheckIn: "2026-04-30T15:20:54Z",
  mdmProfilePresent: true,
  mdmOrganization: "Contoso",
  jamfConnectInstalled: true,
  jamfConnectVersion: "2.16.0",
  jamfConnectIdp: "Microsoft",
  fdaStatus: "granted",
  directories: {
    jamfLog: true,
    jamfAppSupport: true,
    jamfReceipts: true,
    jamfUserLogs: true,
    selfServiceLog: true,
    connectLog: true,
    connectUserLogs: true,
  },
  summary: "JAMF binary detected (11.26.1-t1774880441315) · JAMF Connect installed",
};

/** Sizes are those of the committed fixture logs in `src-tauri/tests/fixtures`. */
export const JAMF_LOG_SCAN: JamfLogScanResult = {
  files: [
    {
      path: "/var/log/jamf.log",
      fileName: "jamf.log",
      sizeBytes: 1180,
      modifiedUnixMs: Date.parse("2026-04-30T15:20:54Z"),
      sourceDirectory: "/var/log",
    },
    {
      path: "/Library/Logs/JAMFConnect.log",
      fileName: "JAMFConnect.log",
      sizeBytes: 398,
      modifiedUnixMs: Date.parse("2026-04-29T09:14:30Z"),
      sourceDirectory: "/Library/Logs",
    },
    {
      path: "/Users/jdoe/Library/Logs/JAMF/selfservice.log",
      fileName: "selfservice.log",
      sizeBytes: 812,
      modifiedUnixMs: Date.parse("2026-04-29T15:03:11Z"),
      sourceDirectory: "/Users/jdoe/Library/Logs/JAMF",
    },
    {
      path: "/Users/jdoe/Library/Logs/JAMF/JAMF Connect/JAMFConnect.log",
      fileName: "JAMFConnect.log",
      sizeBytes: 398,
      modifiedUnixMs: Date.parse("2026-04-29T09:14:30Z"),
      sourceDirectory: "/Users/jdoe/Library/Logs/JAMF/JAMF Connect",
    },
  ],
  scannedDirectories: [
    "/Library/Application Support/JAMF/Logs",
    "/Users/jdoe/Library/Logs/JAMF",
    "/Users/jdoe/Library/Logs/JAMF/JAMF Connect",
  ],
  totalSizeBytes: 1180 + 398 + 812 + 398,
};

/** `rawLineOffset` values are the byte offsets of the lines in the fixture log. */
export const JAMF_POLICY_LOG: JamfPolicyLogResult = {
  events: [
    {
      timestamp: "2026-04-29T12:40:46Z",
      trigger: { type: "other", value: "info" },
      policyId: null,
      policyName: null,
      result: { type: "unknown" },
      durationMs: null,
      rawLineOffset: 0,
      rawLine:
        "Wed Apr 29 12:40:46 MAC-EXAMPLE0001 jamf[87148]: Removing existing launchd task /Library/LaunchAgents/com.jamfsoftware.jamfhelper.plist...",
    },
    {
      timestamp: "2026-04-29T12:40:46Z",
      trigger: { type: "recurringCheckIn" },
      policyId: null,
      policyName: null,
      result: { type: "unknown" },
      durationMs: null,
      rawLineOffset: 139,
      rawLine:
        'Wed Apr 29 12:40:46 MAC-EXAMPLE0001 jamf[87148]: Checking for policies triggered by "recurring check-in" for user "jdoe"...',
    },
    {
      timestamp: "2026-04-29T12:40:50Z",
      trigger: { type: "other", value: "patch-check" },
      policyId: null,
      policyName: null,
      result: { type: "inProgress" },
      durationMs: null,
      rawLineOffset: 263,
      rawLine: "Wed Apr 29 12:40:50 MAC-EXAMPLE0001 jamf[87148]: Checking for patches...",
    },
    {
      timestamp: "2026-04-29T12:40:51Z",
      trigger: { type: "other", value: "patch-check" },
      policyId: null,
      policyName: null,
      result: { type: "success" },
      durationMs: null,
      rawLineOffset: 336,
      rawLine: "Wed Apr 29 12:40:51 MAC-EXAMPLE0001 jamf[87148]: No patch policies were found.",
    },
    {
      timestamp: "2026-04-29T13:16:49Z",
      trigger: { type: "recurringCheckIn" },
      policyId: null,
      policyName: null,
      result: { type: "unknown" },
      durationMs: null,
      rawLineOffset: 415,
      rawLine:
        'Wed Apr 29 13:16:49 MAC-EXAMPLE0001 jamf[91196]: Checking for policies triggered by "recurring check-in" for user "jdoe"...',
    },
    {
      timestamp: "2026-04-29T13:16:54Z",
      trigger: { type: "other", value: "execute" },
      policyId: null,
      policyName: "Update Inventory (Daily)",
      result: { type: "inProgress" },
      // Bounded by the same invocation's next line (13:16:55, `jamf[91196]`).
      durationMs: 1000,
      rawLineOffset: 539,
      rawLine:
        "Wed Apr 29 13:16:54 MAC-EXAMPLE0001 jamf[91196]: Executing Policy Update Inventory (Daily)",
    },
    {
      timestamp: "2026-04-29T13:16:55Z",
      trigger: { type: "other", value: "patch-check" },
      policyId: null,
      policyName: null,
      result: { type: "inProgress" },
      durationMs: null,
      rawLineOffset: 630,
      rawLine: "Wed Apr 29 13:16:55 MAC-EXAMPLE0001 jamf[91196]: Checking for patches...",
    },
    {
      timestamp: "2026-04-29T13:23:00Z",
      trigger: { type: "policyId", value: "332" },
      policyId: "332",
      policyName: null,
      result: { type: "unknown" },
      durationMs: null,
      rawLineOffset: 703,
      rawLine: "Wed Apr 29 13:23:00 MAC-EXAMPLE0001 jamf[92532]: Checking for policy ID 332...",
    },
    {
      timestamp: "2026-04-29T13:23:04Z",
      trigger: { type: "other", value: "execute" },
      policyId: null,
      policyName: "Google Chrome Installer",
      result: { type: "inProgress" },
      // 13:23:04 → 13:23:29, both under `jamf[92532]`.
      durationMs: 25_000,
      rawLineOffset: 782,
      rawLine: "Wed Apr 29 13:23:04 MAC-EXAMPLE0001 jamf[92532]: Executing Policy Google Chrome Installer",
    },
    {
      timestamp: "2026-04-29T13:23:29Z",
      trigger: { type: "other", value: "info" },
      policyId: null,
      policyName: null,
      result: { type: "unknown" },
      durationMs: null,
      rawLineOffset: 872,
      rawLine:
        "Wed Apr 29 13:23:29 MAC-EXAMPLE0001 jamf[92532]: Inventory will be updated when all queued actions in Self Service are complete.",
    },
    {
      timestamp: "2026-04-30T10:19:50Z",
      trigger: { type: "other", value: "execute" },
      policyId: null,
      policyName: "Reboot Popup (Weekly)",
      result: { type: "inProgress" },
      // Sole event of its invocation — nothing to measure against.
      durationMs: null,
      rawLineOffset: 1001,
      rawLine: "Thu Apr 30 10:19:50 MAC-EXAMPLE0001 jamf[15033]: Executing Policy Reboot Popup (Weekly)",
    },
    {
      timestamp: "2026-04-30T15:20:54Z",
      trigger: { type: "other", value: "execute" },
      policyId: null,
      policyName: "Update Inventory (Daily)",
      result: { type: "inProgress" },
      durationMs: null,
      rawLineOffset: 1089,
      rawLine: "Thu Apr 30 15:20:54 MAC-EXAMPLE0001 jamf[18318]: Executing Policy Update Inventory (Daily)",
    },
  ],
  totalLines: 12,
  unparsedLines: 0,
  sourcePath: "/var/log/jamf.log",
};

/**
 * The twelve timestamped lines of the fixture log. The timestamp-less line is
 * dropped by the parser, which is why the fixture has thirteen lines and the
 * tab reports twelve events.
 */
export const JAMF_SELF_SERVICE_EVENTS: JamfSelfServiceEvent[] = [
  {
    timestamp: "2026-04-29T14:59:40Z",
    action: "launch",
    itemName: null,
    result: null,
    rawLine: "[2026-04-29 14:59:40] Application successfully launched",
  },
  {
    timestamp: "2026-04-29T14:59:41Z",
    action: "info",
    itemName: "Self Service Core initialized",
    result: null,
    rawLine: "[2026-04-29 14:59:41] Self Service Core initialized",
  },
  {
    timestamp: "2026-04-29T14:59:41Z",
    action: "connectivity",
    itemName: null,
    result: "negotiating",
    rawLine:
      "[2026-04-29 14:59:41] Server Connectivity State change - state: negotiating, user: nil",
  },
  {
    timestamp: "2026-04-29T14:59:42Z",
    action: "connectivity",
    itemName: null,
    result: "active",
    rawLine: "[2026-04-29 14:59:42] Server Connectivity State change - state: active, user: nil",
  },
  {
    timestamp: "2026-04-29T14:59:42Z",
    action: "request",
    itemName: "updateDevicePushToken",
    result: null,
    rawLine: "[2026-04-29 14:59:42] Request: updateDevicePushToken",
  },
  {
    timestamp: "2026-04-29T14:59:43Z",
    action: "request",
    itemName: "getPolicies",
    result: null,
    rawLine: "[2026-04-29 14:59:43] Request: getPolicies",
  },
  {
    timestamp: "2026-04-29T14:59:44Z",
    action: "request",
    itemName: "getMacApps",
    result: null,
    rawLine: "[2026-04-29 14:59:44] Request: getMacApps",
  },
  {
    timestamp: "2026-04-29T15:00:01Z",
    action: "warning",
    itemName:
      "A customized icon is larger than recommended. To reduce app memory usage, resize it.",
    result: null,
    rawLine:
      "[2026-04-29 15:00:01] WARNING: A customized icon is larger than recommended. To reduce app memory usage, resize it.",
  },
  {
    timestamp: "2026-04-29T15:00:02Z",
    action: "triggerPolicy",
    itemName: null,
    result: null,
    rawLine: "[2026-04-29 15:00:02] Binary Request: triggerPolicy",
  },
  {
    timestamp: "2026-04-29T15:00:22Z",
    action: "triggerPolicy",
    itemName: null,
    result: null,
    rawLine: "[2026-04-29 15:00:22] Binary Request: triggerPolicy",
  },
  {
    timestamp: "2026-04-29T15:02:05Z",
    action: "doRecon",
    itemName: null,
    result: null,
    rawLine: "[2026-04-29 15:02:05] Binary Request: doRecon",
  },
  {
    timestamp: "2026-04-29T15:03:11Z",
    action: "info",
    itemName: "Failed to find local icon path for Self Service Classic default icon",
    result: null,
    rawLine:
      "[2026-04-29 15:03:11] Failed to find local icon path for Self Service Classic default icon",
  },
];

export const JAMF_CONNECT_EVENTS: JamfConnectEvent[] = [
  {
    timestamp: "2026-04-29T09:12:03Z",
    eventType: "Login",
    idp: "Microsoft",
    user: "adam@example.com",
    message: "User adam@example.com authenticated via OIDC (provider=Microsoft)",
    rawLine:
      "2026-04-29T09:12:03+0000 [INFO] [Login] User adam@example.com authenticated via OIDC (provider=Microsoft)",
  },
  {
    timestamp: "2026-04-29T09:12:08Z",
    eventType: "Sync",
    idp: null,
    user: "adam@example.com",
    message: "Password sync completed for user adam@example.com",
    rawLine:
      "2026-04-29T09:12:08+0000 [INFO] [Sync] Password sync completed for user adam@example.com",
  },
  {
    timestamp: "2026-04-29T09:14:00Z",
    eventType: "Sync",
    idp: null,
    user: "bob@example.com",
    message: "Password mismatch for user bob@example.com",
    rawLine: "2026-04-29T09:14:00+0000 [WARN] [Sync] Password mismatch for user bob@example.com",
  },
  {
    timestamp: "2026-04-29T09:14:30Z",
    eventType: "Login",
    idp: null,
    user: "mallory@example.com",
    message: "Authentication failed for user mallory@example.com (reason=invalid_credentials)",
    rawLine:
      "2026-04-29T09:14:30+0000 [ERROR] [Login] Authentication failed for user mallory@example.com (reason=invalid_credentials)",
  },
];

export const JAMF_PROFILES: JamfProfilesResult = {
  profiles: [
    {
      profileIdentifier: "com.contoso.mdm.pppc-baseline",
      profileDisplayName: "Contoso PPPC Baseline",
      profileOrganization: "Contoso",
      profileType: "Configuration",
      profileUuid: "5E1D2C7A-0000-4000-8000-EXAMPLE00001",
      installDate: "2026-04-29T09:00:00Z",
      payloads: [
        {
          payloadIdentifier: "com.jamfsoftware.tcc.management",
          payloadDisplayName: "Privacy Preferences Policy Control",
          payloadType: "com.apple.TCC.configuration-profile-policy",
          payloadUuid: "5E1D2C7A-0000-4000-8000-EXAMPLE00002",
          payloadData: null,
          payloadDescription: null,
          payloadVersion: 1,
        },
      ],
      isManaged: true,
      verificationState: "verified",
      description: null,
      source: "manual",
      removalDisallowed: true,
    },
  ],
  matchedOrganization: "Contoso",
};

/** Command name → the value the shim's `invoke` returns for it. */
export const JAMF_IPC_OVERRIDES: Record<string, unknown> = {
  jamf_collect_environment: JAMF_ENVIRONMENT,
  jamf_scan_logs: JAMF_LOG_SCAN,
  jamf_parse_policy_log: JAMF_POLICY_LOG,
  jamf_filter_profiles: JAMF_PROFILES,
  jamf_parse_self_service_log: JAMF_SELF_SERVICE_EVENTS,
  jamf_parse_connect_log: JAMF_CONNECT_EVENTS,
};
