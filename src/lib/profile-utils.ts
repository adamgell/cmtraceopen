import type { MacosMdmProfile } from "../workspaces/macos-diag/types";

// ---------------------------------------------------------------------------
// Payload type knowledge base
// ---------------------------------------------------------------------------

interface PayloadTypeInfo {
  friendlyName: string;
  description: string;
}

/** Maps Apple payload type identifiers to human-readable names and descriptions. */
const PAYLOAD_TYPE_INFO: Record<string, PayloadTypeInfo> = {
  "com.apple.security.firewall": {
    friendlyName: "Firewall",
    description: "Manages the macOS Application Firewall — controls incoming connections, stealth mode, and app-level allow/block rules.",
  },
  "com.apple.systempolicy.control": {
    friendlyName: "Gatekeeper",
    description: "Controls macOS Gatekeeper — determines which apps are allowed to run based on their signing and notarization status.",
  },
  "com.apple.MCX": {
    friendlyName: "Managed Client (MCX)",
    description: "Legacy Managed Client settings — commonly used to enforce FileVault disk encryption policy.",
  },
  "com.apple.ManagedClient.preferences": {
    friendlyName: "Managed Preferences",
    description: "Delivers managed application preferences to a specific app via its bundle ID.",
  },
  "com.apple.extensiblesso": {
    friendlyName: "Enterprise SSO",
    description: "Configures Extensible Single Sign-On — enables Microsoft Entra ID (Azure AD) authentication across apps and the login window via Platform SSO.",
  },
  "com.apple.TCC.configuration-profile-policy": {
    friendlyName: "Privacy Preferences (PPPC)",
    description: "Privacy Preferences Policy Control — pre-approves app permissions for Accessibility, Full Disk Access, Screen Capture, and other TCC-protected services.",
  },
  "com.apple.servicemanagement": {
    friendlyName: "Background Items",
    description: "Controls which background items (launch daemons and agents) are allowed to run — manages the 'Login Items & Extensions' list.",
  },
  "com.apple.system-extension-policy": {
    friendlyName: "System Extensions",
    description: "Manages which system extensions (network, endpoint security, driver) are allowed to load by team ID and bundle ID.",
  },
  "com.apple.security.scep": {
    friendlyName: "SCEP Certificate",
    description: "Simple Certificate Enrollment Protocol — automatically provisions device or user identity certificates from a SCEP server.",
  },
  "com.apple.security.root": {
    friendlyName: "Root Certificate",
    description: "Installs a trusted root CA certificate into the system keychain for certificate chain validation.",
  },
  "com.apple.mdm": {
    friendlyName: "MDM Enrollment",
    description: "Mobile Device Management enrollment payload — defines the MDM server URL, check-in URL, push topic, and access rights.",
  },
  "com.apple.desktop": {
    friendlyName: "Desktop Settings",
    description: "Manages desktop wallpaper and display settings — can lock the wallpaper to a specific image.",
  },
};

/** Maps individual setting keys to human-readable descriptions. */
const SETTING_DESCRIPTIONS: Record<string, string> = {
  // Firewall
  EnableFirewall: "Enable the macOS Application Firewall",
  EnableStealthMode: "Hide Mac from network scans (no ICMP/port scan responses)",
  AllowSigned: "Allow built-in signed software to receive incoming connections",
  AllowSignedApp: "Allow downloaded signed software to receive incoming connections",
  BlockAllIncoming: "Block all incoming connections except basic services (DHCP, Bonjour)",
  // Gatekeeper
  AllowIdentifiedDevelopers: "Allow apps from identified developers (not just App Store)",
  EnableAssessment: "Enable Gatekeeper app security assessment",
  EnableXProtectMalwareUpload: "Upload malware samples to Apple for XProtect analysis",
  // MCX / FileVault
  dontAllowFDEDisable: "Prevent users from disabling FileVault disk encryption",
  // OneDrive
  KFMSilentOptIn: "Silently redirect Desktop & Documents to OneDrive (tenant ID)",
  KFMOptInWithWizard: "Show wizard prompting user to move folders to OneDrive (tenant ID)",
  KFMBlockOptOut: "Prevent users from redirecting folders back to local Mac",
  KFMSilentOptInDesktop: "Include Desktop folder in silent Known Folder Move",
  KFMSilentOptInDocuments: "Include Documents folder in silent Known Folder Move",
  KFMSilentOptInWithNotification: "Show notification during silent Known Folder Move",
  BlockExternalSync: "Block syncing libraries shared from other organizations",
  DisablePersonalSync: "Prevent users from syncing personal OneDrive accounts",
  DisableAutoConfig: "Disable automatic OneDrive account configuration",
  DisableTutorial: "Skip the OneDrive tutorial on first run",
  EnableAllOcsiClients: "Enable co-authoring and real-time collaboration for Office files",
  FilesOnDemandEnabled: "Enable Files On-Demand (download files only when accessed)",
  HideDockIcon: "Hide the OneDrive icon from the Dock",
  OpenAtLogin: "Start OneDrive automatically at user login",
  EnableODIgnore: "File patterns excluded from OneDrive sync",
  // Edge
  SmartScreenEnabled: "Enable Microsoft Defender SmartScreen for site safety",
  SmartScreenPuaEnabled: "Block potentially unwanted apps (PUA)",
  PasswordManagerEnabled: "Enable the built-in password manager",
  PasswordMonitorAllowed: "Alert if saved passwords appear in data breaches",
  PasswordProtectionWarningTrigger: "Warn when passwords are reused or phished",
  AutofillAddressEnabled: "Enable address autofill in forms",
  AutofillCreditCardEnabled: "Enable credit card autofill in forms",
  ExtensionInstallForcelist: "Extensions force-installed (cannot be removed by user)",
  ExtensionInstallBlocklist: "Blocked extensions (* = block all except allowlist)",
  ExtensionInstallAllowlist: "Extensions users are allowed to install",
  BlockExternalExtensions: "Block extensions from outside the Edge Add-ons store",
  ForceSync: "Force enable browser sync across devices",
  ForceEphemeralProfiles: "Delete browsing data when all browser windows close",
  HideFirstRunExperience: "Skip the Edge first-run setup wizard",
  BrowserSignin: "Browser sign-in policy (0=Disabled, 1=Enabled, 2=Forced)",
  BrowserAddProfileEnabled: "Allow users to add new browser profiles",
  TrackingPrevention: "Tracking prevention (0=Off, 1=Basic, 2=Balanced, 3=Strict)",
  DownloadRestrictions: "Download restrictions (0=None, 1=Block dangerous, 2=Block PUAs, 3=Block all)",
  SSLVersionMin: "Minimum TLS version required for HTTPS connections",
  PreventSmartScreenPromptOverride: "Prevent users from bypassing SmartScreen warnings for sites",
  PreventSmartScreenPromptOverrideForFiles: "Prevent users from bypassing SmartScreen warnings for downloads",
  AuthSchemes: "Allowed HTTP authentication schemes",
  AutoImportAtFirstRun: "Auto-import from other browsers on first run (4=none)",
  ImportBrowserSettings: "Import browser settings from default browser",
  ImportHistory: "Import browsing history from default browser",
  ImportHomepage: "Import homepage from default browser",
  ImportPaymentInfo: "Import payment info from default browser",
  ImportSavedPasswords: "Import saved passwords from default browser",
  ImportSearchEngine: "Import search engine from default browser",
  ComponentUpdatesEnabled: "Enable automatic component updates (Widevine, CRLSets)",
  DNSInterceptionChecksEnabled: "Enable DNS interception checks",
  EnableMediaRouter: "Enable Google Cast / media router",
  NativeMessagingUserLevelHosts: "Allow user-level native messaging hosts",
  ProactiveAuthEnabled: "Enable proactive authentication for Microsoft services",
  RelaunchNotification: "How to notify about pending relaunch (1=Subtle, 2=Required)",
  PersonalizationReportingEnabled: "Send browsing data for ad personalization",
  AdsSettingForIntrusiveAdsSites: "Ads on intrusive ad sites (1=Allow, 2=Block)",
  EnterpriseHardwarePlatformAPIEnabled: "Allow managed extensions to use hardware platform API",
  ExperimentationAndConfigurationServiceControl: "Experimentation service (0=Disabled, 1=Config only, 2=Full)",
  BrowserNetworkTimeQueriesEnabled: "Enable network time queries to Google",
  ClearBrowsingDataOnExit: "Clear browsing data when browser exits",
  ClearCachedImagesAndFilesOnExit: "Clear cached images/files when browser exits",
  // MAU (Microsoft AutoUpdate)
  ChannelName: "Update channel (Current, Preview, Beta, Custom)",
  HowToCheck: "Update mode (AutomaticDownload, AutomaticCheck, Manual)",
  ManifestServer: "URL for the update manifest server",
  UpdateCache: "URL for the update download cache (CDN)",
  StartDaemonOnAppLaunch: "Start MAU background daemon when Office apps launch",
  DisableInsiderCheckbox: "Hide the Insider / Preview checkbox in MAU UI",
  EnableCheckForUpdatesButton: "Show the Check for Updates button in MAU UI",
  GuardAgainstAppModification: "Protect Office apps from being modified by third parties",
  AcknowledgedDataCollectionPolicy: "Data collection consent level (RequiredDataOnly, RequiredAndOptional)",
  "UpdateDeadline.DaysBeforeForcedQuit": "Days before forcing app quit to apply updates",
  UpdaterOptimization: "Update delivery optimization strategy (Network, Local)",
  // Office
  OfficeAutoSignIn: "Auto sign-in to Office using the device's Entra ID account",
  OfficeActivationEmailAddress: "Email address used for Office license activation",
  // SSO
  ExtensionIdentifier: "Bundle ID of the SSO browser extension",
  AuthenticationMethod: "Authentication method (Password, UserSecureEnclaveKey, SmartCard)",
  UseSharedDeviceKeys: "Use the same signing/encryption keys for all users on this device",
  EnableAuthorization: "Enable SSO for macOS system authorization prompts",
  EnableCreateUserAtLogin: "Allow creating new macOS users at login via SSO",
  NewUserAuthorizationMode: "Admin rights for new SSO-created users (Standard, Admin)",
  UserAuthorizationMode: "Admin rights for existing SSO users (Standard, Admin)",
  ScreenLockedBehavior: "SSO behavior when screen is locked (DoNotHandle)",
  RegistrationToken: "Token for Platform SSO device registration",
  TeamIdentifier: "Apple Developer Team ID for the SSO extension",
  Type: "SSO extension type (Redirect, Credential)",
  URLs: "URLs handled by the SSO extension",
  // Desktop
  "override-picture-path": "Locked wallpaper image file path",
  // MDM
  AccessRights: "MDM access rights bitmask (8191 = full access)",
  CheckInURL: "URL the device checks in to for MDM commands",
  ServerURL: "MDM server URL for command polling",
  CheckOutWhenRemoved: "Notify MDM server when profile is removed",
  SignMessage: "Require signed MDM messages",
  UseDevelopmentAPNS: "Use Apple Push Notification sandbox (development only)",
  Topic: "APNs push topic for MDM notifications",
  ServerCapabilities: "MDM server capabilities (per-user-connections, bootstraptoken)",
  IdentityCertificateUUID: "UUID of the identity certificate used for MDM auth",
  // TCC / PPPC
  Allowed: "Permission granted to the app",
  Authorization: "Authorization level (Allow, Deny, AllowStandardUserToSetSystemService)",
  Identifier: "Bundle ID or path of the app being granted permission",
  IdentifierType: "How the app is identified (bundleID, path)",
  CodeRequirement: "Code signing requirement the app must satisfy",
  StaticCode: "Validate code signature at rest (not just at launch)",
  AEReceiverIdentifier: "Bundle ID of the AppleEvent receiver app",
  AEReceiverCodeRequirement: "Code signing requirement for the AppleEvent receiver",
  // System Extensions
  AllowedSystemExtensions: "System extensions allowed to load, by team ID",
  // Service Management
  RuleType: "How the background item is identified (BundleIdentifier, LabelPrefix, TeamIdentifier)",
  RuleValue: "Identifier value for the background item rule",
};

/**
 * Get human-readable info for a payload type.
 */
export function getPayloadTypeInfo(payloadType: string): PayloadTypeInfo | null {
  return PAYLOAD_TYPE_INFO[payloadType] ?? null;
}

/**
 * Get a human-readable description for a setting key.
 */
export function getSettingDescription(key: string): string | null {
  // Try exact match first
  if (SETTING_DESCRIPTIONS[key]) return SETTING_DESCRIPTIONS[key];
  // Strip arrow-prefixed keys like "Edge Updater → RuleType"
  const arrowIdx = key.lastIndexOf(" → ");
  if (arrowIdx >= 0) {
    const baseKey = key.slice(arrowIdx + 3);
    if (SETTING_DESCRIPTIONS[baseKey]) return SETTING_DESCRIPTIONS[baseKey];
  }
  return null;
}

// --- Friendly name derivation ---

const MANAGED_CLIENT_PREFIX = "com.apple.ManagedClient.preferences.";

const KNOWN_BUNDLE_NAMES: Record<string, string> = {
  "com.microsoft.OneDrive": "OneDrive",
  "com.microsoft.Edge": "Microsoft Edge",
  "com.microsoft.autoupdate2": "Microsoft AutoUpdate",
  "com.microsoft.office": "Microsoft Office",
};

/**
 * Derive a human-friendly name for a profile.
 * Returns null if no friendly name can be derived (the display name is already good).
 */
export function deriveFriendlyName(profile: MacosMdmProfile): string | null {
  // Only apply to ManagedClient.preferences profiles
  if (!profile.profileIdentifier.includes("com.apple.ManagedClient.preferences")) {
    return null;
  }

  if (!profile.profileIdentifier.startsWith(MANAGED_CLIENT_PREFIX)) {
    return null;
  }

  const bundleId = profile.profileIdentifier.slice(MANAGED_CLIENT_PREFIX.length);
  if (!bundleId) {
    return null;
  }

  // Check known bundle map first
  if (KNOWN_BUNDLE_NAMES[bundleId]) {
    return KNOWN_BUNDLE_NAMES[bundleId];
  }

  // Fall back to last segment of the bundle ID
  const segments = bundleId.split(".");
  return segments[segments.length - 1] ?? null;
}

// --- Payload data parsing ---

export interface ParsedPayloadEntry {
  key: string;
  value: string;
  type: "string" | "number" | "boolean" | "array" | "dict" | "unknown";
  description?: string;
}

export interface ParsedPayload {
  entries: ParsedPayloadEntry[];
  appTarget?: string;
}

/**
 * Given a starting index just after an opening '{', find the matching '}'.
 * Returns the content between the braces (exclusive), or null if unmatched.
 */
function extractBracedBlock(data: string, startIndex: number): string | null {
  let depth = 1;
  let i = startIndex;
  while (i < data.length && depth > 0) {
    if (data[i] === "{") {
      depth++;
    } else if (data[i] === "}") {
      depth--;
    }
    if (depth > 0) {
      i++;
    }
  }
  if (depth !== 0) {
    return null;
  }
  return data.slice(startIndex, i);
}

/**
 * Collect a multi-line balanced block starting from an opening delimiter.
 * Works for both `(...)` and `{...}`. Returns the full collected string
 * including the opening delimiter already in `start`, and advances `i`.
 */
function collectBalancedBlock(
  lines: string[],
  startIdx: number,
  open: string,
  close: string,
): { block: string; nextIdx: number } {
  let depth = 0;
  let block = "";
  for (let j = startIdx; j < lines.length; j++) {
    const l = lines[j];
    for (const ch of l) {
      if (ch === open) depth++;
      if (ch === close) depth--;
    }
    block += l + "\n";
    if (depth === 0) {
      return { block, nextIdx: j + 1 };
    }
  }
  return { block, nextIdx: lines.length };
}

/**
 * Parse an array of dicts like Rules = ( { Comment = "X"; RuleType = Y; }, { ... } );
 * Returns entries for each dict item showing its key-value pairs.
 */
function parseArrayOfDicts(raw: string, arrayKey: string): ParsedPayloadEntry[] {
  const entries: ParsedPayloadEntry[] = [];

  // Extract content between outer parens
  const parenStart = raw.indexOf("(");
  const parenEnd = raw.lastIndexOf(")");
  if (parenStart < 0 || parenEnd < 0) return entries;
  const inner = raw.slice(parenStart + 1, parenEnd);

  // Find each dict { ... } in the inner content
  let pos = 0;
  let dictIndex = 0;
  while (pos < inner.length) {
    const braceStart = inner.indexOf("{", pos);
    if (braceStart < 0) break;
    const block = extractBracedBlock(inner, braceStart + 1);
    if (!block) break;
    pos = braceStart + 1 + block.length + 1;

    // Parse the dict entries
    const dictEntries = parseFlatDict(block);
    if (dictEntries.length > 0) {
      // Find a good label for this dict item
      const commentEntry = dictEntries.find(
        (e) => e.key.toLowerCase() === "comment",
      );
      const label = commentEntry
        ? commentEntry.value
        : `${arrayKey} [${dictIndex}]`;
      // Add a header entry for the dict
      for (const entry of dictEntries) {
        if (entry.key.toLowerCase() === "comment") continue;
        entries.push({
          key: `${label} → ${entry.key}`,
          value: entry.value,
          type: entry.type,
        });
      }
    }
    dictIndex++;
  }

  return entries;
}

/**
 * Extract a simple array value like `( "item1", "item2", item3 )`.
 * The input `raw` may contain `key = (` prefix from block collection.
 * Returns the items joined with ", ".
 */
function parseSimpleArrayValue(raw: string): string {
  // Find the opening paren and closing paren
  const parenStart = raw.indexOf("(");
  const parenEnd = raw.lastIndexOf(")");
  if (parenStart < 0 || parenEnd <= parenStart) return raw.trim();
  const inner = raw.slice(parenStart + 1, parenEnd).trim();
  const items = inner
    .split(/\s*,\s*/)
    .map((s) => s.replace(/^"(.*)"$/, "$1").trim())
    .filter((s) => s.length > 0);
  return items.join(", ");
}

/**
 * Parse flat key = value; assignments from a NeXTSTEP plist dict body (without outer braces).
 */
function parseFlatDict(body: string): ParsedPayloadEntry[] {
  const entries: ParsedPayloadEntry[] = [];
  const lines = body.split("\n");
  let i = 0;

  while (i < lines.length) {
    const line = lines[i].trim();

    // Skip blank lines and structural-only lines
    if (!line || line === "{" || line === "}" || line === "(" || line === ")" || line === ");") {
      i++;
      continue;
    }

    // Match key = value pattern
    const kvMatch = line.match(/^"?([^"=]+?)"?\s*=\s*(.*)/);
    if (!kvMatch) {
      i++;
      continue;
    }

    const key = kvMatch[1].trim();
    let valueStr = kvMatch[2].trim();

    // Case 1: value is a dict  { ... }
    if (valueStr.startsWith("{")) {
      const { block, nextIdx } = collectBalancedBlock(lines, i, "{", "}");
      i = nextIdx;
      // Try to recursively parse the inner dict for display
      const innerMatch = block.match(/\{([\s\S]*)\}/);
      const inner = innerMatch ? innerMatch[1] : "";
      const innerEntries = parseFlatDict(inner);
      if (innerEntries.length > 0) {
        // Inline the inner entries with a prefix
        for (const entry of innerEntries) {
          entries.push({
            key: `${key} → ${entry.key}`,
            value: entry.value,
            type: entry.type,
          });
        }
      } else {
        entries.push({ key, value: "{ ... }", type: "dict" });
      }
      continue;
    }

    // Case 2: value is an array  ( ... )
    if (valueStr.startsWith("(")) {
      const { block, nextIdx } = collectBalancedBlock(lines, i, "(", ")");
      i = nextIdx;
      // Check if this is an array of dicts (contains '{')
      if (block.includes("{")) {
        const dictEntries = parseArrayOfDicts(block, key);
        if (dictEntries.length > 0) {
          entries.push(...dictEntries);
          continue;
        }
      }
      // Simple array of values
      entries.push({
        key,
        value: parseSimpleArrayValue(block),
        type: "array",
      });
      continue;
    }

    // Case 3: simple value (terminated by ;)
    // Remove trailing semicolon
    valueStr = valueStr.replace(/;\s*$/, "").trim();

    // Quoted string
    if (valueStr.startsWith('"') && valueStr.endsWith('"')) {
      entries.push({
        key,
        value: valueStr.slice(1, -1),
        type: "string",
      });
      i++;
      continue;
    }

    // Number
    if (/^\d+$/.test(valueStr)) {
      const num = parseInt(valueStr, 10);
      if (num === 0 || num === 1) {
        entries.push({ key, value: valueStr, type: "boolean" });
      } else {
        entries.push({ key, value: valueStr, type: "number" });
      }
      i++;
      continue;
    }

    // Unquoted string / fallback
    entries.push({ key, value: valueStr, type: "string" });
    i++;
  }

  return entries;
}

/**
 * Parse a NeXTSTEP plist text dictionary into structured data for display.
 */
export function parsePayloadData(data: string): ParsedPayload {
  const result: ParsedPayload = { entries: [] };

  // Detect ManagedClient.preferences pattern with mcx_preference_settings
  // Key may be quoted: "mcx_preference_settings" =     {
  const mcxMatch = data.match(/"?mcx_preference_settings"?\s*=\s*\{/);
  if (mcxMatch) {
    // Extract the app target from PayloadContent
    const appMatch = data.match(/"(com\.[^"]+)"\s*=\s*\{/);
    if (appMatch) {
      result.appTarget = appMatch[1];
    }
    // Extract the mcx_preference_settings block
    const mcxStart = mcxMatch.index! + mcxMatch[0].length;
    const settingsBlock = extractBracedBlock(data, mcxStart);
    if (settingsBlock) {
      result.entries = parseFlatDict(settingsBlock);
      enrichEntries(result.entries);
      return result;
    }
  }

  // For non-MCX profiles, parse the top-level dict
  const trimmed = data.trim();
  if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
    result.entries = parseFlatDict(trimmed.slice(1, -1));
  }

  enrichEntries(result.entries);
  return result;
}

function enrichEntries(entries: ParsedPayloadEntry[]): void {
  for (const entry of entries) {
    if (!entry.description) {
      entry.description = getSettingDescription(entry.key) ?? undefined;
    }
  }
}
