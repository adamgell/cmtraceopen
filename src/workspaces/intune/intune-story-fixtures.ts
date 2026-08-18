import type { EventLogAnalysis } from "../../types/event-log";
import type {
  DownloadStat,
  GuidRegistryEntry,
  IntuneDiagnosticInsight,
  IntuneEvent,
  IntuneSummary,
} from "./types";

export const APP_GUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
export const GRAPH_APP_NAME = "Contoso Graph Portal";
export const FAILED_EVENT_NAME = "Win32 App Install Failed — Contoso Company Portal";
export const SUCCESS_EVENT_NAME = "Win32 App Detected — Contoso Company Portal";
export const GUID_ONLY_EVENT_NAME = "Content download retry";
export const SCRIPT_EVENT_NAME = "PowerShell Script — Inventory Collection";
export const SCRIPT_BODY = "Write-Output 'Collect inventory'";
export const DOWNLOAD_NAME = "ContosoCompanyPortal.intunewin";
export const APPWORKLOAD_PATH = "C:/Logs/IME/AppWorkload.log";
export const AGENT_EXECUTOR_PATH = "C:/Logs/IME/AgentExecutor.log";
export const ANALYZED_PATH = "C:/Logs/IME";

export const FAILED_EVENT_START = "2026-04-01T19:00:42.578Z";
export const SUCCESS_EVENT_START = "2026-04-01T18:00:00.000Z";
export const SCRIPT_EVENT_START = "2026-03-20T12:00:00.000Z";
export const DOWNLOAD_TIMESTAMP = "2026-04-01T19:00:40.000Z";

export const FAILED_EVENT: IntuneEvent = {
  id: 1,
  eventType: "Win32App",
  name: FAILED_EVENT_NAME,
  guid: APP_GUID,
  status: "Failed",
  startTime: FAILED_EVENT_START,
  endTime: "2026-04-01T19:01:12.000Z",
  durationSecs: 30,
  errorCode: "0x87D30067",
  detail: [
    `Download failed for app id: ${APP_GUID} with error code = 0x87D30067`,
    "",
    "AppWorkload context:",
    `  L11 2026-04-01T19:00:41.000Z [Win32App][V3Processor] Processing subgraph with app ids: ${APP_GUID}`,
    `> L12 2026-04-01T19:00:42.578Z Download failed for app id: ${APP_GUID} with error code = 0x87D30067`,
  ].join("\n"),
  sourceFile: APPWORKLOAD_PATH,
  lineNumber: 12,
  startTimeEpoch: Date.parse(FAILED_EVENT_START),
  endTimeEpoch: Date.parse("2026-04-01T19:01:12.000Z"),
};

export const SUCCESS_EVENT: IntuneEvent = {
  id: 2,
  eventType: "Win32App",
  name: SUCCESS_EVENT_NAME,
  guid: APP_GUID,
  status: "Success",
  startTime: SUCCESS_EVENT_START,
  endTime: "2026-04-01T18:00:20.000Z",
  durationSecs: 20,
  errorCode: null,
  detail: "Installed successfully",
  sourceFile: APPWORKLOAD_PATH,
  lineNumber: 4,
  startTimeEpoch: Date.parse(SUCCESS_EVENT_START),
  endTimeEpoch: Date.parse("2026-04-01T18:00:20.000Z"),
};

export const SCRIPT_EVENT: IntuneEvent = {
  id: 3,
  eventType: "PowerShellScript",
  name: SCRIPT_EVENT_NAME,
  guid: "11111111-2222-3333-4444-555555555555",
  status: "Success",
  startTime: SCRIPT_EVENT_START,
  endTime: "2026-03-20T12:00:05.000Z",
  durationSecs: 5,
  errorCode: null,
  detail: "Script completed",
  sourceFile: AGENT_EXECUTOR_PATH,
  lineNumber: 88,
  startTimeEpoch: Date.parse(SCRIPT_EVENT_START),
  endTimeEpoch: Date.parse("2026-03-20T12:00:05.000Z"),
  scriptBody: SCRIPT_BODY,
};

export const GUID_ONLY_EVENT: IntuneEvent = {
  id: 5,
  eventType: "ContentDownload",
  name: GUID_ONLY_EVENT_NAME,
  guid: APP_GUID,
  status: "Failed",
  startTime: "2026-04-01T19:00:41.000Z",
  endTime: null,
  durationSecs: null,
  errorCode: "0x87D30067",
  detail: `Download failed for application ${APP_GUID}`,
  sourceFile: APPWORKLOAD_PATH,
  lineNumber: 11,
  startTimeEpoch: Date.parse("2026-04-01T19:00:41.000Z"),
  endTimeEpoch: null,
};

export const REPEAT_FAILED_EVENT: IntuneEvent = {
  ...FAILED_EVENT,
  id: 4,
  name: FAILED_EVENT_NAME,
  startTime: "2026-04-01T19:10:00.000Z",
  endTime: "2026-04-01T19:10:20.000Z",
  startTimeEpoch: Date.parse("2026-04-01T19:10:00.000Z"),
  endTimeEpoch: Date.parse("2026-04-01T19:10:20.000Z"),
  lineNumber: 40,
};

export const DOWNLOAD: DownloadStat = {
  contentId: "content-contoso-portal",
  name: DOWNLOAD_NAME,
  sizeBytes: 1048576,
  speedBps: 524288,
  doPercentage: 72.5,
  durationSecs: 12.4,
  success: true,
  timestamp: DOWNLOAD_TIMESTAMP,
  timestampEpoch: Date.parse(DOWNLOAD_TIMESTAMP),
};

export const SUMMARY: IntuneSummary = {
  totalEvents: 4,
  win32Apps: 3,
  wingetApps: 0,
  scripts: 1,
  remediations: 0,
  succeeded: 2,
  failed: 2,
  inProgress: 0,
  pending: 0,
  timedOut: 0,
  totalDownloads: 1,
  successfulDownloads: 1,
  failedDownloads: 0,
  failedScripts: 0,
  logTimeSpan: "Mar 20 – Apr 1",
};

export const DIAGNOSTIC: IntuneDiagnosticInsight = {
  id: "diag-download-fail",
  severity: "Error",
  category: "Download",
  remediationPriority: "Immediate",
  title: "Win32 content download failed",
  summary: "Contoso Company Portal failed to retrieve content from Delivery Optimization.",
  likelyCause: "Content location or DO peering failed before install started.",
  evidence: [
    "AppWorkload reported 0x87D30067 for Contoso Company Portal",
    "Download row ContosoCompanyPortal.intunewin completed after the failure",
  ],
  nextChecks: ["Confirm the content URI is reachable", "Review DO service health"],
  suggestedFixes: ["Retry the app assignment after confirming content availability"],
  focusAreas: ["Download", "Install"],
  affectedSourceFiles: [APPWORKLOAD_PATH],
  relatedErrorCodes: ["0x87D30067"],
};

export const GRAPH_GUID_REGISTRY: Record<string, GuidRegistryEntry> = {
  [APP_GUID]: {
    name: GRAPH_APP_NAME,
    source: "GraphApi",
    category: "app",
    publisher: "Contoso",
  },
};

export const EVENT_LOG_ANALYSIS: EventLogAnalysis = {
  sourceKind: "Live",
  entries: [
    {
      id: 501,
      channel: "DeviceManagementAdmin",
      channelDisplay: "DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
      provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider",
      eventId: 404,
      severity: "Error",
      timestamp: FAILED_EVENT_START,
      computer: "WORKSTATION01",
      message: "Intune Management Extension reported a content download failure.",
      correlationActivityId: null,
      sourceFile: "live://DeviceManagementAdmin",
    },
  ],
  channelSummaries: [
    {
      channel: "DeviceManagementAdmin",
      channelDisplay: "DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
      entryCount: 1,
      errorCount: 1,
      warningCount: 0,
      timestampBounds: {
        firstTimestamp: FAILED_EVENT_START,
        lastTimestamp: FAILED_EVENT_START,
      },
      sourceFile: "live://DeviceManagementAdmin",
    },
  ],
  correlationLinks: [
    {
      eventLogEntryId: 501,
      linkedIntuneEventId: 1,
      linkedDiagnosticId: DIAGNOSTIC.id,
      correlationKind: "ErrorCodeMatch",
      timeDeltaSecs: 2,
    },
  ],
  parsedFileCount: 1,
  totalEntryCount: 1,
  errorEntryCount: 1,
  warningEntryCount: 0,
  timestampBounds: {
    firstTimestamp: FAILED_EVENT_START,
    lastTimestamp: FAILED_EVENT_START,
  },
  liveQuery: {
    attemptedChannelCount: 2,
    successfulChannelCount: 2,
    channelsWithResultsCount: 1,
    failedChannelCount: 0,
    perChannelEntryLimit: 200,
    channels: [
      {
        channel: "DeviceManagementAdmin",
        channelDisplay: "DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
        channelPath: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
        sourceFile: "live://DeviceManagementAdmin",
        status: "Success",
        entryCount: 1,
        errorMessage: null,
      },
      {
        channel: "Autopilot",
        channelDisplay: "Microsoft-Windows-Provisioning-Diagnostics-Provider/Admin",
        channelPath: "Microsoft-Windows-Provisioning-Diagnostics-Provider/Admin",
        sourceFile: "live://Autopilot",
        status: "Empty",
        entryCount: 0,
        errorMessage: null,
      },
    ],
  },
};

export const LIVE_EMPTY_EVENT_LOG_ANALYSIS: EventLogAnalysis = {
  ...EVENT_LOG_ANALYSIS,
  entries: [],
  channelSummaries: [],
  correlationLinks: [],
  totalEntryCount: 0,
  errorEntryCount: 0,
  parsedFileCount: 0,
  liveQuery: {
    attemptedChannelCount: 2,
    successfulChannelCount: 1,
    channelsWithResultsCount: 0,
    failedChannelCount: 1,
    perChannelEntryLimit: 200,
    channels: [
      {
        channel: "DeviceManagementAdmin",
        channelDisplay: "DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
        channelPath: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
        sourceFile: "live://DeviceManagementAdmin",
        status: "Empty",
        entryCount: 0,
        errorMessage: null,
      },
      {
        channel: "Autopilot",
        channelDisplay: "Microsoft-Windows-Provisioning-Diagnostics-Provider/Admin",
        channelPath: "Microsoft-Windows-Provisioning-Diagnostics-Provider/Admin",
        sourceFile: "live://Autopilot",
        status: "Failed",
        entryCount: 0,
        errorMessage: "Access is denied.",
      },
    ],
  },
};

export const STORY_EVENTS = [
  FAILED_EVENT,
  SUCCESS_EVENT,
  SCRIPT_EVENT,
  REPEAT_FAILED_EVENT,
];
export const STORY_DOWNLOADS = [DOWNLOAD];
export const STORY_SOURCE_FILES = [APPWORKLOAD_PATH, AGENT_EXECUTOR_PATH];
