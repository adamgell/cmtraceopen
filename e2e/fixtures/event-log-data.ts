/**
 * Synthetic Event Logs dataset for the screenshot harness.
 *
 * A TypeScript port of the mockup generator (`wbBuild` in Workbench.dc.html): seeded
 * PRNG (seed 1337), 25 templates, about 1,331 events across System, Application, AAD/Operational
 * and DeviceManagement/Admin. Security is reported as an `accessDenied` coverage gap, not events.
 *
 * Everything here is fictional. Contoso names are placeholders and the only user name is the
 * neutral `user01`. Timestamps are anchored to a fixed base date so captures are deterministic;
 * nothing reads the wall clock.
 */
import type {
  DiagnosisSummary,
  EvtxChannelInfo,
  EvtxCoverageGap,
  EvtxLevel,
  EvtxParseResult,
  EvtxRecord,
} from "../../src/workspaces/event-log/types";
import type {
  TimelineItem,
  TimelineSeverity,
} from "../../src/workspaces/event-log/unified-timeline";

const COMPUTER = "CONTOSO-PC01";
/** Mockup day starts 10:20:00 UTC on 2026-10-06; `s` is seconds after that. */
const BASE_EPOCH_MS = Date.UTC(2026, 9, 6, 10, 20, 0);
const END = 86400;

type ChannelKey = "sys" | "app" | "aad" | "dm";

const CHANNELS: Record<ChannelKey, { name: string; file: string }> = {
  sys: { name: "System", file: "System.evtx" },
  app: { name: "Application", file: "Application.evtx" },
  aad: { name: "Microsoft-Windows-AAD/Operational", file: "AAD-Operational.evtx" },
  dm: {
    name: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
    file: "DeviceManagement-Admin.evtx",
  },
};

/** Where the fixture's "files" live. Fictional path; the backend is never asked to read it. */
export const EVENT_LOG_FIXTURE_DIR = "C:\\Fixture\\EventLogs";
export const EVENT_LOG_FIXTURE_PATHS = (Object.values(CHANNELS) as { file: string }[]).map(
  ({ file }) => `${EVENT_LOG_FIXTURE_DIR}\\${file}`,
);
const SECURITY_PATH = `${EVENT_LOG_FIXTURE_DIR}\\Security.evtx`;

interface GeneratedEvent {
  chKey: ChannelKey;
  id: string;
  lvl: EvtxLevel;
  prov: string;
  msg: string;
  s: number;
  rec: number;
}

function generateEvents(): GeneratedEvent[] {
  let seed = 1337;
  const rnd = (): number => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const pick = <T,>(a: T[]): T => a[Math.floor(rnd() * a.length)];

  const svcs = [
    "Windows Update",
    "Background Intelligent Transfer Service",
    "Microsoft Edge Update",
    "WinHTTP Web Proxy Auto-Discovery",
    "Windows Modules Installer",
    "Delivery Optimization",
    "Intune Management Extension",
  ];
  const hosts = [
    "enterpriseregistration.windows.net",
    "login.microsoftonline.com",
    "enrollment.manage.microsoft.com",
    "contoso.sharepoint.com",
  ];
  const apps = [
    "Contoso VPN Client 4.2 (x64)",
    "Microsoft 365 Apps",
    "7-Zip 23.01 (x64)",
    "Company Portal",
    "Adobe Acrobat Reader DC",
  ];
  const spread = (): number => Math.floor(rnd() * END);
  const late = (): number => Math.floor(END - Math.pow(rnd(), 2.2) * END);
  const at = (list: number[]) => {
    let i = 0;
    return (): number => list[i++ % list.length];
  };

  type Template = [
    ChannelKey,
    string,
    EvtxLevel,
    string,
    string | (() => string),
    number,
    () => number,
  ];
  const T: Template[] = [
    ["sys", "7036", "Information", "Service Control Manager", () => "The " + pick(svcs) + " service entered the " + pick(["running", "stopped"]) + " state.", 300, spread],
    ["sys", "7040", "Information", "Service Control Manager", "The start type of the Background Intelligent Transfer Service service was changed from demand start to auto start.", 60, spread],
    ["sys", "1014", "Warning", "DNS-Client", () => "Name resolution for the name " + pick(hosts) + " timed out after none of the configured DNS servers responded.", 90, late],
    ["sys", "7031", "Warning", "Service Control Manager", "The Contoso Update Service service terminated unexpectedly. It has done this 1 time(s).", 20, spread],
    ["sys", "10016", "Warning", "DistributedCOM", "The application-specific permission settings do not grant Local Activation permission for the COM Server application.", 70, spread],
    ["sys", "16", "Information", "Kernel-General", "The access history in hive \\??\\C:\\Users\\user01\\NTUSER.DAT was cleared.", 80, spread],
    ["sys", "1", "Information", "Kernel-General", "The system time has changed.", 10, spread],
    ["sys", "41", "Critical", "Kernel-Power", "The system has rebooted without cleanly shutting down first.", 1, at([62100])],
    ["sys", "6005", "Information", "EventLog", "The Event log service was started.", 2, at([62230, 15000])],
    ["app", "1000", "Error", "Application Error", "Faulting application name: ContosoAgent.exe, version: 4.2.0.1, faulting module: ntdll.dll", 12, spread],
    ["app", "1001", "Information", "Windows Error Reporting", "Fault bucket 2187364520, type 4. Event Name: APPCRASH", 14, spread],
    ["app", "16384", "Information", "Security-SPP", "Successfully scheduled Software Protection service for re-start.", 120, spread],
    ["app", "1033", "Information", "MsiInstaller", () => "Windows Installer installed the product. Product Name: " + pick(apps) + ".", 25, spread],
    ["app", "11708", "Error", "MsiInstaller", "Product: Contoso VPN Client 4.2 (x64) -- Installation failed.", 4, late],
    ["app", "0", "Information", "edgeupdate", "Service started", 150, spread],
    ["app", "1040", "Information", "MsiInstaller", "Beginning a Windows Installer transaction.", 40, spread],
    ["app", "1530", "Warning", "User Profile Service", "Windows detected your registry file is still in use by other applications or services.", 30, spread],
    ["aad", "1098", "Warning", "Microsoft-Windows-AAD", "Token broker operation failed.", 40, late],
    ["aad", "1104", "Information", "Microsoft-Windows-AAD", "AAD Cloud AP plugin call Plugin initialize returned success.", 90, spread],
    ["aad", "1081", "Information", "Microsoft-Windows-AAD", "OAuth response received for resource https://enrollment.manage.microsoft.com/.", 60, spread],
    ["aad", "1097", "Warning", "Microsoft-Windows-AAD", "Http request status: 400. Method: POST.", 36, late],
    ["dm", "76", "Error", "DeviceManagement-Enterprise-Diagnostics-Provider", "Auto MDM Enroll: Failed", 11, at([82318, 82565, 83207, 84065, 79800, 76200, 72600, 69000, 58000, 45000, 30000])],
    ["dm", "72", "Information", "DeviceManagement-Enterprise-Diagnostics-Provider", "MDM Enroll: auto-enrollment triggered by policy", 13, at([82312, 82558, 83200, 84059, 79794, 76194, 72594, 68994, 57994, 44994, 29994, 20000, 10000])],
    ["dm", "813", "Information", "DeviceManagement-Enterprise-Diagnostics-Provider", "MDM PolicyManager: Set policy int, Area: (DeviceLock).", 50, spread],
    ["dm", "404", "Error", "DeviceManagement-Enterprise-Diagnostics-Provider", "MDM ConfigurationManager: Command failure status. Configuration Source: (MDM).", 3, late],
  ];

  const ev: GeneratedEvent[] = [];
  for (const [chKey, id, lvl, prov, msg, count, time] of T) {
    for (let i = 0; i < count; i++) {
      // Evaluation order matters: the message draws from the PRNG before the time does.
      const message = typeof msg === "function" ? msg() : msg;
      const s = Math.max(0, Math.min(END - 1, time()));
      ev.push({ chKey, id, lvl, prov, msg: message, s, rec: 0 });
    }
  }
  ev.sort((a, b) => b.s - a.s);
  ev.forEach((e, i) => {
    e.rec = 88213 + (ev.length - i) * 3;
  });
  return ev;
}

function xmlEscape(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function toRecord(e: GeneratedEvent, index: number): EvtxRecord {
  const channel = CHANNELS[e.chKey].name;
  const epoch = BASE_EPOCH_MS + e.s * 1000;
  const timestamp = new Date(epoch).toISOString();
  return {
    id: index + 1,
    eventRecordId: e.rec,
    timestamp,
    timestampEpoch: epoch,
    provider: e.prov,
    channel,
    eventId: Number(e.id),
    level: e.lvl,
    computer: COMPUTER,
    message: e.msg,
    eventData: [{ name: "Data", value: e.msg }],
    rawXml:
      `<Event><System><Provider Name="${e.prov}"/><EventID>${e.id}</EventID>` +
      `<EventRecordID>${e.rec}</EventRecordID><TimeCreated SystemTime="${timestamp}"/>` +
      `<Channel>${channel}</Channel><Computer>${COMPUTER}</Computer></System>` +
      `<EventData><Data>${xmlEscape(e.msg)}</Data></EventData></Event>`,
    sourceLabel: CHANNELS[e.chKey].file,
    originKind: "event",
  };
}

const SEVERITY: Record<EvtxLevel, TimelineSeverity> = {
  Critical: "critical",
  Error: "error",
  Warning: "warning",
  Information: "info",
  Verbose: "verbose",
};

const SECURITY_GAP: EvtxCoverageGap = {
  source: SECURITY_PATH,
  kind: "accessDenied",
  reason: "Access denied: the Security channel requires elevation. No events were read.",
};

export interface EventLogFixture {
  /** Reply for `evtx_parse_files`. */
  parseResult: EvtxParseResult;
  /** Timeline items for `evtx_query_analysis_timeline`, oldest first. */
  timelineItems: TimelineItem[];
  /** Reply for `evtx_diagnose_analysis_session`. */
  diagnosis: DiagnosisSummary;
}

export function buildEventLogFixture(): EventLogFixture {
  const events = generateEvents();
  const records = events.map(toRecord);

  const channels: EvtxChannelInfo[] = (Object.keys(CHANNELS) as ChannelKey[]).map((key) => ({
    name: CHANNELS[key].name,
    eventCount: events.filter((e) => e.chKey === key).length,
    sourceType: { file: { path: `${EVENT_LOG_FIXTURE_DIR}\\${CHANNELS[key].file}` } },
    enabledState: "enabled",
  }));

  const parseResult: EvtxParseResult = {
    records,
    channels,
    totalRecords: records.length,
    parseErrors: 0,
    errorMessages: [],
    coverageGaps: [SECURITY_GAP],
  };

  const timelineItems: TimelineItem[] = records
    .map((record): TimelineItem => ({
      timestampMs: record.timestampEpoch,
      severity: SEVERITY[record.level],
      message: record.message,
      origin: {
        kind: "event",
        stableId: `${record.channel}|${record.eventRecordId}`,
        source: record.sourceLabel,
        machine: COMPUTER,
        bundle: null,
        channel: record.channel,
        provider: record.provider,
        processId: null,
        eventId: record.eventId,
        recordId: record.eventRecordId,
      },
    }))
    .sort((a, b) => a.timestampMs - b.timestampMs);

  // Obviously synthetic and minimal: no findings, only the Security coverage gap.
  const diagnosis: DiagnosisSummary = {
    findings: [],
    evidence: [],
    coverageGaps: [
      {
        id: "fixture-security-gap",
        source: SECURITY_PATH,
        state: "accessDenied",
        detail: SECURITY_GAP.reason,
        evidence: [],
      },
    ],
    correlations: [],
    events: [],
    overview: {
      outcome: "insufficientEvidence",
      headline: "Synthetic fixture: Security channel was not readable.",
      findingCount: 0,
      actionableFindingCount: 0,
      coverageGapCount: 1,
      evidenceCount: 0,
      correlationCount: 0,
      errorTokenEventCount: 0,
    },
  };

  return { parseResult, timelineItems, diagnosis };
}
