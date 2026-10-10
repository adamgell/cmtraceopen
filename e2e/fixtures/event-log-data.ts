/**
 * Synthetic Event Logs dataset for the screenshot harness.
 *
 * A TypeScript port of the mockup generator (`wbBuild` in Workbench.dc.html): seeded
 * PRNG (seed 1337), 25 templates, about 1,331 events across System, Application, AAD/Operational
 * and DeviceManagement/Admin. Security is requested but not readable (see below).
 *
 * Everything here is fictional. Contoso names are placeholders and the only user name is the
 * neutral `user01`. Timestamps are anchored to a fixed base date so captures are deterministic;
 * nothing reads the wall clock.
 *
 * Provider convention
 * -------------------
 * Channel names and provider names are the real ones, because a real .evtx file carries both:
 * `Provider Name` in the event XML is the full provider name (`Microsoft-Windows-Kernel-Power`),
 * not the short form an Event Viewer column or a mockup shows. Providers that really are
 * un-prefixed (`Service Control Manager`, `MsiInstaller`, `Application Error`, `EventLog`,
 * `edgeupdate`, `Windows Error Reporting`) keep their real names.
 *
 * Two kinds of reply
 * ------------------
 * 1. `evtx_parse_files` needs real .evtx files to be produced by the backend, so it is BUILT HERE
 *    by `buildParseResult()`, following `parse_evtx_manifest` field by field. Every non-obvious
 *    field cites the Rust that produces it.
 * 2. The analysis-session and diagnosis replies are NOT written by hand. They are the output of
 *    the real engine (`src-tauri/src/event_log/analysis_session.rs`) run over these records, and
 *    are committed in `event-log-engine-replies.json`. Regenerate with
 *    `node e2e/fixtures/capture-event-log-replies.mjs` (see that script's header).
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type {
  DiagnosisSummary,
  EventLogSourceManifest,
  EventLogSourceSelection,
  EvtxChannelInfo,
  EvtxCoverageGap,
  EvtxLevel,
  EvtxParseResult,
  EvtxRecord,
} from "../../src/workspaces/event-log/types";
import type {
  EventLogAnalysisSessionStatus,
  EventLogAnalysisTimelinePage,
} from "../../src/lib/commands";

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
/** Manifest order: the backend expands sources in request order (parser.rs:134-196). */
const CHANNEL_ORDER: ChannelKey[] = ["sys", "app", "aad", "dm"];

/** Where the fixture's "files" live. Fictional path; the backend is never asked to read it. */
export const EVENT_LOG_FIXTURE_DIR = "C:\\Fixture\\EventLogs";
const channelPath = (key: ChannelKey): string =>
  `${EVENT_LOG_FIXTURE_DIR}\\${CHANNELS[key].file}`;
const SECURITY_PATH = `${EVENT_LOG_FIXTURE_DIR}\\Security.evtx`;
/** Every path the UI requests, in request order. Security is requested and unreadable. */
export const EVENT_LOG_FIXTURE_PATHS = [...CHANNEL_ORDER.map(channelPath), SECURITY_PATH];

/** Mirrors EVENT_LOG_ANALYSIS_CHUNK_RECORD_LIMIT and _PAGE_SIZE in event-analysis-session.ts. */
export const ENGINE_CHUNK_RECORD_LIMIT = 1_000;
export const ENGINE_PAGE_SIZE = 1_000;
/** Fixed placeholder so a regeneration only changes the JSON when the engine's answer changes. */
export const ENGINE_SESSION_ID = "00000000-0000-4000-8000-000000000828";

const DM_PROVIDER = "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider";

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
    ["sys", "1014", "Warning", "Microsoft-Windows-DNS-Client", () => "Name resolution for the name " + pick(hosts) + " timed out after none of the configured DNS servers responded.", 90, late],
    ["sys", "7031", "Warning", "Service Control Manager", "The Contoso Update Service service terminated unexpectedly. It has done this 1 time(s).", 20, spread],
    ["sys", "10016", "Warning", "Microsoft-Windows-DistributedCOM", "The application-specific permission settings do not grant Local Activation permission for the COM Server application.", 70, spread],
    ["sys", "16", "Information", "Microsoft-Windows-Kernel-General", "The access history in hive \\??\\C:\\Users\\user01\\NTUSER.DAT was cleared.", 80, spread],
    ["sys", "1", "Information", "Microsoft-Windows-Kernel-General", "The system time has changed.", 10, spread],
    ["sys", "41", "Critical", "Microsoft-Windows-Kernel-Power", "The system has rebooted without cleanly shutting down first.", 1, at([62100])],
    ["sys", "6005", "Information", "EventLog", "The Event log service was started.", 2, at([62230, 15000])],
    ["app", "1000", "Error", "Application Error", "Faulting application name: ContosoAgent.exe, version: 4.2.0.1, faulting module: ntdll.dll", 12, spread],
    ["app", "1001", "Information", "Windows Error Reporting", "Fault bucket 2187364520, type 4. Event Name: APPCRASH", 14, spread],
    ["app", "16384", "Information", "Microsoft-Windows-Security-SPP", "Successfully scheduled Software Protection service for re-start.", 120, spread],
    ["app", "1033", "Information", "MsiInstaller", () => "Windows Installer installed the product. Product Name: " + pick(apps) + ".", 25, spread],
    ["app", "11708", "Error", "MsiInstaller", "Product: Contoso VPN Client 4.2 (x64) -- Installation failed.", 4, late],
    ["app", "0", "Information", "edgeupdate", "Service started", 150, spread],
    ["app", "1040", "Information", "MsiInstaller", "Beginning a Windows Installer transaction.", 40, spread],
    ["app", "1530", "Warning", "Microsoft-Windows-User Profiles Service", "Windows detected your registry file is still in use by other applications or services.", 30, spread],
    ["aad", "1098", "Warning", "Microsoft-Windows-AAD", "Token broker operation failed.", 40, late],
    ["aad", "1104", "Information", "Microsoft-Windows-AAD", "AAD Cloud AP plugin call Plugin initialize returned success.", 90, spread],
    ["aad", "1081", "Information", "Microsoft-Windows-AAD", "OAuth response received for resource https://enrollment.manage.microsoft.com/.", 60, spread],
    ["aad", "1097", "Warning", "Microsoft-Windows-AAD", "Http request status: 400. Method: POST.", 36, late],
    ["dm", "76", "Error", DM_PROVIDER, "Auto MDM Enroll: Failed", 11, at([82318, 82565, 83207, 84065, 79800, 76200, 72600, 69000, 58000, 45000, 30000])],
    ["dm", "72", "Information", DM_PROVIDER, "MDM Enroll: auto-enrollment triggered by policy", 13, at([82312, 82558, 83200, 84059, 79794, 76194, 72594, 68994, 57994, 44994, 29994, 20000, 10000])],
    ["dm", "813", "Information", DM_PROVIDER, "MDM PolicyManager: Set policy int, Area: (DeviceLock).", 50, spread],
    ["dm", "404", "Error", DM_PROVIDER, "MDM ConfigurationManager: Command failure status. Configuration Source: (MDM).", 3, late],
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

/**
 * Builds the record `parse_evtx_file` would emit. The optional System fields the dataset does
 * not model (task, opcode, process, thread, SID, keywords) are `null`, and `mapped` is `[]`:
 * the backend serializes `None` as `null` with no skip attribute (models.rs:148-185).
 *
 * - `eventRecordIdText`: `system.event_record_id.map(|v| v.to_string())` (parser.rs:2413).
 * - `sourceLabel`: the manifest entry's path, written by `append_parsed_file`
 *   (`record.source_label = source_path`, parser.rs:1784-1787).
 */
function toRecord(e: GeneratedEvent): EvtxRecord {
  const channel = CHANNELS[e.chKey].name;
  const epoch = BASE_EPOCH_MS + e.s * 1000;
  const timestamp = new Date(epoch).toISOString();
  return {
    id: 0,
    eventRecordId: e.rec,
    eventRecordIdText: String(e.rec),
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
    sourceLabel: channelPath(e.chKey),
    originKind: "event",
    task: null,
    opcode: null,
    processId: null,
    threadId: null,
    userSid: null,
    keywords: null,
    mapped: [],
  };
}

/** The sources the picker sends to `evtx_expand_sources`: every path as a `file` selection. */
export function buildSourceSelections(): EventLogSourceSelection[] {
  return EVENT_LOG_FIXTURE_PATHS.map((path) => ({ path, kind: "file" }));
}

/**
 * Reply for `evtx_expand_sources` (`build_source_manifest_for_selections`, parser.rs:125-200).
 *
 * - Each readable file becomes one entry, in request order: `source_id` is `source_identity(path)`
 *   (lower-cased on Windows, parser.rs:1227-1236), `path` the normalized path, and `kind` the
 *   requested `file` (the push is at parser.rs:911-917).
 * - Security.evtx is not readable: `symlink_metadata` is denied, so expansion records
 *   `SourceCoverage::AccessDenied { path, reason: "source metadata access was denied" }`
 *   (parser.rs:715-724) and creates no entry.
 */
export function buildSourceManifest(): EventLogSourceManifest {
  return {
    entries: CHANNEL_ORDER.map((key) => ({
      sourceId: channelPath(key).toLowerCase(),
      path: channelPath(key),
      kind: "file",
    })),
    coverage: [{ kind: "accessDenied", path: SECURITY_PATH, reason: ACCESS_DENIED_REASON }],
  };
}

const ACCESS_DENIED_REASON = "source metadata access was denied";

/**
 * Reply for `evtx_parse_manifest` over `buildSourceManifest()`.
 *
 * Mirrors `evtx_parse_manifest` -> `parse_evtx_manifest`
 * (src-tauri/src/event_log/commands.rs:190-199;
 * `parse_evtx_manifest` parser.rs:1548-1564; its batch body `parse_evtx_manifest_with_batches`
 * parser.rs:1584-1770):
 *
 * - Records: within a file the EVTX reader yields ascending record order; across files they are
 *   gathered in manifest order and then stably sorted by `timestamp_epoch`, and `id` is the index
 *   in that order starting from 0 (parser.rs:1557-1560).
 * - Channels: one entry per file with records, `ChannelSourceType::File { path }` and
 *   `Enabled`, in manifest order (`append_parsed_file`, parser.rs:1842-1868).
 * - Security.evtx: the manifest carries one `SourceCoverage::AccessDenied` row and no entry for it
 *   (parser.rs:715-724). That one coverage row is mirrored three ways: `coverage` (the manifest
 *   rows as-is), `coverageGaps` via `coverage_gap_from_source_coverage` (parser.rs:1370-1388, kind `accessDenied`), and
 *   `errorMessages` via `format_coverage_gap` (`"<source>: <reason>"`, parser.rs:1461-1468), with
 *   `parseErrors = manifest.coverage.len()` (parser.rs:1595-1600). No record or channel is
 *   emitted for the unreadable file.
 * - `totalRecords` is the record count (overwritten with `records.len()` at parser.rs:1562);
 *   `archiveMembers` is empty. The result is assembled at parser.rs:1757-1767.
 */
export function buildParseResult(): EvtxParseResult {
  const order = (key: ChannelKey): number => CHANNEL_ORDER.indexOf(key);
  const events = generateEvents().sort(
    (a, b) => order(a.chKey) - order(b.chKey) || a.s - b.s || a.rec - b.rec,
  );
  const records = events
    .map(toRecord)
    .sort((a, b) => a.timestampEpoch - b.timestampEpoch)
    .map((record, index) => ({ ...record, id: index }));

  const channels: EvtxChannelInfo[] = CHANNEL_ORDER.map((key) => ({
    name: CHANNELS[key].name,
    eventCount: events.filter((e) => e.chKey === key).length,
    sourceType: { file: { path: channelPath(key) } },
    enabledState: "enabled",
  }));

  const reason = ACCESS_DENIED_REASON;
  return {
    records,
    channels,
    totalRecords: records.length,
    parseErrors: 1,
    errorMessages: [`${SECURITY_PATH}: ${reason}`],
    coverageGaps: [{ source: SECURITY_PATH, kind: "accessDenied", reason }],
    coverage: [{ kind: "accessDenied", path: SECURITY_PATH, reason }],
    archiveMembers: [],
  };
}

/**
 * Exactly what the capture feeds the engine, and what the spec expects the UI to send: the records
 * as appended, the diagnose coverage gaps, and the chunk and page sizes.
 */
export function engineInput(parseResult: EvtxParseResult) {
  return {
    records: parseResult.records,
    coverageGaps: parseResult.coverageGaps ?? [],
    chunkRecordLimit: ENGINE_CHUNK_RECORD_LIMIT,
    pageSize: ENGINE_PAGE_SIZE,
    sessionId: ENGINE_SESSION_ID,
  };
}

/** SHA-256 of the canonical (`JSON.stringify`, fixed key order) engine input. */
export function engineInputSha256(parseResult: EvtxParseResult): string {
  return createHash("sha256").update(JSON.stringify(engineInput(parseResult))).digest("hex");
}

/** What the engine saw and answered for one capture; the file is written by the capture script. */
export interface EngineReplies {
  /** Human-readable note repeated at the top of the JSON file. */
  about: string;
  provenance: {
    /** Git commit of the Rust engine that produced these replies. */
    engineCommit: string;
    /** Workspace dirty state when captured, so a reply from unreviewed code is visible. */
    engineTreeDirty: boolean;
    capturedBy: string;
    /** Hash of `engineInput()`: the replies are only valid for exactly this input. */
    inputSha256: string;
    /** Hash of the engine source files at capture; `capture-event-log-replies.mjs --check`. */
    engineSourceSha256: string;
  };
  sessionId: string;
  /** Number of records in each `evtx_append_analysis_chunk` call, in call order. */
  appendChunkRecordCounts: number[];
  /** The gaps passed to `evtx_diagnose_analysis_session`. */
  diagnoseCoverageGaps: EvtxCoverageGap[];
  create: EventLogAnalysisSessionStatus;
  append: EventLogAnalysisSessionStatus[];
  finalize: EventLogAnalysisSessionStatus;
  timelinePages: { offset: number; limit: number; page: EventLogAnalysisTimelinePage }[];
  diagnosis: DiagnosisSummary;
}

/** The exact engine input, committed so `cargo test` can replay it (see the capture script). */
export const ENGINE_INPUT_PATH = fileURLToPath(
  new URL("./event-log-engine-input.json", import.meta.url),
);

export const ENGINE_REPLIES_PATH = fileURLToPath(
  new URL("./event-log-engine-replies.json", import.meta.url),
);

export function loadEngineReplies(): EngineReplies {
  return JSON.parse(readFileSync(ENGINE_REPLIES_PATH, "utf8")) as EngineReplies;
}
