#!/usr/bin/env node
/**
 * measure-dsregcmd-responsiveness.mjs
 *
 * Measures how long a DsRegCmd bundle analysis keeps the Tauri command thread
 * busy, in the real app, through the real IPC channel (issue #627).
 *
 * It reproduces the two invokes the DsRegCmd workspace fires between
 * `beginAnalysis` (the loading indicator paints) and `setResults` (the
 * indicator dismisses):
 *
 *   1. load_dsregcmd_source("folder", bundlePath)   - source resolution
 *   2. analyze_dsregcmd(input, bundlePath)          - the bundle analysis
 *
 * While the analysis is in flight, the script also measures the latency of an
 * unrelated IPC call (get_available_workspaces) that the app makes all the
 * time. Before issue #627 the synchronous command ran the bundle readers on
 * the command thread, so the unrelated call was delayed by the full analysis
 * duration. After the fix the command thread stays free.
 *
 * The bundle readers are slowed down deterministically by the
 * CMTRACE_SIMULATE_BUNDLE_IO_MS hook (debug builds), so the measurement works
 * on any local disk without needing genuinely slow hardware.
 *
 * Usage:
 *   node scripts/measure-dsregcmd-responsiveness.mjs [--port 9222] [--samples 5]
 *       [--delay-ms 150] [--bundle <path>] [--cdp-url http://127.0.0.1:9222]
 *
 * The app under test must be a debug build (the delay hook is compiled out of
 * release builds) launched with WebView2 remote debugging:
 *   $env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--remote-debugging-port=9222"
 *   $env:CMTRACE_SIMULATE_BUNDLE_IO_MS = "150"
 *   .\src-tauri\target\debug\cmtrace-open.exe
 */

import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function readArg(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index === -1 || index + 1 >= process.argv.length) return fallback;
  return process.argv[index + 1];
}

const port = Number(readArg("--port", 9222));
const samples = Number(readArg("--samples", 5));
const delayMs = Number(readArg("--delay-ms", 150));
const bundleArg = readArg("--bundle", null);

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("--port must be an integer between 1 and 65535");
}
if (!Number.isInteger(samples) || samples < 1) {
  throw new Error("--samples must be a positive integer");
}
if (!Number.isFinite(delayMs) || delayMs <= 0) {
  throw new Error("--delay-ms must be a positive number");
}

// ---------------------------------------------------------------------------
// Synthetic slow-storage bundle (mirrors the Rust unit-test fixture shape)
// ---------------------------------------------------------------------------

const DSREGCMD_SAMPLE = `+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+
 AzureAdJoined : YES
 DomainJoined = NO
 WorkplaceJoined : NO
 EnterpriseJoined : NO
 TenantId : 11111111-2222-3333-4444-555555555555
 DeviceId : abcdefab-1111-2222-3333-abcdefabcdef
 TenantName : Contoso
 MdmUrl : https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc
 AzureAdPrt : YES
 AzureAdPrtUpdateTime : 2025-03-10 10:00:00.000 UTC
 Previous Prt Attempt : 2025-03-10 09:55:00.000 UTC
 Attempt Status : 0xc000006d
 HTTP status : 401
 User Context : SYSTEM
 SessionIsNotRemote : NO
 AD Connectivity Test : PASS
 DRS Discovery Test : FAIL [0x801c0021]
 Client ErrorCode : 0x801c03f2
 KeySignTest : PASSED
 AadRecoveryEnabled : NO
 DeviceCertificateValidity : [ 2025-03-01 00:00:00.000 UTC -- 2025-03-20 00:00:00.000 UTC ]
`;

function buildBundleFixture() {
  const root = mkdtempSync(join(tmpdir(), "dsregcmd-bundle-"));
  const evidence = join(root, "evidence");
  mkdirSync(join(evidence, "command-output"), { recursive: true });
  mkdirSync(join(evidence, "registry"), { recursive: true });
  mkdirSync(join(evidence, "connectivity"), { recursive: true });
  mkdirSync(join(evidence, "event-logs"), { recursive: true });
  mkdirSync(join(evidence, "scheduled-tasks"), { recursive: true });

  writeFileSync(join(root, "manifest.json"), '{\n  "manifestPath": "manifest.json"\n}\n');
  writeFileSync(join(evidence, "command-output", "dsregcmd-status.txt"), DSREGCMD_SAMPLE);

  writeFileSync(
    join(evidence, "registry", "policymanager-device.reg"),
    'Windows Registry Editor Version 5.00\n\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\Current\\Device\\PassportForWork\\Policies]\n    "UsePassportForWork"=dword:00000001\n',
  );
  writeFileSync(
    join(evidence, "registry", "policymanager-providers.reg"),
    'Windows Registry Editor Version 5.00\n\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\Providers\\{11111111-1111-1111-1111-111111111111}\\default\\Device\\PassportForWork\\Policies]\n    "UsePassportForWork"=dword:00000001\n',
  );
  writeFileSync(
    join(evidence, "registry", "os-version.reg"),
    'Windows Registry Editor Version 5.00\n\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion]\n    "CurrentBuild"="22631"\n',
  );
  writeFileSync(
    join(evidence, "registry", "proxy-internet-settings.reg"),
    'Windows Registry Editor Version 5.00\n\n[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings]\n    "ProxyEnable"=dword:00000001\n',
  );
  writeFileSync(
    join(evidence, "registry", "enrollments.reg"),
    'Windows Registry Editor Version 5.00\n\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Enrollments\\{11111111-2222-3333-4444-555555555555}]\n    "UPN"="user@contoso.com"\n',
  );

  writeFileSync(
    join(evidence, "connectivity", "endpoint-tests.json"),
    JSON.stringify([
      {
        endpoint: "https://enterpriseregistration.windows.net",
        reachable: true,
        statusCode: 200,
        latencyMs: 42,
        errorMessage: null,
        timestamp: "2026-09-18T00:00:00Z",
      },
    ]),
  );
  writeFileSync(
    join(evidence, "connectivity", "scp-query.json"),
    JSON.stringify({
      scpFound: true,
      tenantDomain: "contoso.com",
      azureadId: "11111111-2222-3333-4444-555555555555",
      keywords: ["azureADId:11111111-2222-3333-4444-555555555555"],
      domainController: "dc1.contoso.com",
      error: null,
    }),
  );
  writeFileSync(
    join(evidence, "scheduled-tasks", "enterprise-mgmt-tasks.json"),
    JSON.stringify({
      enterpriseMgmtGuids: ["{11111111-2222-3333-4444-555555555555}"],
    }),
  );
  writeFileSync(join(evidence, "event-logs", "dsregcmd-events.json"), "{}");

  return root;
}

// ---------------------------------------------------------------------------
// CDP plumbing (Node >= 22 global WebSocket)
// ---------------------------------------------------------------------------

async function findPageTarget() {
  const response = await fetch(`http://127.0.0.1:${port}/json/list`);
  if (!response.ok) {
    throw new Error(
      `CDP endpoint not reachable (HTTP ${response.status}). Is the app running with --remote-debugging-port=${port}?`,
    );
  }
  const targets = await response.json();
  const page = targets.find(
    (target) => target.type === "page" && target.url.startsWith("http") && target.webSocketDebuggerUrl,
  );
  if (!page) {
    throw new Error("No app page target found at the CDP endpoint.");
  }
  return page.webSocketDebuggerUrl;
}

const REQUEST_TIMEOUT_MS = 30_000;

class CdpSession {
  constructor(url) {
    this.ws = new WebSocket(url);
    this.nextId = 1;
    this.pending = new Map();
  }

  rejectPending(error) {
    for (const { reject, timer } of this.pending.values()) {
      clearTimeout(timer);
      reject(error);
    }
    this.pending.clear();
  }

  async open() {
    await new Promise((resolve, reject) => {
      this.ws.addEventListener("open", resolve, { once: true });
      this.ws.addEventListener("error", reject, { once: true });
    });
    this.ws.addEventListener("message", (event) => {
      const message = JSON.parse(event.data);
      if (message.id && this.pending.has(message.id)) {
        const { resolve, reject, timer } = this.pending.get(message.id);
        clearTimeout(timer);
        this.pending.delete(message.id);
        if (message.error) reject(new Error(message.error.message));
        else resolve(message.result);
      }
    });
    this.ws.addEventListener("close", () => {
      this.rejectPending(new Error("CDP connection closed before the request completed"));
    });
    this.ws.addEventListener("error", () => {
      this.rejectPending(new Error("CDP connection failed before the request completed"));
    });
    await this.call("Runtime.enable");
  }

  call(method, params = {}) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`CDP request ${method} timed out after ${REQUEST_TIMEOUT_MS}ms`));
      }, REQUEST_TIMEOUT_MS);
      this.pending.set(id, { resolve, reject, timer });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  async evaluate(expression) {
    const result = await this.call("Runtime.evaluate", {
      expression,
      awaitPromise: true,
      returnByValue: true,
    });
    if (result.exceptionDetails) {
      throw new Error(
        `Page evaluation failed: ${result.exceptionDetails.text ?? JSON.stringify(result.exceptionDetails.exception?.description)}`,
      );
    }
    return result.result.value;
  }

  close() {
    this.ws.close();
  }
}

// ---------------------------------------------------------------------------
// Sample
// ---------------------------------------------------------------------------

function sampleExpression(bundlePath, input) {
  const inputJson = JSON.stringify(input);
  return `(async () => {
    const invoke = window.__TAURI_INTERNALS__.invoke.bind(window.__TAURI_INTERNALS__);
    if (!window.__TAURI_INTERNALS__) throw new Error("no Tauri internals in page");

    // 1. Source resolution: the invoke the workspace fires right after
    //    beginAnalysis paints the loading indicator.
    const tSource = performance.now();
    const resolved = await invoke("load_dsregcmd_source", {
      kind: "folder",
      path: ${JSON.stringify(bundlePath)},
    });
    const sourceMs = performance.now() - tSource;

    // 2. Analysis + unrelated IPC: the analysis is fired without awaiting,
    //    and an unrelated call (the same one the shell makes all the time)
    //    is timed while the analysis runs in flight.
    const tAnalyze = performance.now();
    const analysis = invoke("analyze_dsregcmd", {
      input: ${inputJson},
      bundlePath: ${JSON.stringify(bundlePath)},
    });

    const tUnrelated = performance.now();
    const workspaces = await invoke("get_available_workspaces");
    const unrelatedMs = performance.now() - tUnrelated;

    const analysisResult = await analysis;
    const analysisMs = performance.now() - tAnalyze;

    return {
      sourceMs,
      unrelatedMs,
      analysisMs,
      loadingIndicatorMs: sourceMs + analysisMs,
      workspaceCount: workspaces?.length ?? null,
      hadEvidence: analysisResult?.activeEvidence != null,
    };
  })()`;
}

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? (sorted[middle - 1] + sorted[middle]) / 2
    : sorted[middle];
}

function round(value) {
  return Math.round(value * 10) / 10;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const bundlePath = bundleArg ?? buildBundleFixture();
  const input = DSREGCMD_SAMPLE;
  const expectedStall = 7 * delayMs;

  const wsUrl = await findPageTarget();
  const session = new CdpSession(wsUrl);
  await session.open();

  console.log(
    `Measuring against the running app (CDP port ${port}, ${samples} samples, ${delayMs}ms simulated bundle I/O per reader).`,
  );

  const rows = [];
  for (let index = 0; index < samples; index += 1) {
    const row = await session.evaluate(sampleExpression(bundlePath, input));
    rows.push(row);
    console.log(
      `  sample ${index + 1}: unrelated_ipc=${round(row.unrelatedMs)}ms loading_indicator=${round(row.loadingIndicatorMs)}ms ` +
        `(source=${round(row.sourceMs)}ms analysis=${round(row.analysisMs)}ms workspaces=${row.workspaceCount} hadEvidence=${row.hadEvidence})`,
    );
  }

  session.close();

  const unrelated = rows.map((row) => row.unrelatedMs);
  const loading = rows.map((row) => row.loadingIndicatorMs);
  const analysis = rows.map((row) => row.analysisMs);

  const summary = {
    samples,
    simulated_io_per_reader_ms: delayMs,
    expected_stall_ms: expectedStall,
    unrelated_ipc_median_ms: round(median(unrelated)),
    unrelated_ipc_max_ms: round(Math.max(...unrelated)),
    loading_indicator_median_ms: round(median(loading)),
    analysis_median_ms: round(median(analysis)),
  };

  console.log("\nSummary (real app, real IPC channel):");
  console.log(JSON.stringify(summary, null, 2));

  const fail = [];
  if (median(unrelated) > 100) {
    fail.push(
      `unrelated IPC median ${summary.unrelated_ipc_median_ms}ms exceeds 100ms while the analysis runs`,
    );
  }
  if (median(loading) < expectedStall * 0.9) {
    fail.push(
      `loading indicator median ${summary.loading_indicator_median_ms}ms is far below the ${expectedStall}ms simulated stall - is CMTRACE_SIMULATE_BUNDLE_IO_MS=${delayMs} set on the app process?`,
    );
  }

  if (fail.length > 0) {
    console.error("\nFAIL:");
    for (const reason of fail) console.error(`  - ${reason}`);
    process.exit(1);
  }
  console.log("\nPASS: the command thread stays responsive while the analysis runs off it.");
}

main().catch((error) => {
  console.error(`measurement failed: ${error.message}`);
  process.exit(1);
});
