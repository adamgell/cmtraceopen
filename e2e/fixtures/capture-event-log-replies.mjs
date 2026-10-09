#!/usr/bin/env node
/**
 * Regenerates e2e/fixtures/event-log-engine-replies.json: the analysis-session and diagnosis
 * replies the Event Logs screenshot spec replays.
 *
 * Why this exists
 * ---------------
 * Those replies must never be hand-written. A hand-written "no findings" diagnosis for a dataset
 * that holds 11 failed MDM enrollments is a claim the engine cannot make. So this script runs the
 * REAL engine (`EventLogAnalysisSession` in src-tauri/src/event_log/analysis_session.rs) over the
 * fixture's records and writes down exactly what it answers, with the same call sequence the UI
 * makes (event-analysis-session.ts): create, append in chunks of 1,000 records, finalize, every
 * timeline page of 1,000, then diagnose with the coverage gaps.
 *
 * Why not the debug IPC bridge (127.0.0.1:1422)
 * ---------------------------------------------
 * The bridge (src-tauri/src/ipc_bridge.rs) is a hand-written `match` over a few file-parsing and
 * lookup commands. It has no arm for any `evtx_*` command (unknown commands answer "debug IPC
 * bridge does not implement command"), and the session commands need `tauri::State<AppState>`,
 * which the bridge does not hold. Starting `npm run app:dev` would therefore not answer them. The
 * capture runs the engine's own session type in-process instead: same code, no Tauri runtime.
 *
 * How it works
 * ------------
 * 1. Writes the fixture's records and gaps to a temp JSON file.
 * 2. Runs the committed, ignored, env-gated test `event_log::analysis_session::screenshot_replies::
 *    capture_event_log_replies` (src-tauri/src/event_log/analysis_session.rs) with
 *    CMTRACE_EVENT_LOG_REPLIES_INPUT / _OUTPUT pointing at temp files. This script never edits a
 *    source file.
 * 3. Writes the engine output plus provenance (git commit, dirty flag) to the JSON fixture.
 *
 * Regenerate (from the repo root; needs a Rust toolchain and Node 22.6+ for type stripping):
 *
 *   node e2e/fixtures/capture-event-log-replies.mjs
 *
 * Re-run it whenever the dataset (event-log-data.ts), the frontend's analysis call sequence, or
 * the engine's session/diagnosis logic changes. The spec fails loudly if the UI's requests no
 * longer match what was captured, so a stale file cannot be replayed silently.
 *
 * Determinism: the session id is a fixed placeholder, so a re-run changes the JSON only when the
 * engine's answer changes.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildParseResult, ENGINE_REPLIES_PATH } from "./event-log-data.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "..", "..");
const TAURI = path.join(REPO, "src-tauri");
const TEST_NAME = "event_log::analysis_session::screenshot_replies::capture_event_log_replies";

/** Mirrors EVENT_LOG_ANALYSIS_CHUNK_RECORD_LIMIT and _PAGE_SIZE in event-analysis-session.ts. */
const CHUNK_RECORD_LIMIT = 1_000;
const PAGE_SIZE = 1_000;
const SESSION_ID = "00000000-0000-4000-8000-000000000828";

function git(...args) {
  return execFileSync("git", args, { cwd: REPO, encoding: "utf8" }).trim();
}

const parseResult = buildParseResult();
const tempDir = mkdtempSync(path.join(os.tmpdir(), "cmtrace-event-log-capture-"));
const inputPath = path.join(tempDir, "input.json");
const outputPath = path.join(tempDir, "output.json");
writeFileSync(
  inputPath,
  JSON.stringify({
    records: parseResult.records,
    // The gaps the UI sends to diagnose: the parse result's coverage gaps, merged by
    // mergeDiagnosisCoverageGaps (EventLogWorkspace.tsx). The spec asserts this equality.
    coverageGaps: parseResult.coverageGaps,
    chunkRecordLimit: CHUNK_RECORD_LIMIT,
    pageSize: PAGE_SIZE,
    sessionId: SESSION_ID,
  }),
);

const engineCommit = git("rev-parse", "HEAD");
const engineTreeDirty =
  git("status", "--porcelain", "--", "src-tauri/src", "crates", "Cargo.toml", "Cargo.lock") !== "";

execFileSync(
  "cargo",
  ["test", "--locked", "--lib", TEST_NAME, "--", "--ignored", "--exact", "--nocapture"],
  {
    cwd: TAURI,
    stdio: "inherit",
    env: {
      ...process.env,
      CMTRACE_EVENT_LOG_REPLIES_INPUT: inputPath,
      CMTRACE_EVENT_LOG_REPLIES_OUTPUT: outputPath,
    },
  },
);
if (!existsSync(outputPath)) {
  throw new Error("the capture test ran but wrote no output (was the test name filtered out?)");
}

const engine = JSON.parse(readFileSync(outputPath, "utf8"));
const replies = {
  about:
    "Replies captured from the real event-log analysis engine (EventLogAnalysisSession) over the " +
    "records in event-log-data.ts. Do not edit by hand. Regenerate with " +
    "`node e2e/fixtures/capture-event-log-replies.mjs`; engineCommit is the commit the engine " +
    "was built from.",
  provenance: {
    engineCommit,
    engineTreeDirty,
    capturedBy: "e2e/fixtures/capture-event-log-replies.mjs",
  },
  ...engine,
};
writeFileSync(ENGINE_REPLIES_PATH, JSON.stringify(replies, null, 2) + "\n");
rmSync(tempDir, { recursive: true, force: true });

console.log(
  `wrote ${path.relative(REPO, ENGINE_REPLIES_PATH)} ` +
    `(outcome ${replies.diagnosis.overview.outcome}, ` +
    `${replies.diagnosis.overview.findingCount} findings, commit ${engineCommit})`,
);
