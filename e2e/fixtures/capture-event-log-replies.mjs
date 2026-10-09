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
 * Regenerate (from the repo root; needs a Rust toolchain and Node 22.18+ or 23.6+, where TypeScript
 * type stripping is on by default; Node 22.6 to 22.17 need `--experimental-strip-types`):
 *
 *   node e2e/fixtures/capture-event-log-replies.mjs
 *
 * Check, read-only, that the committed replies still match the dataset and the engine source
 * (no cargo, no writes; exits 1 with a reason when they do not):
 *
 *   node e2e/fixtures/capture-event-log-replies.mjs --check
 *
 * The replies record `inputSha256` (the exact engine input) and `engineSourceSha256` (the engine
 * sources). The spec compares the first at test time and fails if the dataset changed; only
 * `--check` can compare the second, because spec code must not shell out. Run `--check` after any
 * change under src-tauri/src/event_log or crates/cmtraceopen-parser/src.
 *
 * Re-run the capture whenever the dataset (event-log-data.ts), the frontend's analysis call
 * sequence, or the engine's session/diagnosis logic changes. The spec fails loudly if the UI's
 * requests no longer match what was captured, so a stale file cannot be replayed silently.
 *
 * Determinism: the session id is a fixed placeholder, so for the same input and engine source a
 * re-run reproduces the engine's replies exactly. Only `provenance.engineCommit` and
 * `engineTreeDirty` track the checkout and so change with it.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import {
  buildParseResult,
  ENGINE_REPLIES_PATH,
  engineInput,
  engineInputSha256,
} from "./event-log-data.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "..", "..");
const TAURI = path.join(REPO, "src-tauri");
const TEST_NAME = "event_log::analysis_session::screenshot_replies::capture_event_log_replies";

/** Sources whose behavior decides the replies. Whole directories: a false alarm costs 12 s. */
const ENGINE_SOURCES = [
  "src-tauri/src/event_log",
  "crates/cmtraceopen-parser/src",
  "src-tauri/Cargo.toml",
  "Cargo.lock",
];
const DIRTY_PATHS = [...ENGINE_SOURCES, "e2e/fixtures/event-log-data.ts"];

function git(...args) {
  return execFileSync("git", args, { cwd: REPO, encoding: "utf8" }).trim();
}

/** Content hash of the working-tree engine sources, so it is right on a dirty or clean tree. */
function engineSourceSha256() {
  const files = git("ls-files", "--cached", "--others", "--exclude-standard", "--", ...ENGINE_SOURCES)
    .split("\n")
    .filter(Boolean)
    .sort();
  const hash = createHash("sha256");
  for (const file of files) {
    let content = Buffer.alloc(0);
    try {
      content = readFileSync(path.join(REPO, file));
    } catch {
      // Tracked but deleted in the working tree: the hash still changes via the missing content.
    }
    hash.update(file).update("\0").update(content).update("\0");
  }
  return hash.digest("hex");
}

const parseResult = buildParseResult();

if (process.argv.includes("--check")) {
  const { provenance } = JSON.parse(readFileSync(ENGINE_REPLIES_PATH, "utf8"));
  const problems = [];
  if (provenance.inputSha256 !== engineInputSha256(parseResult)) {
    problems.push("the dataset (event-log-data.ts) changed since capture");
  }
  if (provenance.engineSourceSha256 !== engineSourceSha256()) {
    problems.push("the engine changed since capture (src-tauri/src/event_log, parser crate, Cargo)");
  }
  if (problems.length > 0) {
    console.error(`event-log-engine-replies.json is stale: ${problems.join("; ")}.`);
    console.error("Regenerate with `node e2e/fixtures/capture-event-log-replies.mjs`.");
    process.exit(1);
  }
  console.log("event-log-engine-replies.json matches the dataset and the engine sources.");
  process.exit(0);
}

const tempDir = mkdtempSync(path.join(os.tmpdir(), "cmtrace-event-log-capture-"));
const inputPath = path.join(tempDir, "input.json");
const outputPath = path.join(tempDir, "output.json");
writeFileSync(inputPath, JSON.stringify(engineInput(parseResult)));

const engineCommit = git("rev-parse", "HEAD");
const engineTreeDirty =
  git("status", "--porcelain", "--", ...DIRTY_PATHS) !== "";

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
    inputSha256: engineInputSha256(parseResult),
    engineSourceSha256: engineSourceSha256(),
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
