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
 * 1. Writes the fixture's records and gaps to e2e/fixtures/event-log-engine-input.json (committed).
 * 2. Runs the committed, ignored, env-gated test `event_log::analysis_session::screenshot_replies::
 *    capture_event_log_replies` (src-tauri/src/event_log/analysis_session.rs) with
 *    CMTRACE_EVENT_LOG_REPLIES_INPUT / _OUTPUT pointing at that file and a temp file. This script never edits a
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
 * Beyond this script, `cargo test event_log::analysis_session` (CI: Check & Test (Rust)) runs the
 * non-ignored test `screenshot_replies::committed_engine_replies_match_the_engine`, which replays
 * the committed input through the engine and requires the result to equal the committed replies
 * (ignoring `about`, `provenance.engineCommit`, `provenance.engineTreeDirty` and
 * `provenance.capturedBy`). It also pins `provenance.inputSha256` to the SHA-256 of the committed
 * input bytes; `--check` verifies `engineSourceSha256`. A hand edit of the replies fails there.
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
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import {
  buildParseResult,
  ENGINE_INPUT_PATH,
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
      // Strip CR so a Windows checkout with core.autocrlf=true hashes the same as the LF original.
      content = Buffer.from(
        readFileSync(path.join(REPO, file)).filter((byte) => byte !== 0x0d),
      );
    } catch {
      // Tracked but deleted in the working tree: the hash still changes via the missing content.
    }
    hash.update(file).update("\0").update(content).update("\0");
  }
  return hash.digest("hex");
}

/**
 * Publishes the committed fixtures (`[target, text]` pairs, in order) so a failure at any point
 * leaves the old set intact. This is the only place the script writes under e2e/fixtures.
 *
 * Each new file is first written in full next to its target (same directory, so the final
 * `renameSync` is atomic on one filesystem and never exposes a truncated file). Every existing
 * target is copied to a same-directory backup. The targets are then renamed into place one by
 * one; if any rename fails, the ones already done are restored from their backups. Staged and
 * backup files are removed in a `finally`.
 */
function publishFixtures(pairs) {
  const staged = pairs.map(([target]) => `${target}.staged-${process.pid}`);
  const backups = pairs.map(([target]) => `${target}.backup-${process.pid}`);
  const published = [];
  try {
    pairs.forEach(([target, text], i) => {
      writeFileSync(staged[i], text);
      if (existsSync(target)) copyFileSync(target, backups[i]);
    });
    pairs.forEach(([target], i) => {
      renameSync(staged[i], target);
      published.push(i);
    });
  } catch (error) {
    for (const i of published.reverse()) {
      if (existsSync(backups[i])) renameSync(backups[i], pairs[i][0]);
      else rmSync(pairs[i][0], { force: true });
    }
    throw error;
  } finally {
    for (const file of [...staged, ...backups]) rmSync(file, { force: true });
  }
}

const parseResult = buildParseResult();

if (process.argv.includes("--check")) {
  const { provenance } = JSON.parse(readFileSync(ENGINE_REPLIES_PATH, "utf8"));
  const problems = [];
  if (provenance.inputSha256 !== engineInputSha256(parseResult)) {
    problems.push("the dataset (event-log-data.ts) changed since capture");
  }
  let committedInput = null;
  try {
    committedInput = readFileSync(ENGINE_INPUT_PATH, "utf8");
  } catch {
    // Reported below.
  }
  if (committedInput !== JSON.stringify(engineInput(parseResult))) {
    problems.push(
      "event-log-engine-input.json is missing or differs from the dataset (event-log-data.ts)",
    );
  }
  if (provenance.engineSourceSha256 !== engineSourceSha256()) {
    problems.push("the engine changed since capture (src-tauri/src/event_log, parser crate, Cargo)");
  }
  if (problems.length > 0) {
    console.error(`event-log-engine-replies.json is stale: ${problems.join("; ")}.`);
    console.error("Regenerate with `node e2e/fixtures/capture-event-log-replies.mjs`.");
    console.error(
      "(The cargo test event_log::analysis_session::screenshot_replies replays the committed " +
        "input against the committed replies on every run.)",
    );
    process.exit(1);
  }
  console.log("event-log-engine-replies.json matches the dataset and the engine sources.");
  process.exit(0);
}

const tempDir = mkdtempSync(path.join(os.tmpdir(), "cmtrace-event-log-capture-"));
// Nothing under e2e/fixtures is touched until the capture has succeeded and its output has been
// validated, so a failed run leaves the committed input and replies exactly as they were.
try {
  const inputPath = path.join(tempDir, "input.json");
  const outputPath = path.join(tempDir, "output.json");
  const inputText = JSON.stringify(engineInput(parseResult));
  writeFileSync(inputPath, inputText);

  const engineCommit = git("rev-parse", "HEAD");
  const engineTreeDirty = git("status", "--porcelain", "--", ...DIRTY_PATHS) !== "";

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
  if (engine.sessionId !== engineInput(parseResult).sessionId || !engine.diagnosis?.overview) {
    throw new Error("the capture output is not an engine reply set (missing sessionId or diagnosis)");
  }
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
  const repliesText = JSON.stringify(replies, null, 2) + "\n";

  publishFixtures([
    [ENGINE_INPUT_PATH, inputText],
    [ENGINE_REPLIES_PATH, repliesText],
  ]);

  console.log(
    `wrote ${path.relative(REPO, ENGINE_REPLIES_PATH)} ` +
      `(outcome ${replies.diagnosis.overview.outcome}, ` +
      `${replies.diagnosis.overview.findingCount} findings, commit ${engineCommit})`,
  );
} finally {
  rmSync(tempDir, { recursive: true, force: true });
}
