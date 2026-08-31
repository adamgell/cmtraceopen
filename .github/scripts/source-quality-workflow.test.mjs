import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workflowUrl = new URL("../workflows/cmtrace-ci.yml", import.meta.url);
const expectedChangedRangeStep = `      - name: Changed-range whitespace
        env:
          BEFORE_SHA: \${{ github.event.before }}
          PR_BASE_SHA: \${{ github.event.pull_request.base.sha }}
        run: |
          if [[ "$GITHUB_EVENT_NAME" == "pull_request" ]]; then
            base="$PR_BASE_SHA"
          else
            base="$BEFORE_SHA"
          fi

          if [[ ! "$base" =~ ^[0-9a-f]{40}$ ]] || [[ "$base" =~ ^0+$ ]]; then
            base="$(git rev-list --max-parents=0 HEAD)"
          fi

          if ! git cat-file -e "\${base}^{commit}" 2>/dev/null; then
            base="$(git rev-list --max-parents=0 HEAD)"
          fi

          if git rev-parse --verify "\${base}^" >/dev/null 2>&1; then
            git diff --check "$base...HEAD"
          else
            git diff --check "$(git hash-object -t tree /dev/null)" HEAD
          fi
`;

function assertRequiredTriggers(workflow) {
  assert.match(
    workflow,
    /^on:\n  push:\n    branches: \[main, codex\/parser-family-skeleton\]\n  pull_request:\n(?:    #.*\n)*    branches: \[main, codex\/parser-family-skeleton\]$/m,
    "required push and pull-request branch triggers missing"
  );
}

function sourceQualityJob(workflow) {
  const sourceQuality = workflow.match(/^  source-quality:\n/m);
  assert.ok(sourceQuality, "source-quality job missing");

  const jobLines = [];
  for (const line of workflow.slice(sourceQuality.index + sourceQuality[0].length).split("\n")) {
    if (line === "" || /^ {4}/.test(line)) {
      jobLines.push(line);
    } else {
      break;
    }
  }

  return jobLines.join("\n");
}

function changedRangeStep(job) {
  const stepStart = job.match(/^      - name: Changed-range whitespace\n/m);
  assert.ok(stepStart, "changed-range whitespace step missing");

  return job
    .slice(stepStart.index)
    .split("\n")
    .filter((line) => !/^[ \t]*#/.test(line))
    .join("\n");
}

function assertSourceQualityRequirements(workflow) {
  const job = sourceQualityJob(workflow);

  assert.match(job, /^    steps:\n/m, "source-quality steps missing");
  assert.doesNotMatch(job, /^    if:/m, "source-quality job must not be conditional");
  assert.doesNotMatch(job, /^    continue-on-error:/m, "source-quality job must not soften failures");
  assert.doesNotMatch(job, /^        if:/m, "source-quality steps must not be conditional");
  assert.doesNotMatch(job, /^        continue-on-error:/m, "source-quality steps must not soften failures");
  assert.match(
    job,
    /^      - uses: actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\.0\.1\n        with:\n          fetch-depth: 0\n          persist-credentials: false$/m,
    "full-history credential-free checkout missing"
  );
  assert.match(
    job,
    /^      - name: Setup pinned Rust quality toolchain\n        uses: dtolnay\/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n        with:\n          toolchain: "1\.92\.0"\n          components: rustfmt\n          targets: wasm32-unknown-unknown$/m,
    "pinned rustfmt and wasm toolchain missing"
  );
  assert.match(
    job,
    /^      - name: Rust formatting\n        run: cargo fmt --all -- --check$/m,
    "format gate missing"
  );
  assert.match(
    job,
    /^      - name: Parser wasm portability\n        run: cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown$/m,
    "parser wasm gate missing"
  );
  assert.equal(
    changedRangeStep(job),
    expectedChangedRangeStep,
    "changed-range whitespace step must match the complete executable contract"
  );
}

test("source-quality gates formatting, wasm portability, and the changed range", async () => {
  const workflow = await readFile(workflowUrl, "utf8");

  assertRequiredTriggers(workflow);
  assertSourceQualityRequirements(workflow);
});

test("source-quality requirements reject bypasses", async () => {
  const inertWorkflow = `jobs:
  source-quality:
    name: Source Quality
    runs-on: ubuntu-latest
    steps:
      - run: true
  check:
    # fetch-depth: 0
    # persist-credentials: false
    # toolchain: "1.92.0"
    # components: rustfmt
    # targets: wasm32-unknown-unknown
    # cargo fmt --all -- --check
    # cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
    # git diff --check "$base...HEAD"
    # github.event.pull_request.base.sha
    # github.event.before
`;

  assert.throws(() => assertSourceQualityRequirements(inertWorkflow));

  const workflow = await readFile(workflowUrl, "utf8");
  const disabledJob = workflow.replace(
    /^  source-quality:\n/m,
    "  source-quality:\n    if: ${{ github.repository != 'adamgell/cmtraceopen' }}\n"
  );
  const disabledFormatting = workflow.replace(
    "      - name: Rust formatting\n        run: cargo fmt --all -- --check",
    "      - name: Rust formatting\n        run: cargo fmt --all -- --check\n        if: false"
  );
  const softFailingWasm = workflow.replace(
    "      - name: Parser wasm portability\n        run: cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown",
    "      - name: Parser wasm portability\n        run: cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown\n        continue-on-error: true"
  );
  const earlyExit = workflow.replace(
    '        run: |\n          if [[ "$GITHUB_EVENT_NAME" == "pull_request" ]]; then',
    '        run: |\n          exit 0\n          if [[ "$GITHUB_EVENT_NAME" == "pull_request" ]]; then'
  );
  const softFailingJob = workflow.replace(
    /^  source-quality:\n/m,
    "  source-quality:\n    continue-on-error: true\n"
  );
  const inlineExit = workflow.replace(
    '          if [[ "$GITHUB_EVENT_NAME" == "pull_request" ]]; then',
    '          if true; then exit 0; fi\n          if [[ "$GITHUB_EVENT_NAME" == "pull_request" ]]; then'
  );
  const commentedExit = workflow.replace(
    '          if [[ "$GITHUB_EVENT_NAME" == "pull_request" ]]; then',
    '          # exit 0\n          if [[ "$GITHUB_EVENT_NAME" == "pull_request" ]]; then'
  );
  const quotedExitMention = workflow.replace(
    '          if [[ "$GITHUB_EVENT_NAME" == "pull_request" ]]; then',
    '          # "exit 0"\n          if [[ "$GITHUB_EVENT_NAME" == "pull_request" ]]; then'
  );

  assert.throws(() => assertSourceQualityRequirements(disabledJob));
  assert.throws(() => assertSourceQualityRequirements(disabledFormatting));
  assert.throws(() => assertSourceQualityRequirements(softFailingWasm));
  assert.throws(() => assertSourceQualityRequirements(earlyExit));
  assert.throws(() => assertSourceQualityRequirements(softFailingJob));
  assert.throws(() => assertSourceQualityRequirements(inlineExit));
  assert.doesNotThrow(() => assertSourceQualityRequirements(commentedExit));
  assert.doesNotThrow(() => assertSourceQualityRequirements(quotedExitMention));
});
