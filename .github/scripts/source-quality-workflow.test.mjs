import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workflowUrl = new URL("../workflows/cmtrace-ci.yml", import.meta.url);
const expectedSourceQualityJob = `  source-quality:
    name: Source Quality (fmt / wasm / whitespace)
    runs-on: ubuntu-latest
    defaults:
      run:
        shell: bash --noprofile --norc -e -o pipefail {0}
    env:
      BASH_ENV: /dev/null
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false

      - name: Setup pinned Rust quality toolchain
        uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable
        with:
          toolchain: "1.92.0"
          components: rustfmt
          targets: wasm32-unknown-unknown

      - name: Rust formatting
        run: cargo fmt --all -- --check

      - name: Parser wasm portability
        run: cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown

      - name: Changed-range whitespace
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

  return sourceQuality[0] + jobLines.join("\n");
}

function assertWorkflowPreamble(workflow) {
  const jobsStart = workflow.indexOf("\njobs:\n");
  assert.notEqual(jobsStart, -1, "workflow jobs missing");

  const preamble = workflow.slice(0, jobsStart);
  assert.doesNotMatch(preamble, /^defaults:/m, "root workflow defaults are not allowed");
  assert.doesNotMatch(preamble, /^env:/m, "root workflow environment is not allowed");
}

function assertSourceQualityRequirements(workflow) {
  assertWorkflowPreamble(workflow);
  assert.equal(
    sourceQualityJob(workflow),
    expectedSourceQualityJob,
    "source-quality job must match the complete ordered executable contract"
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
  const customShell = workflow.replace(
    "    steps:\n",
    "    defaults:\n      run:\n        shell: bash -c 'bash \"$1\"; exit 0' _ {0}\n    steps:\n"
  );
  const bashEnvBypass = workflow.replace(
    "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
    "      - name: Disable later shell failures\n        run: |\n          printf 'exit 0\\n' > \"$GITHUB_WORKSPACE/skip.sh\"\n          printf 'BASH_ENV=%s/skip.sh\\n' \"$GITHUB_WORKSPACE\" >> \"$GITHUB_ENV\"\n\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
  );
  const rootShell = workflow.replace(
    "\njobs:\n",
    "\ndefaults:\n  run:\n    shell: bash -c 'bash \"$1\"; exit 0' _ {0}\n\njobs:\n"
  );
  const rootBashEnv = workflow.replace(
    "\njobs:\n",
    "\nenv:\n  BASH_ENV: $GITHUB_WORKSPACE/skip.sh\n\njobs:\n"
  );

  assert.throws(() => assertSourceQualityRequirements(disabledJob));
  assert.throws(() => assertSourceQualityRequirements(disabledFormatting));
  assert.throws(() => assertSourceQualityRequirements(softFailingWasm));
  assert.throws(() => assertSourceQualityRequirements(earlyExit));
  assert.throws(() => assertSourceQualityRequirements(softFailingJob));
  assert.throws(() => assertSourceQualityRequirements(inlineExit));
  assert.throws(() => assertSourceQualityRequirements(customShell));
  assert.throws(() => assertSourceQualityRequirements(bashEnvBypass));
  assert.throws(() => assertSourceQualityRequirements(rootShell));
  assert.throws(() => assertSourceQualityRequirements(rootBashEnv));
});
