import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workflowUrl = new URL("../workflows/cmtrace-ci.yml", import.meta.url);

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

function assertSourceQualityRequirements(workflow) {
  const job = sourceQualityJob(workflow);

  assert.match(job, /^    steps:\n/m, "source-quality steps missing");
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
  assert.match(
    job,
    /^      - name: Changed-range whitespace\n        env:\n          BEFORE_SHA: \$\{\{ github\.event\.before \}\}\n          PR_BASE_SHA: \$\{\{ github\.event\.pull_request\.base\.sha \}\}\n        run: \|\n(?:          .*\n|\n)*          git diff --check "\$base\.\.\.HEAD"$/m,
    "range whitespace gate missing"
  );
}

test("source-quality gates formatting, wasm portability, and the changed range", async () => {
  const workflow = await readFile(workflowUrl, "utf8");

  assertSourceQualityRequirements(workflow);
});

test("source-quality requirements cannot be satisfied outside the job", () => {
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
});
