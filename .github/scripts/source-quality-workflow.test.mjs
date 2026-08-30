import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workflowUrl = new URL("../workflows/cmtrace-ci.yml", import.meta.url);

test("source-quality gates formatting, wasm portability, and the changed range", async () => {
  const workflow = await readFile(workflowUrl, "utf8");

  assert.match(workflow, /^  source-quality:\n/m, "source-quality job missing");
  assert.match(workflow, /fetch-depth: 0/, "full history is required for range checks");
  assert.match(workflow, /toolchain: "1\.92\.0"/, "rustfmt toolchain must be pinned");
  assert.match(workflow, /components: rustfmt/, "rustfmt component must be installed");
  assert.match(workflow, /targets: wasm32-unknown-unknown/, "wasm target must be installed");
  assert.match(workflow, /cargo fmt --all -- --check/, "format gate missing");
  assert.match(
    workflow,
    /cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown/,
    "parser wasm gate missing"
  );
  assert.match(workflow, /git diff --check "\$base\.\.\.HEAD"/, "range whitespace gate missing");
  assert.match(workflow, /github\.event\.pull_request\.base\.sha/, "PR base SHA missing");
  assert.match(workflow, /github\.event\.before/, "push base SHA missing");
});
