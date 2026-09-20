import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const workflowDir = fileURLToPath(
  new URL("../.github/workflows/", import.meta.url),
);

const LOCAL_ACTION = /^\s*-?\s*uses:\s*\.\/\.github\/actions\//;
const CHECKOUT = /^\s*-?\s*uses:\s*actions\/checkout@/;
const JOB_HEADER = /^ {2}([A-Za-z0-9_-]+):\s*$/;

/**
 * Split a workflow into its job blocks by 2-space indentation, which is what
 * every job name sits at under `jobs:`. Text scanning rather than a YAML
 * dependency keeps this test runnable from the CI step that already runs the
 * other workflow contract tests.
 */
function jobBlocks(contents) {
  const blocks = [];
  let current = null;

  for (const line of contents.split("\n")) {
    const header = JOB_HEADER.exec(line);
    if (header) {
      current = { name: header[1], lines: [] };
      blocks.push(current);
      continue;
    }
    if (current) {
      current.lines.push(line);
    }
  }

  return blocks;
}

test("a job that runs a local action checks the repository out first", () => {
  const workflows = readdirSync(workflowDir).filter((name) =>
    /\.ya?ml$/.test(name),
  );
  assert.ok(workflows.length > 0, "expected workflows to scan");

  const offenders = [];

  for (const workflow of workflows) {
    const blocks = jobBlocks(readFileSync(join(workflowDir, workflow), "utf8"));

    for (const job of blocks) {
      const localActionAt = job.lines.findIndex((line) =>
        LOCAL_ACTION.test(line),
      );
      if (localActionAt === -1) {
        continue;
      }

      const checkoutAt = job.lines.findIndex((line) => CHECKOUT.test(line));
      if (checkoutAt === -1 || checkoutAt > localActionAt) {
        offenders.push(`${workflow}: ${job.name}`);
      }
    }
  }

  assert.deepEqual(
    offenders,
    [],
    "a local `uses: ./.github/actions/...` is resolved from the workspace, so " +
      "the job fails with \"Can't find 'action.yml'\" unless it checks the " +
      "repository out earlier in the same job",
  );
});

test("the guard detects a job that names a local action without checking out", () => {
  // The v1.6.0 manifest publisher, before the fix: the job's only step was the
  // local action, so there was no checkout to find.
  const broken = [
    "  publish-updater-manifest:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - name: Publish updater manifest",
    "        uses: ./.github/actions/publish-updater-manifest",
    "",
  ].join("\n");

  const [job] = jobBlocks(broken);
  const localActionAt = job.lines.findIndex((line) => LOCAL_ACTION.test(line));
  const checkoutAt = job.lines.findIndex((line) => CHECKOUT.test(line));

  assert.notEqual(localActionAt, -1, "fixture must name a local action");
  assert.equal(checkoutAt, -1, "fixture must not check the repository out");
  assert.ok(
    checkoutAt === -1 || checkoutAt > localActionAt,
    "the guard must reject a local action with no earlier checkout",
  );
});
