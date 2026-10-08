import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const workflow = () => read(".github/workflows/cmtrace-appimage-runtime.yml");

test("runtime allocation is manual, reviewed-ref-only, first attempt, Ubuntu 22.04 recovery with platform timeout", () => {
  const text = workflow();
  assert.match(text, /on:\n  workflow_dispatch:/);
  assert.doesNotMatch(text, /\n  (push|pull_request|pull_request_target|schedule|workflow_run):/);
  assert.match(text, /github.ref == 'refs\/heads\/codex\/pr821-ubuntu-runtime'/);
  assert.ok(text.includes('[[ "$GITHUB_SHA" == "$REVIEWED_HARNESS_SHA" ]]'));
  assert.match(text, /GITHUB_RUN_ATTEMPT.*== 1/);
  assert.doesNotMatch(text, /timeout-minutes:/);
  assert.match(text, /max-parallel: 2/);
  assert.match(text, /os: \[ubuntu-22\.04\]/);
  assert.match(text, /cancel-in-progress: false/);
  assert.doesNotMatch(text, /continue-on-error|retry|workflow_call/);
});

test("runtime uses only immutable actions and the fixed artifact with read permissions", () => {
  const text = workflow();
  assert.match(text, /permissions:\n  contents: read\n  actions: read/);
  assert.doesNotMatch(text, /: write/);
  assert.match(text, /artifact-ids: '11569479897'/);
  assert.match(text, /run-id: '37817985168'/);
  assert.doesNotMatch(text, /11311507149|37222916777|11320025934|37247506529/);
  assert.match(text, /repository: adamgell\/cmtraceopen/);
  assert.match(text, /persist-credentials: false/);
  const uses = [...text.matchAll(/uses: ([^\n]+)/g)];
  assert.equal(uses.length, 3);
  for (const [, use] of uses) assert.match(use, /^actions\/(checkout|download-artifact|upload-artifact)@[a-f0-9]{40} /);
  assert.match(text, /git diff --exit-code "\$REVIEWED_HARNESS_SHA" HEAD --/);
  assert.match(text, /scripts\/appimage_runtime/);
});

test("runtime uploads an explicit sanitized allowlist with seven-day retention", () => {
  const text = workflow();
  const upload = text.slice(text.indexOf("      - name: Upload sanitized evidence"));
  assert.match(upload, /retention-days: 7/);
  assert.match(upload, /if: always\(\)/);
  assert.doesNotMatch(upload, /\*|\.log|\.AppImage|provenance/);
  for (const path of ["summary.json", "ordinary-initial.png", "ordinary-final.png", "catalog-renderer-subset-initial.png", "catalog-renderer-subset-final.png"]) assert.ok(upload.includes(path), path);
  assert.match(text, /sudo env -i PATH=\/usr\/bin:\/bin:\/usr\/sbin:\/sbin/);
  assert.match(text, /\/usr\/bin\/python3 -m appimage_runtime.host/);
});

test("ordinary PR checks exercise only harmless harness contracts", () => {
  const ci = read(".github/workflows/cmtrace-ci.yml");
  assert.ok(ci.includes("scripts/appimage-runtime-workflow.test.mjs"));
  assert.ok(ci.includes("/usr/bin/python3 scripts/appimage_runtime_test.py"));
  assert.ok(ci.includes("scripts/event-log-export-workflow.test.mjs"));
  assert.ok(ci.includes("scripts/ci-qa-citations.test.mjs"));
  assert.doesNotMatch(ci, /appimage_runtime\.host|cmtrace-appimage-runtime.yml/);
});
