import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import test from "node:test";

const workflowsUrl = new URL("../workflows/", import.meta.url);

// actions/checkout persists GITHUB_TOKEN in .git/config unless the step sets
// `persist-credentials: false`, and every later step that runs repository code
// can read it. Each entry below is a job that still needs the default, or that
// has not been audited yet; remove an entry when its checkout gains the
// setting. Any NEW checkout that is not listed must set it.
const PENDING_AUDIT = new Set([
  // tracked in #906: fixed by PR #900. Left out of this change so the two PRs
  // merge without a conflict; remove this entry once #900 has landed.
  "cmtrace-ci.yml:msrv",
  // tracked in #906 (publish-nightly-release runs git tag and git push)
  "cmtrace-nightly-signed.yml:publish-nightly-release",
  // tracked in #906
  "cmtrace-nightly-signed.yml:metadata",
  // tracked in #906
  "cmtrace-nightly-signed.yml:windows-signed-nightly",
  // tracked in #906
  "cmtrace-nightly-signed.yml:macos-signed-nightly",
  // tracked in #906
  "cmtrace-release.yml:release",
  // tracked in #906 (prepare-windows-release runs git tag and git push)
  "codesign.yml:prepare-windows-release",
  // tracked in #906
  "codesign.yml:windows-signed-release",
  // tracked in #906 (snapshot runs git fetch and git push)
  "download-metrics.yml:snapshot",
]);

// Minimal line scanner so the test needs no YAML dependency. Workflows here use
// two-space job keys under `jobs:` and `- ` step items.
function findCheckouts(name, text) {
  const lines = text.split(/\r?\n/);
  const found = [];
  let inJobs = false;
  let job = null;
  let stepStart = -1;
  const steps = [];
  const flush = (end) => {
    if (stepStart >= 0) {
      steps.push({ job, block: lines.slice(stepStart, end).join("\n") });
    }
    stepStart = -1;
  };
  lines.forEach((line, i) => {
    if (/^jobs:\s*$/.test(line)) {
      inJobs = true;
      return;
    }
    if (!inJobs) return;
    const jobMatch = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line);
    if (jobMatch) {
      flush(i);
      job = jobMatch[1];
      return;
    }
    if (/^\s*- /.test(line) && job) {
      flush(i);
      stepStart = i;
    }
  });
  flush(lines.length);
  for (const step of steps) {
    if (/uses:\s*actions\/checkout@/.test(step.block)) {
      found.push({
        id: `${name}:${step.job}`,
        hardened: /^\s*persist-credentials:\s*false\s*(#.*)?$/m.test(step.block),
      });
    }
  }
  return found;
}

test("every actions/checkout sets persist-credentials: false or is pending audit", async () => {
  const names = (await readdir(workflowsUrl)).filter((n) => /\.ya?ml$/.test(n));
  const all = [];
  for (const name of names) {
    const text = await readFile(new URL(name, workflowsUrl), "utf8");
    all.push(...findCheckouts(name, text));
  }
  assert.ok(all.length > 0, "expected to find actions/checkout steps");

  const offenders = all
    .filter((c) => !c.hardened && !PENDING_AUDIT.has(c.id))
    .map((c) => c.id);
  assert.deepEqual(
    offenders,
    [],
    "checkout without persist-credentials: false (issue #906): " + offenders.join(", "),
  );

  // An entry may become hardened without failing here (so #900 can land on its
  // own), but it must still name a real checkout.
  const stale = [...PENDING_AUDIT].filter((id) => !all.some((c) => c.id === id));
  assert.deepEqual(stale, [], "PENDING_AUDIT names no checkout, remove it: " + stale.join(", "));
});
