import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import test from "node:test";

const workflowsUrl = new URL("../workflows/", import.meta.url);
const actionsUrl = new URL("../actions/", import.meta.url);

// actions/checkout persists GITHUB_TOKEN in .git/config unless the step sets
// `persist-credentials: false` under its own `with:`, and every later step that
// runs repository code can read it.
//
// Ids are `<workflow file>:<job>:<ordinal of the checkout within the job,
// starting at 1>`. The list is EXACT: the test fails when an entry names a
// checkout that does not exist and when a listed checkout is already hardened
// (remove the entry then). Any checkout that is not listed must be hardened.
//
// Merge order with PR #900: #900 hardens the msrv checkout, #913 lists it.
// Merge #900 first; then update #913 from main (a merge commit, no force push)
// and remove the `cmtrace-ci.yml:msrv:1` entry before #913 merges. CI does not
// re-run when main moves and the ruleset does not require up-to-date branches,
// so merging in the wrong order would turn main red. If #913 were merged first,
// #900 would have to be updated from main and drop the entry before merging.
const PENDING_AUDIT = new Set([
  // tracked in #906: fixed by PR #900 (see the merge-order note above)
  "cmtrace-ci.yml:msrv:1",
  // tracked in #906 (runs git tag and git push, so it needs the credential)
  "cmtrace-nightly-signed.yml:publish-nightly-release:1",
  // tracked in #906
  "cmtrace-nightly-signed.yml:metadata:1",
  // tracked in #906
  "cmtrace-nightly-signed.yml:windows-signed-nightly:1",
  // tracked in #906
  "cmtrace-nightly-signed.yml:macos-signed-nightly:1",
  // tracked in #906
  "cmtrace-release.yml:release:1",
  // tracked in #906 (runs git tag and git push, so it needs the credential)
  "codesign.yml:prepare-windows-release:1",
  // tracked in #906
  "codesign.yml:windows-signed-release:1",
  // tracked in #906 (runs git fetch and git push, so it needs the credential)
  "download-metrics.yml:snapshot:1",
]);

const stripComment = (line) => line.replace(/(^|\s)#.*$/, "").trimEnd();
const indentOf = (line) => line.length - line.trimStart().length;
const unquote = (s) => s.replace(/^(["'])(.*)\1$/, "$2");

// Minimal indentation scanner so the test needs no YAML dependency. It returns
// the checkouts found, the job names seen and the number of code lines that
// mention actions/checkout@ (the fail-closed cross-check).
export function scan(label, text) {
  const raw = text.split(/\r?\n/);
  const lines = raw.map(stripComment);
  const checkouts = [];
  const aliases = [];
  const jobs = new Set();
  const mentions = lines.filter((l) => /actions\/checkout@/i.test(l)).length;
  const hasJobs = lines.some((l) => /^jobs:\s*$/.test(l));
  const isComposite = !hasJobs;
  let inJobs = isComposite;
  let job = isComposite ? "action" : null;
  const ordinals = new Map();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    if (/^jobs:\s*$/.test(line)) {
      inJobs = true;
      continue;
    }
    if (!inJobs) continue;
    if (!isComposite && indentOf(line) === 0) {
      inJobs = false;
      continue;
    }
    if (!isComposite) {
      const header = /^ {2}(\S.*?)\s*:\s*$/.exec(line);
      if (header && indentOf(line) === 2) {
        job = unquote(header[1]);
        jobs.add(job);
        continue;
      }
    }
    const stepsKey = /^(\s*)steps:\s*$/.exec(line);
    if (!stepsKey || job === null) continue;
    if (isComposite) jobs.add(job);
    const keyIndent = stepsKey[1].length;

    // Walk the step items of this steps: list.
    let j = i + 1;
    let stepIndent = -1;
    while (j < lines.length) {
      const l = lines[j];
      if (!l.trim()) {
        j++;
        continue;
      }
      const ind = indentOf(l);
      const isDash = /^\s*-(\s|$)/.test(l);
      if (stepIndent < 0) {
        if (!isDash || ind < keyIndent) break;
        stepIndent = ind;
      }
      if (ind < stepIndent || (ind === stepIndent && !isDash)) break;
      if (!(isDash && ind === stepIndent)) {
        j++;
        continue;
      }
      // One step: this dash line up to the next code line at indent <= ind.
      let end = j + 1;
      while (end < lines.length && (!lines[end].trim() || indentOf(lines[end]) > ind)) end++;
      const block = lines.slice(j, end);
      // Re-indent so the dash line reads as a direct key line.
      // A YAML alias step expands to something the scanner cannot see.
      if (/^\s*-\s*\*/.test(block[0])) {
        aliases.push(`${label}:${job}:alias@line${j + 1}`);
        j = end;
        continue;
      }
      const first = block[0];
      const after = first.slice(ind + 1);
      let k;
      if (after.trim()) {
        k = ind + 1 + (after.length - after.trimStart().length);
        block[0] = " ".repeat(k) + after.trimStart();
      } else {
        const next = block.slice(1).find((b) => b.trim());
        k = next ? indentOf(next) : ind + 2;
        block[0] = "";
      }
      const direct = (re) => block.findIndex((b) => indentOf(b) === k && re.test(b));
      const usesAt = direct(/^\s*uses:\s*["']?actions\/checkout@/i);
      if (usesAt >= 0) {
        let hardened = false;
        const withAt = direct(/^\s*with:\s*$/);
        if (withAt >= 0) {
          let childIndent = -1;
          for (let m = withAt + 1; m < block.length; m++) {
            const b = block[m];
            if (!b.trim()) continue;
            const bi = indentOf(b);
            if (bi <= k) break;
            if (childIndent < 0) childIndent = bi;
            if (bi === childIndent && /^\s*persist-credentials:\s*false\s*$/.test(b)) hardened = true;
          }
        }
        const n = (ordinals.get(job) ?? 0) + 1;
        ordinals.set(job, n);
        checkouts.push({ id: `${label}:${job}:${n}`, hardened });
      }
      j = end;
    }
    i = j - 1;
  }
  return { checkouts, aliases, jobs, mentions, hasJobs };
}

export function findCheckouts(label, text) {
  return scan(label, text).checkouts;
}

export function evaluate(checkouts, pending) {
  const ids = new Set(checkouts.map((c) => c.id));
  return {
    offenders: checkouts.filter((c) => !c.hardened && !pending.has(c.id)).map((c) => c.id),
    missing: [...pending].filter((id) => !ids.has(id)),
    staleHardened: checkouts.filter((c) => c.hardened && pending.has(c.id)).map((c) => c.id),
  };
}

async function readAll() {
  const sources = [];
  for (const name of (await readdir(workflowsUrl)).filter((n) => /\.ya?ml$/.test(n))) {
    sources.push([name, await readFile(new URL(name, workflowsUrl), "utf8")]);
  }
  for (const dir of await readdir(actionsUrl, { withFileTypes: true }).catch(() => [])) {
    if (!dir.isDirectory()) continue;
    for (const file of ["action.yml", "action.yaml"]) {
      const text = await readFile(new URL(`${dir.name}/${file}`, actionsUrl), "utf8").catch(() => null);
      if (text !== null) sources.push([`actions/${dir.name}/${file}`, text]);
    }
  }
  return sources;
}

test("every actions/checkout sets persist-credentials: false or is pending audit", async () => {
  const all = [];
  for (const [label, text] of await readAll()) {
    const result = scan(label, text);
    assert.equal(
      result.checkouts.length,
      result.mentions,
      `${label}: scanner found ${result.checkouts.length} checkouts but ${result.mentions} lines mention actions/checkout@`,
    );
    if (result.hasJobs) assert.ok(result.jobs.size > 0, `${label}: jobs: present but no job parsed`);
    assert.deepEqual(result.aliases, [], `${label}: alias steps cannot be scanned for checkouts`);
    all.push(...result.checkouts);
  }
  assert.ok(all.length > 0, "expected to find actions/checkout steps");

  const { offenders, missing, staleHardened } = evaluate(all, PENDING_AUDIT);
  assert.deepEqual(offenders, [], "checkout without persist-credentials: false (issue #906): " + offenders.join(", "));
  assert.deepEqual(missing, [], "PENDING_AUDIT names no checkout, remove it: " + missing.join(", "));
  assert.deepEqual(staleHardened, [], "PENDING_AUDIT entry is already hardened, remove it: " + staleHardened.join(", "));
});

const wf = (step) => `name: x
jobs: # jobs
  build:
    runs-on: ubuntu-latest
    steps:
${step}
`;

test("fixture: unhardened checkout is an offender", () => {
  const c = findCheckouts("a.yml", wf("      - uses: actions/checkout@abc # v1"));
  assert.deepEqual(c, [{ id: "a.yml:build:1", hardened: false }]);
  assert.deepEqual(evaluate(c, new Set()).offenders, ["a.yml:build:1"]);
});

test("fixture: hardened checkout passes", () => {
  const c = findCheckouts("a.yml", wf("      - uses: actions/checkout@abc\n        with:\n          fetch-depth: 0\n          persist-credentials: false # ok"));
  assert.equal(c[0].hardened, true);
  assert.deepEqual(evaluate(c, new Set()), { offenders: [], missing: [], staleHardened: [] });
});

test("fixture: key under env: does not count", () => {
  const c = findCheckouts("a.yml", wf("      - uses: actions/checkout@abc\n        env:\n          persist-credentials: false"));
  assert.equal(c[0].hardened, false);
});

test("fixture: key nested deeper than with: children does not count", () => {
  const c = findCheckouts("a.yml", wf("      - uses: actions/checkout@abc\n        with:\n          x:\n            persist-credentials: false"));
  assert.equal(c[0].hardened, false);
});

test("fixture: key in a later step or job mapping does not count", () => {
  const text = `jobs:
  build:
    steps:
      - uses: actions/checkout@abc
    env:
      persist-credentials: false
`;
  assert.equal(findCheckouts("a.yml", text)[0].hardened, false);
});

test("fixture: commented-out, quoted, true and expression values fail closed", () => {
  for (const v of ["# persist-credentials: false", "persist-credentials: 'false'", "persist-credentials: true", "persist-credentials: ${{ false }}", "persist-credentials: False"]) {
    const c = findCheckouts("a.yml", wf(`      - uses: actions/checkout@abc\n        with:\n          ${v}`));
    assert.equal(c[0].hardened, false, v);
  }
});

test("fixture: second checkout in an allowlisted job has its own id and fails", () => {
  const c = findCheckouts("a.yml", wf("      - uses: actions/checkout@abc\n      - run: echo hi\n      - uses: actions/checkout@abc"));
  assert.deepEqual(c.map((x) => x.id), ["a.yml:build:1", "a.yml:build:2"]);
  assert.deepEqual(evaluate(c, new Set(["a.yml:build:1"])).offenders, ["a.yml:build:2"]);
});

test("fixture: hardened allowlisted checkout is stale, absent entry is missing", () => {
  const c = findCheckouts("a.yml", wf("      - uses: actions/checkout@abc\n        with:\n          persist-credentials: false"));
  const r = evaluate(c, new Set(["a.yml:build:1", "a.yml:gone:1"]));
  assert.deepEqual(r.staleHardened, ["a.yml:build:1"]);
  assert.deepEqual(r.missing, ["a.yml:gone:1"]);
});

test("fixture: quoted uses and lone dash steps are detected", () => {
  assert.equal(findCheckouts("a.yml", wf(`      - uses: "actions/checkout@abc"`)).length, 1);
  assert.equal(findCheckouts("a.yml", wf(`      - uses: 'actions/checkout@abc'`)).length, 1);
  const lone = findCheckouts("a.yml", wf("      -\n        uses: actions/checkout@abc\n        with:\n          persist-credentials: false"));
  assert.deepEqual(lone, [{ id: "a.yml:build:1", hardened: true }]);
});

test("fixture: quoted job keys and commented headers are handled", () => {
  const text = `jobs:
  "q-job": # c
    steps:
      - uses: actions/checkout@abc
  other: # c
    steps:
      - name: n
        uses: actions/checkout@abc
`;
  assert.deepEqual(findCheckouts("a.yml", text).map((x) => x.id), ["a.yml:q-job:1", "a.yml:other:1"]);
});

test("fixture: composite action steps are scanned", () => {
  const text = `name: c
runs:
  using: composite
  steps:
    - uses: actions/checkout@abc
`;
  assert.deepEqual(findCheckouts("actions/c/action.yml", text), [{ id: "actions/c/action.yml:action:1", hardened: false }]);
});

test("fixture: a flow-style checkout the scanner cannot parse trips the cross-check", () => {
  const r = scan("a.yml", wf("      - {uses: actions/checkout@abc}"));
  assert.notEqual(r.checkouts.length, r.mentions);
});

test("fixture: Actions/Checkout with no with: is an offender (case-insensitive)", () => {
  const r = scan("a.yml", wf("      - uses: Actions/Checkout@abc"));
  assert.equal(r.mentions, 1);
  assert.deepEqual(r.checkouts, [{ id: "a.yml:build:1", hardened: false }]);
  assert.deepEqual(evaluate(r.checkouts, new Set()).offenders, ["a.yml:build:1"]);
});

test("fixture: an alias step is reported", () => {
  const r = scan("a.yml", wf("      - *shared"));
  assert.equal(r.aliases.length, 1);
});

test("fixture: sibling env: after with: does not leak into with:", () => {
  const c = findCheckouts(
    "a.yml",
    wf("      - uses: actions/checkout@abc\n        with:\n          fetch-depth: 0\n        env:\n          persist-credentials: false"),
  );
  assert.equal(c[0].hardened, false);
});
