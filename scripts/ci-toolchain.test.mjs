import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repoRoot = fileURLToPath(new URL("../", import.meta.url));
const workflowDir = join(repoRoot, ".github/workflows");

/**
 * The `dtolnay/rust-toolchain` ref that installs the channel this repository
 * pins. Its `action.yml` hardcodes that version, so the ref *is* the version —
 * which is why the SHA has to change whenever the channel does.
 *
 * The test cannot verify the SHA really is that action ref while offline; it can
 * verify that the file, the comment and every workflow agree, which is what
 * drifts in practice.
 */
const PINNED_REF = {
  sha: "ce678459e9fc7500d337468f904b95f1b5c10b5e",
  version: "1.98.1",
};

/**
 * The ref used by steps that pass an explicit `toolchain:` input. Version refs
 * remove that input, so the MSRV job — which asks for 1.88 — has to keep using
 * an input-accepting ref.
 */
const INPUT_ACCEPTING_REF = {
  sha: "29eef336d9b2848a0b548edc03f92a220660cdb8",
  version: "stable",
};

const USES = /uses:\s*dtolnay\/rust-toolchain@([0-9a-f]{40})\s*(?:#\s*(.*))?$/;

function toolchainSteps(contents) {
  const lines = contents.split("\n");
  const steps = [];

  lines.forEach((line, index) => {
    const match = USES.exec(line.trim());
    if (!match) {
      return;
    }

    // An explicit `toolchain:` input in the step's `with:` block is what tells
    // the two ref families apart.
    const lookahead = lines.slice(index + 1, index + 4).join("\n");
    const inputMatch = /^\s+toolchain:\s*"?([^"\n]+?)"?\s*$/m.exec(lookahead);
    steps.push({
      sha: match[1],
      comment: (match[2] ?? "").trim(),
      hasInput: inputMatch !== null,
      inputVersion: inputMatch ? inputMatch[1].trim() : null,
      line: index + 1,
    });
  });

  return steps;
}

test("rust-toolchain.toml pins the channel the workflows install", () => {
  const manifest = readFileSync(join(repoRoot, "rust-toolchain.toml"), "utf8");
  const match = manifest.match(/^channel\s*=\s*"([^"]+)"/m);
  assert.ok(match, "rust-toolchain.toml must declare a channel");
  assert.equal(
    match[1],
    PINNED_REF.version,
    "rust-toolchain.toml and the pinned action ref must name the same version",
  );
});

test("every workflow installs the pinned toolchain, or asks for its own", () => {
  const offenders = workflowNames().flatMap((workflow) =>
    refOffenders(workflow, readFileSync(join(workflowDir, workflow), "utf8")),
  );

  assert.deepEqual(
    offenders,
    [],
    "a step without a `toolchain:` input installs the pinned channel, so it must " +
      "use the pinned ref; a step with one must use a ref that accepts inputs",
  );
});

/**
 * The MSRV job asks for the floor `src-tauri/Cargo.toml` declares. Any other
 * explicit `toolchain:` input is a second source of truth for the channel, and
 * a second source of truth is how the Source Quality job came to run rustfmt
 * from 1.92.0 while every local `cargo fmt` ran the pinned 1.98.1: the ref was
 * right for a step with an input, so nothing objected to the version.
 */
const MSRV_INPUT = "1.88";

/**
 * The workflow filenames the guards scan.
 *
 * Asserted non-empty. The filter here once required a literal backslash
 * (`/\\.ya?ml$/`), which matches no real filename, so the guard below passed
 * while inspecting no workflow at all. An empty list has to fail rather than
 * pass silently, because every assertion built on it is vacuous when it is empty.
 */
function workflowNames() {
  const names = readdirSync(workflowDir).filter((name) =>
    /\.ya?ml$/.test(name),
  );
  assert.ok(
    names.length > 0,
    "expected workflows to scan; an empty list would make this guard vacuous",
  );
  return names;
}

/**
 * The explicit `toolchain:` inputs that are neither the pinned channel nor the
 * MSRV floor, collected by the same rule the workflow-wide guard applies.
 *
 * Shared with the drift tests deliberately. A drift test that only parsed its
 * fixture and asserted `inputVersion !== PINNED_REF.version` keeps passing if the
 * policy itself starts allowing the drifted value — it never consults the policy,
 * so it cannot notice the policy becoming wrong. Routing the fixture through this
 * function makes the test fail for that reason too.
 */
function inputOffenders(workflow, contents) {
  const offenders = [];

  for (const step of toolchainSteps(contents)) {
    if (step.inputVersion === null) {
      continue;
    }
    if (
      step.inputVersion !== PINNED_REF.version &&
      step.inputVersion !== MSRV_INPUT
    ) {
      offenders.push(
        `${workflow}:${step.line} asks for ${step.inputVersion}, expected ${PINNED_REF.version} or the MSRV floor ${MSRV_INPUT}`,
      );
    }
  }

  return offenders;
}

/**
 * The steps whose ref does not match what their shape calls for: a step with a
 * `toolchain:` input must use an input-accepting ref, and a step without one must
 * use the pinned ref, with a comment naming the channel it installs.
 *
 * Shared with the drift tests for the same reason as `inputOffenders`: a test that
 * only parsed its fixture never consulted this rule.
 */
function refOffenders(workflow, contents) {
  const offenders = [];

  for (const step of toolchainSteps(contents)) {
    const expected = step.hasInput ? INPUT_ACCEPTING_REF : PINNED_REF;
    if (step.sha !== expected.sha) {
      offenders.push(
        `${workflow}:${step.line} uses ${step.sha}, expected ${expected.sha} (${expected.version})`,
      );
      continue;
    }
    if (step.comment !== expected.version) {
      offenders.push(
        `${workflow}:${step.line} is commented "${step.comment}", expected "${expected.version}"`,
      );
    }
  }

  return offenders;
}

test("an explicit toolchain input is the pinned channel or the MSRV floor", () => {
  const offenders = workflowNames().flatMap((workflow) =>
    inputOffenders(workflow, readFileSync(join(workflowDir, workflow), "utf8")),
  );

  assert.deepEqual(
    offenders,
    [],
    "a step must install the pinned channel unless it is the MSRV job",
  );
});

test("the guard detects a step pinned to a third channel", () => {
  const drifted = [
    "      - name: Setup Rust",
    `        uses: dtolnay/rust-toolchain@${INPUT_ACCEPTING_REF.sha} # stable`,
    "        with:",
    '          toolchain: "1.92.0"',
  ].join("\n");

  // Routed through the guard's own policy rather than merely parsed. Asserting
  // only `inputVersion !== PINNED_REF.version` would keep passing if the policy
  // started allowing 1.92.0, which is the drift this test exists to catch.
  const offenders = inputOffenders("fixture.yml", drifted);
  assert.equal(
    offenders.length,
    1,
    "the guard must report a version that overrides the pin",
  );
  assert.match(offenders[0], /1\.92\.0/, "the report must name the version");
});

test("the guard detects a step left on the wrong ref", () => {
  const drifted = [
    "      - name: Setup Rust",
    `        uses: dtolnay/rust-toolchain@${INPUT_ACCEPTING_REF.sha} # stable`,
    "",
  ].join("\n");

  // Routed through the guard's own rule rather than only parsed, so the test also
  // fails if the ref policy itself becomes wrong.
  const offenders = refOffenders("fixture.yml", drifted);
  assert.equal(
    offenders.length,
    1,
    `a step with no input must use the pinned ref: ${JSON.stringify(offenders)}`,
  );
});

/**
 * The enumeration has to match real filenames, and it has to fail rather than pass
 * when it matches nothing.
 *
 * The filter here once read `/\\.ya?ml$/`, which requires a **literal backslash**
 * and therefore matched no workflow at all: `workflows` was empty, the loop never
 * ran and `offenders` stayed `[]`. A workflow could have adopted
 * `toolchain: "1.92.0"` — the exact drift the guard exists to catch — and the test
 * would still have passed.
 */
test("the workflow filter matches real filenames, and the old one matched none", () => {
  const files = ["cmtrace-ci.yml", "codesign.yml", "nightly.yaml"];
  assert.deepEqual(
    files.filter((name) => /\.ya?ml$/.test(name)),
    files,
    "plain .yml and .yaml names must match",
  );

  assert.deepEqual(
    ["trailing-backslash.yml\\", "readme.md", "workflow.yml.bak"].filter((name) =>
      /\.ya?ml$/.test(name),
    ),
    [],
    "a trailing backslash is not a special case, and non-workflow names do not match",
  );

  assert.deepEqual(
    files.filter((name) => /\\.ya?ml$/.test(name)),
    [],
    "the filter this guard used to carry matched no real filename, which made every " +
      "assertion built on it vacuous",
  );
});

test("the guard discovers real workflows rather than an empty list", () => {
  const names = workflowNames();

  assert.ok(
    names.includes("cmtrace-ci.yml"),
    `the CI workflow must be discovered, found: ${names.join(", ")}`,
  );
  assert.ok(
    names.length >= 2,
    `expected several workflows, discovered ${names.length}`,
  );
  for (const name of names) {
    assert.match(name, /\.ya?ml$/, `${name} must be a workflow filename`);
  }
});

test("a drifted step planted in a discovered workflow reaches the offender set", () => {
  const name = "cmtrace-ci.yml";
  const planted =
    readFileSync(join(workflowDir, name), "utf8") +
    [
      "",
      "      - name: Drifted",
      `        uses: dtolnay/rust-toolchain@${INPUT_ACCEPTING_REF.sha} # stable`,
      "        with:",
      '          toolchain: "1.92.0"',
      "",
    ].join("\n");

  const offenders = inputOffenders(name, planted);
  assert.equal(
    offenders.length,
    1,
    `the planted step must be reported: ${JSON.stringify(offenders)}`,
  );
  assert.match(offenders[0], /1\.92\.0/, "the report must name the planted version");
});

test("the drift policy accepts the pin and the floor, and rejects anything else", () => {
  const step = (version) =>
    [
      "      - name: Setup Rust",
      `        uses: dtolnay/rust-toolchain@${INPUT_ACCEPTING_REF.sha} # stable`,
      "        with:",
      `          toolchain: "${version}"`,
    ].join("\n");

  assert.deepEqual(
    inputOffenders("fixture.yml", step(PINNED_REF.version)),
    [],
    "the repository pin is accepted",
  );
  assert.deepEqual(
    inputOffenders("fixture.yml", step(MSRV_INPUT)),
    [],
    "the MSRV floor is accepted",
  );
  assert.equal(
    inputOffenders("fixture.yml", step("1.92.0")).length,
    1,
    "a stale explicit version is rejected",
  );
  assert.equal(
    inputOffenders("fixture.yml", step("1.70.0")).length,
    1,
    "an unknown explicit version is rejected",
  );
});

test("the ref guard rejects a comment that names the wrong channel", () => {
  const mislabelled = [
    "      - name: Setup Rust",
    `        uses: dtolnay/rust-toolchain@${PINNED_REF.sha} # stable`,
    "",
  ].join("\n");

  const offenders = refOffenders("fixture.yml", mislabelled);
  assert.equal(
    offenders.length,
    1,
    `the comment must name the channel the ref installs: ${JSON.stringify(offenders)}`,
  );
});
