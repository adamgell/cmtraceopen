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
    steps.push({
      sha: match[1],
      comment: (match[2] ?? "").trim(),
      hasInput: /^\s+toolchain:/m.test(lookahead),
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
  const workflows = readdirSync(workflowDir).filter((name) =>
    /\.ya?ml$/.test(name),
  );
  assert.ok(workflows.length > 0, "expected workflows to scan");

  const offenders = [];

  for (const workflow of workflows) {
    const steps = toolchainSteps(
      readFileSync(join(workflowDir, workflow), "utf8"),
    );

    for (const step of steps) {
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
  }

  assert.deepEqual(
    offenders,
    [],
    "a step without a `toolchain:` input installs the pinned channel, so it must " +
      "use the pinned ref; a step with one must use a ref that accepts inputs",
  );
});

test("the guard detects a step left on the wrong ref", () => {
  const drifted = [
    "      - name: Setup Rust",
    `        uses: dtolnay/rust-toolchain@${INPUT_ACCEPTING_REF.sha} # stable`,
    "",
  ].join("\n");

  const [step] = toolchainSteps(drifted);
  assert.equal(step.hasInput, false, "fixture must have no toolchain input");
  assert.notEqual(
    step.sha,
    PINNED_REF.sha,
    "the guard must reject a step that would float with stable",
  );
});
