import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflow = (name) => readFileSync(new URL(`../.github/workflows/${name}.yml`, import.meta.url), "utf8");

test("only application package producers select the Ubuntu 22.04 baseline", () => {
  for (const name of ["cmtrace-ci", "cmtrace-release"]) {
    assert.match(workflow(name), /- os: ubuntu-22\.04\n\s+target: x86_64-unknown-linux-gnu/);
  }
  assert.match(workflow("cmtrace-ci"), /check:\n\s+name: Check & Test \(Rust\)\n\s+runs-on: ubuntu-latest/);
});

test("compiled application caches cannot restore a different Ubuntu baseline", () => {
  const build = workflow("cmtrace-ci").split("\n  build:\n")[1];
  for (const line of build.split("\n").filter((line) => /(?:key|restore-keys):/.test(line) && /cargo/.test(line))) {
    assert.match(line, /\$\{\{ matrix\.os \}\}-\$\{\{ matrix\.target \}\}-cargo-appimage-v1-/);
  }
});

test("both producers require the archive guard inside the pinned action build command", () => {
  for (const name of ["cmtrace-ci", "cmtrace-release"]) {
    const text = workflow(name);
    const action = text.split("uses: tauri-apps/tauri-action@")[1].split("\n      - name:")[0];
    assert.ok(action.includes("CMTRACE_APPIMAGE_VERIFY_ROOT: ${{ runner.os == 'Linux' && 'src-tauri/target/x86_64-unknown-linux-gnu/release/bundle' || '' }}"), name);
    if (name === "cmtrace-ci") assert.ok(action.includes("SOURCE_COMMIT: ${{ github.event.pull_request.head.sha || github.sha }}"), name);
    // A release dispatch checks out the tag; github.sha is the workflow ref.
    // Its source identity must come from the checked-out commit.
    else assert.ok(!action.includes("SOURCE_COMMIT:"), name);
    assert.ok(text.includes("squashfs-tools pax-utils python3-pyelftools python3-apt"), name);
    assert.ok(text.indexOf("run: node scripts/ci-bundle-outputs.mjs clean") < text.indexOf("uses: tauri-apps/tauri-action@"), name);
    assert.ok(text.includes("provenance/appimage-abi.json"), name);
  }
});

test("CI runs the archive policy and wrapper regressions", () => {
  const text = workflow("cmtrace-ci");
  assert.ok(text.includes("scripts/appimage-workflow.test.mjs"));
  assert.ok(text.includes("/usr/bin/python3 -B -m unittest discover -s scripts -p appimage_abi_test.py"));
});
