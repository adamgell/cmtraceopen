import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflow = (name) => readFileSync(new URL(`../.github/workflows/${name}.yml`, import.meta.url), "utf8");

test("Linux CI refreshes the preinstalled FreeType provider before archive inspection", () => {
  const build = workflow("cmtrace-ci").split("\n  build:\n")[1];
  const install = build.split("- name: Install Linux dependencies\n")[1].split("\n      - name:")[0];
  assert.match(install, /sudo apt-get update/);
  const packages = install.split("sudo apt-get install -y")[1];
  assert.match(packages, /\blibfreetype6\b/);
  assert.doesNotMatch(install, /apt-get (?:upgrade|dist-upgrade)|allow-unauthenticated|trusted=yes/);
  assert.ok(build.indexOf("- name: Install Linux dependencies") < build.indexOf("- name: Build Tauri app"));
});

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
    assert.ok(text.includes("squashfs-tools python3-venv python3-apt"), name);
    assert.ok(text.includes("--system-site-packages .appimage-abi-venv"), name);
    assert.ok(text.includes("--require-hashes --only-binary=:all: -r scripts/appimage-abi-requirements.txt"), name);
    assert.ok(text.indexOf("run: node scripts/ci-bundle-outputs.mjs clean") < text.indexOf("uses: tauri-apps/tauri-action@"), name);
    assert.ok(text.includes("provenance/appimage-abi.json"), name);
  }
});

test("CI runs the archive policy and wrapper regressions", () => {
  const text = workflow("cmtrace-ci");
  assert.ok(text.includes("scripts/appimage-workflow.test.mjs"));
  assert.ok(text.includes(".appimage-abi-venv/bin/python -B -m unittest discover -s scripts -p appimage_abi_test.py"));
});

test("release evidence retains the uploaded AppImage and report under their bundle directories", () => {
  const steps = workflow("cmtrace-release").split("\n      - name: ");
  const buildIndex = steps.findIndex((step) => step.startsWith("Build and create release\n"));
  assert.ok(buildIndex >= 0);
  const build = steps[buildIndex];
  const evidence = steps[buildIndex + 1];
  // The pinned action awaits buildProject(), then uploadReleaseAssets(). Keep
  // this upload immediately after it, with no rebuild, signing or copy step.
  assert.match(build, /uses: tauri-apps\/tauri-action@1deb371b0cd8bd54025b384f1cd735e725c4060f /);
  assert.ok(build.includes("TAURI_SIGNING_PRIVATE_KEY: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}"));
  assert.ok(build.includes("args: --target ${{ matrix.target }}"));
  assert.ok(evidence.startsWith("Upload AppImage inspection evidence\n"));
  assert.match(evidence, /if: runner\.os == 'Linux'\n/);
  assert.match(evidence, /uses: actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a /);
  assert.ok(evidence.includes("name: appimage-abi-${{ matrix.label }}"));
  assert.match(evidence, /if-no-files-found: error/);
  assert.doesNotMatch(evidence, /continue-on-error|always\(\)|\n\s+run:/);
  const paths = evidence.match(/          path: \|\n((?:            .+\n)+)/)?.[1]
    .trim().split("\n").map((path) => path.trim());
  const root = "src-tauri/target/${{ matrix.target }}/release/bundle/";
  // upload-artifact@043fb46's multi-path LCA is bundle/, so the downloaded
  // artifact has appimage/<name>.AppImage and provenance/appimage-abi.json.
  assert.deepEqual(paths, [root + "appimage/*.AppImage", root + "provenance/appimage-abi.json"]);
});
