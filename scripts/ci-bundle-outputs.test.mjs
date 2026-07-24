import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import test from "node:test";

const scriptPath = fileURLToPath(
  new URL("./ci-bundle-outputs.mjs", import.meta.url),
);
const workflowPath = fileURLToPath(
  new URL("../.github/workflows/cmtrace-ci.yml", import.meta.url),
);

function createBundleWorkspace(t) {
  const root = mkdtempSync(join(tmpdir(), "cmtrace-ci-bundle-"));
  const releaseRoot = join(
    root,
    "src-tauri",
    "target",
    "test-target",
    "release",
  );
  const bundleRoot = join(releaseRoot, "bundle");
  mkdirSync(bundleRoot, { recursive: true });
  writeFileSync(
    join(root, "package.json"),
    `${JSON.stringify({ version: "1.4.0" }, null, 2)}\n`,
  );
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return { bundleRoot, releaseRoot, root };
}

function writeFixture(path, contents = "fixture") {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents);
}

function runWithBundleRootInput(
  mode,
  bundleRootInput,
  workspaceRoot,
  environment = {},
) {
  return spawnSync(process.execPath, [scriptPath, mode], {
    cwd: workspaceRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      ...environment,
      BUNDLE_ROOT: bundleRootInput,
    },
  });
}

function run(mode, bundleRoot, workspaceRoot, environment = {}) {
  return runWithBundleRootInput(
    mode,
    relative(workspaceRoot, bundleRoot),
    workspaceRoot,
    environment,
  );
}

test("clean removes cached bundles without deleting release siblings", (t) => {
  const { bundleRoot, releaseRoot, root } = createBundleWorkspace(t);
  writeFixture(join(bundleRoot, "msi", "CMTrace Open_1.3.2_x64.msi"));
  const sibling = join(releaseRoot, "cmtrace-open.exe");
  writeFixture(sibling, "keep");

  const result = run("clean", bundleRoot, root);

  assert.equal(result.status, 0, result.stderr);
  assert.equal(existsSync(bundleRoot), false);
  assert.equal(readFileSync(sibling, "utf8"), "keep");
});

test("verify accepts only packages for the expected version", (t) => {
  const { bundleRoot, root } = createBundleWorkspace(t);
  writeFixture(join(bundleRoot, "msi", "CMTrace Open_1.4.0_x64_en-US.msi"));
  writeFixture(join(bundleRoot, "nsis", "CMTrace Open_1.4.0_x64-setup.exe"));

  const result = run("verify", bundleRoot, root);

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Verified 2 current-version bundle packages/);
});

test("verify rejects stale versioned packages beside the current build", (t) => {
  const { bundleRoot, root } = createBundleWorkspace(t);
  writeFixture(join(bundleRoot, "msi", "CMTrace Open_1.4.0_x64_en-US.msi"));
  writeFixture(join(bundleRoot, "msi", "CMTrace Open_1.3.2_x64_en-US.msi"));

  const result = run("verify", bundleRoot, root);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Unexpected bundle versions/);
  assert.match(result.stderr, /CMTrace Open_1\.3\.2_x64_en-US\.msi/);
});

test("verify rejects a prerelease that only prefixes the expected version", (t) => {
  const { bundleRoot, root } = createBundleWorkspace(t);
  writeFixture(
    join(bundleRoot, "msi", "CMTrace Open_1.4.0-beta.1_x64_en-US.msi"),
  );

  const result = run("verify", bundleRoot, root);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Unexpected bundle versions/);
  assert.match(result.stderr, /1\.4\.0-beta\.1/);
});

test("verify rejects a stale version even when the current token appears later", (t) => {
  const { bundleRoot, root } = createBundleWorkspace(t);
  writeFixture(
    join(bundleRoot, "msi", "CMTrace Open_1.3.2_1.4.0_x64_en-US.msi"),
  );

  const result = run("verify", bundleRoot, root);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Unexpected bundle versions/);
  assert.match(result.stderr, /1\.3\.2_1\.4\.0/);
});

test("verify rejects an empty bundle directory", (t) => {
  const { bundleRoot, root } = createBundleWorkspace(t);

  const result = run("verify", bundleRoot, root);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /No bundle packages found/);
});

test("clean refuses a path outside a target release bundle", (t) => {
  const root = mkdtempSync(join(tmpdir(), "cmtrace-ci-bundle-unsafe-"));
  const unsafeRoot = join(root, "elsewhere");
  mkdirSync(unsafeRoot);
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const result = run("clean", unsafeRoot, root);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /target-specific release bundle directory/);
  assert.equal(existsSync(unsafeRoot), true);
});

test("clean refuses a Windows drive-qualified relative path", (t) => {
  const root = mkdtempSync(join(tmpdir(), "cmtrace-ci-bundle-drive-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const result = runWithBundleRootInput("clean", "D:release\\bundle", root);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /drive-qualified/i);
});

test("clean refuses an intermediate symbolic link outside the target tree", (t) => {
  const root = mkdtempSync(join(tmpdir(), "cmtrace-ci-bundle-link-"));
  const externalRoot = mkdtempSync(join(tmpdir(), "cmtrace-ci-external-"));
  const targetRoot = join(root, "src-tauri", "target");
  const linkedTarget = join(targetRoot, "test-target");
  const externalBundle = join(externalRoot, "release", "bundle");
  const sentinel = join(externalBundle, "keep.txt");
  mkdirSync(targetRoot, { recursive: true });
  writeFixture(sentinel, "keep");
  symlinkSync(
    externalRoot,
    linkedTarget,
    process.platform === "win32" ? "junction" : "dir",
  );
  t.after(() => {
    rmSync(root, { recursive: true, force: true });
    rmSync(externalRoot, { recursive: true, force: true });
  });

  const result = run("clean", join(linkedTarget, "release", "bundle"), root);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /symbolic link/i);
  assert.equal(readFileSync(sentinel, "utf8"), "keep");
});

test("verify cannot override the repository package version", (t) => {
  const { bundleRoot, root } = createBundleWorkspace(t);
  writeFixture(join(bundleRoot, "msi", "CMTrace Open_1.3.2_x64_en-US.msi"));

  const result = run("verify", bundleRoot, root, {
    EXPECTED_VERSION: "1.3.2",
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Unexpected bundle versions for 1\.4\.0/);
});

function assertWorkflowContract(workflowText) {
  const workflow = workflowText.replace(/\r\n?/g, "\n");
  const buildJobStart = workflow.indexOf("\n  build:\n");
  assert.notEqual(buildJobStart, -1, "build job must exist");

  const buildJob = workflow.slice(buildJobStart);
  const orderedSteps = [
    "- name: Cache Rust dependencies",
    "- name: Remove cached bundle outputs",
    "- name: Build Tauri app",
    "- name: Verify current-version bundle outputs",
    "- name: Upload artifacts",
  ];
  let previousIndex = -1;
  for (const step of orderedSteps) {
    const index = buildJob.indexOf(step);
    assert.notEqual(index, -1, `${step} must exist in the build job`);
    assert.ok(index > previousIndex, `${step} must follow the previous step`);
    previousIndex = index;
  }

  assert.match(
    workflow,
    /- name: CI bundle output contract tests\n\s+run: node --test scripts\/ci-bundle-outputs\.test\.mjs scripts\/ci-windows-provenance\.test\.mjs/,
  );
  assert.match(
    buildJob,
    /- name: Remove cached bundle outputs[\s\S]*?BUNDLE_ROOT: src-tauri\/target\/\$\{\{ matrix\.target \}\}\/release\/bundle[\s\S]*?run: node scripts\/ci-bundle-outputs\.mjs clean/,
  );
  assert.match(
    buildJob,
    /- name: Verify current-version bundle outputs[\s\S]*?BUNDLE_ROOT: src-tauri\/target\/\$\{\{ matrix\.target \}\}\/release\/bundle[\s\S]*?run: node scripts\/ci-bundle-outputs\.mjs verify/,
  );
}

function assertMsrvWorkflowContract(workflowText) {
  const workflow = workflowText.replace(/\r\n?/g, "\n");
  const jobStart = workflow.indexOf("\n  msrv:\n");
  assert.notEqual(jobStart, -1, "MSRV job must exist");

  const nextJobStart = workflow.indexOf("\n  frontend:\n", jobStart);
  assert.notEqual(nextJobStart, -1, "frontend job must follow the MSRV job");
  const msrvJob = workflow.slice(jobStart, nextJobStart);
  assert.match(
    msrvJob,
    /strategy:\n\s+matrix:\n\s+os: \[ubuntu-latest, windows-latest\]/,
  );
  assert.match(msrvJob, /runs-on: \$\{\{ matrix\.os \}\}/);
  assert.match(
    msrvJob,
    /- name: Install system dependencies\n\s+if: runner\.os == 'Linux'/,
  );
  const orderedSteps = [
    "- name: Install system dependencies",
    "- name: Setup Rust 1.77.2",
    "- name: Cache Rust dependencies",
    "- name: Rust MSRV check",
  ];
  let previousIndex = -1;
  for (const step of orderedSteps) {
    const index = msrvJob.indexOf(step);
    assert.notEqual(index, -1, `${step} must exist in the MSRV job`);
    assert.ok(index > previousIndex, `${step} must follow the previous step`);
    previousIndex = index;
  }

  assert.match(
    msrvJob,
    /- name: Setup Rust 1\.77\.2[\s\S]*?uses: dtolnay\/rust-toolchain@[0-9a-f]{40}[\s\S]*?toolchain: "1\.77\.2"/,
  );
  assert.match(
    msrvJob,
    /- name: Cache Rust dependencies[\s\S]*?src-tauri\/target\/[\s\S]*?key: \$\{\{ runner\.os \}\}-cargo-msrv-1\.77\.2-\$\{\{ hashFiles\('Cargo\.lock'\) \}\}/,
  );
  assert.match(
    msrvJob,
    /- name: Rust MSRV check\n\s+run: cargo \+1\.77\.2 check --workspace --all-features --locked/,
  );
}

test("CI cleans and verifies bundle outputs around every package build", () => {
  assertWorkflowContract(readFileSync(workflowPath, "utf8"));
});

test("CI bundle workflow contract accepts CRLF line endings", () => {
  const workflow = readFileSync(workflowPath, "utf8").replaceAll("\n", "\r\n");

  assert.doesNotThrow(() => assertWorkflowContract(workflow));
});

test("CI enforces the declared Rust 1.77.2 MSRV", () => {
  assertMsrvWorkflowContract(readFileSync(workflowPath, "utf8"));
});

test("CI MSRV workflow contract accepts CRLF line endings", () => {
  const workflow = readFileSync(workflowPath, "utf8").replaceAll("\n", "\r\n");

  assert.doesNotThrow(() => assertMsrvWorkflowContract(workflow));
});
