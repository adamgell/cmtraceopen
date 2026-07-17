import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import test from "node:test";

const scriptPath = fileURLToPath(
  new URL("./ci-windows-provenance.mjs", import.meta.url),
);
const workflowPath = fileURLToPath(
  new URL("../.github/workflows/cmtrace-ci.yml", import.meta.url),
);
const runbookPath = fileURLToPath(
  new URL("../docs/esp-diagnostics-windows-vm-acceptance.md", import.meta.url),
);

const SOURCE_COMMIT = "a".repeat(40);
const BUILD_COMMIT = "b".repeat(40);
const TARGET = "x86_64-pc-windows-msvc";
const TAURI_BUNDLE_MARKER_PREFIX = "__TAURI_BUNDLE_TYPE_VAR_";
const TAURI_STANDALONE_MARKER = `${TAURI_BUNDLE_MARKER_PREFIX}UNK`;

function stampBundleType(executable, marker) {
  const stamped = Buffer.from(executable);
  const offset = stamped.indexOf(TAURI_STANDALONE_MARKER);
  assert.notEqual(offset, -1, "fixture must contain the standalone marker");
  stamped.write(marker, offset + TAURI_BUNDLE_MARKER_PREFIX.length, "ascii");
  return stamped;
}

function writeFixture(path, contents) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents);
}

function sha256(contents) {
  return createHash("sha256").update(contents).digest("hex");
}

function createWorkspace(t) {
  const root = mkdtempSync(join(tmpdir(), "cmtrace-windows-provenance-"));
  const releaseRoot = join(root, "src-tauri", "target", TARGET, "release");
  const bundleRoot = join(releaseRoot, "bundle");
  mkdirSync(bundleRoot, { recursive: true });
  writeFixture(
    join(root, "package.json"),
    `${JSON.stringify({ version: "1.4.0" }, null, 2)}\n`,
  );
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return { bundleRoot, releaseRoot, root };
}

function run(root, releaseRoot, environment = {}) {
  return spawnSync(process.execPath, [scriptPath], {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env,
      GITHUB_SHA: BUILD_COMMIT,
      SOURCE_COMMIT,
      RELEASE_ROOT: relative(root, releaseRoot),
      TARGET_TRIPLE: TARGET,
      ...environment,
    },
  });
}

test("writes exact-head Windows executable and installer provenance", (t) => {
  const { bundleRoot, releaseRoot, root } = createWorkspace(t);
  const executable = Buffer.from(
    `exact release executable ${TAURI_STANDALONE_MARKER} suffix`,
  );
  const msiExecutable = stampBundleType(executable, "MSI");
  const nsisExecutable = stampBundleType(executable, "NSS");
  const msi = Buffer.from("exact msi package");
  const nsis = Buffer.from("exact nsis package");
  writeFixture(join(releaseRoot, "cmtrace-open.exe"), executable);
  writeFixture(
    join(bundleRoot, "msi", "CMTrace Open_1.4.0_x64_en-US.msi"),
    msi,
  );
  writeFixture(
    join(bundleRoot, "nsis", "CMTrace Open_1.4.0_x64-setup.exe"),
    nsis,
  );

  const result = run(root, releaseRoot);

  assert.equal(result.status, 0, result.stderr);
  const manifestPath = join(
    bundleRoot,
    "provenance",
    "windows-build-provenance.json",
  );
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  assert.deepEqual(manifest, {
    schemaVersion: 2,
    sourceCommit: SOURCE_COMMIT,
    buildCommit: BUILD_COMMIT,
    target: TARGET,
    packageVersion: "1.4.0",
    releaseExecutable: {
      path: "cmtrace-open.exe",
      bytes: executable.length,
      sha256: sha256(executable),
    },
    installers: [
      {
        path: "msi/CMTrace Open_1.4.0_x64_en-US.msi",
        bytes: msi.length,
        sha256: sha256(msi),
        bundleType: "msi",
        expectedInstalledExecutable: {
          path: "cmtrace-open.exe",
          bytes: msiExecutable.length,
          sha256: sha256(msiExecutable),
          derivation: "tauriBundleTypeMarkerV1",
        },
      },
      {
        path: "nsis/CMTrace Open_1.4.0_x64-setup.exe",
        bytes: nsis.length,
        sha256: sha256(nsis),
        bundleType: "nsis",
        expectedInstalledExecutable: {
          path: "cmtrace-open.exe",
          bytes: nsisExecutable.length,
          sha256: sha256(nsisExecutable),
          derivation: "tauriBundleTypeMarkerV1",
        },
      },
    ],
  });
});

test("rejects installer extensions outside their canonical bundle directories", (t) => {
  for (const relativePath of [
    ["msi", "CMTrace Open_1.4.0_x64-setup.exe"],
    ["nsis", "CMTrace Open_1.4.0_x64_en-US.msi"],
    ["CMTrace Open_1.4.0_x64_en-US.msi"],
  ]) {
    const { bundleRoot, releaseRoot, root } = createWorkspace(t);
    writeFixture(
      join(releaseRoot, "cmtrace-open.exe"),
      `release ${TAURI_STANDALONE_MARKER}`,
    );
    writeFixture(join(bundleRoot, ...relativePath), "installer");

    const result = run(root, releaseRoot);

    assert.notEqual(result.status, 0, relativePath.join("/"));
    assert.match(result.stderr, /canonical Windows bundle path/i);
  }
});

test("fails closed unless the standalone executable has exactly one Tauri marker", (t) => {
  for (const [label, executable] of [
    ["missing", Buffer.from("release executable without a marker")],
    [
      "duplicate",
      Buffer.from(`${TAURI_STANDALONE_MARKER}${TAURI_STANDALONE_MARKER}`),
    ],
  ]) {
    const { bundleRoot, releaseRoot, root } = createWorkspace(t);
    writeFixture(join(releaseRoot, "cmtrace-open.exe"), executable);
    writeFixture(
      join(bundleRoot, "msi", "CMTrace Open_1.4.0_x64_en-US.msi"),
      "msi",
    );

    const result = run(root, releaseRoot);

    assert.notEqual(result.status, 0, label);
    assert.match(result.stderr, /exactly one.*Tauri.*marker/i, label);
    assert.equal(
      existsSync(
        join(bundleRoot, "provenance", "windows-build-provenance.json"),
      ),
      false,
      label,
    );
  }
});

test("fails closed when the release executable is missing", (t) => {
  const { bundleRoot, releaseRoot, root } = createWorkspace(t);
  writeFixture(
    join(bundleRoot, "msi", "CMTrace Open_1.4.0_x64_en-US.msi"),
    "msi",
  );

  const result = run(root, releaseRoot);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /release executable/i);
  assert.equal(
    existsSync(join(bundleRoot, "provenance", "windows-build-provenance.json")),
    false,
  );
});

test("rejects a release root outside the target-specific build tree", (t) => {
  const { root } = createWorkspace(t);
  const outside = join(root, "outside", "release");
  mkdirSync(outside, { recursive: true });

  const result = run(root, outside);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /target-specific release directory/i);
});

test("rejects a commit or target that cannot identify the exact build", (t) => {
  const { releaseRoot, root } = createWorkspace(t);

  const badBuildCommit = run(root, releaseRoot, { GITHUB_SHA: "main" });
  assert.notEqual(badBuildCommit.status, 0);
  assert.match(badBuildCommit.stderr, /GITHUB_SHA/);

  const badSourceCommit = run(root, releaseRoot, { SOURCE_COMMIT: "HEAD" });
  assert.notEqual(badSourceCommit.status, 0);
  assert.match(badSourceCommit.stderr, /SOURCE_COMMIT/);

  const badTarget = run(root, releaseRoot, {
    TARGET_TRIPLE: "aarch64-apple-darwin",
  });
  assert.notEqual(badTarget.status, 0);
  assert.match(badTarget.stderr, /Windows target/i);
});

test("workflow records provenance after package verification and uploads it", () => {
  const workflow = readFileSync(workflowPath, "utf8").replace(/\r\n?/g, "\n");
  const verify = workflow.indexOf(
    "- name: Verify current-version bundle outputs",
  );
  const provenance = workflow.indexOf(
    "- name: Record Windows build provenance",
  );
  const upload = workflow.indexOf("- name: Upload artifacts");

  assert.ok(verify >= 0, "bundle verification step must exist");
  assert.ok(provenance > verify, "provenance must follow package verification");
  assert.ok(upload > provenance, "artifact upload must follow provenance");
  assert.match(
    workflow,
    /- name: Record Windows build provenance\n\s+if: runner\.os == 'Windows'[\s\S]*?RELEASE_ROOT: src-tauri\/target\/\$\{\{ matrix\.target \}\}\/release[\s\S]*?TARGET_TRIPLE: \$\{\{ matrix\.target \}\}[\s\S]*?SOURCE_COMMIT: \$\{\{ github\.event\.pull_request\.head\.sha \|\| github\.sha \}\}[\s\S]*?run: node scripts\/ci-windows-provenance\.mjs/,
  );
  assert.match(
    workflow,
    /src-tauri\/target\/\$\{\{ matrix\.target \}\}\/release\/bundle\/provenance\/windows-build-provenance\.json/,
  );
});

test("Windows acceptance selects one schema-v2 installer by hash", () => {
  const runbook = readFileSync(runbookPath, "utf8").replace(/\r\n?/g, "\n");

  assert.match(runbook, /\$Provenance\.schemaVersion -ne 2/);
  assert.match(
    runbook,
    /\$_\.sha256 -eq \$ActualInstallerSha256\.ToLowerInvariant\(\)/,
  );
  assert.match(runbook, /\$InstallerMatches\.Count -ne 1/);
  assert.match(runbook, /Unsupported installer extension/);
  assert.match(
    runbook,
    /\$SelectedInstaller\.expectedInstalledExecutable\.sha256/,
  );
  assert.match(
    runbook,
    /\$SelectedInstaller\.expectedInstalledExecutable\.bytes/,
  );
  assert.match(runbook, /tauriBundleTypeMarkerV1/);
  assert.match(
    runbook,
    /must not be used as their expected installed-file hash/,
  );
});
