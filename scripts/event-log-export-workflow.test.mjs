import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const ci = read(".github/workflows/cmtrace-ci.yml");
const release = read(".github/workflows/cmtrace-release.yml");

// Match the repository's two-space job / six-space step indentation. Fail if a
// required block disappears; actionlint separately validates the complete YAML.
function job(workflow, name) {
  const block = workflow.match(new RegExp(`^  ${name}:\\n(.*?)(?=^  [\\w-]+:|$(?![\\s\\S]))`, "ms"));
  assert.ok(block, `missing job ${name}`);
  return block[1];
}

function steps(block) {
  return block.split(/^      - /m).slice(1);
}

const publisher = job(release, "publish-event-log-export");

function assertLinuxPrerequisites(block) {
  const ordered = steps(block);
  const build = ordered.findIndex((step) => /run: cargo build\b/.test(step));
  const install = ordered.findIndex((step) => /sudo apt-get install/.test(step));
  assert.ok(install >= 0 && install < build, "install Linux dependencies before Cargo build");
  assert.match(ordered[install], /if: runner\.os == 'Linux'/);
  assert.match(ordered[install], /sudo apt-get update/);
  for (const dependency of ["libwebkit2gtk-4.1-dev", "libgtk-3-dev", "libayatana-appindicator3-dev", "librsvg2-dev", "patchelf"]) {
    assert.ok(ordered[install].includes(dependency), `missing Linux dependency ${dependency}`);
  }
}

test("exporter publisher installs Linux prerequisites before building", () => {
  assertLinuxPrerequisites(publisher);
});

test("the Linux guard rejects absent, incomplete, or late installation", () => {
  assert.throws(() => assertLinuxPrerequisites(publisher.replace(/libgtk-3-dev/g, "removed-package")));
  const ordered = steps(publisher);
  const install = ordered.find((step) => /sudo apt-get install/.test(step));
  assert.ok(install, "publisher must have an install step to mutate");
  const without = ordered.filter((step) => step !== install);
  assert.throws(() => assertLinuxPrerequisites(without.map((step) => `      - ${step}`).join("")));
  assert.throws(() => assertLinuxPrerequisites([...without, install].map((step) => `      - ${step}`).join("")));
});

test("CI, release and README select only event-log with the lockfile", () => {
  const smoke = steps(job(ci, "check")).find((step) => step.startsWith("name: Build and smoke the headless event-log exporter"));
  assert.ok(smoke, "missing exporter smoke step");
  for (const block of [smoke, publisher, read("README.md")]) {
    const commands = block.split("\n").filter((line) => /cargo (build|run).*--bin event-log-export/.test(line));
    assert.ok(commands.length > 0, "expected exporter commands");
    for (const command of commands) {
      assert.match(command, /--locked\b/);
      assert.match(command, /--no-default-features\b/);
      assert.match(command, /--features event-log\b/);
    }
  }
  assert.match(smoke, /cargo run.*-- --help/);
  assert.match(publisher, /cargo build.*--release.*--target \$\{\{ matrix.target \}\}/);
});

test("publisher checks out the resolved release tag before building", () => {
  assert.match(publisher, /^    needs: release$/m);
  const ordered = steps(publisher);
  assert.match(ordered[0], /uses: actions\/checkout@/);
  assert.match(ordered[0], /persist-credentials: false/);
  assert.match(ordered[0], /ref: refs\/tags\/\$\{\{ needs.release.outputs.tag_name \}\}/);
});

test("direct Cargo exporter build keeps the dev URL and excludes custom-protocol", () => {
  const config = JSON.parse(read("src-tauri/tauri.conf.json"));
  assert.ok(config.build.devUrl, "direct Cargo builds use devUrl instead of embedding frontendDist");
  const manifest = read("src-tauri/Cargo.toml");
  const feature = manifest.match(/^event-log = \[([\s\S]*?)\]/m);
  assert.ok(feature, "event-log feature must exist");
  // --no-default-features applies to this package, not its Tauri dependency.
  assert.doesNotMatch(feature[1], /custom-protocol/);
  assert.match(manifest, /^tauri = \{ version = "2", features = \[\] \}/m);
});

test("upload script reads the configured target directory for every release target", (t) => {
  assert.match(read(".cargo/config.toml"), /^target-dir = "src-tauri\/target"$/m);
  const matrix = [...publisher.matchAll(/- os: ([\w-]+)\n\s+target: ([\w-]+)\n\s+label: [^\n]+\n\s+exe: (\.exe|"")/g)];
  assert.deepEqual(matrix.map((entry) => entry[2]), ["x86_64-pc-windows-msvc", "aarch64-apple-darwin", "x86_64-unknown-linux-gnu"]);
  const upload = steps(publisher).find((step) => step.startsWith("name: Attach it to the release"));
  assert.ok(upload, "missing upload step");
  assert.match(upload, /shell: bash/);
  const script = upload.split("        run: |\n")[1];
  assert.ok(script, "missing upload script");
  for (const [, , target, extension] of matrix) {
    const root = mkdtempSync(join(tmpdir(), "cmtrace-exporter-contract-"));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const exe = extension === '""' ? "" : extension;
    const binaryDir = join(root, "src-tauri", "target", target, "release");
    mkdirSync(binaryDir, { recursive: true });
    writeFileSync(join(binaryDir, `event-log-export${exe}`), `binary for ${target}`);
    // No network or publication: record the CLI boundary while executing the
    // workflow's real copy/naming logic against a Cargo-shaped directory.
    mkdirSync(join(root, "bin"));
    writeFileSync(join(root, "bin", "gh"), '#!/bin/sh\nprintf "%s\\n" "$@" > gh-args.txt\n', { mode: 0o755 });
    const expanded = script
      .replaceAll("${{ matrix.target }}", target)
      .replaceAll("${{ matrix.exe }}", exe)
      .replaceAll("${{ needs.release.outputs.version }}", "1.6.1")
      .replaceAll("${{ needs.release.outputs.tag_name }}", "v1.6.1");
    assert.doesNotMatch(expanded, /\$\{\{/);
    const result = spawnSync("bash", ["-e", "-o", "pipefail", "-c", expanded], {
      cwd: root,
      env: { PATH: `${join(root, "bin")}:${process.env.PATH}` },
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(result.status, 0, result.stderr);
    const asset = `event-log-export-1.6.1-${target}${exe}`;
    assert.equal(readFileSync(join(root, asset), "utf8"), `binary for ${target}`);
    assert.deepEqual(readFileSync(join(root, "gh-args.txt"), "utf8").trim().split("\n"), ["release", "upload", "v1.6.1", asset, "--clobber"]);
  }
});

test("the exporter contract suite is included in CI", () => {
  assert.match(job(ci, "frontend"), /node --test[^\n]*scripts\/event-log-export-workflow\.test\.mjs/);
});
