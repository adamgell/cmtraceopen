import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const wrapper = new URL("./tauri.mjs", import.meta.url);
const profile = fileURLToPath(new URL("../src-tauri/tauri.appimage.conf.json", import.meta.url));
const key = "CMTRACE_TAURI_BUNDLE_TARGETS";

async function invocation(args, platform = "linux", arch = "x64") {
  const { tauriInvocation } = await import(wrapper);
  return tauriInvocation(args, { [key]: '["stale"]', UNRELATED: "preserved" }, platform, arch);
}

test("default Linux builds add only the first config override, preserving every existing argument", async () => {
  const args = ["build", "--config", "a path/lite.json", "--config={\"bundle\":{\"targets\":[\"deb\"]}}", "--target=x86_64-unknown-linux-gnu", "--", "--no-default-features", "--features", "literal value"];
  const result = await invocation(args);
  assert.deepEqual(result.args, ["build", "--config", profile, ...args.slice(1)]);
  assert.deepEqual(result.env, { [key]: "null", UNRELATED: "preserved" });
  assert.deepEqual(args.slice(-4), ["--", "--no-default-features", "--features", "literal value"]);
});

test("explicit bundle lists preserve Tauri's comma, space, repeated and short-option forms", async () => {
  for (const args of [
    ["build", "--bundles", "deb", "appimage"],
    ["build", "--bundles=deb,appimage"],
    ["bundle", "-b", "deb", "-b", "appimage"],
    ["build", "-bdeb,appimage"],
    ["build", "-db=deb,appimage"],
    ["-vv", "build", "--bundles", "deb", "-vbappimage"],
  ]) {
    const result = await invocation(args);
    const commandIndex = args.findIndex((arg) => arg === "build" || arg === "bundle");
    assert.deepEqual(result.args, [...args.slice(0, commandIndex + 1), "--config", profile, ...args.slice(commandIndex + 1)], JSON.stringify(args));
    assert.deepEqual(JSON.parse(result.env[key]), ["deb", "appimage"]);
  }
});

test("deb, rpm and empty CLI selections do not add a profile, even with stale inherited context", async () => {
  for (const [args, bundles] of [
    [["build", "--bundles", "deb"], ["deb"]],
    [["bundle", "--bundles=deb,rpm"], ["deb", "rpm"]],
    [["build", "-bdeb"], ["deb"]],
    [["build", "--bundles", "--ci"], []],
    [["build", "--config", profile, "--bundles", "deb"], ["deb"]],
  ]) {
    const result = await invocation(args);
    assert.deepEqual(result.args, args);
    assert.deepEqual(JSON.parse(result.env[key]), bundles);
  }
});

test("unknown selections are not assumed to exclude AppImage", async () => {
  const result = await invocation(["build", "--bundles", "future-format"]);
  assert.ok(result.args.includes(profile));
  assert.equal(result.env[key], '["future-format"]');
});

test("config contents, other option values and the Cargo tail cannot masquerade as bundle flags", async () => {
  for (const args of [
    ["build", '--config={"text":"--bundles deb"}'],
    ["build", "-c{\"text\":\"-bdeb\"}"],
    ["build", "-rbuild-wrapper"],
    ["build", "-fbackend"],
    ["build", "--", "--bundles", "deb", "--no-bundle"],
  ]) {
    const result = await invocation(args);
    assert.deepEqual(result.args, ["build", "--config", profile, ...args.slice(1)]);
    assert.equal(result.env[key], "null");
  }
});

test("no-bundle, help and other subcommands are passed through without preparation", async () => {
  for (const args of [["build", "--no-bundle"], ["build", "--help"], ["build", "-vh"], ["--version"], ["dev"], ["signer", "sign", "a file.sig"]]) {
    const result = await invocation(args);
    assert.deepEqual(result.args, args);
    assert.notEqual(result.env[key], '["stale"]');
  }
});

test("host and explicit target selection preserve non-Linux and other-architecture paths", async () => {
  for (const [platform, arch] of [["darwin", "arm64"], ["win32", "x64"], ["linux", "arm64"]]) {
    assert.deepEqual((await invocation(["build"], platform, arch)).args, ["build"]);
  }
  for (const args of [["build", "--target", "aarch64-apple-darwin"], ["build", "--target=x86_64-pc-windows-msvc"], ["build", "-taarch64-unknown-linux-gnu"]]) {
    assert.deepEqual((await invocation(args)).args, args);
  }
  for (const target of [["--target", "x86_64-unknown-linux-gnu"], ["--target=x86_64-unknown-linux-gnu"], ["-tx86_64-unknown-linux-gnu"], ["-vt", "x86_64-unknown-linux-gnu"]]) {
    const args = ["build", ...target];
    assert.deepEqual((await invocation(args, "darwin", "arm64")).args, ["build", "--config", profile, ...target]);
  }
});

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), "cmtrace-tauri-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const cli = join(directory, "owned-cli-fixture.mjs");
  const driver = join(directory, "driver.mjs");
  await writeFile(driver, `import { runTauri } from ${JSON.stringify(wrapper.href)}; await runTauri(process.argv.slice(2), ${JSON.stringify(cli)});\n`);
  return { directory, cli, driver };
}

test("the real child-process boundary preserves argv, cwd, stdio and exit status without recursion", async (t) => {
  const { directory, cli, driver } = await fixture(t);
  const args = ["build", "--target", "x86_64-unknown-linux-gnu", "--bundles", "deb", "--", "a path/with 'quotes'"];
  for (const code of [0, 23]) {
    await writeFile(cli, `console.log(JSON.stringify({args: process.argv.slice(2), cwd: process.cwd(), selection: process.env.${key}})); console.error("fixture stderr"); process.exit(${code});\n`);
    const result = spawnSync(process.execPath, [driver, ...args], { cwd: directory, encoding: "utf8", timeout: 5_000 });
    assert.equal(result.status, code, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { args, cwd: await realpath(directory), selection: '["deb"]' });
    assert.equal(result.stderr, "fixture stderr\n");
  }
});

test("opt-in publication guard awaits preflight, build and final inspection in order", async (t) => {
  const { directory, cli, driver } = await fixture(t);
  const inspector = join(directory, "owned-inspector.mjs");
  await writeFile(inspector, 'console.log(process.argv[2]); if (process.argv[2] === "verify") process.exit(Number(process.env.FIXTURE_VERIFY_EXIT ?? 0));\n');
  await writeFile(cli, 'console.log("BUILD"); process.exit(Number(process.env.FIXTURE_BUILD_EXIT ?? 0));\n');
  await writeFile(driver, `import { runTauri } from ${JSON.stringify(wrapper.href)}; await runTauri(process.argv.slice(2), ${JSON.stringify(cli)}, [process.execPath, ${JSON.stringify(inspector)}]);\n`);
  for (const [build, verify, expected, output] of [[0, 0, 0, "preflight\nBUILD\nverify\n"], [0, 37, 37, "preflight\nBUILD\nverify\n"], [23, 0, 23, "preflight\nBUILD\n"]]) {
    const result = spawnSync(process.execPath, [driver, "build", "--target=x86_64-unknown-linux-gnu"], {
      cwd: directory, encoding: "utf8", timeout: 5_000,
      env: { ...process.env, CMTRACE_APPIMAGE_VERIFY_ROOT: "fixture-root", FIXTURE_BUILD_EXIT: String(build), FIXTURE_VERIFY_EXIT: String(verify) },
    });
    assert.equal(result.status, expected, result.stderr);
    assert.equal(result.stdout, output);
  }
});

test("guard preflight failure prevents the build and action metadata commands remain ungated", async (t) => {
  const { directory, cli, driver } = await fixture(t);
  const inspector = join(directory, "inspector.mjs");
  await writeFile(inspector, 'console.log("PREFLIGHT"); process.exit(41);\n');
  await writeFile(cli, 'console.log("CLI");\n');
  await writeFile(driver, `import { runTauri } from ${JSON.stringify(wrapper.href)}; await runTauri(process.argv.slice(2), ${JSON.stringify(cli)}, [process.execPath, ${JSON.stringify(inspector)}]);\n`);
  const env = { ...process.env, CMTRACE_APPIMAGE_VERIFY_ROOT: "fixture-root" };
  const build = spawnSync(process.execPath, [driver, "build", "--target=x86_64-unknown-linux-gnu"], { env, encoding: "utf8", timeout: 5_000 });
  assert.equal(build.status, 41, build.stderr);
  assert.equal(build.stdout, "PREFLIGHT\n");
  const info = spawnSync(process.execPath, [driver, "--version"], { env, encoding: "utf8", timeout: 5_000 });
  assert.equal(info.status, 0, info.stderr);
  assert.equal(info.stdout, "CLI\n");
});

test("guard cancellation fails numerically during either child, even if that child exits zero", { skip: process.platform === "win32" }, async (t) => {
  const { directory, cli, driver } = await fixture(t);
  const inspector = join(directory, "inspector.mjs");
  const waitForCancellation = 'process.on("SIGTERM", () => process.exit(0)); console.log("READY"); setInterval(() => {}, 1000);';
  await writeFile(driver, `import { runTauri } from ${JSON.stringify(wrapper.href)}; await runTauri(process.argv.slice(2), ${JSON.stringify(cli)}, [process.execPath, ${JSON.stringify(inspector)}]);\n`);
  for (const phase of ["preflight", "build", "verify"]) {
    await writeFile(cli, phase === "build" ? waitForCancellation : 'console.log("BUILD");');
    await writeFile(inspector, `if (process.argv[2] === ${JSON.stringify(phase)}) { ${waitForCancellation} }`);
    const child = spawn(process.execPath, [driver, "build", "--target=x86_64-unknown-linux-gnu"], { env: { ...process.env, CMTRACE_APPIMAGE_VERIFY_ROOT: "fixture-root" }, stdio: ["ignore", "pipe", "pipe"] });
    const closed = once(child, "close");
    const timer = setTimeout(() => child.kill("SIGKILL"), 5_000);
    let output = "";
    child.stdout.on("data", (data) => { output += data; if (output.includes("READY")) child.kill("SIGTERM"); });
    const [code, signal] = await closed;
    clearTimeout(timer);
    assert.equal(code, 1, phase);
    assert.equal(signal, null, phase);
  }
});

test("termination is forwarded to the CLI child and preserved by the wrapper", { skip: process.platform === "win32" }, async (t) => {
  const { cli, driver } = await fixture(t);
  await writeFile(cli, 'console.log("READY"); setInterval(() => {}, 1000);\n');
  const child = spawn(process.execPath, [driver, "dev"], { stdio: ["ignore", "pipe", "pipe"] });
  t.after(() => child.kill("SIGKILL"));
  const timer = setTimeout(() => child.kill("SIGKILL"), 5_000);
  t.after(() => clearTimeout(timer));
  const closed = once(child, "close");
  await Promise.race([
    once(child.stdout, "data"),
    closed.then(() => { throw new Error("wrapper exited before CLI fixture was ready"); }),
  ]);
  child.kill("SIGTERM");
  const [code, signal] = await closed;
  assert.equal(code, null);
  assert.equal(signal, "SIGTERM");
});

test("documented build scripts retain their arguments through the narrow wrapper", async () => {
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url)));
  assert.deepEqual(Object.fromEntries(["tauri", "app:build:release", "app:build:debug", "app:build:exe-only", "app:build:lite"].map((name) => [name, pkg.scripts[name]])), {
    tauri: "node scripts/tauri.mjs",
    "app:build:release": "node scripts/tauri.mjs build",
    "app:build:debug": "node scripts/tauri.mjs build --debug",
    "app:build:exe-only": "node scripts/tauri.mjs build --no-bundle",
    "app:build:lite": "node scripts/tauri.mjs build --config src-tauri/tauri.lite.conf.json -- --no-default-features",
  });
  assert.equal(pkg.scripts["app:dev"], "tauri dev");
});

test("CI and release retain the pinned action's npm-script contract", async () => {
  // Verified source: tauri-action@1deb371b0cd8bd54025b384f1cd735e725c4060f
  // src/runner.ts:55-70 picks npm run tauri when the package has a tauri script;
  // src/utils.ts:401-428 checks that script and package-lock.json. Keep those
  // inputs and the audited action revision intact, rather than assuming every
  // action version or a tauriScript override invokes our npm entry point.
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url)));
  assert.ok(pkg.devDependencies["@tauri-apps/cli"]);
  assert.equal(pkg.scripts.tauri, "node scripts/tauri.mjs");
  assert.ok((await stat(new URL("../package-lock.json", import.meta.url))).isFile());
  for (const name of ["cmtrace-ci.yml", "cmtrace-release.yml", "cmtrace-nightly-signed.yml"]) {
    const workflow = await readFile(new URL(`../.github/workflows/${name}`, import.meta.url), "utf8");
    assert.match(workflow, /uses: tauri-apps\/tauri-action@1deb371b0cd8bd54025b384f1cd735e725c4060f/);
    assert.match(workflow, /projectPath: \./);
    assert.doesNotMatch(workflow, /\btauriScript:/);
  }
});
