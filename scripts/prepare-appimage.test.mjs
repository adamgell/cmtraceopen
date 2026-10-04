import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import test from "node:test";

const script = new URL("./prepare-appimage.mjs", import.meta.url);

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), "cmtrace-apprun-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

test("only the AppImage profile installs the preparation hook and CI runs these regressions", async () => {
  const config = JSON.parse(await readFile(new URL("../src-tauri/tauri.conf.json", import.meta.url)));
  assert.equal(config.build.beforeBundleCommand, undefined);
  const profile = JSON.parse(await readFile(new URL("../src-tauri/tauri.appimage.conf.json", import.meta.url)));
  assert.deepEqual(profile, { build: { beforeBundleCommand: "node scripts/prepare-appimage.mjs" } });
  const workflow = await readFile(new URL("../.github/workflows/cmtrace-ci.yml", import.meta.url), "utf8");
  assert.ok(workflow.includes("scripts/prepare-appimage.test.mjs"));
});

async function runHook(t, { selection, config, cache, platform = "linux", arch = "x86_64", additionalEnv = {}, preloadSource = 'globalThis.fetch = async () => { throw new Error("UNEXPECTED_NETWORK"); };\n' } = {}) {
  const { spawnSync } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const directory = await fixture(t);
  const preload = join(directory, "offline.mjs");
  await writeFile(preload, preloadSource);
  const env = { ...process.env, ...additionalEnv, TAURI_ENV_PLATFORM: platform, TAURI_ENV_ARCH: arch, XDG_CACHE_HOME: cache ?? join(directory, "cold-cache") };
  delete env.CMTRACE_TAURI_BUNDLE_TARGETS;
  delete env.TAURI_CONFIG;
  if (selection !== undefined) env.CMTRACE_TAURI_BUNDLE_TARGETS = selection;
  if (config !== undefined) env.TAURI_CONFIG = config;
  return spawnSync(process.execPath, ["--import", preload, fileURLToPath(script)], { env, encoding: "utf8", timeout: 5_000 });
}

test("explicit deb-only, rpm-only and empty selections work offline with a cold cache", async (t) => {
  const cache = join(await fixture(t), "cold-cache");
  for (const selection of ['["deb"]', '["rpm"]', '[]']) {
    const result = await runHook(t, { selection, cache });
    assert.equal(result.status, 0, result.stderr);
    assert.doesNotMatch(result.stderr, /UNEXPECTED_NETWORK/);
    await assert.rejects(stat(cache), { code: "ENOENT" });
  }
});

test("non-AppImage selections never inspect or repair the launcher cache", async (t) => {
  const cache = join(await fixture(t), "not-a-directory");
  await writeFile(cache, "untouched");
  for (const selection of ['["deb"]', '["rpm"]']) {
    const result = await runHook(t, { selection, cache });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(await readFile(cache, "utf8"), "untouched");
  }
});

test("Tauri-parsed config-only deb selections skip preparation, but explicit AppImage overrides config", async (t) => {
  const config = JSON.stringify({ bundle: { targets: ["deb"] } });
  const deb = await runHook(t, { selection: "null", config });
  assert.equal(deb.status, 0, deb.stderr);
  const appimage = await runHook(t, { selection: '["appimage"]', config });
  assert.equal(appimage.status, 1);
  assert.match(appimage.stderr, /UNEXPECTED_NETWORK/);
  const explicitDeb = await runHook(t, { selection: '["deb"]', config: '{"bundle":{"targets":"appimage"}}' });
  assert.equal(explicitDeb.status, 0, explicitDeb.stderr);
});

test("base, Linux platform and Tauri-parsed override targets retain merge precedence and null removal", async (t) => {
  const { needsAppImageLauncher } = await import(script);
  const directory = await fixture(t);
  const selected = (override) => needsAppImageLauncher({ CMTRACE_TAURI_BUNDLE_TARGETS: "null", ...(override === undefined ? {} : { TAURI_CONFIG: JSON.stringify(override) }) }, directory);
  await writeFile(join(directory, "tauri.conf.json"), '{"bundle":{"targets":"all"}}');
  assert.equal(await selected(), true);
  await writeFile(join(directory, "tauri.linux.conf.json"), '{"bundle":{"targets":["deb"]}}');
  assert.equal(await selected(), false);
  assert.equal(await selected({ build: { beforeBundleCommand: "node scripts/prepare-appimage.mjs" } }), false);
  assert.equal(await selected({ bundle: { targets: "AppImage" } }), true);
  assert.equal(await selected({ bundle: { targets: [] } }), false);
  assert.equal(await selected({ bundle: { targets: ["rpm"] } }), false);
  assert.equal(await selected({ bundle: { targets: null } }), true);
  assert.equal(await selected({ bundle: null }), true);
  await writeFile(join(directory, "tauri.linux.conf.json"), '{"bundle":null}');
  assert.equal(await selected(), true);
  await writeFile(join(directory, "tauri.linux.conf.json5"), '{bundle: {targets: "deb"}}');
  await assert.rejects(selected(), /requires JSON base\/platform config/);
  // An explicit CLI selection wins without consulting any config file.
  assert.equal(await needsAppImageLauncher({ CMTRACE_TAURI_BUNDLE_TARGETS: '["deb"]' }, "/missing/config"), false);
});

test("selected AppImage hooks enforce checksum failure before creating a cold cache", async (t) => {
  const cache = join(await fixture(t), "cold-cache");
  const result = await runHook(t, { selection: '["appimage"]', cache, preloadSource: 'globalThis.fetch = async () => new Response("corrupt launcher");\n' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /SHA-256 verification/);
  await assert.rejects(stat(cache), { code: "ENOENT" });
});

test("selected AppImage hooks repair a warm cache despite a deb-only config override", async (t) => {
  const { mkdir } = await import("node:fs/promises");
  const cache = await fixture(t);
  await mkdir(join(cache, "tauri"));
  const launcher = join(cache, "tauri", "AppRun-x86_64");
  await writeFile(launcher, "existing launcher", { mode: 0o770 });
  const result = await runHook(t, { selection: '["appimage"]', config: '{"bundle":{"targets":"deb"}}', cache });
  assert.equal(result.status, 0, result.stderr);
  assert.equal((await stat(launcher)).mode & 0o777, 0o755);
  assert.equal(await readFile(launcher, "utf8"), "existing launcher");
});

test("malformed or unknown bundle selection fails before cache access or download", async (t) => {
  for (const options of [
    { selection: "not json" },
    { selection: '{}' },
    { selection: '["future-format"]' },
    { selection: "null", config: "not json" },
    { selection: "null", config: '{"bundle":{"targets":{}}}' },
    { selection: "null", config: '{"bundle":{"targets":"future-format"}}' },
  ]) {
    const result = await runHook(t, options);
    assert.equal(result.status, 1);
    assert.doesNotMatch(result.stderr, /UNEXPECTED_NETWORK/);
  }
});

test("non-Linux and non-x86_64 hooks do not prepare a launcher", async (t) => {
  for (const [platform, arch] of [["darwin", "aarch64"], ["windows", "x86_64"], ["linux", "aarch64"]]) {
    const result = await runHook(t, { platform, arch, selection: '["appimage"]' });
    assert.equal(result.status, 0, result.stderr);
  }
});

test("a cached 0770 launcher becomes readable and executable by any user without replacing its bytes", async (t) => {
  const { prepareAppImageLauncher } = await import(script);
  const directory = await fixture(t);
  const launcher = join(directory, "AppRun-x86_64");
  await writeFile(launcher, "cached launcher");
  await chmod(launcher, 0o770);
  await prepareAppImageLauncher(directory, () => assert.fail("cached launcher must not download"));
  assert.equal((await stat(launcher)).mode & 0o777, 0o755);
  assert.equal(await readFile(launcher, "utf8"), "cached launcher");
});

test("a cold cache installs executable launcher bytes even with a restrictive umask", async (t) => {
  const { prepareAppImageLauncher } = await import(script);
  const directory = join(await fixture(t), "tauri");
  const oldUmask = process.umask(0o077);
  try {
    await prepareAppImageLauncher(directory, async () => Buffer.from("downloaded launcher"));
  } finally {
    process.umask(oldUmask);
  }
  const launcher = join(directory, "AppRun-x86_64");
  assert.equal((await stat(launcher)).mode & 0o777, 0o755);
  assert.equal(await readFile(launcher, "utf8"), "downloaded launcher");
});

test("a failed download does not leave a launcher for Tauri to package", async (t) => {
  const { prepareAppImageLauncher } = await import(script);
  const directory = await fixture(t);
  await assert.rejects(prepareAppImageLauncher(directory, async () => { throw new Error("network failure"); }), /network failure/);
  await assert.rejects(stat(join(directory, "AppRun-x86_64")), { code: "ENOENT" });
});

test("upstream HTTP errors and changed launcher bytes fail verification", async () => {
  const { downloadLauncher } = await import(script);
  await assert.rejects(downloadLauncher(async () => new Response("missing", { status: 404 })), /404/);
  await assert.rejects(downloadLauncher(async () => new Response("corrupt launcher")), /SHA-256/);
});

test("cache selection follows Tauri's Linux XDG cache rules", async () => {
  const { launcherCacheDirectory } = await import(script);
  assert.equal(launcherCacheDirectory({ XDG_CACHE_HOME: "/custom/cache" }, "/home/user"), "/custom/cache/tauri");
  assert.equal(launcherCacheDirectory({ XDG_CACHE_HOME: "relative" }, "/home/user"), "/home/user/.cache/tauri");
  assert.equal(launcherCacheDirectory({}, "/home/user"), "/home/user/.cache/tauri");
});

test("local tool cache selection follows Cargo metadata and config override precedence", async (t) => {
  const { selectedLauncherCacheDirectory } = await import(script);
  const directory = await fixture(t);
  const target = join(directory, "custom cargo target");
  const env = { XDG_CACHE_HOME: join(directory, "global-cache") };
  await writeFile(join(directory, "tauri.conf.json"), '{"bundle":{"useLocalToolsDir":true}}');
  const metadata = async (tauriDirectory, inheritedEnv) => {
    assert.equal(tauriDirectory, directory);
    assert.deepEqual(inheritedEnv, env);
    return target;
  };
  assert.equal(await selectedLauncherCacheDirectory(env, directory, metadata), join(target, ".tauri"));
  await writeFile(join(directory, "tauri.linux.conf.json"), '{"bundle":{"useLocalToolsDir":false}}');
  assert.equal(await selectedLauncherCacheDirectory(env, directory, () => assert.fail("global cache must not run Cargo metadata")), join(env.XDG_CACHE_HOME, "tauri"));
  assert.equal(await selectedLauncherCacheDirectory({ ...env, TAURI_CONFIG: '{"bundle":{"useLocalToolsDir":true}}' }, directory, async () => target), join(target, ".tauri"));
  for (const override of [{ bundle: { useLocalToolsDir: null } }, { bundle: null }]) {
    assert.equal(await selectedLauncherCacheDirectory({ ...env, TAURI_CONFIG: JSON.stringify(override) }, directory, () => assert.fail("removed setting must default to global cache")), join(env.XDG_CACHE_HOME, "tauri"));
  }
});

test("Cargo metadata uses Tauri's command, cwd and environment without running a native tool in this test", async (t) => {
  const { readCargoTargetDirectory } = await import(script);
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const { realpath } = await import("node:fs/promises");
  const directory = await fixture(t);
  const ownedFixture = join(directory, "metadata-fixture.mjs");
  await writeFile(ownedFixture, 'import assert from "node:assert/strict"; assert.deepEqual(process.argv.slice(2), ["metadata", "--no-deps", "--format-version", "1"]); assert.equal(process.cwd(), process.env.EXPECTED_CWD); console.log(JSON.stringify({target_directory: process.env.CARGO_TARGET_DIR}));\n');
  const env = { ...process.env, CARGO_TARGET_DIR: join(directory, "target override"), EXPECTED_CWD: await realpath(directory) };
  const runFixture = (command, args, options) => {
    assert.equal(command, "cargo");
    return promisify(execFile)(process.execPath, [ownedFixture, ...args], options);
  };
  assert.equal(await readCargoTargetDirectory(directory, env, runFixture), env.CARGO_TARGET_DIR);
  for (const stdout of ['{}', '{"target_directory":"relative"}', 'invalid json']) {
    await assert.rejects(readCargoTargetDirectory(directory, env, async () => ({ stdout })));
  }
  await assert.rejects(readCargoTargetDirectory(directory, env, async () => { throw new Error("metadata failed"); }), /metadata failed/);
});

test("a warm local launcher is repaired without touching a cold global cache or downloading", async (t) => {
  const { selectedLauncherCacheDirectory, prepareAppImageLauncher } = await import(script);
  const { mkdir } = await import("node:fs/promises");
  const directory = await fixture(t);
  const target = join(directory, "cargo-target");
  const globalCache = join(directory, "absent-global-cache");
  const localCache = join(target, ".tauri");
  await writeFile(join(directory, "tauri.conf.json"), '{"bundle":{"useLocalToolsDir":true}}');
  await mkdir(localCache, { recursive: true });
  const launcher = join(localCache, "AppRun-x86_64");
  await writeFile(launcher, "local cached launcher", { mode: 0o770 });
  const selected = await selectedLauncherCacheDirectory({ XDG_CACHE_HOME: globalCache }, directory, async () => target);
  await prepareAppImageLauncher(selected, () => assert.fail("warm local cache must not download"));
  assert.equal((await stat(launcher)).mode & 0o777, 0o755);
  assert.equal(await readFile(launcher, "utf8"), "local cached launcher");
  await assert.rejects(stat(globalCache), { code: "ENOENT" });
});

test("the hook uses the selected local cache through an owned Cargo metadata process fixture", async (t) => {
  const { mkdir } = await import("node:fs/promises");
  const directory = await fixture(t);
  const localCache = join(directory, "cargo-target", ".tauri");
  const globalCache = join(directory, "cold-global-cache");
  await mkdir(localCache, { recursive: true });
  const launcher = join(localCache, "AppRun-x86_64");
  await writeFile(launcher, "local launcher", { mode: 0o770 });
  const cargo = join(directory, "cargo");
  await writeFile(cargo, `#!${process.execPath}\nrequire("node:assert/strict").deepEqual(process.argv.slice(2), ["metadata", "--no-deps", "--format-version", "1"]); console.log(JSON.stringify({target_directory: process.env.CARGO_TARGET_DIR}));\n`, { mode: 0o755 });
  const result = await runHook(t, {
    selection: '["appimage"]', config: '{"bundle":{"useLocalToolsDir":true}}', cache: globalCache,
    additionalEnv: { PATH: `${directory}${delimiter}${process.env.PATH}`, CARGO_TARGET_DIR: join(directory, "cargo-target") },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal((await stat(launcher)).mode & 0o777, 0o755);
  assert.equal(await readFile(launcher, "utf8"), "local launcher");
  await assert.rejects(stat(globalCache), { code: "ENOENT" });
});

test("the configured hook repairs a cached Linux launcher and leaves macOS targets alone", async (t) => {
  const { spawnSync } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const { mkdir } = await import("node:fs/promises");
  const directory = await fixture(t);
  await mkdir(join(directory, "tauri"));
  const launcher = join(directory, "tauri", "AppRun-x86_64");
  await writeFile(launcher, "cached launcher");
  await chmod(launcher, 0o770);
  const run = (platform) => spawnSync(process.execPath, [fileURLToPath(script)], {
    env: { ...process.env, TAURI_ENV_PLATFORM: platform, TAURI_ENV_ARCH: "x86_64", XDG_CACHE_HOME: directory },
    encoding: "utf8",
  });
  const mac = run("darwin");
  assert.equal(mac.status, 0, mac.stderr);
  assert.equal((await stat(launcher)).mode & 0o777, 0o770);
  const linux = run("linux");
  assert.equal(linux.status, 0, linux.stderr);
  assert.equal((await stat(launcher)).mode & 0o777, 0o755);
});
