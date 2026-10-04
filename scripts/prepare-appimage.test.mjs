import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const script = new URL("./prepare-appimage.mjs", import.meta.url);

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), "cmtrace-apprun-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

test("Tauri runs launcher preparation before bundling and CI runs these regressions", async () => {
  const config = JSON.parse(await readFile(new URL("../src-tauri/tauri.conf.json", import.meta.url)));
  assert.equal(config.build.beforeBundleCommand, "node scripts/prepare-appimage.mjs");
  const workflow = await readFile(new URL("../.github/workflows/cmtrace-ci.yml", import.meta.url), "utf8");
  assert.ok(workflow.includes("scripts/prepare-appimage.test.mjs"));
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
