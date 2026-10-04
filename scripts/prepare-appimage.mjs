import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { chmod, mkdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

// Tauri 2.11.x downloads this launcher as 0770, then copies that mode into
// the root-owned AppDir. Prepare it as 0755 before bundling and signing.
const launcherUrl = "https://github.com/tauri-apps/binary-releases/releases/download/apprun-old/AppRun-x86_64";
const launcherSha256 = "f30140a43a0a59e46db21bdefdf749b9e9f2c6946e92afabbacf98b8ae73fb4f";
const tauriDirectory = fileURLToPath(new URL("../src-tauri", import.meta.url));

function includesAppImage(targets, configured = false) {
  if (configured && typeof targets === "string" && targets.toLowerCase() === "all") return true;
  const formats = configured && typeof targets === "string" ? [targets] : targets;
  const known = ["deb", "rpm", "appimage", "nsis", "msi", "app", "dmg", "updater"];
  if (!Array.isArray(formats) || formats.some((value) => typeof value !== "string" || !known.includes(value.toLowerCase()))) {
    throw new Error("Cannot determine AppImage preparation: unknown bundle targets");
  }
  return formats.some((value) => value.toLowerCase() === "appimage");
}

// Project RFC 7396 config merging onto the two bundle settings we need. Tauri supplies its
// already parsed and merged CLI overrides in TAURI_CONFIG; --bundles is separate.
function configuredBundle(previous, config) {
  if (!config || typeof config !== "object" || Array.isArray(config)) throw new Error("Invalid Tauri config object");
  if (!("bundle" in config)) return previous;
  if (config.bundle === null) return { targets: "all", useLocalToolsDir: false };
  if (typeof config.bundle !== "object" || Array.isArray(config.bundle)) throw new Error("Invalid Tauri bundle config");
  return {
    targets: "targets" in config.bundle ? config.bundle.targets ?? "all" : previous.targets,
    useLocalToolsDir: "useLocalToolsDir" in config.bundle ? config.bundle.useLocalToolsDir ?? false : previous.useLocalToolsDir,
  };
}

async function readBundleConfig(env, directory) {
  // This repository uses JSON base/platform files. Do not guess when a new
  // format is introduced; CLI --config formats are already handled by Tauri.
  for (const name of ["tauri.conf.json5", "Tauri.toml", "tauri.linux.conf.json5", "Tauri.linux.toml"]) {
    try {
      await stat(join(directory, name));
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw error;
    }
    throw new Error(`AppImage selection requires JSON base/platform config: ${name}`);
  }
  let bundle = configuredBundle({ targets: "all", useLocalToolsDir: false }, JSON.parse(await readFile(join(directory, "tauri.conf.json"), "utf8")));
  try {
    bundle = configuredBundle(bundle, JSON.parse(await readFile(join(directory, "tauri.linux.conf.json"), "utf8")));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (env.TAURI_CONFIG !== undefined) bundle = configuredBundle(bundle, JSON.parse(env.TAURI_CONFIG));
  return bundle;
}

export async function needsAppImageLauncher(env = process.env, directory = tauriDirectory) {
  const selection = env.CMTRACE_TAURI_BUNDLE_TARGETS;
  // A raw CLI invocation that explicitly opts into this profile prepares it.
  if (selection === undefined) return true;
  const explicit = JSON.parse(selection);
  if (explicit !== null) return includesAppImage(explicit);
  return includesAppImage((await readBundleConfig(env, directory)).targets, true);
}

export async function readCargoTargetDirectory(directory, env, runCargo = promisify(execFile)) {
  // Match Tauri's local_tools_directory setting, which uses Cargo metadata even
  // when a build's Cargo argument tail specifies a different --target-dir.
  const { stdout } = await runCargo("cargo", ["metadata", "--no-deps", "--format-version", "1"], {
    cwd: directory, env, encoding: "utf8", timeout: 60_000,
  });
  const target = JSON.parse(stdout).target_directory;
  if (typeof target !== "string" || !isAbsolute(target)) throw new Error("Cargo metadata did not return an absolute target_directory");
  return target;
}

export async function selectedLauncherCacheDirectory(env = process.env, directory = tauriDirectory, cargoTargetDirectory = readCargoTargetDirectory) {
  const { useLocalToolsDir } = await readBundleConfig(env, directory);
  if (typeof useLocalToolsDir !== "boolean") throw new Error("Invalid bundle.useLocalToolsDir setting");
  return useLocalToolsDir ? join(await cargoTargetDirectory(directory, env), ".tauri") : launcherCacheDirectory(env);
}

export async function downloadLauncher(fetchLauncher = fetch) {
  const response = await fetchLauncher(launcherUrl, { signal: AbortSignal.timeout(60_000) });
  if (!response.ok) throw new Error(`AppRun download failed: HTTP ${response.status}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  if (createHash("sha256").update(bytes).digest("hex") !== launcherSha256) {
    throw new Error("AppRun download failed SHA-256 verification");
  }
  return bytes;
}

export function launcherCacheDirectory(env = process.env, userHome = homedir()) {
  const cache = env.XDG_CACHE_HOME;
  return join(cache && isAbsolute(cache) ? cache : join(userHome, ".cache"), "tauri");
}

export async function prepareAppImageLauncher(cacheDirectory, loadLauncher = downloadLauncher) {
  const launcher = join(cacheDirectory, "AppRun-x86_64");
  let existing;
  try {
    existing = await stat(launcher);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (existing && !existing.isFile()) throw new Error(`AppRun is not a file: ${launcher}`);
  if (!existing) {
    const bytes = await loadLauncher();
    await mkdir(cacheDirectory, { recursive: true });
    const temporary = `${launcher}.${process.pid}.tmp`;
    try {
      await writeFile(temporary, bytes, { mode: 0o755 });
      await chmod(temporary, 0o755); // Also works with a restrictive umask.
      await rename(temporary, launcher);
    } finally {
      await rm(temporary, { force: true });
    }
  }
  await chmod(launcher, 0o755);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const platform = process.env.TAURI_ENV_PLATFORM ?? process.platform;
  const arch = process.env.TAURI_ENV_ARCH ?? (process.arch === "x64" ? "x86_64" : process.arch);
  // CMTrace currently publishes only the Linux x86_64 AppImage.
  if (platform === "linux" && arch === "x86_64" && await needsAppImageLauncher()) {
    await prepareAppImageLauncher(await selectedLauncherCacheDirectory());
  }
}
