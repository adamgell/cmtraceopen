import { createHash } from "node:crypto";
import { chmod, mkdir, rename, rm, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import { pathToFileURL } from "node:url";

// Tauri 2.11.x downloads this launcher as 0770, then copies that mode into
// the root-owned AppDir. Prepare it as 0755 before bundling and signing.
const launcherUrl = "https://github.com/tauri-apps/binary-releases/releases/download/apprun-old/AppRun-x86_64";
const launcherSha256 = "f30140a43a0a59e46db21bdefdf749b9e9f2c6946e92afabbacf98b8ae73fb4f";

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
  if (platform === "linux" && arch === "x86_64") {
    await prepareAppImageLauncher(launcherCacheDirectory());
  }
}
