import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

// Every Tauri updater target this project ships, and the release artifact each
// one points at. `darwin-aarch64` and `darwin-aarch64-app` intentionally share
// an artifact: Tauri reads the first and the `{os}-{arch}-{bundle}` form is the
// newer alias for the same download. Same story for the two AppImage keys.
export const UPDATER_TARGETS = [
  { key: "windows-x86_64", artifact: (v) => `CMTrace-Open_${v}_x64-setup.exe` },
  { key: "windows-aarch64", artifact: (v) => `CMTrace-Open_${v}_arm64-setup.exe` },
  { key: "darwin-aarch64", artifact: (v) => `CMTrace.Open_${v}_aarch64.app.tar.gz` },
  { key: "darwin-aarch64-app", artifact: (v) => `CMTrace.Open_${v}_aarch64.app.tar.gz` },
  { key: "linux-x86_64", artifact: (v) => `CMTrace.Open_${v}_amd64.AppImage` },
  { key: "linux-x86_64-appimage", artifact: (v) => `CMTrace.Open_${v}_amd64.AppImage` },
  { key: "linux-x86_64-deb", artifact: (v) => `CMTrace.Open_${v}_amd64.deb` },
  { key: "linux-x86_64-rpm", artifact: (v) => `CMTrace.Open-${v}-1.x86_64.rpm` },
];

export const MANIFEST_FILENAME = "latest.json";

function assetUrl(repository, tagName, fileName) {
  return `https://github.com/${repository}/releases/download/${tagName}/${encodeURIComponent(fileName)}`;
}

/**
 * Build the stable updater manifest from whatever the release already carries.
 *
 * Two properties matter, and both come from deriving entries out of the
 * release's own assets rather than out of the job that happens to be running:
 *
 * - Convergent. Each release workflow sees the same assets, so the manifest
 *   they compute for a given set of uploads is identical. Two publishers racing
 *   is no longer a lost update, because they write the same bytes.
 * - Monotonic. Entries already published are carried forward when this run
 *   cannot see their artifact yet, so a publisher that runs before the other
 *   platform has uploaded can only ever add keys, never remove them.
 *
 * `missing` is reported rather than thrown: the first workflow to finish is
 * legitimately incomplete, and an entry that never arrives means its build job
 * failed, which is already red.
 */
export function buildUpdaterManifest({
  version,
  tagName,
  repository,
  signatures,
  publishedManifest = null,
  pubDate,
}) {
  const platforms = { ...(publishedManifest?.platforms ?? {}) };
  const missing = [];
  const resolved = [];

  for (const target of UPDATER_TARGETS) {
    const artifact = target.artifact(version);
    const signature = signatures.get(`${artifact}.sig`);

    if (signature === undefined) {
      if (!platforms[target.key]) missing.push(target.key);
      continue;
    }

    platforms[target.key] = {
      signature,
      url: assetUrl(repository, tagName, artifact),
      version: tagName,
    };
    resolved.push(target.key);
  }

  return {
    manifest: {
      version: tagName,
      notes: `CMTrace Open ${tagName}`,
      // Preserved so a later publisher does not restamp the release date.
      pub_date: publishedManifest?.pub_date ?? pubDate,
      platforms,
    },
    missing,
    resolved,
  };
}

/**
 * Read `<name>.sig` files out of a directory listing into the map
 * buildUpdaterManifest expects. Signatures are produced on Windows runners as
 * well as Unix ones, so CR is stripped alongside LF.
 */
export async function readSignatures(directory, fileNames) {
  const signatures = new Map();

  for (const fileName of fileNames) {
    if (!fileName.endsWith(".sig")) continue;
    const contents = await readFile(path.join(directory, fileName), "utf8");
    signatures.set(fileName, contents.replace(/[\r\n]/g, ""));
  }

  return signatures;
}

function requireValue(name, value) {
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function readJsonIfPresent(filePath) {
  try {
    return JSON.parse(await readFile(filePath, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

async function main() {
  const signatureDir = process.env.SIGNATURE_DIR ?? "signatures";
  const publishedPath = process.env.PUBLISHED_MANIFEST ?? "";
  const outputPath = process.env.OUTPUT_PATH ?? MANIFEST_FILENAME;

  const { readdir } = await import("node:fs/promises");
  const entries = await readdir(signatureDir);

  const { manifest, missing, resolved } = buildUpdaterManifest({
    version: requireValue("VERSION", process.env.VERSION),
    tagName: requireValue("TAG_NAME", process.env.TAG_NAME),
    repository: requireValue("GITHUB_REPOSITORY", process.env.GITHUB_REPOSITORY),
    signatures: await readSignatures(signatureDir, entries),
    publishedManifest: publishedPath ? await readJsonIfPresent(publishedPath) : null,
    pubDate: new Date().toISOString(),
  });

  await writeFile(outputPath, `${JSON.stringify(manifest, null, 2)}\n`);

  console.log(`resolved: ${resolved.join(", ") || "none"}`);
  console.log(`missing: ${missing.join(", ") || "none"}`);

  if (missing.length > 0) {
    // A warning rather than a failure. The workflow that finishes first has
    // legitimately not seen the other platform's uploads yet, and a target that
    // never arrives means its build job failed and is already reporting red.
    console.log(
      `::warning::Updater manifest is missing ${missing.join(", ")}. ` +
        "This is expected until every platform has uploaded; if it persists, a build job failed.",
    );
  }
}

export function isMainModule(importMetaUrl, argvPath = process.argv[1]) {
  if (!argvPath) return false;
  return importMetaUrl === new URL(`file://${path.resolve(argvPath)}`).href;
}

if (isMainModule(import.meta.url)) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
