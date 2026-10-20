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

/** Build entries only from this release's current signature assets. */
export function buildUpdaterManifest({
  version,
  tagName,
  repository,
  signatures,
  publishedManifest = null,
  pubDate,
}) {
  const platforms = {};
  const missing = [];
  const resolved = [];

  for (const target of UPDATER_TARGETS) {
    const artifact = target.artifact(version);
    const signature = signatures.get(`${artifact}.sig`);

    if (signature === undefined) {
      missing.push(target.key);
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
      pub_date: publishedManifest?.version === tagName ? publishedManifest.pub_date ?? pubDate : pubDate,
      platforms,
    },
    missing,
    resolved,
  };
}

export function missingUpdaterAssets({ version, tagName, assets }) {
  if (!/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(version) || ![version, `v${version}`].includes(tagName)) {
    throw new Error("Invalid stable updater version/tag identity");
  }
  if (!Array.isArray(assets)) throw new Error("Release assets must be an array");
  const names = assets.map(asset => asset.name);
  if (names.some(name => typeof name !== "string") || new Set(names).size !== names.length) {
    throw new Error("Invalid or duplicate release asset names");
  }
  const required = [...new Set(UPDATER_TARGETS.map(target => target.artifact(version)))];
  return required.flatMap(name => [name, `${name}.sig`]).filter(name => !names.includes(name));
}

export function assertCompleteUpdaterManifest({ manifest, version, tagName, repository, signatures, assets }) {
  const missing = missingUpdaterAssets({ version, tagName, assets });
  if (missing.length) throw new Error(`Incomplete updater asset coverage: ${missing.join(", ")}`);
  const keys = Object.keys(manifest.platforms ?? {}).sort();
  const expectedKeys = UPDATER_TARGETS.map(target => target.key).sort();
  if (manifest.version !== tagName || JSON.stringify(keys) !== JSON.stringify(expectedKeys)) {
    throw new Error("Incomplete or unexpected updater platform coverage");
  }
  for (const target of UPDATER_TARGETS) {
    const artifact = target.artifact(version);
    const signature = signatures.get(`${artifact}.sig`);
    if (typeof signature !== "string" || !signature.trim()) throw new Error(`Missing updater signature: ${artifact}`);
    const entry = manifest.platforms[target.key];
    if (entry.version !== tagName || entry.url !== assetUrl(repository, tagName, artifact) || entry.signature !== signature) {
      throw new Error(`Updater entry does not match current release assets: ${target.key}`);
    }
  }
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

  const version = requireValue("VERSION", process.env.VERSION);
  const tagName = requireValue("TAG_NAME", process.env.TAG_NAME);
  const repository = requireValue("GITHUB_REPOSITORY", process.env.GITHUB_REPOSITORY);
  const assets = JSON.parse(await readFile(requireValue("RELEASE_ASSETS", process.env.RELEASE_ASSETS), "utf8"));
  const missing = missingUpdaterAssets({ version, tagName, assets });
  if (process.argv.includes("--check-assets")) {
    if (missing.length) {
      console.log(`Waiting for updater assets: ${missing.join(", ")}`);
      process.exitCode = 2;
    }
    return;
  }
  const { readdir } = await import("node:fs/promises");
  const signatures = await readSignatures(signatureDir, await readdir(signatureDir));
  const { manifest } = buildUpdaterManifest({
    version, tagName, repository, signatures,
    publishedManifest: publishedPath ? await readJsonIfPresent(publishedPath) : null,
    pubDate: new Date().toISOString(),
  });
  assertCompleteUpdaterManifest({ manifest, version, tagName, repository, signatures, assets });
  await writeFile(outputPath, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`Complete updater coverage: ${Object.keys(manifest.platforms).join(", ")}`);
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
