import { access, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

export const NIGHTLY_UPDATER_ENDPOINT =
  "https://github.com/adamgell/cmtraceopen/releases/download/nightly/latest.json";

const DEFAULT_PACKAGE_JSON_PATH = "package.json";
const DEFAULT_TAURI_CONFIG_PATH = "src-tauri/tauri.conf.json";
const DEFAULT_CARGO_TOML_PATH = "src-tauri/Cargo.toml";

function requireValue(name, value) {
  if (!value) {
    throw new Error(`${name} is required`);
  }

  return value;
}

function assertNightlyVersion(version) {
  if (!/^\d+\.\d+\.\d+-nightly\.\d{8}\.\d+\.[0-9a-z-]+$/i.test(version)) {
    throw new Error(`Nightly version must be a semver prerelease, got ${version}`);
  }
}

async function readJson(filePath) {
  return JSON.parse(await readFile(filePath, "utf8"));
}

async function writeJson(filePath, value) {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function replaceCargoPackageVersion(cargoToml, version) {
  const lines = cargoToml.split(/\r?\n/);
  let inPackageSection = false;
  let replaced = false;

  const nextLines = lines.map((line) => {
    if (/^\[package\]\s*$/.test(line)) {
      inPackageSection = true;
      return line;
    }

    if (inPackageSection && /^\[/.test(line)) {
      inPackageSection = false;
    }

    if (inPackageSection && /^version\s*=\s*"[^"]+"\s*$/.test(line)) {
      replaced = true;
      return `version = "${version}"`;
    }

    return line;
  });

  if (!replaced) {
    throw new Error("Could not find [package] version in Cargo.toml");
  }

  return nextLines.join("\n");
}

export async function applyNightlyChannel({
  root,
  version,
  endpoint = NIGHTLY_UPDATER_ENDPOINT,
  packageJsonPath = DEFAULT_PACKAGE_JSON_PATH,
  tauriConfigPath = DEFAULT_TAURI_CONFIG_PATH,
  cargoTomlPath = DEFAULT_CARGO_TOML_PATH,
}) {
  assertNightlyVersion(version);

  const packagePath = path.join(root, packageJsonPath);
  const tauriPath = path.join(root, tauriConfigPath);
  const cargoPath = path.join(root, cargoTomlPath);

  const packageJson = await readJson(packagePath);
  packageJson.version = version;
  await writeJson(packagePath, packageJson);

  const tauriConfig = await readJson(tauriPath);
  tauriConfig.version = version;
  tauriConfig.plugins ??= {};
  tauriConfig.plugins.updater ??= {};
  tauriConfig.plugins.updater.endpoints = [endpoint];
  await writeJson(tauriPath, tauriConfig);

  const cargoToml = await readFile(cargoPath, "utf8");
  await writeFile(cargoPath, replaceCargoPackageVersion(cargoToml, version));
}

async function readTrimmed(filePath) {
  return (await readFile(filePath, "utf8")).trim();
}

function assetUrl(repository, tagName, fileName) {
  return `https://github.com/${repository}/releases/download/${tagName}/${encodeURIComponent(fileName)}`;
}

export async function buildNightlyManifest({
  assetsDir,
  assetPrefix,
  repository,
  tagName,
  displayVersion,
  buildId,
  runUrl,
  pubDate = new Date(),
}) {
  assertNightlyVersion(displayVersion);

  const assets = {
    "windows-x86_64": `${assetPrefix}_x64-setup.exe`,
    "windows-aarch64": `${assetPrefix}_arm64-setup.exe`,
    "darwin-aarch64": `${assetPrefix}_macOS-arm64.app.tar.gz`,
  };

  const platforms = {};
  for (const [target, fileName] of Object.entries(assets)) {
    const artifactPath = path.join(assetsDir, fileName);
    const signaturePath = `${artifactPath}.sig`;
    await access(artifactPath);
    const signature = await readTrimmed(signaturePath);

    platforms[target] = {
      signature,
      url: assetUrl(repository, tagName, fileName),
      version: displayVersion,
    };
  }

  const manifest = {
    version: displayVersion,
    notes: [
      `CMTrace Open nightly ${buildId}`,
      "",
      `Workflow run: ${runUrl}`,
    ].join("\n"),
    pub_date: pubDate.toISOString(),
    platforms,
  };

  const manifestPath = path.join(assetsDir, "latest.json");
  await writeJson(manifestPath, manifest);
  return manifestPath;
}

async function main() {
  const command = process.argv[2];

  if (command === "apply") {
    await applyNightlyChannel({
      root: process.env.GITHUB_WORKSPACE ?? process.cwd(),
      version: requireValue("DISPLAY_VERSION", process.env.DISPLAY_VERSION),
      endpoint: process.env.NIGHTLY_UPDATER_ENDPOINT ?? NIGHTLY_UPDATER_ENDPOINT,
    });
    return;
  }

  if (command === "manifest") {
    await buildNightlyManifest({
      assetsDir: process.env.RELEASE_ASSETS_DIR ?? "release-assets",
      assetPrefix: requireValue("ASSET_PREFIX", process.env.ASSET_PREFIX),
      repository: requireValue("GITHUB_REPOSITORY", process.env.GITHUB_REPOSITORY),
      tagName: requireValue("TAG_NAME", process.env.TAG_NAME),
      displayVersion: requireValue("DISPLAY_VERSION", process.env.DISPLAY_VERSION),
      buildId: requireValue("BUILD_ID", process.env.BUILD_ID),
      runUrl: requireValue("RUN_URL", process.env.RUN_URL),
    });
    return;
  }

  throw new Error("Usage: node .github/scripts/nightly-channel.mjs <apply|manifest>");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
