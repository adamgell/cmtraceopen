import { access, readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

export const NIGHTLY_UPDATER_ENDPOINT =
  "https://github.com/adamgell/cmtraceopen/releases/download/nightly/latest.json";

const DEFAULT_PACKAGE_JSON_PATH = "package.json";
const DEFAULT_TAURI_CONFIG_PATH = "src-tauri/tauri.conf.json";
const DEFAULT_LITE_TAURI_CONFIG_PATH = "src-tauri/tauri.lite.conf.json";
const DEFAULT_CARGO_TOML_PATH = "src-tauri/Cargo.toml";
const DEFAULT_INSTALLER_PACKAGE_PATH = "src-tauri/installer/package.signed.json";

const NIGHTLY_PRODUCT_NAME = "CMTrace Open Nightly";
const NIGHTLY_LITE_PRODUCT_NAME = "CMTrace Open Nightly Lite";

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

async function readJsonIfExists(filePath) {
  try {
    return await readJson(filePath);
  } catch (error) {
    if (error?.code === "ENOENT") {
      return null;
    }

    throw error;
  }
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

function setWindowTitles(tauriConfig, title) {
  const windows = tauriConfig.app?.windows;
  if (!Array.isArray(windows)) {
    return;
  }

  for (const windowConfig of windows) {
    windowConfig.title = title;
  }
}

function nightlyInstallerDescription(version) {
  return [
    `Nightly signed build ${version}.`,
    "Includes both the full and lite editions.",
    "Automatic updates use the nightly channel.",
  ].join(" ");
}

function applyNightlyInstallerMetadata(installerPackage, version) {
  installerPackage.packageName = NIGHTLY_PRODUCT_NAME;
  installerPackage.msi ??= {};
  installerPackage.msi.packageName = NIGHTLY_PRODUCT_NAME;
  installerPackage.msi.installDialog ??= {};
  installerPackage.msi.installDialog.packageDescription = nightlyInstallerDescription(version);

  if (Array.isArray(installerPackage.shortcuts)) {
    for (const shortcut of installerPackage.shortcuts) {
      const target = shortcut.target ?? "";
      if (target.endsWith("cmtrace-open-lite.exe")) {
        shortcut.name = NIGHTLY_LITE_PRODUCT_NAME;
      } else if (target.endsWith("cmtrace-open.exe")) {
        shortcut.name = NIGHTLY_PRODUCT_NAME;
      }
    }
  }
}

export async function applyNightlyChannel({
  root,
  version,
  endpoint = NIGHTLY_UPDATER_ENDPOINT,
  packageJsonPath = DEFAULT_PACKAGE_JSON_PATH,
  tauriConfigPath = DEFAULT_TAURI_CONFIG_PATH,
  liteTauriConfigPath = DEFAULT_LITE_TAURI_CONFIG_PATH,
  cargoTomlPath = DEFAULT_CARGO_TOML_PATH,
  installerPackagePath = DEFAULT_INSTALLER_PACKAGE_PATH,
}) {
  assertNightlyVersion(version);

  const packagePath = path.join(root, packageJsonPath);
  const tauriPath = path.join(root, tauriConfigPath);
  const liteTauriPath = path.join(root, liteTauriConfigPath);
  const cargoPath = path.join(root, cargoTomlPath);
  const installerPath = path.join(root, installerPackagePath);

  const packageJson = await readJson(packagePath);
  packageJson.version = version;
  await writeJson(packagePath, packageJson);

  const tauriConfig = await readJson(tauriPath);
  tauriConfig.productName = NIGHTLY_PRODUCT_NAME;
  tauriConfig.version = version;
  setWindowTitles(tauriConfig, NIGHTLY_PRODUCT_NAME);
  tauriConfig.plugins ??= {};
  tauriConfig.plugins.updater ??= {};
  tauriConfig.plugins.updater.endpoints = [endpoint];
  await writeJson(tauriPath, tauriConfig);

  const liteTauriConfig = await readJsonIfExists(liteTauriPath);
  if (liteTauriConfig) {
    liteTauriConfig.productName = NIGHTLY_LITE_PRODUCT_NAME;
    setWindowTitles(liteTauriConfig, NIGHTLY_LITE_PRODUCT_NAME);
    await writeJson(liteTauriPath, liteTauriConfig);
  }

  const installerPackage = await readJsonIfExists(installerPath);
  if (installerPackage) {
    applyNightlyInstallerMetadata(installerPackage, version);
    await writeJson(installerPath, installerPackage);
  }

  const cargoToml = await readFile(cargoPath, "utf8");
  await writeFile(cargoPath, replaceCargoPackageVersion(cargoToml, version));
}

async function readTrimmed(filePath) {
  return (await readFile(filePath, "utf8")).trim();
}

async function findFileByBasename(root, fileName) {
  const matches = [];

  async function walk(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const entryPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await walk(entryPath);
      } else if (entry.isFile() && entry.name === fileName) {
        matches.push(entryPath);
      }
    }
  }

  await walk(root);

  if (matches.length !== 1) {
    throw new Error(
      `Expected exactly one ${fileName} under ${root}, found ${matches.length}`
    );
  }

  return matches[0];
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
    const artifactPath = await findFileByBasename(assetsDir, fileName);
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
