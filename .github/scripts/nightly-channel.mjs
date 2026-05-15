import { access, readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const NIGHTLY_UPDATER_ENDPOINT =
  "https://github.com/adamgell/cmtraceopen/releases/download/nightly/latest.json";

const DEFAULT_PACKAGE_JSON_PATH = "package.json";
const DEFAULT_TAURI_CONFIG_PATH = "src-tauri/tauri.conf.json";
const DEFAULT_LITE_TAURI_CONFIG_PATH = "src-tauri/tauri.lite.conf.json";
const DEFAULT_CARGO_TOML_PATH = "src-tauri/Cargo.toml";
const DEFAULT_INSTALLER_PACKAGE_PATH = "src-tauri/installer/package.signed.json";

export const NIGHTLY_PRODUCT_NAME = "CMTrace Open Nightly";
export const NIGHTLY_LITE_PRODUCT_NAME = "CMTrace Open Lite Nightly";
export const NIGHTLY_IDENTIFIER = "com.cmtrace.open.nightly";
export const NIGHTLY_INSTALL_DIR = "%ProgramFiles%\\CMTrace Open Nightly";
export const NIGHTLY_UPGRADE_CODE = "{7B16F0D6-2B7B-4D4B-9F71-4F1A9F64C0E3}";

const NIGHTLY_FULL_EXE_NAME = "cmtrace-open-nightly.exe";
const NIGHTLY_LITE_EXE_NAME = "cmtrace-open-lite-nightly.exe";
const NIGHTLY_FULL_BINARY_NAME = "cmtrace-open-nightly";
const NIGHTLY_LITE_BINARY_NAME = "cmtrace-open-lite-nightly";
const INSTALLER_TARGETS = [
  {
    productName: NIGHTLY_LITE_PRODUCT_NAME,
    stableExeName: "cmtrace-open-lite.exe",
    nightlyExeName: NIGHTLY_LITE_EXE_NAME,
  },
  {
    productName: NIGHTLY_PRODUCT_NAME,
    stableExeName: "cmtrace-open.exe",
    nightlyExeName: NIGHTLY_FULL_EXE_NAME,
  },
];

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

export function deriveNightlyMsiVersion(baseVersion, runNumber) {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(baseVersion);
  if (!match) {
    throw new Error(`Base version must be semver-like for MSI ProductVersion, got ${baseVersion}`);
  }

  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  const run = Number(runNumber);

  if (![major, minor, patch, run].every(Number.isInteger) || run < 1) {
    throw new Error(`Nightly run number must be a positive integer, got ${runNumber}`);
  }

  if (major > 255 || minor > 255) {
    throw new Error(`MSI major and minor versions must be between 0 and 255, got ${baseVersion}`);
  }

  const build = patch + run;
  if (build < 1 || build > 65535) {
    throw new Error(`MSI nightly build number must be between 1 and 65535, got ${build}`);
  }

  return `${major}.${minor}.${build}`;
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

function normalizedWindowsPath(value) {
  return String(value ?? "").replaceAll("/", "\\").toLowerCase();
}

function resolveInstallerTarget(value) {
  const normalizedValue = normalizedWindowsPath(value);
  return INSTALLER_TARGETS.find(
    ({ stableExeName, nightlyExeName }) =>
      normalizedValue.endsWith(stableExeName) || normalizedValue.endsWith(nightlyExeName)
  );
}

function installerTargetPath(target) {
  return `$.installDir\\${target.nightlyExeName}`;
}

function applyNightlyInstallerMetadata(installerPackage, version) {
  installerPackage.packageName = NIGHTLY_PRODUCT_NAME;
  installerPackage.installDir = NIGHTLY_INSTALL_DIR;
  installerPackage.msi ??= {};
  installerPackage.msi.packageName = NIGHTLY_PRODUCT_NAME;
  installerPackage.msi.upgradeCode = NIGHTLY_UPGRADE_CODE;
  installerPackage.msi.installDialog ??= {};
  installerPackage.msi.installDialog.packageDescription = nightlyInstallerDescription(version);

  if (Array.isArray(installerPackage.fileSystemEntries)) {
    for (const entry of installerPackage.fileSystemEntries) {
      const target = resolveInstallerTarget(entry.targetPath);
      if (target) {
        entry.targetPath = installerTargetPath(target);
      }
    }
  }

  if (Array.isArray(installerPackage.shortcuts)) {
    for (const shortcut of installerPackage.shortcuts) {
      const target = resolveInstallerTarget(shortcut.target);
      if (target) {
        shortcut.name = target.productName;
        shortcut.target = installerTargetPath(target);
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
  tauriConfig.mainBinaryName = NIGHTLY_FULL_BINARY_NAME;
  tauriConfig.version = version;
  tauriConfig.identifier = NIGHTLY_IDENTIFIER;
  setWindowTitles(tauriConfig, NIGHTLY_PRODUCT_NAME);
  tauriConfig.plugins ??= {};
  tauriConfig.plugins.updater ??= {};
  tauriConfig.plugins.updater.endpoints = [endpoint];
  await writeJson(tauriPath, tauriConfig);

  const liteTauriConfig = await readJsonIfExists(liteTauriPath);
  if (liteTauriConfig) {
    liteTauriConfig.productName = NIGHTLY_LITE_PRODUCT_NAME;
    liteTauriConfig.mainBinaryName = NIGHTLY_LITE_BINARY_NAME;
    liteTauriConfig.identifier = NIGHTLY_IDENTIFIER;
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

  if (command === "msi-version") {
    const baseVersion = process.env.BASE_VERSION ?? process.argv[3];
    const runNumber = process.env.GITHUB_RUN_NUMBER ?? process.argv[4];
    console.log(
      deriveNightlyMsiVersion(
        requireValue("BASE_VERSION", baseVersion),
        requireValue("GITHUB_RUN_NUMBER", runNumber)
      )
    );
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

  throw new Error("Usage: node .github/scripts/nightly-channel.mjs <apply|manifest|msi-version>");
}

export function isMainModule(importMetaUrl, argvPath = process.argv[1]) {
  if (!argvPath) {
    return false;
  }

  return path.resolve(fileURLToPath(importMetaUrl)) === path.resolve(argvPath);
}

if (isMainModule(import.meta.url)) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
