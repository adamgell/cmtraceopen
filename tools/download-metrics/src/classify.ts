import type {
  Architecture,
  AssetClassification,
  ClassifiedReleaseAsset,
  SourceLabel,
} from "./types";

const RELEASE_STEM = String.raw`(?:\d+\.\d+\.\d+|Nightly_\d{8}_\d+_[0-9a-fA-F]+)`;
const WINDOWS_STEM = String.raw`CMTrace-Open_${RELEASE_STEM}`;
const WINDOWS_LITE_STEM = String.raw`CMTrace-Open-Lite_${RELEASE_STEM}`;
const MACOS_STEM = String.raw`(?:CMTrace\.Open_\d+\.\d+\.\d+_aarch64|CMTrace-Open_Nightly_\d{8}_\d+_[0-9a-fA-F]+_macOS-arm64)`;
const LINUX_STEM = String.raw`CMTrace\.Open_${RELEASE_STEM}_amd64`;
const RPM_STEM = String.raw`CMTrace\.Open-${RELEASE_STEM}-1\.x86_64`;

const UPDATER_ARCHIVE_SIGNATURE = new RegExp(`^${MACOS_STEM}\\.app\\.tar\\.gz\\.sig$`);
const UPDATER_ARCHIVE = new RegExp(`^${MACOS_STEM}\\.app\\.tar\\.gz$`);
const SETUP_SIGNATURE = new RegExp(`^${WINDOWS_STEM}_(x64|arm64)-setup\\.exe\\.sig$`);
const SETUP = new RegExp(`^${WINDOWS_STEM}_(x64|arm64)-setup\\.exe$`);
const DMG = new RegExp(`^${MACOS_STEM}\\.dmg$`);
const APPIMAGE_SIGNATURE = new RegExp(`^${LINUX_STEM}\\.AppImage\\.sig$`);
const APPIMAGE = new RegExp(`^${LINUX_STEM}\\.AppImage$`);
const DEB_SIGNATURE = new RegExp(`^${LINUX_STEM}\\.deb\\.sig$`);
const DEB = new RegExp(`^${LINUX_STEM}\\.deb$`);
const RPM_SIGNATURE = new RegExp(`^${RPM_STEM}\\.rpm\\.sig$`);
const RPM = new RegExp(`^${RPM_STEM}\\.rpm$`);
const MSI = new RegExp(`^${WINDOWS_STEM}_(x64|arm64)\\.msi$`);
const LITE_PORTABLE_EXE = new RegExp(`^${WINDOWS_LITE_STEM}_(x64|arm64)\\.exe$`);
const FULL_PORTABLE_EXE = new RegExp(`^${WINDOWS_STEM}_(x64|arm64)\\.exe$`);

const UNKNOWN: AssetClassification = {
  platform: "unknown",
  architecture: "unknown",
  edition: "unknown",
  packageType: "unknown",
  deliveryRole: "unknown",
};

const SOURCE_LABELS = new Set<SourceLabel>([
  "download-home",
  "github-readme",
  "github-release",
  "cmtraceopen-product",
  "nightly-builds-page",
  "project-docs",
]);

function windowsClassification(
  architecture: Architecture,
  packageType: "portable-exe" | "msi" | "nsis-setup" | "signature",
  edition: "full" | "lite" = "full",
): AssetClassification {
  return {
    platform: "windows",
    architecture,
    edition,
    packageType,
    deliveryRole:
      packageType === "signature"
        ? "supporting-file"
        : packageType === "nsis-setup"
          ? "mixed-manual-update"
          : "manual-only",
  };
}

function linuxClassification(
  packageType: "appimage" | "deb" | "rpm" | "signature",
): AssetClassification {
  return {
    platform: "linux",
    architecture: "x64",
    edition: "full",
    packageType,
    deliveryRole:
      packageType === "signature"
        ? "supporting-file"
        : packageType === "appimage"
          ? "mixed-manual-update"
          : "manual-only",
  };
}

export function classifyAsset(name: string): AssetClassification {
  if (/^latest\.json$/.test(name)) {
    return {
      platform: "cross-platform",
      architecture: "unknown",
      edition: "not-applicable",
      packageType: "updater-manifest",
      deliveryRole: "updater-only",
    };
  }

  if (/^sbom-[A-Za-z0-9._-]+\.cdx\.json$/.test(name)) {
    return {
      platform: "cross-platform",
      architecture: "unknown",
      edition: "not-applicable",
      packageType: "sbom",
      deliveryRole: "supporting-file",
    };
  }

  if (UPDATER_ARCHIVE_SIGNATURE.test(name)) {
    return {
      platform: "macos",
      architecture: "arm64",
      edition: "full",
      packageType: "signature",
      deliveryRole: "supporting-file",
    };
  }

  if (UPDATER_ARCHIVE.test(name)) {
    return {
      platform: "macos",
      architecture: "arm64",
      edition: "full",
      packageType: "updater-archive",
      deliveryRole: "updater-only",
    };
  }

  const setupSignature = SETUP_SIGNATURE.exec(name);
  if (setupSignature) {
    return windowsClassification(setupSignature[1] as Architecture, "signature");
  }

  const setup = SETUP.exec(name);
  if (setup) {
    return windowsClassification(setup[1] as Architecture, "nsis-setup");
  }

  if (DMG.test(name)) {
    return {
      platform: "macos",
      architecture: "arm64",
      edition: "full",
      packageType: "dmg",
      deliveryRole: "manual-only",
    };
  }

  if (APPIMAGE_SIGNATURE.test(name)) {
    return linuxClassification("signature");
  }

  if (APPIMAGE.test(name)) {
    return linuxClassification("appimage");
  }

  if (DEB_SIGNATURE.test(name)) {
    return linuxClassification("signature");
  }

  if (DEB.test(name)) {
    return linuxClassification("deb");
  }

  if (RPM_SIGNATURE.test(name)) {
    return linuxClassification("signature");
  }

  if (RPM.test(name)) {
    return linuxClassification("rpm");
  }

  const msi = MSI.exec(name);
  if (msi) {
    return windowsClassification(msi[1] as Architecture, "msi");
  }

  const litePortableExe = LITE_PORTABLE_EXE.exec(name);
  if (litePortableExe) {
    return windowsClassification(litePortableExe[1] as Architecture, "portable-exe", "lite");
  }

  const fullPortableExe = FULL_PORTABLE_EXE.exec(name);
  if (fullPortableExe) {
    return windowsClassification(fullPortableExe[1] as Architecture, "portable-exe");
  }

  if (/^.+\.sig$/.test(name)) {
    return {
      platform: "unknown",
      architecture: "unknown",
      edition: "unknown",
      packageType: "signature",
      deliveryRole: "supporting-file",
    };
  }

  return { ...UNKNOWN };
}

export function recommendationRank(asset: ClassifiedReleaseAsset): number | null {
  if (
    asset.platform === "windows" &&
    asset.architecture === "x64" &&
    asset.edition === "full" &&
    asset.packageType === "portable-exe"
  ) {
    return 0;
  }

  if (
    asset.platform === "macos" &&
    asset.architecture === "arm64" &&
    asset.edition === "full" &&
    asset.packageType === "dmg"
  ) {
    return 10;
  }

  if (
    asset.platform === "linux" &&
    asset.architecture === "x64" &&
    asset.edition === "full" &&
    asset.packageType === "appimage"
  ) {
    return 20;
  }

  return null;
}

export function normalizeSource(value: string | null): SourceLabel {
  return value !== null && SOURCE_LABELS.has(value as SourceLabel)
    ? (value as SourceLabel)
    : "unknown";
}
