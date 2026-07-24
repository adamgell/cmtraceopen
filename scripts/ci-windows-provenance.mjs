#!/usr/bin/env node

import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { extname, isAbsolute, relative, resolve, sep } from "node:path";

const OUTPUT_RELATIVE_PATH = ["provenance", "windows-build-provenance.json"];
const TAURI_BUNDLE_MARKER_PREFIX = Buffer.from(
  "__TAURI_BUNDLE_TYPE_VAR_",
  "ascii",
);
const TAURI_STANDALONE_MARKER = Buffer.from(
  "__TAURI_BUNDLE_TYPE_VAR_UNK",
  "ascii",
);
const WINDOWS_BUNDLE_TYPES = [
  {
    directory: "msi",
    extension: ".msi",
    bundleType: "msi",
    marker: Buffer.from("MSI", "ascii"),
  },
  {
    directory: "nsis",
    extension: ".exe",
    bundleType: "nsis",
    marker: Buffer.from("NSS", "ascii"),
  },
];

function fail(message) {
  console.error(message);
  process.exitCode = 1;
}

function requireExactCommit(value, variableName) {
  if (!/^[0-9a-f]{40}$/.test(value ?? "")) {
    throw new Error(
      `${variableName} must be an exact 40-character lowercase commit`,
    );
  }
  return value;
}

function requireWindowsTarget(value) {
  if (!/^[A-Za-z0-9_]+-pc-windows-[A-Za-z0-9_]+$/.test(value ?? "")) {
    throw new Error("TARGET_TRIPLE must identify a Windows target");
  }
  return value;
}

function assertNoSymlink(path, label) {
  const entry = lstatSync(path, { throwIfNoEntry: false });
  if (!entry) {
    throw new Error(`${label} does not exist: ${path}`);
  }
  if (entry.isSymbolicLink()) {
    throw new Error(`${label} cannot be a symbolic link or junction`);
  }
  return entry;
}

function resolveReleaseRoot(input, target) {
  if (!input) {
    throw new Error("RELEASE_ROOT is required");
  }
  if (isAbsolute(input) || /^[A-Za-z]:/.test(input)) {
    throw new Error("RELEASE_ROOT must be a target-specific release directory");
  }

  const workspaceRoot = realpathSync.native(process.cwd());
  const targetRoot = resolve(workspaceRoot, "src-tauri", "target");
  const releaseRoot = resolve(workspaceRoot, input);
  const relativeRoot = relative(targetRoot, releaseRoot);
  const parts = relativeRoot.split(sep);
  if (
    isAbsolute(relativeRoot) ||
    parts.length !== 2 ||
    parts[0] !== target ||
    parts[1].toLowerCase() !== "release"
  ) {
    throw new Error("RELEASE_ROOT must be a target-specific release directory");
  }

  let current = workspaceRoot;
  for (const part of ["src-tauri", "target", target, "release"]) {
    current = resolve(current, part);
    assertNoSymlink(current, "release path component");
  }
  return releaseRoot;
}

function expectedVersion() {
  const packageJson = JSON.parse(readFileSync("package.json", "utf8"));
  if (typeof packageJson.version !== "string" || packageJson.version === "") {
    throw new Error("package.json must declare a non-empty version");
  }
  return packageJson.version;
}

function hashBytes(bytes) {
  return {
    bytes: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
}

function hashFile(path) {
  return hashBytes(readFileSync(path));
}

function evidenceForFile(path, displayPath) {
  const entry = assertNoSymlink(path, displayPath);
  if (!entry.isFile()) {
    throw new Error(`${displayPath} must be a regular file`);
  }
  return { path: displayPath, ...hashFile(path) };
}

function locateStandaloneBundleMarker(executableBytes) {
  const markerOffset = executableBytes.indexOf(TAURI_STANDALONE_MARKER);
  const duplicateOffset =
    markerOffset < 0
      ? -1
      : executableBytes.indexOf(
          TAURI_STANDALONE_MARKER,
          markerOffset + TAURI_STANDALONE_MARKER.length,
        );
  if (markerOffset < 0 || duplicateOffset >= 0) {
    throw new Error(
      "Windows release executable must contain exactly one Tauri standalone bundle marker",
    );
  }
  return markerOffset;
}

function expectedInstalledExecutableEvidence(
  executableBytes,
  markerOffset,
  bundleSpec,
) {
  const installedBytes = Buffer.from(executableBytes);
  bundleSpec.marker.copy(
    installedBytes,
    markerOffset + TAURI_BUNDLE_MARKER_PREFIX.length,
  );
  return {
    path: "cmtrace-open.exe",
    ...hashBytes(installedBytes),
    derivation: "tauriBundleTypeMarkerV1",
  };
}

function bundleSpecForInstaller(displayPath) {
  const pathParts = displayPath.split("/");
  const extension = extname(displayPath).toLowerCase();
  const bundleSpec = WINDOWS_BUNDLE_TYPES.find(
    (candidate) =>
      pathParts.length === 2 &&
      pathParts[0] === candidate.directory &&
      extension === candidate.extension,
  );
  if (!bundleSpec) {
    throw new Error(
      `Windows installer must use a canonical Windows bundle path: ${displayPath}`,
    );
  }
  return bundleSpec;
}

function installerEvidence(path, displayPath, executableBytes, markerOffset) {
  const bundleSpec = bundleSpecForInstaller(displayPath);
  return {
    ...evidenceForFile(path, displayPath),
    bundleType: bundleSpec.bundleType,
    expectedInstalledExecutable: expectedInstalledExecutableEvidence(
      executableBytes,
      markerOffset,
      bundleSpec,
    ),
  };
}

function collectInstallers(
  bundleRoot,
  executableBytes,
  markerOffset,
  current = bundleRoot,
  installers = [],
) {
  for (const entry of readdirSync(current, { withFileTypes: true })) {
    const path = resolve(current, entry.name);
    if (entry.isSymbolicLink()) {
      throw new Error(
        "Windows bundle cannot contain symbolic links or junctions",
      );
    }
    if (entry.isDirectory()) {
      collectInstallers(
        bundleRoot,
        executableBytes,
        markerOffset,
        path,
        installers,
      );
      continue;
    }
    const extension = extname(entry.name).toLowerCase();
    if (entry.isFile() && (extension === ".msi" || extension === ".exe")) {
      const displayPath = relative(bundleRoot, path).split(sep).join("/");
      installers.push(
        installerEvidence(path, displayPath, executableBytes, markerOffset),
      );
    }
  }
  return installers;
}

function writeManifest(bundleRoot, manifest) {
  const outputDirectory = resolve(bundleRoot, OUTPUT_RELATIVE_PATH[0]);
  const existingDirectory = lstatSync(outputDirectory, {
    throwIfNoEntry: false,
  });
  if (existingDirectory?.isSymbolicLink()) {
    throw new Error(
      "provenance output directory cannot be a symbolic link or junction",
    );
  }
  mkdirSync(outputDirectory, { recursive: true });

  const outputPath = resolve(bundleRoot, ...OUTPUT_RELATIVE_PATH);
  const temporaryPath = `${outputPath}.tmp-${process.pid}`;
  try {
    writeFileSync(temporaryPath, `${JSON.stringify(manifest, null, 2)}\n`, {
      encoding: "utf8",
      flag: "wx",
    });
    renameSync(temporaryPath, outputPath);
  } finally {
    rmSync(temporaryPath, { force: true });
  }
  return outputPath;
}

try {
  const sourceCommit = requireExactCommit(
    process.env.SOURCE_COMMIT,
    "SOURCE_COMMIT",
  );
  const buildCommit = requireExactCommit(process.env.GITHUB_SHA, "GITHUB_SHA");
  const target = requireWindowsTarget(process.env.TARGET_TRIPLE);
  const releaseRoot = resolveReleaseRoot(process.env.RELEASE_ROOT, target);
  const bundleRoot = resolve(releaseRoot, "bundle");
  const bundleEntry = assertNoSymlink(bundleRoot, "Windows bundle directory");
  if (!bundleEntry.isDirectory()) {
    throw new Error("Windows bundle directory must be a directory");
  }

  const executablePath = resolve(releaseRoot, "cmtrace-open.exe");
  if (!existsSync(executablePath)) {
    throw new Error("Windows release executable is missing");
  }
  const executableEntry = assertNoSymlink(
    executablePath,
    "Windows release executable",
  );
  if (!executableEntry.isFile()) {
    throw new Error("Windows release executable must be a regular file");
  }
  const executableBytes = readFileSync(executablePath);
  const markerOffset = locateStandaloneBundleMarker(executableBytes);
  const installers = collectInstallers(
    bundleRoot,
    executableBytes,
    markerOffset,
  ).sort((left, right) => left.path.localeCompare(right.path));
  if (installers.length === 0) {
    throw new Error("No Windows installer packages were found");
  }

  const manifest = {
    schemaVersion: 2,
    sourceCommit,
    buildCommit,
    target,
    packageVersion: expectedVersion(),
    releaseExecutable: {
      path: "cmtrace-open.exe",
      ...hashBytes(executableBytes),
    },
    installers,
  };
  const outputPath = writeManifest(bundleRoot, manifest);
  console.log(`Recorded exact Windows build provenance at ${outputPath}`);
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}
