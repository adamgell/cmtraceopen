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
  statSync,
  writeFileSync,
} from "node:fs";
import { extname, isAbsolute, relative, resolve, sep } from "node:path";

const OUTPUT_RELATIVE_PATH = ["provenance", "windows-build-provenance.json"];

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

function hashFile(path) {
  const bytes = readFileSync(path);
  return {
    bytes: statSync(path).size,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
}

function evidenceForFile(path, displayPath) {
  const entry = assertNoSymlink(path, displayPath);
  if (!entry.isFile()) {
    throw new Error(`${displayPath} must be a regular file`);
  }
  return { path: displayPath, ...hashFile(path) };
}

function collectInstallers(bundleRoot, current = bundleRoot, installers = []) {
  for (const entry of readdirSync(current, { withFileTypes: true })) {
    const path = resolve(current, entry.name);
    if (entry.isSymbolicLink()) {
      throw new Error(
        "Windows bundle cannot contain symbolic links or junctions",
      );
    }
    if (entry.isDirectory()) {
      collectInstallers(bundleRoot, path, installers);
      continue;
    }
    const extension = extname(entry.name).toLowerCase();
    if (entry.isFile() && (extension === ".msi" || extension === ".exe")) {
      installers.push(
        evidenceForFile(path, relative(bundleRoot, path).split(sep).join("/")),
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
  const installers = collectInstallers(bundleRoot).sort((left, right) =>
    left.path.localeCompare(right.path),
  );
  if (installers.length === 0) {
    throw new Error("No Windows installer packages were found");
  }

  const manifest = {
    schemaVersion: 1,
    sourceCommit,
    buildCommit,
    target,
    packageVersion: expectedVersion(),
    releaseExecutable: evidenceForFile(executablePath, "cmtrace-open.exe"),
    installers,
  };
  const outputPath = writeManifest(bundleRoot, manifest);
  console.log(`Recorded exact Windows build provenance at ${outputPath}`);
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}
