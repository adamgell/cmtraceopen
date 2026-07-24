#!/usr/bin/env node

import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
} from "node:fs";
import {
  basename,
  extname,
  isAbsolute,
  relative,
  resolve,
  sep,
} from "node:path";

const PACKAGE_EXTENSIONS = new Set([
  ".appimage",
  ".deb",
  ".dmg",
  ".exe",
  ".msi",
]);

function fail(message) {
  console.error(message);
  process.exitCode = 1;
}

function resolveTargetBundleRoot(input) {
  if (!input) {
    throw new Error("BUNDLE_ROOT is required");
  }

  if (isAbsolute(input)) {
    throw new Error(
      "BUNDLE_ROOT must be a target-specific release bundle directory",
    );
  }
  if (/^[A-Za-z]:/.test(input)) {
    throw new Error("BUNDLE_ROOT cannot be a drive-qualified path");
  }

  const workspaceRoot = realpathSync.native(process.cwd());
  const targetRoot = resolve(workspaceRoot, "src-tauri", "target");
  const root = resolve(workspaceRoot, input);
  const relativeRoot = relative(targetRoot, root);
  if (isAbsolute(relativeRoot)) {
    throw new Error(
      "BUNDLE_ROOT must be a target-specific release bundle directory",
    );
  }
  const parts = relativeRoot.split(sep);
  const normalized = parts.map((part) => part.toLowerCase());
  const isTargetBundle =
    normalized.length === 3 &&
    normalized[0] !== "" &&
    normalized[0] !== "." &&
    normalized[0] !== ".." &&
    normalized[1] === "release" &&
    normalized[2] === "bundle";

  if (!isTargetBundle) {
    throw new Error(
      "BUNDLE_ROOT must be a target-specific release bundle directory",
    );
  }

  let current = workspaceRoot;
  for (const part of ["src-tauri", "target", parts[0], "release", "bundle"]) {
    current = resolve(current, part);
    const stats = lstatSync(current, { throwIfNoEntry: false });
    if (!stats) {
      break;
    }
    if (stats.isSymbolicLink()) {
      throw new Error(
        "BUNDLE_ROOT cannot traverse a symbolic link or junction",
      );
    }
  }

  return root;
}

function collectPackages(root, current = root, packages = []) {
  for (const entry of readdirSync(current, { withFileTypes: true })) {
    const path = resolve(current, entry.name);
    if (entry.isDirectory()) {
      collectPackages(root, path, packages);
    } else if (
      entry.isFile() &&
      PACKAGE_EXTENSIONS.has(extname(entry.name).toLowerCase())
    ) {
      packages.push(relative(root, path));
    }
  }
  return packages;
}

function expectedVersion() {
  const packageJson = JSON.parse(readFileSync("package.json", "utf8"));
  if (typeof packageJson.version !== "string" || packageJson.version === "") {
    throw new Error("package.json must declare a non-empty version");
  }
  return packageJson.version;
}

function packageVersion(path) {
  const fields = basename(path).split("_");
  return fields.length >= 3 ? fields[1] : undefined;
}

function clean(root) {
  rmSync(root, { recursive: true, force: true });
  console.log(`Removed cached bundle outputs from ${root}`);
}

function verify(root) {
  if (!existsSync(root)) {
    throw new Error(`No bundle packages found under ${root}`);
  }

  const packages = collectPackages(root).sort((left, right) =>
    left.localeCompare(right),
  );
  if (packages.length === 0) {
    throw new Error(`No bundle packages found under ${root}`);
  }

  const version = expectedVersion();
  const unexpected = packages.filter(
    (path) => packageVersion(path) !== version,
  );

  if (unexpected.length > 0) {
    throw new Error(
      `Unexpected bundle versions for ${version}: ${unexpected.join(", ")}`,
    );
  }

  console.log(
    `Verified ${packages.length} current-version bundle packages for ${version}`,
  );
}

try {
  const mode = process.argv[2];
  const root = resolveTargetBundleRoot(process.env.BUNDLE_ROOT);
  if (mode === "clean") {
    clean(root);
  } else if (mode === "verify") {
    verify(root);
  } else {
    throw new Error("Usage: ci-bundle-outputs.mjs <clean|verify>");
  }
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}
