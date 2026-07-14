import {
  access,
  mkdir,
  readFile,
  realpath,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { fileURLToPath } from "node:url";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
} from "node:path";

import { listReleases, type Fetcher } from "./github";
import { reconcileSnapshots } from "./reconcile";
import { buildSummary, toCsv } from "./report";
import type { Snapshot } from "./types";

const DEFAULT_REPOSITORY_ROOT = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const TEMP_DIRECTORY = ".download-metrics-tmp";
const REPORT_BACKUP_DIRECTORY = ".download-metrics-reports-backup";
const SNAPSHOT_BACKUP_FILE = ".download-metrics-snapshot-backup";

export type CollectOptions = {
  outputDirectory: string;
  previousPath?: string;
  fetcher?: Fetcher;
  clock?: () => Date;
  token?: string;
  repositoryRoot?: string;
};

export type CollectPaths = {
  snapshot: string;
  latestJson: string;
  latestCsv: string;
  summary: string;
};

export type CollectResult = {
  snapshot: Snapshot;
  paths: CollectPaths;
};

export type CollectDependencies = {
  fetcher?: Fetcher;
  clock?: () => Date;
  env?: Record<string, string | undefined>;
  repositoryRoot?: string;
  reportError?: (message: string) => void;
};

function isAtOrBelow(candidate: string, parent: string): boolean {
  const pathFromParent = relative(parent, candidate);
  return (
    pathFromParent === "" ||
    (!pathFromParent.startsWith("..") && !isAbsolute(pathFromParent))
  );
}

async function canonicalPath(path: string): Promise<string> {
  const missingSegments: string[] = [];
  let cursor = resolve(path);

  for (;;) {
    try {
      return resolve(await realpath(cursor), ...missingSegments);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "ENOENT" && code !== "ENOTDIR") {
        throw error;
      }
      const parent = dirname(cursor);
      if (parent === cursor) {
        return resolve(cursor, ...missingSegments);
      }
      missingSegments.unshift(basename(cursor));
      cursor = parent;
    }
  }
}

async function safeOutputDirectory(
  outputDirectory: string,
  repositoryRoot: string,
): Promise<string> {
  if (outputDirectory.trim() === "") {
    throw new Error("Unsafe output directory: the path is empty");
  }

  const output = await canonicalPath(outputDirectory);
  const root = await canonicalPath(repositoryRoot);
  const gitDirectory = await canonicalPath(join(repositoryRoot, ".git"));
  if (output === root || isAtOrBelow(output, gitDirectory)) {
    throw new Error(
      "Unsafe output directory: repository root and .git paths are not allowed",
    );
  }
  return output;
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

async function readPrevious(path: string): Promise<Snapshot | null> {
  try {
    return JSON.parse(await readFile(path, "utf8")) as Snapshot;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }
    throw new Error(
      `Unable to read previous snapshot ${path}: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

function timestampFileName(capturedAt: string): string {
  return `${capturedAt.replaceAll(":", "-")}.json`;
}

function json(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

async function restorePath(backup: string, destination: string): Promise<void> {
  if (!(await pathExists(backup))) {
    return;
  }
  await rm(destination, { recursive: true, force: true });
  await rename(backup, destination);
}

async function publishAtomically(
  output: string,
  paths: CollectPaths,
  snapshotContents: string,
  csvContents: string,
  summaryContents: string,
): Promise<void> {
  const staging = join(output, TEMP_DIRECTORY);
  const stagedSnapshot = join(staging, "snapshot.json");
  const stagedReports = join(staging, "reports");
  const reports = join(output, "reports");
  const reportsBackup = join(output, REPORT_BACKUP_DIRECTORY);
  const snapshotBackup = join(output, SNAPSHOT_BACKUP_FILE);
  let reportsBackedUp = false;
  let snapshotBackedUp = false;
  let snapshotInstalled = false;
  let reportsInstalled = false;

  await mkdir(output, { recursive: true });
  await rm(staging, { recursive: true, force: true });
  await rm(reportsBackup, { recursive: true, force: true });
  await rm(snapshotBackup, { force: true });

  try {
    await mkdir(stagedReports, { recursive: true });
    await Promise.all([
      writeFile(stagedSnapshot, snapshotContents, { encoding: "utf8", flag: "wx" }),
      writeFile(join(stagedReports, "latest-assets.json"), snapshotContents, {
        encoding: "utf8",
        flag: "wx",
      }),
      writeFile(join(stagedReports, "latest-assets.csv"), csvContents, {
        encoding: "utf8",
        flag: "wx",
      }),
      writeFile(join(stagedReports, "summary.json"), summaryContents, {
        encoding: "utf8",
        flag: "wx",
      }),
    ]);

    await mkdir(dirname(paths.snapshot), { recursive: true });
    if (await pathExists(reports)) {
      await rename(reports, reportsBackup);
      reportsBackedUp = true;
    }
    if (await pathExists(paths.snapshot)) {
      await rename(paths.snapshot, snapshotBackup);
      snapshotBackedUp = true;
    }

    await rename(stagedSnapshot, paths.snapshot);
    snapshotInstalled = true;
    await rename(stagedReports, reports);
    reportsInstalled = true;

    await rm(reportsBackup, { recursive: true, force: true });
    await rm(snapshotBackup, { force: true });
  } catch (error) {
    if (reportsInstalled) {
      await rm(reports, { recursive: true, force: true });
    }
    if (snapshotInstalled) {
      await rm(paths.snapshot, { force: true });
    }
    if (reportsBackedUp) {
      await restorePath(reportsBackup, reports);
    }
    if (snapshotBackedUp) {
      await restorePath(snapshotBackup, paths.snapshot);
    }
    throw error;
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
}

export async function collectDownloads(
  options: CollectOptions,
): Promise<CollectResult> {
  const output = await safeOutputDirectory(
    options.outputDirectory,
    options.repositoryRoot ?? DEFAULT_REPOSITORY_ROOT,
  );
  const capturedAt = (options.clock ?? (() => new Date()))().toISOString();
  const previousPath = options.previousPath ?? join(output, "reports/latest-assets.json");
  const previous = await readPrevious(resolve(previousPath));
  const releases = await listReleases(options.fetcher ?? fetch, options.token);
  const snapshot = reconcileSnapshots(previous, releases, capturedAt);
  const paths: CollectPaths = {
    snapshot: join(
      output,
      "snapshots",
      capturedAt.slice(0, 4),
      capturedAt.slice(5, 7),
      timestampFileName(capturedAt),
    ),
    latestJson: join(output, "reports/latest-assets.json"),
    latestCsv: join(output, "reports/latest-assets.csv"),
    summary: join(output, "reports/summary.json"),
  };

  await publishAtomically(
    output,
    paths,
    json(snapshot),
    toCsv(snapshot),
    json(buildSummary(snapshot)),
  );
  return { snapshot, paths };
}

function parseArguments(argv: string[]): {
  outputDirectory: string;
  previousPath?: string;
} {
  let outputDirectory: string | undefined;
  let previousPath: string | undefined;

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument !== "--output" && argument !== "--previous") {
      throw new Error(`Unknown argument: ${argument}`);
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) {
      throw new Error(`Missing value for ${argument}`);
    }
    if (argument === "--output") {
      if (outputDirectory !== undefined) {
        throw new Error("Duplicate --output argument");
      }
      outputDirectory = value;
    } else {
      if (previousPath !== undefined) {
        throw new Error("Duplicate --previous argument");
      }
      previousPath = value;
    }
    index += 1;
  }

  if (outputDirectory === undefined) {
    throw new Error("Usage: npm run collect -- --output <directory> [--previous <latest.json>]");
  }
  return { outputDirectory, previousPath };
}

function redact(message: string, token: string | undefined): string {
  return token ? message.replaceAll(token, "[REDACTED]") : message;
}

export async function runCli(
  argv: string[] = process.argv.slice(2),
  dependencies: CollectDependencies = {},
): Promise<number> {
  const env = dependencies.env ?? process.env;
  const token = env.GITHUB_TOKEN;
  try {
    const arguments_ = parseArguments(argv);
    await collectDownloads({
      ...arguments_,
      token,
      fetcher: dependencies.fetcher,
      clock: dependencies.clock,
      repositoryRoot: dependencies.repositoryRoot,
    });
    return 0;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    (dependencies.reportError ?? console.error)(redact(message, token));
    return 1;
  }
}

if (
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  process.exitCode = await runCli();
}
