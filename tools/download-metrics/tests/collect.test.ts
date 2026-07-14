import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  collectDownloads,
  runCli,
  type CollectDependencies,
} from "../src/collect";
import type { GitHubAsset, GitHubRelease, Snapshot } from "../src/types";

const CAPTURED_AT = "2026-07-14T00:17:00.000Z";
const createdRoots: string[] = [];

afterEach(async () => {
  const { rm } = await import("node:fs/promises");
  await Promise.all(createdRoots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function temporaryRoot(): Promise<string> {
  const root = await realpath(await mkdtemp(join(tmpdir(), "cmtrace-metrics-")));
  createdRoots.push(root);
  return root;
}

function asset(
  id: number,
  name: string,
  downloadCount: number,
): GitHubAsset {
  return {
    id,
    name,
    created_at: "2026-07-13T10:00:00Z",
    updated_at: "2026-07-13T11:00:00Z",
    size: 1_024 + id,
    content_type: "application/octet-stream",
    download_count: downloadCount,
    browser_download_url: `https://github.com/adamgell/cmtraceopen/releases/download/v1.4.0/${name}`,
  };
}

function releases(counts: { portable: number; setup: number; manifest: number }): GitHubRelease[] {
  return [
    {
      id: 14,
      tag_name: "v1.4.0",
      name: "CMTrace Open 1.4.0",
      published_at: "2026-04-01T12:30:00Z",
      prerelease: false,
      draft: false,
      assets: [
        asset(101, "CMTrace-Open_1.4.0_x64.exe", counts.portable),
        asset(102, "CMTrace-Open_1.4.0_x64-setup.exe", counts.setup),
      ],
    },
    {
      id: 15,
      tag_name: "nightly",
      name: "Nightly",
      published_at: "2026-07-13T12:30:00Z",
      prerelease: true,
      draft: false,
      assets: [asset(103, "latest.json", counts.manifest)],
    },
  ];
}

function fetcherFor(payload: GitHubRelease[]) {
  return vi.fn(async () => Response.json(payload));
}

const clock = () => new Date(CAPTURED_AT);

async function expectMissing(path: string): Promise<void> {
  await expect(access(path)).rejects.toThrow();
}

describe("deterministic download collection", () => {
  it("writes only the exact snapshot and report set beneath the provided output directory", async () => {
    const root = await temporaryRoot();
    const output = join(root, "provided-output");
    const sentinel = join(root, "outside.txt");
    await writeFile(sentinel, "untouched\n");

    const result = await collectDownloads({
      outputDirectory: output,
      fetcher: fetcherFor(releases({ portable: 12, setup: 8, manifest: 30 })),
      clock,
      repositoryRoot: join(root, "source-repository"),
    });

    const snapshotPath = join(
      output,
      "snapshots/2026/07/2026-07-14T00-17-00.000Z.json",
    );
    expect(result.paths).toEqual({
      snapshot: snapshotPath,
      latestJson: join(output, "reports/latest-assets.json"),
      latestCsv: join(output, "reports/latest-assets.csv"),
      summary: join(output, "reports/summary.json"),
    });

    const snapshot = JSON.parse(await readFile(snapshotPath, "utf8")) as Snapshot;
    expect(snapshot).toMatchObject({
      schemaVersion: 1,
      repository: "adamgell/cmtraceopen",
      capturedAt: CAPTURED_AT,
    });
    expect(snapshot.assets).toHaveLength(3);
    expect(await readFile(join(output, "reports/latest-assets.json"), "utf8")).toBe(
      `${JSON.stringify(snapshot, null, 2)}\n`,
    );

    const csv = await readFile(join(output, "reports/latest-assets.csv"), "utf8");
    expect(csv.split("\n", 1)[0]).toBe(
      "snapshot_at,release_id,release_tag,channel,published_at,prerelease,asset_id,name,created_at,updated_at,size,content_type,download_count,delta,platform,architecture,edition,package_type,delivery_role,status",
    );
    const summary = JSON.parse(await readFile(join(output, "reports/summary.json"), "utf8"));
    expect(summary).toEqual({
      "manual-only": { cumulative: 12, delta: 0 },
      "mixed-manual-update": { cumulative: 8, delta: 0 },
      "updater-only": { cumulative: 30, delta: 0 },
      "supporting-file": { cumulative: 0, delta: 0 },
      unknown: { cumulative: 0, delta: 0 },
    });
    expect(await readFile(sentinel, "utf8")).toBe("untouched\n");
    await expectMissing(join(root, "snapshots"));
    await expectMissing(join(root, "reports"));
  });

  it("uses the prior latest report by default and emits real deltas", async () => {
    const root = await temporaryRoot();
    const output = join(root, "output");
    const options = {
      outputDirectory: output,
      clock,
      repositoryRoot: join(root, "source-repository"),
    };
    await collectDownloads({
      ...options,
      fetcher: fetcherFor(releases({ portable: 12, setup: 8, manifest: 30 })),
    });
    await collectDownloads({
      ...options,
      clock: () => new Date("2026-07-15T00:17:00.000Z"),
      fetcher: fetcherFor(releases({ portable: 14, setup: 9, manifest: 35 })),
    });

    const summary = JSON.parse(await readFile(join(output, "reports/summary.json"), "utf8"));
    expect(summary).toMatchObject({
      "manual-only": { cumulative: 14, delta: 2 },
      "mixed-manual-update": { cumulative: 9, delta: 1 },
      "updater-only": { cumulative: 35, delta: 5 },
    });
  });
});

describe("collector safety and failure behavior", () => {
  it.each(["repository root", ".git", ".git descendant"])(
    "rejects the %s as an output directory without writing",
    async (kind) => {
      const root = await temporaryRoot();
      const repositoryRoot = join(root, "repository");
      const output =
        kind === "repository root"
          ? repositoryRoot
          : kind === ".git"
            ? join(repositoryRoot, ".git")
            : join(repositoryRoot, ".git", "objects");

      await expect(
        collectDownloads({
          outputDirectory: output,
          fetcher: fetcherFor([]),
          clock,
          repositoryRoot,
        }),
      ).rejects.toThrow("Unsafe output directory");
      await expectMissing(output);
    },
  );

  it("rejects an output symlink that resolves inside .git", async () => {
    const root = await temporaryRoot();
    const repositoryRoot = join(root, "repository");
    const gitTarget = join(repositoryRoot, ".git", "metrics");
    const outputLink = join(root, "output-link");
    await mkdir(gitTarget, { recursive: true });
    await symlink(gitTarget, outputLink);

    await expect(
      collectDownloads({
        outputDirectory: outputLink,
        fetcher: fetcherFor([]),
        clock,
        repositoryRoot,
      }),
    ).rejects.toThrow("Unsafe output directory");
    await expectMissing(join(gitTarget, "reports"));
  });

  it.each([
    ["GitHub API failure", () => vi.fn(async () => new Response("no", { status: 503, statusText: "Unavailable" }))],
    ["invalid count", () => fetcherFor(releases({ portable: -1, setup: 8, manifest: 30 }))],
    ["negative delta", () => fetcherFor(releases({ portable: 11, setup: 8, manifest: 30 }))],
  ])("preserves the last valid reports after %s", async (_label, failingFetcher) => {
    const root = await temporaryRoot();
    const output = join(root, "output");
    const base = {
      outputDirectory: output,
      clock,
      repositoryRoot: join(root, "source-repository"),
    };
    await collectDownloads({
      ...base,
      fetcher: fetcherFor(releases({ portable: 12, setup: 8, manifest: 30 })),
    });
    const before = await Promise.all(
      ["latest-assets.json", "latest-assets.csv", "summary.json"].map((name) =>
        readFile(join(output, "reports", name), "utf8"),
      ),
    );

    await expect(
      collectDownloads({ ...base, fetcher: failingFetcher() }),
    ).rejects.toThrow();

    const after = await Promise.all(
      ["latest-assets.json", "latest-assets.csv", "summary.json"].map((name) =>
        readFile(join(output, "reports", name), "utf8"),
      ),
    );
    expect(after).toEqual(before);
  });

  it("leaves all last-valid reports untouched when publishing cannot create the snapshot path", async () => {
    const root = await temporaryRoot();
    const output = join(root, "output");
    const reports = join(output, "reports");
    const repositoryRoot = join(root, "source-repository");
    await collectDownloads({
      outputDirectory: output,
      fetcher: fetcherFor(
        releases({ portable: 12, setup: 8, manifest: 30 }),
      ),
      clock,
      repositoryRoot,
    });
    const reportNames = [
      "latest-assets.json",
      "latest-assets.csv",
      "summary.json",
    ];
    const before = await Promise.all(
      reportNames.map((name) => readFile(join(reports, name), "utf8")),
    );

    await rm(join(output, "snapshots"), { recursive: true });
    await writeFile(join(output, "snapshots"), "blocks snapshot directory\n");
    const fetcher = fetcherFor(
      releases({ portable: 13, setup: 9, manifest: 31 }),
    );

    await expect(
      collectDownloads({
        outputDirectory: output,
        fetcher,
        clock,
        repositoryRoot,
      }),
    ).rejects.toThrow(/ENOTDIR|EEXIST/);
    expect(fetcher).toHaveBeenCalledOnce();
    const after = await Promise.all(
      reportNames.map((name) => readFile(join(reports, name), "utf8")),
    );
    expect(after).toEqual(before);
  });

  it("uses GITHUB_TOKEN only for API auth and redacts it from CLI errors", async () => {
    const root = await temporaryRoot();
    const token = "ghp_do-not-print-this";
    const errors: string[] = [];
    const fetcher = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(new Headers(init?.headers).get("authorization")).toBe(`Bearer ${token}`);
      return new Response("failure", {
        status: 500,
        statusText: `server repeated ${token}`,
      });
    });
    const dependencies: CollectDependencies = {
      fetcher,
      clock,
      env: { GITHUB_TOKEN: token },
      repositoryRoot: join(root, "source-repository"),
      reportError: (message) => errors.push(message),
    };

    await expect(
      runCli(["--output", join(root, "output")], dependencies),
    ).resolves.toBe(1);
    expect(errors.join("\n")).not.toContain(token);
    expect(errors.join("\n")).toContain("[REDACTED]");
  });

  it("requires --output and rejects unknown or incomplete arguments", async () => {
    const reportError = vi.fn();
    const dependencies: CollectDependencies = {
      fetcher: fetcherFor([]),
      clock,
      env: {},
      repositoryRoot: resolve("/source"),
      reportError,
    };

    await expect(runCli([], dependencies)).resolves.toBe(1);
    await expect(runCli(["--unknown"], dependencies)).resolves.toBe(1);
    await expect(runCli(["--output"], dependencies)).resolves.toBe(1);
    expect(reportError).toHaveBeenCalledTimes(3);
  });
});

describe("dedicated download-metrics workflow", () => {
  it("is dormant locally and can push only HEAD to the dedicated branch", async () => {
    const workflowPath = resolve(
      dirname(new URL(import.meta.url).pathname),
      "../../../.github/workflows/download-metrics.yml",
    );
    const workflow = await readFile(workflowPath, "utf8");

    expect(workflow).toContain('cron: "17 0 * * *"');
    expect(workflow).toMatch(/workflow_dispatch:\s*\n/);
    expect(workflow).toMatch(/permissions:\s*\n\s+contents: write/);
    expect(workflow).toMatch(/concurrency:\s*\n\s+group: download-metrics\s*\n\s+cancel-in-progress: false/);
    expect(workflow).toContain("ref: main");
    expect(workflow).toContain("npm test");
    expect(workflow).toContain("npm run check");
    expect(workflow).toContain("metrics-worktree");
    expect(workflow).toContain(
      "git -C metrics-worktree rm -rf --ignore-unmatch .",
    );
    expect(workflow).toContain("git -C metrics-worktree add -- snapshots reports");
    expect(workflow).toContain(
      "git -C metrics-worktree push origin HEAD:download-metrics",
    );
    expect(workflow).not.toMatch(/git push[^\n]*\bmain\b/);
    expect(workflow.match(/push origin/g)).toHaveLength(1);
  });

  it("documents local use, baseline semantics, direct traffic, and inactive status", async () => {
    const readme = await readFile(
      resolve(dirname(new URL(import.meta.url).pathname), "../README.md"),
      "utf8",
    );
    expect(readme).toContain("cumulative requests");
    expect(readme).toMatch(/not\s+users or installations/);
    expect(readme).toContain("first snapshot");
    expect(readme).toContain("baseline");
    expect(readme).toMatch(/direct GitHub/i);
    expect(readme).toContain("updater traffic");
    expect(readme).toContain("Negative deltas fail");
    expect(readme).toContain("has not been activated or pushed");
  });
});
