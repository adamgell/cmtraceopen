import { describe, expect, it, vi } from "vitest";

import { listReleases } from "../src/github";
import type { GitHubRelease } from "../src/types";

const release = (
  id: number,
  overrides: Partial<GitHubRelease> = {},
): GitHubRelease => ({
  id,
  tag_name: `v${id}`,
  name: `Release ${id}`,
  published_at: "2026-07-13T00:00:00Z",
  prerelease: false,
  draft: false,
  assets: [
    {
      id: id * 10,
      name: `asset-${id}.exe`,
      created_at: "2026-07-13T00:00:00Z",
      updated_at: "2026-07-13T01:00:00Z",
      size: 123,
      content_type: "application/x-msdownload",
      download_count: 42,
      browser_download_url: `https://github.com/adamgell/cmtraceopen/releases/download/v${id}/asset-${id}.exe`,
    },
  ],
  ...overrides,
});

const jsonPages = (pages: GitHubRelease[][]) =>
  vi.fn(
    async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response(JSON.stringify(pages.shift()), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
  );

describe("GitHub release pagination", () => {
  it("requests full pages until GitHub returns an empty page", async () => {
    const pages = [
      Array.from({ length: 100 }, (_, index) => release(index + 1)),
      Array.from({ length: 100 }, (_, index) => release(index + 101)),
      [],
    ];
    const fetcher = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response(JSON.stringify(pages.shift()), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );

    const result = await listReleases(fetcher);

    expect(result).toHaveLength(200);
    expect(fetcher).toHaveBeenCalledTimes(3);
    for (const [index, call] of fetcher.mock.calls.entries()) {
      const [input, init] = call;
      expect(String(input)).toBe(
        `https://api.github.com/repos/adamgell/cmtraceopen/releases?per_page=100&page=${index + 1}`,
      );
      expect(init).toEqual({
        headers: {
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
        },
      });
    }
  });

  it("stops after a short page and preserves release and asset fields", async () => {
    const expected = [release(7), release(8)];
    const fetcher = vi.fn(async () => Response.json(expected));

    await expect(listReleases(fetcher)).resolves.toEqual(expected);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("adds a bearer token only when one is supplied", async () => {
    const fetcher = vi.fn(async () => Response.json([]));

    await listReleases(fetcher, "secret-token");

    expect(fetcher).toHaveBeenCalledWith(
      "https://api.github.com/repos/adamgell/cmtraceopen/releases?per_page=100&page=1",
      {
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: "Bearer secret-token",
          "X-GitHub-Api-Version": "2022-11-28",
        },
      },
    );
  });

  it("throws a descriptive error for a non-success response", async () => {
    const fetcher = vi.fn(
      async () =>
        new Response("rate limited", { status: 403, statusText: "Forbidden" }),
    );

    await expect(listReleases(fetcher)).rejects.toThrow(
      "GitHub releases request failed on page 1: 403 Forbidden",
    );
  });
});

describe("draft release exclusion", () => {
  it("omits draft releases while keeping published ones", async () => {
    // cmtrace-release.yml sets releaseDraft: true, so every stable release
    // exists as a draft with its assets already uploaded until a human
    // publishes it. An authenticated token sees those drafts.
    const published = release(1);
    const draft = release(2, { draft: true });

    const result = await listReleases(jsonPages([[published, draft]]));

    expect(result).toEqual([published]);
  });

  it("keeps prereleases, which are the published nightly channel", async () => {
    const stable = release(1);
    const nightly = release(2, { prerelease: true });

    const result = await listReleases(jsonPages([[stable, nightly]]));

    expect(result).toEqual([stable, nightly]);
  });

  it("does not let a draft on a full page terminate pagination early", async () => {
    // Regression guard for the tempting one-line fix. Filtering before the
    // short-page check makes this first page look like 99 < PER_PAGE, so the
    // loop would return after one request and silently drop page two.
    const first = Array.from({ length: 100 }, (_, index) =>
      index === 50 ? release(index + 1, { draft: true }) : release(index + 1),
    );
    const second = [release(101)];
    const fetcher = jsonPages([first, second]);

    const result = await listReleases(fetcher);

    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(result).toHaveLength(100);
    expect(result.some((entry) => entry.draft)).toBe(false);
    expect(result.at(-1)?.id).toBe(101);
  });

  it("keeps paginating when an entire full page is drafts", async () => {
    const first = Array.from({ length: 100 }, (_, index) =>
      release(index + 1, { draft: true }),
    );
    const second = [release(101)];
    const fetcher = jsonPages([first, second]);

    const result = await listReleases(fetcher);

    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(result).toEqual([release(101)]);
  });
});
