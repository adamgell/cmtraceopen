import type { GitHubRelease } from "./types";

const RELEASES_ENDPOINT =
  "https://api.github.com/repos/adamgell/cmtraceopen/releases";
const PER_PAGE = 100;

export type Fetcher = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

export async function listReleases(
  fetcher: Fetcher = fetch,
  token?: string,
): Promise<GitHubRelease[]> {
  const releases: GitHubRelease[] = [];

  for (let page = 1; ; page += 1) {
    const headers: Record<string, string> = {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    };
    if (token !== undefined && token !== "") {
      headers.Authorization = `Bearer ${token}`;
    }

    const response = await fetcher(
      `${RELEASES_ENDPOINT}?per_page=${PER_PAGE}&page=${page}`,
      { headers },
    );
    if (!response.ok) {
      const status = `${response.status} ${response.statusText}`.trim();
      throw new Error(`GitHub releases request failed on page ${page}: ${status}`);
    }

    const pageReleases = (await response.json()) as GitHubRelease[];
    releases.push(...pageReleases);
    if (pageReleases.length < PER_PAGE) {
      // Drafts are excluded here, at the single exit, rather than before the
      // short-page check above. That check is the loop's ONLY termination
      // signal, and it is a statement about the server's page size -- filtering
      // first would silently repurpose it as "fewer than PER_PAGE survived my
      // filter", so one draft on a full page would end pagination early and
      // drop every later release. Prereleases are kept: they are the published
      // nightly channel (see SnapshotAsset.prerelease and the CSV column).
      return releases.filter((release) => !release.draft);
    }
  }
}
