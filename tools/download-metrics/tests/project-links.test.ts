import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

function read(path: string): string {
  return readFileSync(resolve(repositoryRoot, path), "utf8");
}

describe("project-controlled download link boundaries", () => {
  it("routes human-facing stable and nightly links through their branded pages", () => {
    const readme = read("README.md");
    const stableReleaseWorkflow = read(".github/workflows/cmtrace-release.yml");
    const windowsReleaseWorkflow = read(".github/workflows/codesign.yml");
    const nightlyReleaseWorkflow = read(".github/workflows/cmtrace-nightly-signed.yml");

    expect(readme).toContain("https://download.cmtraceopen.com/?source=github-readme");
    expect(readme).not.toContain("https://github.com/adamgell/CMTraceOpen/releases/latest");
    expect(stableReleaseWorkflow).toMatch(
      /releaseBody: \|\n\s+Stable downloads: https:\/\/download\.cmtraceopen\.com\/\?source=github-release/,
    );
    expect(windowsReleaseWorkflow).toMatch(
      /\$releaseNotes = @"\n\s+Stable downloads: https:\/\/download\.cmtraceopen\.com\/\?source=github-release/,
    );
    expect(nightlyReleaseWorkflow).toMatch(
      /cat > release-notes\.md <<EOF\n\s+Nightly build status and downloads: https:\/\/adamgell\.com\/cmtraceopen\//,
    );
  });

  it("keeps updater manifests and payloads on direct GitHub release URLs", () => {
    const stableTauriConfig = read("src-tauri/tauri.conf.json");
    const nightlyChannelScript = read(".github/scripts/nightly-channel.mjs");
    const windowsReleaseWorkflow = read(".github/workflows/codesign.yml");

    expect(stableTauriConfig).toContain(
      "https://github.com/adamgell/cmtraceopen/releases/latest/download/latest.json",
    );
    expect(nightlyChannelScript).toContain(
      "https://github.com/adamgell/cmtraceopen/releases/download/nightly/latest.json",
    );
    expect(nightlyChannelScript).toContain(
      "https://github.com/${repository}/releases/download/${tagName}/${encodeURIComponent(fileName)}",
    );
    expect(windowsReleaseWorkflow).toContain(
      'https://github.com/${{ github.repository }}/releases/download/$env:TAG_NAME/$nsisFileName',
    );

    for (const updaterContent of [
      stableTauriConfig,
      nightlyChannelScript,
      windowsReleaseWorkflow,
    ]) {
      expect(updaterContent).not.toMatch(/download\.cmtraceopen\.com.*latest\.json/);
    }
  });
});
