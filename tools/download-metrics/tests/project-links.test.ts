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
    const stableReleaseNotes = read(".github/release-notes/template.md");
    const stableReleaseWorkflow = read(".github/workflows/cmtrace-release.yml");
    const windowsReleaseWorkflow = read(".github/workflows/codesign.yml");
    const nightlyReleaseWorkflow = read(".github/workflows/cmtrace-nightly-signed.yml");

    expect(readme).toContain("https://download.cmtraceopen.com/?source=github-readme");
    expect(readme).not.toContain("https://github.com/adamgell/CMTraceOpen/releases/latest");
    expect(stableReleaseNotes).toContain(
      "Stable downloads: https://download.cmtraceopen.com/?source=github-release",
    );
    expect(stableReleaseWorkflow).toContain(
      'template=".github/release-notes/template.md"',
    );
    expect(stableReleaseWorkflow).toContain(
      "releaseBody: ${{ steps.notes.outputs.body }}",
    );
    expect(stableReleaseWorkflow).toContain(
      'sed -e "s|{{TAG}}|$TAG_NAME|g" -e "s|{{VERSION}}|$VERSION|g"',
    );
    expect(windowsReleaseWorkflow).toContain(
      '$releaseNotes = $releaseNotes.Replace("{{TAG}}", $env:TAG_NAME)',
    );
    expect(windowsReleaseWorkflow).toContain(
      '$releaseNotes = $releaseNotes.Replace("{{VERSION}}", $env:VERSION)',
    );
    expect(windowsReleaseWorkflow).toContain(
      '$templatePath = ".github/release-notes/template.md"',
    );
    expect(windowsReleaseWorkflow).toContain("--notes-file release-notes.md");
    expect(nightlyReleaseWorkflow).toMatch(
      /cat > release-notes\.md <<EOF\n\s+Nightly build status and downloads: https:\/\/adamgell\.com\/cmtraceopen\//,
    );
  });

  it("keeps updater manifests and payloads on direct GitHub release URLs", () => {
    const stableTauriConfig = read("src-tauri/tauri.conf.json");
    const nightlyChannelScript = read(".github/scripts/nightly-channel.mjs");
    const windowsReleaseWorkflow = read(".github/workflows/codesign.yml");
    const manifestPublisher = read(
      ".github/actions/publish-updater-manifest/action.yml",
    );
    const updaterManifest = read(".github/scripts/updater-manifest.mjs");

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
      'gh release upload $env:TAG_NAME $env:FULL_EXE_PATH $env:LITE_EXE_PATH $env:MSI_PATH $env:NSIS_PATH "$($env:NSIS_PATH).sig" --clobber',
    );
    expect(manifestPublisher).toContain(
      'gh release upload "$TAG_NAME" latest.json --clobber',
    );
    expect(updaterManifest).toContain(
      "https://github.com/${repository}/releases/download/${tagName}/${encodeURIComponent(fileName)}",
    );

    for (const updaterContent of [
      stableTauriConfig,
      nightlyChannelScript,
      windowsReleaseWorkflow,
      manifestPublisher,
      updaterManifest,
    ]) {
      expect(updaterContent).not.toMatch(/download\.cmtraceopen\.com.*latest\.json/);
    }
  });
});
