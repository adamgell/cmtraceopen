import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import {
  NIGHTLY_UPDATER_ENDPOINT,
  applyNightlyChannel,
  buildNightlyManifest,
} from "./nightly-channel.mjs";

async function withTempRepo(testFn) {
  const root = await mkdtemp(path.join(tmpdir(), "cmtrace-nightly-"));
  try {
    await writeFile(
      path.join(root, "package.json"),
      JSON.stringify({ name: "cmtrace-open", version: "1.3.2" }, null, 2)
    );
    await writeFile(
      path.join(root, "tauri.conf.json"),
      JSON.stringify(
        {
          version: "1.3.2",
          plugins: {
            updater: {
              endpoints: [
                "https://github.com/adamgell/cmtraceopen/releases/latest/download/latest.json",
              ],
            },
          },
        },
        null,
        2
      )
    );
    await writeFile(
      path.join(root, "Cargo.toml"),
      [
        "[workspace]",
        "",
        "[package]",
        'name = "cmtrace-open"',
        'version = "1.3.2"',
        "",
      ].join("\n")
    );
    await testFn(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

describe("nightly channel workflow helpers", () => {
  it("applies nightly version and updater endpoint metadata", async () => {
    await withTempRepo(async (root) => {
      await applyNightlyChannel({
        root,
        packageJsonPath: "package.json",
        tauriConfigPath: "tauri.conf.json",
        cargoTomlPath: "Cargo.toml",
        version: "1.3.2-nightly.20260514.42.gabc123def456",
      });

      const packageJson = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
      const tauriConfig = JSON.parse(await readFile(path.join(root, "tauri.conf.json"), "utf8"));
      const cargoToml = await readFile(path.join(root, "Cargo.toml"), "utf8");

      assert.equal(packageJson.version, "1.3.2-nightly.20260514.42.gabc123def456");
      assert.equal(tauriConfig.version, "1.3.2-nightly.20260514.42.gabc123def456");
      assert.deepEqual(tauriConfig.plugins.updater.endpoints, [NIGHTLY_UPDATER_ENDPOINT]);
      assert.match(cargoToml, /version = "1\.3\.2-nightly\.20260514\.42\.gabc123def456"/);
    });
  });

  it("builds a Tauri updater manifest for nightly assets", async () => {
    const assetsDir = await mkdtemp(path.join(tmpdir(), "cmtrace-nightly-assets-"));
    try {
      const assetPrefix = "CMTrace-Open_Nightly_20260514_42_abc123def456";
      const files = [
        `${assetPrefix}_x64-setup.exe`,
        `${assetPrefix}_arm64-setup.exe`,
        `${assetPrefix}_macOS-arm64.app.tar.gz`,
      ];

      for (const file of files) {
        await writeFile(path.join(assetsDir, file), "artifact");
        await writeFile(path.join(assetsDir, `${file}.sig`), `${file}-signature\n`);
      }

      const manifestPath = await buildNightlyManifest({
        assetsDir,
        assetPrefix,
        repository: "adamgell/cmtraceopen",
        tagName: "nightly",
        displayVersion: "1.3.2-nightly.20260514.42.gabc123def456",
        buildId: "20260514.42.abc123def456",
        runUrl: "https://github.com/adamgell/cmtraceopen/actions/runs/42",
        pubDate: new Date("2026-05-14T07:00:00.000Z"),
      });

      const manifest = JSON.parse(await readFile(manifestPath, "utf8"));

      assert.equal(manifest.version, "1.3.2-nightly.20260514.42.gabc123def456");
      assert.equal(
        manifest.platforms["windows-x86_64"].url,
        `https://github.com/adamgell/cmtraceopen/releases/download/nightly/${assetPrefix}_x64-setup.exe`
      );
      assert.equal(
        manifest.platforms["windows-aarch64"].signature,
        `${assetPrefix}_arm64-setup.exe-signature`
      );
      assert.equal(
        manifest.platforms["darwin-aarch64"].url,
        `https://github.com/adamgell/cmtraceopen/releases/download/nightly/${assetPrefix}_macOS-arm64.app.tar.gz`
      );
    } finally {
      await rm(assetsDir, { recursive: true, force: true });
    }
  });
});
