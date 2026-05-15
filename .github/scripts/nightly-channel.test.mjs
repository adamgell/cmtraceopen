import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { pathToFileURL } from "node:url";
import {
  NIGHTLY_UPDATER_ENDPOINT,
  applyNightlyChannel,
  buildNightlyManifest,
  deriveNightlyMsiVersion,
  isMainModule,
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
          productName: "CMTrace Open",
          version: "1.3.2",
          app: {
            windows: [
              {
                title: "CMTrace Open",
              },
            ],
          },
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
      path.join(root, "tauri.lite.conf.json"),
      JSON.stringify(
        {
          productName: "CMTrace Open Lite",
          app: {
            windows: [
              {
                title: "CMTrace Open Lite",
              },
            ],
          },
        },
        null,
        2
      )
    );
    await writeFile(
      path.join(root, "package.signed.json"),
      JSON.stringify(
        {
          packageName: "CMTrace Open",
          installDir: "%ProgramFiles%\\CMTrace Open",
          fileSystemEntries: [
            {
              sourcePath: "%FULL_EXE_PATH%",
              targetPath: "$.installDir\\cmtrace-open.exe",
            },
            {
              sourcePath: "%LITE_EXE_PATH%",
              targetPath: "$.installDir\\cmtrace-open-lite.exe",
            },
          ],
          msi: {
            upgradeCode: "{E8F1A3B7-5C2D-4F6E-9A8B-1D3E5F7A9C2B}",
            installDialog: {
              packageDescription:
                "Open-source CMTrace log viewer with built-in Intune diagnostics.",
            },
          },
          shortcuts: [
            {
              target: "$.installDir\\cmtrace-open.exe",
              name: "CMTrace Open",
            },
            {
              target: "$.installDir\\cmtrace-open-lite.exe",
              name: "CMTrace Open Lite",
            },
          ],
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
  it("detects direct CLI execution using file URLs and filesystem paths", () => {
    const scriptPath = path.resolve("nightly-channel.mjs");

    assert.equal(isMainModule(pathToFileURL(scriptPath).href, scriptPath), true);
    assert.equal(
      isMainModule(pathToFileURL(scriptPath).href, path.resolve("other-script.mjs")),
      false
    );
  });

  it("applies nightly version and updater endpoint metadata", async () => {
    await withTempRepo(async (root) => {
      await applyNightlyChannel({
        root,
        packageJsonPath: "package.json",
        tauriConfigPath: "tauri.conf.json",
        liteTauriConfigPath: "tauri.lite.conf.json",
        cargoTomlPath: "Cargo.toml",
        installerPackagePath: "package.signed.json",
        version: "1.3.2-nightly.20260514.42.gabc123def456",
      });

      const packageJson = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
      const tauriConfig = JSON.parse(await readFile(path.join(root, "tauri.conf.json"), "utf8"));
      const liteTauriConfig = JSON.parse(
        await readFile(path.join(root, "tauri.lite.conf.json"), "utf8")
      );
      const installerPackage = JSON.parse(
        await readFile(path.join(root, "package.signed.json"), "utf8")
      );
      const cargoToml = await readFile(path.join(root, "Cargo.toml"), "utf8");

      assert.equal(packageJson.version, "1.3.2-nightly.20260514.42.gabc123def456");
      assert.equal(tauriConfig.productName, "CMTrace Open Nightly");
      assert.equal(tauriConfig.mainBinaryName, "cmtrace-open-nightly");
      assert.equal(tauriConfig.version, "1.3.2-nightly.20260514.42.gabc123def456");
      assert.equal(tauriConfig.identifier, "com.cmtrace.open.nightly");
      assert.equal(tauriConfig.app.windows[0].title, "CMTrace Open Nightly");
      assert.deepEqual(tauriConfig.plugins.updater.endpoints, [NIGHTLY_UPDATER_ENDPOINT]);
      assert.equal(liteTauriConfig.productName, "CMTrace Open Lite Nightly");
      assert.equal(liteTauriConfig.mainBinaryName, "cmtrace-open-lite-nightly");
      assert.equal(liteTauriConfig.identifier, "com.cmtrace.open.nightly");
      assert.equal(liteTauriConfig.app.windows[0].title, "CMTrace Open Lite Nightly");
      assert.equal(installerPackage.packageName, "CMTrace Open Nightly");
      assert.equal(installerPackage.installDir, "%ProgramFiles%\\CMTrace Open Nightly");
      assert.equal(installerPackage.msi.packageName, "CMTrace Open Nightly");
      assert.equal(installerPackage.msi.upgradeCode, "{7B16F0D6-2B7B-4D4B-9F71-4F1A9F64C0E3}");
      assert.match(
        installerPackage.msi.installDialog.packageDescription,
        /Nightly signed build 1\.3\.2-nightly\.20260514\.42\.gabc123def456/
      );
      assert.match(
        installerPackage.msi.installDialog.packageDescription,
        /nightly channel/
      );
      assert.equal(installerPackage.shortcuts[0].name, "CMTrace Open Nightly");
      assert.equal(installerPackage.shortcuts[0].target, "$.installDir\\cmtrace-open-nightly.exe");
      assert.equal(installerPackage.shortcuts[1].name, "CMTrace Open Lite Nightly");
      assert.equal(
        installerPackage.shortcuts[1].target,
        "$.installDir\\cmtrace-open-lite-nightly.exe"
      );
      assert.equal(
        installerPackage.fileSystemEntries[0].targetPath,
        "$.installDir\\cmtrace-open-nightly.exe"
      );
      assert.equal(
        installerPackage.fileSystemEntries[1].targetPath,
        "$.installDir\\cmtrace-open-lite-nightly.exe"
      );
      assert.match(cargoToml, /version = "1\.3\.2-nightly\.20260514\.42\.gabc123def456"/);
    });
  });

  it("derives an increasing MSI ProductVersion for nightly major upgrades", () => {
    assert.equal(deriveNightlyMsiVersion("1.3.2", "42"), "1.3.44");
    assert.equal(deriveNightlyMsiVersion("1.3.2", "1"), "1.3.3");
    assert.throws(
      () => deriveNightlyMsiVersion("1.3.2", "70000"),
      /MSI nightly build number must be between/
    );
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
      const windowsDir = path.join(assetsDir, "nightly-artifacts");
      await mkdir(windowsDir);

      for (const file of files) {
        const artifactDir = file.includes("macOS") ? assetsDir : windowsDir;
        await writeFile(path.join(artifactDir, file), "artifact");
        await writeFile(path.join(artifactDir, `${file}.sig`), `${file}-signature\n`);
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
