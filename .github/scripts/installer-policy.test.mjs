import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

describe("MSI DISABLEUPDATECHECKS policy (#576)", () => {
  it("exposes DISABLEUPDATECHECKS as a public property passed through SecureCustomProperties", async () => {
    const pkg = JSON.parse(
      await readFile(path.join(repoRoot, "src-tauri/installer/package.signed.json"), "utf8")
    );

    const properties = pkg.msi.properties ?? [];
    const disable = properties.find((p) => p.name === "DISABLEUPDATECHECKS");
    const secure = properties.find((p) => p.name === "SecureCustomProperties");

    assert.equal(disable?.value, "0");
    assert.equal(secure?.value, "DISABLEUPDATECHECKS");
  });

  it("schedules exactly one failing-hard update-policy CA only when DISABLEUPDATECHECKS=1", async () => {
    const pkg = JSON.parse(
      await readFile(path.join(repoRoot, "src-tauri/installer/package.signed.json"), "utf8")
    );
    const actions = pkg.msi.customActions?.powershell ?? [];
    const policyActions = actions.filter((action) =>
      /set-disable-update-checks-policy\.ps1$/.test(action.filePath)
    );
    assert.equal(policyActions.length, 1);

    const [action] = policyActions;
    assert.match(action.filePath, /set-disable-update-checks-policy\.ps1$/);
    assert.equal(action.condition, 'DISABLEUPDATECHECKS="1" AND REMOVE<>"ALL"');
    assert.equal(action.sequence, "EndOfExecution");
    assert.equal(action.continueOnError, false);
  });

  it("writes HKLM via System32 reg.exe /reg:64 so Constrained Language Mode cannot abort install", async () => {
    const script = await readFile(
      path.join(repoRoot, "src-tauri/installer/set-disable-update-checks-policy.ps1"),
      "utf8"
    );
    const executable = script
      .split(/\r?\n/)
      .filter((line) => !line.trim().startsWith("#"))
      .join("\n");

    assert.doesNotMatch(executable, /Microsoft\.Win32\.RegistryKey/);
    assert.match(executable, /System32\\reg\.exe/);
    assert.match(executable, /\/reg:64/);
    assert.match(executable, /DisableUpdateChecks/);
    assert.match(executable, /HKLM\\Software\\CMTrace Open/);
    assert.match(executable, /exit 1/);
  });
});
