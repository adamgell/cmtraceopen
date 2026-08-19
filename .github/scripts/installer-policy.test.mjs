import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const packagePath = path.join(repoRoot, "src-tauri", "installer", "package.signed.json");
const scriptPath = path.join(
  repoRoot,
  "src-tauri",
  "installer",
  "set-disable-update-checks-policy.ps1"
);

async function readInstallerContract() {
  const [packageText, script] = await Promise.all([
    readFile(packagePath, "utf8"),
    readFile(scriptPath, "utf8"),
  ]);
  return { installerPackage: JSON.parse(packageText), script };
}

describe("MSI update-policy packaging contract", () => {
  it("keeps the conditional PowerShell action safe for mpdev embedding", async () => {
    const { installerPackage, script } = await readInstallerContract();
    const action = installerPackage.msi.customActions.powershell.find(
      ({ filePath }) => filePath.endsWith("set-disable-update-checks-policy.ps1")
    );

    assert.deepEqual(action, {
      filePath: "src-tauri\\installer\\set-disable-update-checks-policy.ps1",
      condition: 'DISABLEUPDATECHECKS="1" AND REMOVE<>"ALL"',
      sequence: "EndOfExecution",
      continueOnError: false,
    });
    assert.doesNotMatch(script, /[{}]/);
    assert.match(script, /RegistryView\]::Registry64/);
    assert.match(script, /CreateSubKey\(\$policySubKey\)/);
    assert.match(
      script,
      /SetValue\(\s*\$policyName,\s*1,\s*\[Microsoft\.Win32\.RegistryValueKind\]::DWord/
    );
  });
});
