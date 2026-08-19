# MSI DISABLEUPDATECHECKS Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the MSI `DISABLEUPDATECHECKS=1` install succeed under Master Packager Dev 2.1.1 while preserving the conditional, persistent HKLM update-policy contract.

**Architecture:** Keep the existing MSI PowerShell custom action and MSI condition. Replace the brace-bearing script with a straight-line .NET Registry64 script because the pinned Master Packager Dev embedding path corrupts PowerShell block braces and interpolation braces. Add a source/config regression test and wire it into the existing CI release-script test command.

**Tech Stack:** Master Packager Dev 2.1.1 MSI JSON, PowerShell 5/.NET RegistryKey, Node.js `node:test`, GitHub Actions.

## Global Constraints

- Preserve `DISABLEUPDATECHECKS="1" AND REMOVE<>"ALL"`, `EndOfExecution`, and `continueOnError: false` exactly.
- Write only `HKLM\Software\CMTrace Open\DisableUpdateChecks` as `REG_DWORD 1` in the 64-bit registry view.
- Keep the managed policy across uninstall/upgrade; do not replace it with an unconditional MSI registry table entry.
- The embedded PowerShell source must contain no `{` or `}` characters.
- Do not claim live Windows MSI acceptance from macOS/Linux verification.
- Work only in `/Users/Adam.Gell/repo/cmtraceopen/.worktrees/issue576-msi`; do not touch the dirty root checkout.

---

### Task 1: Add the packaging regression contract

**Files:**
- Create: `.github/scripts/installer-policy.test.mjs`
- Modify: `.github/workflows/cmtrace-ci.yml:166-169`

**Interfaces:**
- Consumes: the real `src-tauri/installer/package.signed.json` and `src-tauri/installer/set-disable-update-checks-policy.ps1` files.
- Produces: a Node test that fails against the current brace-bearing script and passes only when the MSI custom-action contract and brace-free embedding invariant hold.

- [ ] **Step 1: Create the failing test**

Create `.github/scripts/installer-policy.test.mjs` with this exact test:

```js
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
```

- [ ] **Step 2: Wire the test into CI**

Extend the existing release-script test command in `.github/workflows/cmtrace-ci.yml`:

```yaml
      - name: Release script tests
        run: node --test .github/scripts/updater-manifest.test.mjs .github/scripts/nightly-channel.test.mjs .github/scripts/installer-policy.test.mjs
```

Do not change the MSI package metadata in this task.

- [ ] **Step 3: Run the focused test and record RED**

Run:

```bash
node --test .github/scripts/installer-policy.test.mjs
```

Expected result before the script change: **FAIL**, with the assertion that the script must not contain `{` or `}`. This demonstrates the regression test detects the shipped embedding failure shape.

- [ ] **Step 4: Commit the regression contract**

```bash
git add .github/scripts/installer-policy.test.mjs .github/workflows/cmtrace-ci.yml
git commit -m "test: guard MSI update policy embedding"
```

---

### Task 2: Replace the corrupted embedded script and document the fix

**Files:**
- Modify: `src-tauri/installer/set-disable-update-checks-policy.ps1:1-33`
- Modify: `CHANGELOG.md:32-45`

**Interfaces:**
- Consumes: the MSI custom-action metadata and failing test from Task 1.
- Produces: a brace-free PowerShell custom action that writes the same 64-bit HKLM DWORD and remains fatal on registry failure.

- [ ] **Step 1: Replace the script with the minimal brace-free implementation**

The complete file content must be:

```powershell
$ErrorActionPreference = 'Stop'

$policySubKey = 'Software\CMTrace Open'
$policyName = 'DisableUpdateChecks'

$baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::LocalMachine,
    [Microsoft.Win32.RegistryView]::Registry64
)
$policyKey = $baseKey.CreateSubKey($policySubKey)
$policyKey.SetValue(
    $policyName,
    1,
    [Microsoft.Win32.RegistryValueKind]::DWord
)
$policyKey.Dispose()
$baseKey.Dispose()
exit 0
```

This removes all PowerShell block and interpolation braces. `OpenBaseKey` explicitly selects the 64-bit view required by the x64/arm64 MSI, and unhandled exceptions still return a failed custom action because `continueOnError` remains false.

- [ ] **Step 2: Add the Unreleased changelog entry**

Under `## [Unreleased]` → `### Fixed`, add:

```markdown
- **MSI managed update policy (#576)**: Fixed `DISABLEUPDATECHECKS=1` installation failures caused by Master Packager Dev corrupting PowerShell custom-action braces; the MSI now writes the conditional 64-bit HKLM policy successfully.
```

Do not alter the existing README deployment contract.

- [ ] **Step 3: Run the focused test GREEN**

Run:

```bash
node --test .github/scripts/installer-policy.test.mjs
```

Expected result: **PASS**.

- [ ] **Step 4: Commit the implementation**

```bash
git add src-tauri/installer/set-disable-update-checks-policy.ps1 CHANGELOG.md
git commit -m "fix(installer): preserve MSI update policy action"
```

---

### Task 3: Run focused and aggregate verification

**Files:**
- No source changes expected.

**Interfaces:**
- Consumes: the two issue-scoped commits and the exact MSI package contract.
- Produces: reproducible local evidence, with Windows MSI acceptance explicitly separated from macOS/Linux checks.

- [ ] **Step 1: Run all release-script tests**

Run:

```bash
node --test .github/scripts/updater-manifest.test.mjs .github/scripts/nightly-channel.test.mjs .github/scripts/installer-policy.test.mjs
```

Expected result: all tests pass.

- [ ] **Step 2: Run repository format and diff checks**

Run:

```bash
git diff --check
```

Expected result: no output and exit code 0.

- [ ] **Step 3: Run applicable project gates**

Run:

```bash
cargo test --locked -p cmtraceopen-parser
cargo check --manifest-path src-tauri/Cargo.toml
npx tsc --noEmit
```

Expected result: each command exits 0. These gates are regression checks; the changed MSI script is not Rust/TypeScript code.

- [ ] **Step 4: Record the unavailable Windows acceptance gate**

The macOS worktree cannot execute `mpdev`, build an MSI, run `msiexec`, or inspect the Windows registry. Report Windows validation as pending unless an actual Windows runner is available. The required Windows command sequence is:

```powershell
mpdev build src-tauri\installer\package.signed.json --working-dir "$PWD" --properties "$.version=1.5.3" "$.outputFileName=CMTrace-Open_1.5.3_x64" "$.platform=x64"
msiexec /i .\release-artifacts\CMTrace-Open_1.5.3_x64.msi /qn /l*v .\install.log DISABLEUPDATECHECKS=1
Get-ItemPropertyValue 'HKLM:\Software\CMTrace Open' DisableUpdateChecks
```

The MSI log must show no PowerShell parser error, the install must return 0, and the 64-bit HKLM value must be DWORD 1. Also test omitted/0 property, upgrade/repair, and uninstall persistence before calling Windows acceptance complete.

---

## Plan self-review

- Spec coverage: conditional metadata, 64-bit registry write, policy persistence, fatal errors, regression test, CI wiring, changelog, and Windows-only acceptance are covered by Tasks 1–3.
- Placeholder scan: no TODO/TBD or unspecified implementation steps remain.
- Interface consistency: the test expects the existing custom-action fields; Task 2 changes only the script body; Task 3 consumes both commits without requiring a new API.
- Scope check: this is one packaging subsystem and does not need decomposition.
