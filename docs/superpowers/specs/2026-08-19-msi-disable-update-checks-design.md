# MSI DISABLEUPDATECHECKS Fix Design

**Issue:** #576
**Date:** 2026-08-19

## Problem

The x64 MSI released as 1.5.2 fails with error 1603 when invoked with
`DISABLEUPDATECHECKS=1`. The attached verbose MSI log shows that the public
property reaches the elevated server and satisfies the custom-action condition.
The failure occurs when Master Packager Dev 2.1.1 embeds
`set-disable-update-checks-policy.ps1`: the embedded text loses PowerShell block
braces, and PowerShell reports `The Try statement is missing its statement
block`. The source script is valid before embedding; the MSI custom-action
payload is not.

## Goal

Make `msiexec /i CMTrace-Open_<version>_x64.msi DISABLEUPDATECHECKS=1` complete
successfully while preserving the existing managed update-policy contract.

## Contract

- `DISABLEUPDATECHECKS=1` writes the DWORD value
  `HKLM\Software\CMTrace Open\DisableUpdateChecks = 1`.
- The action runs only when `DISABLEUPDATECHECKS="1" AND REMOVE<>"ALL"`.
- The action remains an end-of-execution PowerShell custom action and remains
  fatal on failure (`continueOnError: false`).
- Uninstall does not remove the policy; administrators remove it explicitly.
- The x64/arm64 MSI writes the 64-bit registry view consumed by the 64-bit
  application.
- An MSI install without the property does not write this policy.

## Design

Keep the existing MSI custom-action metadata in
`src-tauri/installer/package.signed.json`. Rewrite
`src-tauri/installer/set-disable-update-checks-policy.ps1` as a straight-line
script with no `{` or `}` characters. Master Packager Dev's embedded-script
transformation cannot remove block braces that are not present, while the
script still uses the .NET registry API to select `Registry64`, create the
policy key, write the DWORD, dispose the handles, and exit successfully. The
existing `$ErrorActionPreference = 'Stop'` plus unhandled exceptions preserves a
fatal custom-action result when registry access fails.

Add a Node test under `.github/scripts/` that reads the real MSI package and
PowerShell file. It asserts the custom-action path, condition, sequence, and
fatal-error setting, and asserts that the embedded script is brace-free. Wire
the test into the existing CI release-script test command. This regression test
covers the exact representation that caused the shipped MSI failure without
requiring Master Packager Dev or Windows on Linux CI.

Add a concise Unreleased changelog entry for #576. README behavior text remains
unchanged because it already documents the intended conditional and persistent
policy.

## Alternatives rejected

1. **Escape PowerShell braces.** The escaping contract is undocumented and
   depends on Master Packager Dev's parser. It would retain the failure-prone
   representation.
2. **Use the package-level MSI registry table.** The schema exposes key/name/
   type/value but no condition or permanence control. It would write the policy
   for every MSI install and would let normal MSI removal delete a policy that
   the current contract intentionally preserves.
3. **Make the custom action non-fatal.** This would allow an installation to
   report success without writing the managed policy, violating the
   evidence-first deployment contract.

## Verification

1. Run the focused Node release-script regression test and confirm it is red
   before the script change and green afterward.
2. Run the full release-script test group and `git diff --check`.
3. Run the repository's applicable Rust/frontend gates from the issue worktree.
4. On a Windows x64 lab or runner, build the MSI with the pinned Master
   Packager Dev 2.1.1, inspect the embedded custom-action payload, install with
   `DISABLEUPDATECHECKS=1`, and verify the 64-bit HKLM DWORD plus the app's
   policy response. Also verify an install without the property and the
   uninstall/upgrade persistence behavior.

The macOS worktree can prove source/config/test contracts but cannot claim live
Windows MSI acceptance.
