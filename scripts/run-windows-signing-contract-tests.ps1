#Requires -Version 7.3
param()
$ErrorActionPreference = 'Stop'
if ($args.Count -ne 0) { throw 'This fixed test runner accepts no arguments.' }
Import-Module Pester -RequiredVersion 5.7.1 -ErrorAction Stop
$tests = @(
    (Join-Path $PSScriptRoot 'verify-windows-release-signatures.Tests.ps1'),
    (Join-Path $PSScriptRoot 'tests/sign-tauri-windows-temp.Tests.ps1')
)
$result = Invoke-Pester -Path $tests -Output Detailed -PassThru
if ($result.FailedCount -gt 0 -or $result.FailedContainersCount -gt 0 -or
    $result.PassedCount -eq 0 -or $result.NotRunCount -gt 0) {
    exit 1
}
exit 0
