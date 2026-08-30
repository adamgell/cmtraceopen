# MSI custom action for DISABLEUPDATECHECKS=1.
# Intentionally a CA (not a Registry table entry) so the HKLM policy survives
# uninstall, matching README.md.
#
# The previous implementation used [Microsoft.Win32.RegistryKey]::OpenBaseKey.
# Master Packager embeds this script and runs it in the elevated execute
# sequence. On managed Windows 11 that session is often Constrained Language
# Mode (WDAC/AppLocker), where those .NET types throw and — with
# continueOnError: false — roll back the whole install (#576).
#
# System32\reg.exe is allowed in CLM. /reg:64 writes the native 64-bit hive
# even when msiexec is 32-bit, matching the app's winreg HKLM lookup.

$ErrorActionPreference = 'Stop'

$regExe = Join-Path $env:SystemRoot 'System32\reg.exe'
$regKey = 'HKLM\Software\CMTrace Open'

if (-not (Test-Path -LiteralPath $regExe)) {
    Write-Output "Failed to set CMTrace Open update policy: reg.exe not found at $regExe"
    exit 1
}

try {
    $output = & $regExe add $regKey /v DisableUpdateChecks /t REG_DWORD /d 1 /reg:64 /f 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Output "Failed to set CMTrace Open update policy: $output"
        exit 1
    }

    Write-Output "CMTrace Open update checks disabled by HKLM policy."
    exit 0
}
catch {
    Write-Output "Failed to set CMTrace Open update policy: $($_.Exception.Message)"
    exit 1
}
