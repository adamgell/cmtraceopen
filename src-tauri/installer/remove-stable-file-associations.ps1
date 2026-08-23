Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$associationIdentities = @(
    @{ ApplicationName = "CMTrace Open"; RegistryStem = "CMTraceOpen" },
    @{ ApplicationName = "CMTrace Open Lite"; RegistryStem = "CMTraceOpenLite" }
)
$extensions = @(".log", ".lo_", ".log_", ".cmtlog")

function Remove-RegistryTreeIfPresent {
    param([Parameter(Mandatory = $true)][string] $Path)

    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
}

function Remove-EmptyRegistryKey {
    param([Parameter(Mandatory = $true)][string] $Path)

    $key = $null
    $remove = $false
    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
        $remove = $null -ne $key -and $key.SubKeyCount -eq 0 -and $key.ValueCount -eq 0
    }
    finally {
        if ($null -ne $key) {
            $key.Dispose()
        }
    }
    if ($remove) {
        Remove-Item -LiteralPath $Path -Force
    }
}

function Remove-AssociationIdentity {
    param(
        [Parameter(Mandatory = $true)][string] $UserRoot,
        [Parameter(Mandatory = $true)][string] $ApplicationName,
        [Parameter(Mandatory = $true)][string] $RegistryStem
    )

    $capabilitiesPath = "Software\$RegistryStem\Capabilities"
    $progId = "$RegistryStem.LogFile"
    $registeredApplicationsPath = "$UserRoot\Software\RegisteredApplications"
    $registeredApplications = $null
    $removeRegisteredApplication = $false
    try {
        $registeredApplications = Get-Item -LiteralPath $registeredApplicationsPath -ErrorAction SilentlyContinue
        $removeRegisteredApplication = (
            $null -ne $registeredApplications -and
            [string] $registeredApplications.GetValue($ApplicationName) -eq $capabilitiesPath
        )
    }
    finally {
        if ($null -ne $registeredApplications) {
            $registeredApplications.Dispose()
        }
    }
    if ($removeRegisteredApplication) {
        Remove-ItemProperty -LiteralPath $registeredApplicationsPath -Name $ApplicationName
    }

    Remove-RegistryTreeIfPresent "$UserRoot\$capabilitiesPath"
    Remove-EmptyRegistryKey "$UserRoot\Software\$RegistryStem"
    Remove-RegistryTreeIfPresent "$UserRoot\Software\Classes\$progId"

    foreach ($extension in $extensions) {
        $openWithPath = "$UserRoot\Software\Classes\$extension\OpenWithProgids"
        $openWithKey = $null
        $removeProgId = $false
        try {
            $openWithKey = Get-Item -LiteralPath $openWithPath -ErrorAction SilentlyContinue
            $removeProgId = $null -ne $openWithKey -and $null -ne $openWithKey.GetValue($progId, $null)
        }
        finally {
            if ($null -ne $openWithKey) {
                $openWithKey.Dispose()
            }
        }
        if ($removeProgId) {
            Remove-ItemProperty -LiteralPath $openWithPath -Name $progId
            Remove-EmptyRegistryKey $openWithPath
        }
    }
}

function Invoke-RegistryHiveOperation {
    param(
        [Parameter(Mandatory = $true)][ValidateSet("LOAD", "UNLOAD")][string] $Operation,
        [Parameter(Mandatory = $true)][string] $HiveName,
        [string] $HivePath
    )

    $arguments = @($Operation, $HiveName)
    if ($Operation -eq "LOAD") {
        $arguments += ('"{0}"' -f $HivePath)
    }
    $registryExecutable = Join-Path $env:SystemRoot "System32\reg.exe"
    $process = Start-Process `
        -FilePath $registryExecutable `
        -ArgumentList $arguments `
        -Wait `
        -PassThru `
        -WindowStyle Hidden
    return [int] $process.ExitCode
}

function Mount-ProfileHiveIfMissing {
    param(
        [Parameter(Mandatory = $true)] $ProfileKey,
        [Parameter(Mandatory = $true)][string] $UserRoot,
        [Parameter(Mandatory = $true)][string] $HiveName
    )

    if (Test-Path -LiteralPath $UserRoot) {
        return $false
    }

    [string] $profileImagePath = Get-ItemPropertyValue `
        -LiteralPath $ProfileKey.PSPath `
        -Name "ProfileImagePath"
    $profileImagePath = [Environment]::ExpandEnvironmentVariables($profileImagePath)
    if ([string]::IsNullOrWhiteSpace($profileImagePath)) {
        throw "ProfileImagePath is empty"
    }

    $ntUserPath = Join-Path $profileImagePath "NTUSER.DAT"
    if (-not (Test-Path -LiteralPath $ntUserPath -PathType Leaf)) {
        throw "profile hive does not exist: $ntUserPath"
    }

    $loadExitCode = Invoke-RegistryHiveOperation `
        -Operation "LOAD" `
        -HiveName $HiveName `
        -HivePath $ntUserPath
    if ($loadExitCode -eq 0) {
        return $true
    }
    if (Test-Path -LiteralPath $UserRoot) {
        return $false
    }

    throw "reg.exe LOAD $HiveName failed with exit code $loadExitCode"
}

$profileListPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
$failures = [System.Collections.Generic.List[string]]::new()
foreach ($profileKey in Get-ChildItem -LiteralPath $profileListPath) {
    $sid = $profileKey.PSChildName
    $userRoot = "Registry::HKEY_USERS\$sid"
    $hiveName = "HKU\$sid"
    $loadedByCleanup = $false
    try {
        $loadedByCleanup = Mount-ProfileHiveIfMissing `
            -ProfileKey $profileKey `
            -UserRoot $userRoot `
            -HiveName $hiveName
        if (-not $loadedByCleanup) {
            # A loaded profile can disappear here when its user logs off. Probe
            # once more immediately before cleanup so the offline hive is not skipped.
            $loadedByCleanup = Mount-ProfileHiveIfMissing `
                -ProfileKey $profileKey `
                -UserRoot $userRoot `
                -HiveName $hiveName
        }

        for ($cleanupAttempt = 0; $cleanupAttempt -lt 2; $cleanupAttempt++) {
            $attemptFailures = [System.Collections.Generic.List[string]]::new()
            foreach ($identity in $associationIdentities) {
                try {
                    Remove-AssociationIdentity -UserRoot $userRoot @identity
                }
                catch {
                    $attemptFailures.Add("$sid/$($identity.ApplicationName): $($_.Exception.Message)")
                }
            }

            if (Test-Path -LiteralPath $userRoot) {
                foreach ($attemptFailure in $attemptFailures) {
                    $failures.Add($attemptFailure)
                }
                break
            }
            $loadedByCleanup = $false
            if ($cleanupAttempt -eq 1) {
                foreach ($attemptFailure in $attemptFailures) {
                    $failures.Add($attemptFailure)
                }
                $failures.Add("$sid/profile: profile hive disappeared during association cleanup")
                break
            }

            $loadedByCleanup = Mount-ProfileHiveIfMissing `
                -ProfileKey $profileKey `
                -UserRoot $userRoot `
                -HiveName $hiveName
        }
    }
    catch {
        $failures.Add("$sid/profile: $($_.Exception.Message)")
    }
    finally {
        if ($loadedByCleanup) {
            try {
                $unloadExitCode = Invoke-RegistryHiveOperation `
                    -Operation "UNLOAD" `
                    -HiveName $hiveName
                if ($unloadExitCode -ne 0) {
                    throw "reg.exe UNLOAD $hiveName failed with exit code $unloadExitCode"
                }
            }
            catch {
                $failures.Add("$sid/unload: $($_.Exception.Message)")
            }
        }
    }
}

try {
    if (-not ("CMTraceOpen.AssociationChange" -as [type])) {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace CMTraceOpen {
    public static class AssociationChange {
        [DllImport("shell32.dll")]
        public static extern void SHChangeNotify(uint eventId, uint flags, IntPtr item1, IntPtr item2);
    }
}
"@
    }
    [CMTraceOpen.AssociationChange]::SHChangeNotify(0x08000000, 0x1000, [IntPtr]::Zero, [IntPtr]::Zero)
}
catch {
    $failures.Add("association notification: $($_.Exception.Message)")
}

if ($failures.Count -gt 0) {
    throw "File-association cleanup failed: $($failures -join '; ')"
}
