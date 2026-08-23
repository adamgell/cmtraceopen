Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$associationIdentities = @(
    @{ ApplicationName = "CMTrace Open Nightly"; RegistryStem = "CMTraceOpenNightly" },
    @{ ApplicationName = "CMTrace Open Lite Nightly"; RegistryStem = "CMTraceOpenLiteNightly" }
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

    $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -ne $key -and $key.SubKeyCount -eq 0 -and $key.ValueCount -eq 0) {
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
    $registeredApplications = Get-Item -LiteralPath $registeredApplicationsPath -ErrorAction SilentlyContinue
    if (
        $null -ne $registeredApplications -and
        [string] $registeredApplications.GetValue($ApplicationName) -eq $capabilitiesPath
    ) {
        Remove-ItemProperty -LiteralPath $registeredApplicationsPath -Name $ApplicationName
    }

    Remove-RegistryTreeIfPresent "$UserRoot\$capabilitiesPath"
    Remove-EmptyRegistryKey "$UserRoot\Software\$RegistryStem"
    Remove-RegistryTreeIfPresent "$UserRoot\Software\Classes\$progId"

    foreach ($extension in $extensions) {
        $openWithPath = "$UserRoot\Software\Classes\$extension\OpenWithProgids"
        $openWithKey = Get-Item -LiteralPath $openWithPath -ErrorAction SilentlyContinue
        if ($null -ne $openWithKey -and $null -ne $openWithKey.GetValue($progId, $null)) {
            Remove-ItemProperty -LiteralPath $openWithPath -Name $progId
            Remove-EmptyRegistryKey $openWithPath
        }
    }
}

$profileListPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
$failures = [System.Collections.Generic.List[string]]::new()
foreach ($profile in Get-ChildItem -LiteralPath $profileListPath) {
    $userRoot = "Registry::HKEY_USERS\$($profile.PSChildName)"
    if (-not (Test-Path -LiteralPath $userRoot)) {
        continue
    }

    foreach ($identity in $associationIdentities) {
        try {
            Remove-AssociationIdentity -UserRoot $userRoot @identity
        }
        catch {
            $failures.Add("$($profile.PSChildName)/$($identity.ApplicationName): $($_.Exception.Message)")
        }
    }
}

if ($failures.Count -gt 0) {
    throw "File-association cleanup failed: $($failures -join '; ')"
}

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
