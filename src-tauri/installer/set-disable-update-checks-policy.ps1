$ErrorActionPreference = 'Stop'

$policySubKey = 'Software\CMTrace Open'
$policyName = 'DisableUpdateChecks'

try {
    $registryView = [Microsoft.Win32.RegistryView]::Default
    if ([Environment]::Is64BitOperatingSystem) {
        $registryView = [Microsoft.Win32.RegistryView]::Registry64
    }

    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        $registryView
    )
    $policyKey = $baseKey.CreateSubKey($policySubKey)
    $policyKey.SetValue($policyName, 1, [Microsoft.Win32.RegistryValueKind]::DWord)

    Write-Output "CMTrace Open update checks disabled by HKLM policy."
    exit 0
}
catch {
    Write-Output "Failed to set CMTrace Open update policy: $($_.Exception.Message)"
    exit 1
}
finally {
    if ($null -ne $policyKey) {
        $policyKey.Dispose()
    }
    if ($null -ne $baseKey) {
        $baseKey.Dispose()
    }
}
