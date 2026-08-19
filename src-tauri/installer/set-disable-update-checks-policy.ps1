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
