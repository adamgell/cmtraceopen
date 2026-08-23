$scriptCases = @(
    @{
        Name = "stable"
        ScriptName = "remove-stable-file-associations.ps1"
        ApplicationNames = @("CMTrace Open", "CMTrace Open Lite")
        RegistryStems = @("CMTraceOpen", "CMTraceOpenLite")
    },
    @{
        Name = "nightly"
        ScriptName = "remove-nightly-file-associations.ps1"
        ApplicationNames = @("CMTrace Open Nightly", "CMTrace Open Lite Nightly")
        RegistryStems = @("CMTraceOpenNightly", "CMTraceOpenLiteNightly")
    }
)

Describe "MSI file-association cleanup" {
    BeforeAll {
        if (-not ("CMTraceOpen.AssociationChange" -as [type])) {
            Add-Type -TypeDefinition @"
using System;
namespace CMTraceOpen {
    public static class AssociationChange {
        public static int NotifyCount { get; private set; }
        public static void Reset() { NotifyCount = 0; }
        public static void SHChangeNotify(uint eventId, uint flags, IntPtr item1, IntPtr item2) {
            NotifyCount++;
        }
    }
}
namespace CMTraceOpen.Tests {
    public sealed class DisposableRegistryKey : IDisposable {
        public int SubKeyCount { get; set; } = 1;
        public int ValueCount { get; set; } = 1;
        public bool IsDisposed { get; private set; }
        public object GetValue(string name) { return null; }
        public object GetValue(string name, object defaultValue) { return null; }
        public void Dispose() { IsDisposed = true; }
    }
}
"@
        }
    }

    BeforeEach {
        [CMTraceOpen.AssociationChange]::Reset()
    }

    It "loads, cleans, and unloads an offline <Name> profile" -ForEach $scriptCases {
        $sid = "S-1-5-21-1000"
        $profileKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
        $userRoot = "Registry::HKEY_USERS\$sid"
        $profileImagePath = Join-Path $TestDrive "Offline User"
        $ntUserPath = Join-Path $profileImagePath "NTUSER.DAT"
        $originalSystemRoot = $env:SystemRoot
        $env:SystemRoot = Join-Path $TestDrive "Windows"

        Mock Get-ChildItem {
            [pscustomobject]@{
                PSChildName = $sid
                PSPath = $profileKey
            }
        }
        Mock Get-ItemPropertyValue { $profileImagePath }
        Mock Test-Path {
            if ($LiteralPath -eq $ntUserPath) {
                return $true
            }
            return $false
        }
        Mock Get-Item { $null }
        Mock Remove-Item {}
        Mock Remove-ItemProperty {}
        Mock Start-Process { [pscustomobject]@{ ExitCode = 0 } }

        try {
            & (Join-Path $PSScriptRoot $ScriptName)
        }
        finally {
            $env:SystemRoot = $originalSystemRoot
        }

        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter {
            $ArgumentList[0] -eq "LOAD" -and
            $ArgumentList[1] -eq "HKU\$sid" -and
            $ArgumentList[2] -eq ('"{0}"' -f $ntUserPath)
        }
        foreach ($registryStem in $RegistryStems) {
            Should -Invoke Test-Path -Times 1 -Exactly -ParameterFilter {
                $LiteralPath -eq "$userRoot\Software\$registryStem\Capabilities"
            }
        }
        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter {
            $ArgumentList[0] -eq "UNLOAD" -and
            $ArgumentList[1] -eq "HKU\$sid"
        }
    }

    It "does not unload an already-loaded <Name> profile" -ForEach $scriptCases {
        $sid = "S-1-5-21-1001"
        $profileKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
        $userRoot = "Registry::HKEY_USERS\$sid"

        Mock Get-ChildItem {
            [pscustomobject]@{
                PSChildName = $sid
                PSPath = $profileKey
            }
        }
        Mock Test-Path { $LiteralPath -eq $userRoot }
        Mock Get-Item { $null }
        Mock Remove-Item {}
        Mock Remove-ItemProperty {}
        Mock Start-Process { [pscustomobject]@{ ExitCode = 0 } }

        & (Join-Path $PSScriptRoot $ScriptName)

        foreach ($registryStem in $RegistryStems) {
            Should -Invoke Test-Path -Times 1 -Exactly -ParameterFilter {
                $LiteralPath -eq "$userRoot\Software\$registryStem\Capabilities"
            }
        }
        Should -Invoke Start-Process -Times 0 -Exactly
    }

    It "does not unload a <Name> profile loaded by a racing process" -ForEach $scriptCases {
        $sid = "S-1-5-21-1002"
        $profileKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
        $userRoot = "Registry::HKEY_USERS\$sid"
        $profileImagePath = Join-Path $TestDrive "Racing User"
        $ntUserPath = Join-Path $profileImagePath "NTUSER.DAT"
        $state = [pscustomobject]@{ UserRootChecks = 0 }
        $originalSystemRoot = $env:SystemRoot
        $env:SystemRoot = Join-Path $TestDrive "Windows"

        Mock Get-ChildItem {
            [pscustomobject]@{
                PSChildName = $sid
                PSPath = $profileKey
            }
        }
        Mock Get-ItemPropertyValue { $profileImagePath }
        Mock Test-Path {
            if ($LiteralPath -eq $userRoot) {
                $state.UserRootChecks += 1
                return $state.UserRootChecks -gt 1
            }
            return $LiteralPath -eq $ntUserPath
        }
        Mock Get-Item { $null }
        Mock Remove-Item {}
        Mock Remove-ItemProperty {}
        Mock Start-Process { [pscustomobject]@{ ExitCode = 32 } }

        try {
            & (Join-Path $PSScriptRoot $ScriptName)
        }
        finally {
            $env:SystemRoot = $originalSystemRoot
        }

        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter {
            $ArgumentList[0] -eq "LOAD" -and
            $ArgumentList[1] -eq "HKU\$sid"
        }
        foreach ($registryStem in $RegistryStems) {
            Should -Invoke Test-Path -Times 1 -Exactly -ParameterFilter {
                $LiteralPath -eq "$userRoot\Software\$registryStem\Capabilities"
            }
        }
        Should -Invoke Start-Process -Times 0 -Exactly -ParameterFilter {
            $ArgumentList[0] -eq "UNLOAD"
        }
    }

    It "unloads its <Name> hive in finally and aggregates cleanup failures" -ForEach $scriptCases {
        $sid = "S-1-5-21-1003"
        $profileKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
        $userRoot = "Registry::HKEY_USERS\$sid"
        $profileImagePath = Join-Path $TestDrive "Failing User"
        $ntUserPath = Join-Path $profileImagePath "NTUSER.DAT"
        $originalSystemRoot = $env:SystemRoot
        $env:SystemRoot = Join-Path $TestDrive "Windows"

        Mock Get-ChildItem {
            [pscustomobject]@{
                PSChildName = $sid
                PSPath = $profileKey
            }
        }
        Mock Get-ItemPropertyValue { $profileImagePath }
        Mock Test-Path {
            if ($LiteralPath -eq $ntUserPath) {
                return $true
            }
            return $false
        }
        Mock Get-Item { throw "cleanup exploded" }
        Mock Remove-Item {}
        Mock Remove-ItemProperty {}
        Mock Start-Process {
            if ($ArgumentList[0] -eq "UNLOAD") {
                return [pscustomobject]@{ ExitCode = 5 }
            }
            return [pscustomobject]@{ ExitCode = 0 }
        }

        $caught = $null
        try {
            & (Join-Path $PSScriptRoot $ScriptName)
        }
        catch {
            $caught = $_
        }
        finally {
            $env:SystemRoot = $originalSystemRoot
        }

        $caught | Should -Not -BeNullOrEmpty
        foreach ($applicationName in $ApplicationNames) {
            $caught.Exception.Message | Should -Match ([regex]::Escape($applicationName))
        }
        $caught.Exception.Message | Should -Match "cleanup exploded"
        $caught.Exception.Message | Should -Match "UNLOAD.*exit code 5"
        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter {
            $ArgumentList[0] -eq "UNLOAD" -and
            $ArgumentList[1] -eq "HKU\$sid"
        }
    }

    It "disposes every <Name> registry key before unloading its offline hive" -ForEach $scriptCases {
        $sid = "S-1-5-21-1004"
        $profileKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
        $userRoot = "Registry::HKEY_USERS\$sid"
        $profileImagePath = Join-Path $TestDrive "Disposable User"
        $ntUserPath = Join-Path $profileImagePath "NTUSER.DAT"
        $keys = [System.Collections.Generic.List[CMTraceOpen.Tests.DisposableRegistryKey]]::new()
        $state = [pscustomobject]@{ AllDisposedAtUnload = $false }
        $originalSystemRoot = $env:SystemRoot
        $env:SystemRoot = Join-Path $TestDrive "Windows"

        Mock Get-ChildItem {
            [pscustomobject]@{
                PSChildName = $sid
                PSPath = $profileKey
            }
        }
        Mock Get-ItemPropertyValue { $profileImagePath }
        Mock Test-Path { $LiteralPath -eq $ntUserPath }
        Mock Get-Item {
            $key = [CMTraceOpen.Tests.DisposableRegistryKey]::new()
            $keys.Add($key)
            return $key
        }
        Mock Remove-Item {}
        Mock Remove-ItemProperty {}
        Mock Start-Process {
            if ($ArgumentList[0] -eq "UNLOAD") {
                $state.AllDisposedAtUnload = @(
                    $keys | Where-Object { -not $_.IsDisposed }
                ).Count -eq 0
            }
            return [pscustomobject]@{ ExitCode = 0 }
        }

        try {
            & (Join-Path $PSScriptRoot $ScriptName)
        }
        finally {
            $env:SystemRoot = $originalSystemRoot
        }

        $keys.Count | Should -BeGreaterThan 0
        @($keys | Where-Object { -not $_.IsDisposed }).Count | Should -Be 0
        $state.AllDisposedAtUnload | Should -BeTrue
    }

    It "notifies Explorer after partial <Name> cleanup failures" -ForEach $scriptCases {
        $sid = "S-1-5-21-1005"
        $profileKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
        $userRoot = "Registry::HKEY_USERS\$sid"

        Mock Get-ChildItem {
            [pscustomobject]@{
                PSChildName = $sid
                PSPath = $profileKey
            }
        }
        Mock Test-Path { $LiteralPath -eq $userRoot }
        Mock Get-Item { throw "partial cleanup failure" }
        Mock Remove-Item {}
        Mock Remove-ItemProperty {}
        Mock Start-Process { [pscustomobject]@{ ExitCode = 0 } }

        { & (Join-Path $PSScriptRoot $ScriptName) } | Should -Throw "*partial cleanup failure*"

        [CMTraceOpen.AssociationChange]::NotifyCount | Should -Be 1
    }
}
