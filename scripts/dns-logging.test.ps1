param(
    [string]$ResumeRoot,
    [string]$SourcePath
)
# No DNS cmdlet or registry access: the production transaction runs against a
# documented diagnostic fixture and a temporary file standing in for its value.
$ErrorActionPreference = 'Stop'
if (-not $SourcePath) { $SourcePath = Join-Path $PSScriptRoot '../src-tauri/src/commands/dns_logging.ps1' }
. $SourcePath
$root = if ($ResumeRoot) { $ResumeRoot } else { Join-Path ([IO.Path]::GetTempPath()) ('cmtrace-dns-test-' + [guid]::NewGuid()) }
if (-not $ResumeRoot) { $null = New-Item -ItemType Directory -Path $root }
$script:recordPath = Join-Path $root 'record.json'
$owned = @('Queries', 'Answers', 'ReceivePackets', 'UdpPackets', 'EnableLoggingToFile')
# Property names/defaults anchored to Microsoft's Get-DnsServerDiagnostics
# Windows Server 2025 reference example; no captured log lines or server data.
function Reset-Fixture {
    $script:config = [pscustomobject][ordered]@{
        SaveLogsToPersistentStorage = $false; Queries = $true; Answers = $false
        Notifications = $true; Update = $false; QuestionTransactions = $false
        UnmatchedResponse = $false; SendPackets = $true; ReceivePackets = $false
        TcpPackets = $true; UdpPackets = $false; FullPackets = $false
        FilterIPAddressList = @(); EventLogLevel = 4; UseSystemEventLog = $false
        EnableLoggingToFile = $true; EnableLogFileRollover = $true
        LogFilePath = 'C:\Logs\dns.log'; MaxMBFileSize = 500000000; WriteThrough = $false
        EnableLoggingForLocalLookupEvent = $false; EnableLoggingForPluginDllEvent = $false
        EnableLoggingForRecursiveLookupEvent = $false; EnableLoggingForRemoteServerEvent = $false
        EnableLoggingForServerStartStopEvent = $false; EnableLoggingForTombstoneEvent = $false
        EnableLoggingForZoneDataWriteEvent = $false; EnableLoggingForZoneLoadingEvent = $false
    }
    if (Test-Path $script:recordPath) { Remove-Item $script:recordPath }
    $script:writes = @(); $script:flushes = 0; $script:released = 0; $script:storeWrites = 0
    $script:valueKind = [Microsoft.Win32.RegistryValueKind]::String
    $script:fault = ''; $script:lockBusy = $false; $script:abandoned = $false
    $script:unsafeKey = ''; $script:reads = 0; $script:nameReads = 0
}
function Assert($condition, [string]$message) { if (-not $condition) { throw $message } }
function Get-DnsServerDiagnostics {
    $script:reads++
    if ($script:fault -eq 'pre-drift' -and $script:reads -eq 2) { $script:config.Notifications = -not $script:config.Notifications }
    if ($script:fault -eq 'read') { throw 'sensitive server read error' }
    $script:config
}
function Set-DnsServerDiagnostics {
    param([bool]$Queries, [bool]$Answers, [bool]$ReceivePackets, [bool]$UdpPackets, [bool]$EnableLoggingToFile, $ErrorAction)
    $call = [ordered]@{}
    foreach ($name in $owned) { Assert ($PSBoundParameters.ContainsKey($name)) "missing owned flag $name"; $call[$name] = $PSBoundParameters[$name] }
    Assert (Test-Path $script:recordPath) 'DNS write before durable capture'
    Assert ($script:flushes -gt 0) 'DNS write before flush'
    $script:writes += ,$call
    if ($script:fault -eq 'apply-before') { throw 'sensitive mutation error' }
    foreach ($name in $owned) {
        $script:config.$name = $call[$name]
        if ($script:fault -eq 'partial' -and $name -eq 'Answers') { throw 'interrupted mutation' }
    }
    if ($script:fault -eq 'post-drift') { $script:config.Notifications = -not $script:config.Notifications }
    if ($script:fault -eq 'apply-after') { throw 'lost successful response' }
}
# Mock only the OS boundaries. Record parsing, hashing, verification and the
# production save/flush/delete order all run unchanged.
function Open-CmtDnsMachine {
    if ($script:fault -eq 'store-open') { throw 'sensitive registry error' }
    New-FixtureKey machine
}
function Read-CmtDnsAcl($key) {
    $owner = if ($script:unsafeKey -eq $key.Level) { 'S-1-5-21-1-2-3-1001' } else { 'S-1-5-32-544' }
    [pscustomobject]@{ Owner = $owner; Rules = @(); HasDacl = $true }
}
function New-FixtureKey([string]$level) {
    $key = [pscustomobject]@{ Level = $level }
    $key | Add-Member ScriptMethod OpenSubKey {
        param($path, $write)
        if ($this.Level -eq 'machine') {
            Assert ($path -ceq 'SOFTWARE\CMTraceOpen') 'wrong application registry parent'
            return New-FixtureKey parent
        }
        Assert ($this.Level -eq 'parent' -and $path -ceq 'DnsDebugLogging') 'wrong recovery key'
        New-FixtureKey leaf
    }
    $key | Add-Member ScriptMethod GetValueNames {
        $script:nameReads++
        if ($script:fault -eq 'save-race' -and $script:nameReads -eq 2) {
            $script:valueKind = [Microsoft.Win32.RegistryValueKind]::Unknown
            [IO.File]::WriteAllText($script:recordPath, 'value created before save must survive')
        }
        # Registry value names are case-insensitive, even if stored differently.
        if (Test-Path $script:recordPath) { 'priorconfiguration' }
    }
    $key | Add-Member ScriptMethod GetValue {
        param($name, $default, $options)
        Assert ($name -ceq 'PriorConfiguration') 'wrong read value'
        # .NET can return the default for an existing unsupported native type.
        if ($script:valueKind -in @([Microsoft.Win32.RegistryValueKind]::Unknown, [Microsoft.Win32.RegistryValueKind]::None)) { return $default }
        if (Test-Path $script:recordPath) { [IO.File]::ReadAllText($script:recordPath) } else { $null }
    }
    $key | Add-Member ScriptMethod GetValueKind { param($name); $script:valueKind }
    $key | Add-Member ScriptMethod SetValue {
        param($name, $value, $kind)
        Assert ($name -ceq 'PriorConfiguration') 'wrong write value'
        if ($script:fault -eq 'store-write') { throw 'store full' }
        $script:storeWrites++
        $script:valueKind = $kind
        [IO.File]::WriteAllText($script:recordPath, $value)
    }
    $key | Add-Member ScriptMethod Flush {
        $script:flushes++
        if ($script:fault -eq 'store-flush') { throw 'flush failed' }
    }
    $key | Add-Member ScriptMethod DeleteValue {
        param($name, $throwOnMissing)
        Assert ($name -ceq 'PriorConfiguration') 'wrong deleted value'
        if ($script:fault -eq 'delete') { throw 'delete failed' }
        Remove-Item $script:recordPath
    }
    $key | Add-Member ScriptMethod Dispose {}
    $key
}
function New-CmtDnsMutex {
    $mutex = [pscustomobject]@{}
    $mutex | Add-Member ScriptMethod WaitOne {
        param($timeout)
        Assert ($timeout -eq 5000) 'unbounded mutex acquisition'
        if ($script:abandoned) { throw [Threading.AbandonedMutexException]::new() }
        -not $script:lockBusy
    }
    $mutex | Add-Member ScriptMethod ReleaseMutex { $script:released++ }
    $mutex | Add-Member ScriptMethod Dispose {}
    $mutex
}
function Expect-Error([string]$action, [string]$code) {
    $result = Invoke-CmtDnsAction $action
    Assert ($result.errorCode -ceq $code) "expected $code, got $($result.errorCode)"
    Assert (-not $result.canRestoreLogging) 'error offered automatic restore'
}
function Enable-Fixture {
    $result = Invoke-CmtDnsAction Enable
    Assert ($null -eq $result.errorCode) "enable failed: $($result.errorCode)"
}
if ($ResumeRoot) {
    $script:config = [IO.File]::ReadAllText((Join-Path $root 'config.json')) | ConvertFrom-Json
    $script:fault = ''; $script:lockBusy = $false; $script:abandoned = $false
    $script:unsafeKey = ''; $script:reads = 0; $script:nameReads = 0; $script:writes = @(); $script:flushes = 1; $script:released = 0; $script:storeWrites = 0
    $script:valueKind = [Microsoft.Win32.RegistryValueKind]::String
    Assert ((Invoke-CmtDnsAction Status).canRestoreLogging) 'fresh process did not find saved recovery'
    Assert ($null -eq (Invoke-CmtDnsAction Disable).errorCode) 'fresh process restore failed'
    [IO.File]::WriteAllText((Join-Path $root 'config.json'), ($script:config | ConvertTo-Json -Depth 5 -Compress))
    Write-Output 'PASS: fresh process restored only from persisted fixture'
    exit 0
}
try {
    Reset-Fixture
    $baseline = $script:config | ConvertTo-Json -Depth 5 -Compress
    Enable-Fixture
    $saved = [IO.File]::ReadAllText($script:recordPath)
    Assert ((Invoke-CmtDnsAction Status).canRestoreLogging) 'no recovery after enable'
    Expect-Error Enable DNS_ALREADY_OWNED
    Assert ([IO.File]::ReadAllText($script:recordPath) -ceq $saved) 'repeat enable overwrote baseline'
    Assert ($script:writes.Count -eq 1) 'repeat enable changed DNS'
    $result = Invoke-CmtDnsAction Disable
    Assert ($null -eq $result.errorCode) 'restore failed'
    Assert (($script:config | ConvertTo-Json -Depth 5 -Compress) -ceq $baseline) 'prior or unrelated configuration lost'
    Assert (-not (Test-Path $script:recordPath)) 'verified restore retained ownership'
    Expect-Error Disable DNS_NOT_OWNED
    Assert ($script:writes.Count -eq 2) 'repeated disable changed DNS'
    Write-Output 'PASS: preconfigured round trip; repeated actions preserve ownership'

    for ($bits = 0; $bits -lt 32; $bits++) {
        Reset-Fixture
        for ($i = 0; $i -lt $owned.Count; $i++) { $script:config.($owned[$i]) = [bool]($bits -band (1 -shl $i)) }
        $baseline = $script:config | ConvertTo-Json -Depth 5 -Compress
        if ($bits -eq 31) {
            Expect-Error Enable DNS_ALREADY_ENABLED
            Assert ($script:writes.Count -eq 0 -and -not (Test-Path $script:recordPath)) 'took ownership of unchanged settings'
        } else {
            Enable-Fixture
            Assert ($null -eq (Invoke-CmtDnsAction Disable).errorCode) "round trip failed at $bits"
            Assert (($script:config | ConvertTo-Json -Depth 5 -Compress) -ceq $baseline) "prior/unrelated value lost at $bits"
        }
    }
    Write-Output 'PASS: all 32 combinations of prior flags; unrelated configuration unchanged'

    Reset-Fixture; $baseline = $script:config | ConvertTo-Json -Depth 5 -Compress
    Enable-Fixture
    [IO.File]::WriteAllText((Join-Path $root 'config.json'), ($script:config | ConvertTo-Json -Depth 5 -Compress))
    & (Get-Process -Id $PID).Path -NoProfile -NonInteractive -File $PSCommandPath -ResumeRoot $root -SourcePath $SourcePath
    Assert ($LASTEXITCODE -eq 0) 'separate recovery process failed'
    Assert ([IO.File]::ReadAllText((Join-Path $root 'config.json')) -ceq $baseline) 'separate process lost original values'
    Assert (-not (Test-Path $script:recordPath)) 'separate process did not clear verified record'

    foreach ($keyLevel in @('parent', 'leaf')) {
        Reset-Fixture; $script:unsafeKey = $keyLevel
        Expect-Error Enable DNS_STORE_UNTRUSTED; Expect-Error Status DNS_STORE_UNTRUSTED
        Assert ($script:writes.Count -eq 0 -and -not (Test-Path $script:recordPath)) "unsafe $keyLevel was used"
    }
    Reset-Fixture; $script:fault = 'pre-drift'; Expect-Error Enable DNS_CONFLICT
    Assert ($script:writes.Count -eq 0 -and (Test-Path $script:recordPath)) 'prewrite drift changed DNS/lost record'
    Write-Output 'PASS: registry parent/leaf trust and immediate prewrite conflict'


    foreach ($faultCase in @('read', 'store-open', 'store-write', 'store-flush')) {
        Reset-Fixture; $script:fault = $faultCase
        $result = Invoke-CmtDnsAction Enable
        Assert ($null -ne $result.errorCode -and $script:writes.Count -eq 0) "capture failure wrote DNS: $faultCase"
    }
    Write-Output 'PASS: capture/store failures make zero DNS writes'

    foreach ($faultCase in @('apply-before', 'apply-after')) {
        Reset-Fixture; $baseline = $script:config | ConvertTo-Json -Depth 5 -Compress
        $script:fault = $faultCase; Expect-Error Enable DNS_APPLY_FAILED
        Assert (Test-Path $script:recordPath) 'apply failure lost recovery'
        $script:fault = ''
        Assert ((Invoke-CmtDnsAction Status).canRestoreLogging) "cannot recover $faultCase"
        $result = Invoke-CmtDnsAction Disable
        Assert ($null -eq $result.errorCode) "recovery failed $faultCase"
        Assert (($script:config | ConvertTo-Json -Depth 5 -Compress) -ceq $baseline) 'recovery changed baseline'
    }
    Reset-Fixture; $script:fault = 'partial'; Expect-Error Enable DNS_APPLY_FAILED
    $script:fault = ''; $count = $script:writes.Count
    Expect-Error Disable DNS_CONFLICT
    Assert ($script:writes.Count -eq $count -and (Test-Path $script:recordPath)) 'ambiguous partial apply changed DNS/lost record'
    Reset-Fixture; Enable-Fixture; $script:fault = 'partial'; Expect-Error Disable DNS_APPLY_FAILED
    $script:fault = ''; Expect-Error Disable DNS_CONFLICT
    Write-Output 'PASS: complete interrupted operations recover; partial operations retain conflict'

    foreach ($property in @('Answers', 'Notifications', 'EnableLogFileRollover')) {
        Reset-Fixture; Enable-Fixture; $script:config.$property = -not $script:config.$property
        Expect-Error Status DNS_CONFLICT; Expect-Error Disable DNS_CONFLICT
        Assert ($script:writes.Count -eq 1 -and (Test-Path $script:recordPath)) "drift overwritten: $property"
    }
    Reset-Fixture; Enable-Fixture; $script:fault = 'post-drift'; Expect-Error Disable DNS_VERIFY_FAILED
    Assert (Test-Path $script:recordPath) 'post-restore drift deleted recovery'
    Reset-Fixture; Enable-Fixture; $script:fault = 'delete'; Expect-Error Disable DNS_STORE_FAILED
    $script:fault = ''; $count = $script:writes.Count
    Assert ($null -eq (Invoke-CmtDnsAction Disable).errorCode) 'baseline cleanup failed'
    Assert ($script:writes.Count -eq $count) 'baseline cleanup rewrote DNS'
    Write-Output 'PASS: external drift and cleanup failures preserve recovery'

    foreach ($kind in @('Unknown', 'None', 'ExpandString', 'DWord', 'Binary', 'MultiString', 'QWord')) {
        Reset-Fixture
        $script:valueKind = [Microsoft.Win32.RegistryValueKind]::$kind
        [IO.File]::WriteAllText($script:recordPath, 'existing value must survive')
        Expect-Error Status DNS_RECORD_INVALID; Expect-Error Enable DNS_RECORD_INVALID; Expect-Error Disable DNS_RECORD_INVALID
        Assert ($script:writes.Count -eq 0 -and $script:storeWrites -eq 0) "unsupported type authorized a write: $kind"
        Assert ([IO.File]::ReadAllText($script:recordPath) -ceq 'existing value must survive') 'existing unsupported value was replaced'
        $saveError = $null
        try { Save-CmtDnsRecord ([ordered]@{ version = 1 }) } catch { $saveError = $_.Exception.Message }
        Assert ($saveError -ceq 'DNS_ALREADY_OWNED') "save did not refuse existing value: $kind"
        Assert ($script:storeWrites -eq 0 -and [IO.File]::ReadAllText($script:recordPath) -ceq 'existing value must survive') 'save replaced unsupported value'
    }
    Reset-Fixture; $script:fault = 'save-race'
    Expect-Error Enable DNS_ALREADY_OWNED
    Assert ($script:writes.Count -eq 0 -and $script:storeWrites -eq 0) 'save race authorized a write'
    Assert ([IO.File]::ReadAllText($script:recordPath) -ceq 'value created before save must survive') 'save race replaced existing value'
    Write-Output 'PASS: every existing non-string record blocks capture and DNS writes'

    Reset-Fixture; Enable-Fixture; $valid = [IO.File]::ReadAllText($script:recordPath)
    foreach ($bad in @('{}', $valid.Replace('"version":1', '"version":2'),
        $valid.Replace('"version":1', '"version":1,"version":1'),
        $valid.Replace('"version":1', '"Version":1'),
        $valid.Replace('"Queries":true', '"Queries":"true"'), ($valid + ' '))) {
        [IO.File]::WriteAllText($script:recordPath, $bad)
        Expect-Error Status DNS_RECORD_INVALID; Expect-Error Enable DNS_RECORD_INVALID; Expect-Error Disable DNS_RECORD_INVALID
        Assert ($script:writes.Count -eq 1) 'tampered record caused DNS writes'
    }
    [IO.File]::WriteAllText($script:recordPath, $valid.Replace('"Queries":true', '"Queries":false'))
    Expect-Error Status DNS_RECORD_INVALID; Expect-Error Disable DNS_RECORD_INVALID
    Expect-Error Enable DNS_ALREADY_OWNED
    Assert ($script:writes.Count -eq 1) 'edited prior boolean caused DNS writes'
    foreach ($change in @('unknown', 'missing', 'mistyped', 'oversized')) {
        Reset-Fixture
        switch ($change) {
            unknown { $script:config | Add-Member NoteProperty UnknownOption $false }
            missing { $script:config.PSObject.Properties.Remove('Queries') }
            mistyped { $script:config.Answers = 'false' }
            oversized { $script:config.LogFilePath = 'x' * 4097 }
        }
        Expect-Error Enable DNS_CONFIG_UNSUPPORTED
        Assert ($script:writes.Count -eq 0) 'unsupported diagnostics changed DNS'
    }
    Write-Output 'PASS: closed versioned records and unsupported diagnostic schemas fail closed'

    Reset-Fixture; $script:lockBusy = $true; Expect-Error Enable DNS_BUSY
    Assert ($script:writes.Count -eq 0 -and $script:released -eq 0) 'contended lock bypassed/released'
    $script:lockBusy = $false; $script:abandoned = $true; Enable-Fixture
    Assert ($script:released -eq 1) 'abandoned acquired lock was not released'
    Write-Output 'PASS: contended and abandoned mutex paths'

    $trusted = 'S-1-5-32-544'; $ordinary = 'S-1-5-21-1-2-3-1001'
    Assert (Test-CmtDnsAcl $trusted @()) 'administrative owner rejected'
    Assert (-not (Test-CmtDnsAcl $ordinary @())) 'ordinary owner accepted'
    $rule = [pscustomobject]@{ IdentityReference = [pscustomobject]@{ Value = $ordinary }; RegistryRights = 2; PropagationFlags = 0; AccessControlType = 0 }
    Assert (-not (Test-CmtDnsAcl $trusted @($rule))) 'ordinary writer accepted'
    $rule.PropagationFlags = 2
    Assert (Test-CmtDnsAcl $trusted @($rule)) 'inherit-only ACE applied to current key'
    Write-Output 'PASS: untrusted registry owner/writer rejected without ACL writes'
} finally {
    Remove-Item $root -Recurse -Force
}
