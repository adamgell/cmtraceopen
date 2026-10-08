# Loaded as source by the native command. No operation runs on dot-sourcing.
# The five setters are intentionally unchanged by this repair. All other
# diagnostics are observed only, to detect conflicts before restoring file logging.
$script:CmtDnsOwned = @('Queries', 'Answers', 'ReceivePackets', 'UdpPackets', 'EnableLoggingToFile')
$script:CmtDnsBooleans = @(
    'SaveLogsToPersistentStorage', 'Queries', 'Answers', 'Notifications', 'Update',
    'QuestionTransactions', 'UnmatchedResponse', 'SendPackets', 'ReceivePackets',
    'TcpPackets', 'UdpPackets', 'FullPackets', 'UseSystemEventLog', 'EnableLoggingToFile',
    'EnableLogFileRollover', 'WriteThrough', 'EnableLoggingForLocalLookupEvent',
    'EnableLoggingForPluginDllEvent', 'EnableLoggingForRecursiveLookupEvent',
    'EnableLoggingForRemoteServerEvent', 'EnableLoggingForServerStartStopEvent',
    'EnableLoggingForTombstoneEvent', 'EnableLoggingForZoneDataWriteEvent',
    'EnableLoggingForZoneLoadingEvent'
)

function ConvertTo-CmtDnsSnapshot($diagnostics) {
    # Schema anchored to the documented Get-DnsServerDiagnostics output:
    # https://learn.microsoft.com/powershell/module/dnsserver/get-dnsserverdiagnostics?view=windowsserver2025-ps
    # Different/missing properties are unsupported, not evidence of disabled logging.
    $names = @($script:CmtDnsBooleans) + @('FilterIPAddressList', 'EventLogLevel', 'LogFilePath', 'MaxMBFileSize')
    $metadata = @('CimClass', 'CimInstanceProperties', 'CimSystemProperties', 'PSComputerName', 'PSShowComputerName', 'RunspaceId')
    $actual = @($diagnostics.PSObject.Properties.Name | Where-Object { $_ -cnotin $metadata })
    if ($actual.Count -ne $names.Count) { throw 'DNS_CONFIG_UNSUPPORTED' }
    foreach ($name in $actual) { if ($name -cnotin $names) { throw 'DNS_CONFIG_UNSUPPORTED' } }
    $snapshot = [ordered]@{}
    foreach ($name in $script:CmtDnsBooleans) {
        if ($diagnostics.$name -isnot [bool]) { throw 'DNS_CONFIG_UNSUPPORTED' }
        $snapshot[$name] = $diagnostics.$name
    }
    foreach ($name in @('EventLogLevel', 'MaxMBFileSize')) {
        $value = $diagnostics.$name
        if (($value -isnot [int] -and $value -isnot [uint32] -and $value -isnot [long] -and $value -isnot [uint64]) -or
            $value -lt 0 -or $value -gt [uint32]::MaxValue) { throw 'DNS_CONFIG_UNSUPPORTED' }
        $snapshot[$name] = [long]$value
    }
    $path = $diagnostics.LogFilePath
    if ($null -ne $path -and ($path -isnot [string] -or $path.Length -gt 4096)) { throw 'DNS_CONFIG_UNSUPPORTED' }
    $snapshot.LogFilePath = $path
    $addresses = @()
    foreach ($address in $diagnostics.FilterIPAddressList) {
        if ($address -isnot [string] -and $address -isnot [Net.IPAddress]) { throw 'DNS_CONFIG_UNSUPPORTED' }
        $parsed = $null
        if (-not [Net.IPAddress]::TryParse([string]$address, [ref]$parsed)) { throw 'DNS_CONFIG_UNSUPPORTED' }
        $addresses += $parsed.ToString()
        if ($addresses.Count -gt 256) { throw 'DNS_CONFIG_UNSUPPORTED' }
    }
    $snapshot.FilterIPAddressList = @($addresses | Sort-Object -CaseSensitive)
    return $snapshot
}

function Get-CmtDnsSnapshot {
    try { $diagnostics = Get-DnsServerDiagnostics -ErrorAction Stop }
    catch { throw 'DNS_READ_FAILED' }
    ConvertTo-CmtDnsSnapshot $diagnostics
}

function Get-CmtDnsHash($snapshot) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes(($snapshot | ConvertTo-Json -Depth 4 -Compress))
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Test-CmtDnsAcl([string]$owner, $rules) {
    $trusted = @('S-1-5-18', 'S-1-5-32-544') # SYSTEM and Administrators only.
    if ($owner -cnotin $trusted) { return $false }
    # SetValue, CreateSubKey, Delete, ChangePermissions, TakeOwnership.
    # ReadPermissions is intentionally absent (it is also part of WriteKey).
    $writeRights = 0x000D0006
    foreach ($rule in $rules) {
        if (([int]$rule.PropagationFlags -band 2) -ne 0) { continue } # InheritOnly
        if ([int]$rule.AccessControlType -eq 0 -and
            ([int]$rule.RegistryRights -band $writeRights) -ne 0 -and
            $rule.IdentityReference.Value -cnotin $trusted) { return $false }
    }
    return $true
}

function Read-CmtDnsAcl($key) {
    $acl = $key.GetAccessControl()
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    return [pscustomobject]@{ Owner = $owner; Rules = $rules; HasDacl = ($null -ne $raw.DiscretionaryAcl) }
}

function Assert-CmtDnsKeyTrusted($key) {
    $acl = Read-CmtDnsAcl $key
    if (-not $acl.HasDacl -or -not (Test-CmtDnsAcl $acl.Owner $acl.Rules)) {
        throw 'DNS_STORE_UNTRUSTED'
    }
}

function Open-CmtDnsMachine {
    [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
}

function Open-CmtDnsStore([bool]$write) {
    $machine = Open-CmtDnsMachine
    $parent = $null; $key = $null
    try {
        $parent = $machine.OpenSubKey('SOFTWARE\CMTraceOpen', $write)
        if ($null -eq $parent -and $write) { $parent = $machine.CreateSubKey('SOFTWARE\CMTraceOpen') }
        if ($null -eq $parent) { return $null }
        Assert-CmtDnsKeyTrusted $parent
        $key = $parent.OpenSubKey('DnsDebugLogging', $write)
        if ($null -eq $key -and $write) { $key = $parent.CreateSubKey('DnsDebugLogging') }
        if ($null -ne $key) { Assert-CmtDnsKeyTrusted $key }
        $result = $key; $key = $null
        return $result
    } finally {
        if ($null -ne $key) { $key.Dispose() }
        if ($null -ne $parent) { $parent.Dispose() }
        $machine.Dispose()
    }
}

function ConvertFrom-CmtDnsRecord([string]$text) {
    if ($text.Length -gt 2048) { throw 'DNS_RECORD_INVALID' }
    try { $record = $text | ConvertFrom-Json -ErrorAction Stop } catch { throw 'DNS_RECORD_INVALID' }
    if ($null -eq $record -or @($record.PSObject.Properties).Count -ne 4 -or
        $record.version -isnot [long] -and $record.version -isnot [int] -or $record.version -ne 1 -or
        @($record.prior.PSObject.Properties).Count -ne 5 -or
        $record.beforeHash -isnot [string] -or $record.expectedHash -isnot [string] -or
        $record.beforeHash -cnotmatch '\A[0-9a-f]{64}\z' -or $record.expectedHash -cnotmatch '\A[0-9a-f]{64}\z') {
        throw 'DNS_RECORD_INVALID'
    }
    $prior = [ordered]@{}
    foreach ($name in $script:CmtDnsOwned) {
        if ($record.prior.$name -isnot [bool]) { throw 'DNS_RECORD_INVALID' }
        $prior[$name] = $record.prior.$name
    }
    $canonical = [ordered]@{ version = 1; prior = $prior; beforeHash = $record.beforeHash; expectedHash = $record.expectedHash }
    # Also rejects duplicates, unknown/case-colliding keys, altered key order,
    # whitespace and alternate numeric forms. We only accept our own serialization.
    if ($text -cne ($canonical | ConvertTo-Json -Depth 4 -Compress)) { throw 'DNS_RECORD_INVALID' }
    return $canonical
}

function Read-CmtDnsRecord {
    $key = $null
    try {
        $key = Open-CmtDnsStore $false
        if ($null -eq $key) { return $null }
        # GetValue can return its null default for an existing unsupported type.
        # Registry value names are case-insensitive; absence is checked separately.
        if ($key.GetValueNames() -notcontains 'PriorConfiguration') { return $null }
        if ($key.GetValueKind('PriorConfiguration') -ne [Microsoft.Win32.RegistryValueKind]::String) {
            throw 'DNS_RECORD_INVALID'
        }
        $text = $key.GetValue('PriorConfiguration', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($text -isnot [string]) { throw 'DNS_RECORD_INVALID' }
        return ConvertFrom-CmtDnsRecord $text
    } finally { if ($null -ne $key) { $key.Dispose() } }
}

function Save-CmtDnsRecord($record) {
    $key = $null
    try {
        $key = Open-CmtDnsStore $true
        if ($key.GetValueNames() -contains 'PriorConfiguration') { throw 'DNS_ALREADY_OWNED' }
        $text = $record | ConvertTo-Json -Depth 4 -Compress
        $key.SetValue('PriorConfiguration', $text, [Microsoft.Win32.RegistryValueKind]::String)
        $key.Flush()
        if ($key.GetValueKind('PriorConfiguration') -ne [Microsoft.Win32.RegistryValueKind]::String -or
            $key.GetValue('PriorConfiguration', $null) -cne $text) { throw 'DNS_STORE_FAILED' }
    } finally { if ($null -ne $key) { $key.Dispose() } }
}

function Remove-CmtDnsRecord($record) {
    $key = $null
    try {
        $key = Open-CmtDnsStore $true
        if ($key.GetValueKind('PriorConfiguration') -ne [Microsoft.Win32.RegistryValueKind]::String -or
            $key.GetValue('PriorConfiguration', $null) -cne ($record | ConvertTo-Json -Depth 4 -Compress)) {
            throw 'DNS_RECORD_INVALID'
        }
        # Never delete this key, its parent, or any other operator-owned value.
        $key.DeleteValue('PriorConfiguration', $true)
        $key.Flush()
    } finally { if ($null -ne $key) { $key.Dispose() } }
}

function New-CmtDnsMutex { [Threading.Mutex]::new($false, 'Global\CMTraceOpen.DnsDebugLogging') }

function Invoke-CmtDnsAction([ValidateSet('Status', 'Enable', 'Disable')][string]$action) {
    $ErrorActionPreference = 'Stop'
    $mutex = $null; $acquired = $false; $failure = 'DNS_STORE_FAILED'
    try {
        $failure = 'DNS_LOCK_FAILED'
        $mutex = New-CmtDnsMutex
        try { $acquired = $mutex.WaitOne(5000) }
        catch {
            if ($_.Exception.GetBaseException() -is [Threading.AbandonedMutexException]) { $acquired = $true }
            else { throw }
        }
        if (-not $acquired) { throw 'DNS_BUSY' }
        $failure = 'DNS_STORE_FAILED'
        $record = Read-CmtDnsRecord
        if ($action -eq 'Status' -and $null -eq $record) {
            return [pscustomobject]@{ canRestoreLogging = $false; errorCode = $null }
        }
        if ($action -eq 'Enable' -and $null -ne $record) { throw 'DNS_ALREADY_OWNED' }
        if ($action -eq 'Disable' -and $null -eq $record) { throw 'DNS_NOT_OWNED' }
        $snapshot = Get-CmtDnsSnapshot
        $currentHash = Get-CmtDnsHash $snapshot
        if ($action -eq 'Enable') {
            $prior = [ordered]@{}
            foreach ($name in $script:CmtDnsOwned) { $prior[$name] = $snapshot[$name]; $snapshot[$name] = $true }
            $expectedHash = Get-CmtDnsHash $snapshot
            if ($expectedHash -ceq $currentHash) { throw 'DNS_ALREADY_ENABLED' }
            $record = [ordered]@{ version = 1; prior = $prior; beforeHash = $currentHash; expectedHash = $expectedHash }
            Save-CmtDnsRecord $record
        } elseif ($currentHash -cne $record.beforeHash -and $currentHash -cne $record.expectedHash) {
            throw 'DNS_CONFLICT'
        } else {
            # A syntactically valid edited prior value must not authorize a DNS
            # write either. Reconstruct both states against the matched full guard.
            foreach ($name in $script:CmtDnsOwned) { $snapshot[$name] = $record.prior[$name] }
            if ((Get-CmtDnsHash $snapshot) -cne $record.beforeHash) { throw 'DNS_RECORD_INVALID' }
            foreach ($name in $script:CmtDnsOwned) { $snapshot[$name] = $true }
            if ((Get-CmtDnsHash $snapshot) -cne $record.expectedHash) { throw 'DNS_RECORD_INVALID' }
        }
        if ($action -eq 'Status') {
            return [pscustomobject]@{ canRestoreLogging = $true; errorCode = $null }
        }
        # An application mutex cannot exclude independent DNS administration.
        # Recheck immediately before mutation, and verify the complete outcome.
        if ((Get-CmtDnsHash (Get-CmtDnsSnapshot)) -cne $currentHash) { throw 'DNS_CONFLICT' }
        if ($action -eq 'Enable' -or $currentHash -cne $record.beforeHash) {
            $switches = @{}
            foreach ($name in $script:CmtDnsOwned) {
                $switches[$name] = if ($action -eq 'Enable') { $true } else { $record.prior[$name] }
            }
            try { Set-DnsServerDiagnostics @switches -ErrorAction Stop | Out-Null }
            catch { throw 'DNS_APPLY_FAILED' }
        }
        $targetHash = if ($action -eq 'Enable') { $record.expectedHash } else { $record.beforeHash }
        if ((Get-CmtDnsHash (Get-CmtDnsSnapshot)) -cne $targetHash) { throw 'DNS_VERIFY_FAILED' }
        if ($action -eq 'Disable') { Remove-CmtDnsRecord $record }
        return [pscustomobject]@{ canRestoreLogging = ($action -eq 'Enable'); errorCode = $null }
    } catch {
        $code = $_.Exception.Message
        if ($code -cnotin @('DNS_CONFIG_UNSUPPORTED', 'DNS_READ_FAILED', 'DNS_STORE_UNTRUSTED',
            'DNS_RECORD_INVALID', 'DNS_STORE_FAILED', 'DNS_ALREADY_OWNED', 'DNS_NOT_OWNED',
            'DNS_ALREADY_ENABLED', 'DNS_CONFLICT', 'DNS_BUSY', 'DNS_APPLY_FAILED', 'DNS_VERIFY_FAILED')) { $code = $failure }
        return [pscustomobject]@{ canRestoreLogging = $false; errorCode = $code }
    } finally {
        if ($acquired) { $mutex.ReleaseMutex() }
        if ($null -ne $mutex) { $mutex.Dispose() }
    }
}
