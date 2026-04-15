<#
.SYNOPSIS
    Collects DNS and DHCP logs from all domain controllers in the current domain.

.DESCRIPTION
    Auto-discovers domain controllers via Active Directory, then pulls DNS debug
    logs, DNS audit EVTX, and DHCP server logs from each via admin shares (UNC).
    Organizes output by server name for use with CMTrace Open's DNS/DHCP workspace.

    Must be run from a domain-joined machine with domain admin or equivalent
    credentials that can access C$ admin shares on the target DCs.

.PARAMETER OutputRoot
    Root directory for collected logs. Defaults to Desktop\DnsDhcpCollection.

.PARAMETER DomainControllers
    Optional list of DC hostnames to collect from. If omitted, auto-discovers
    all DCs in the current domain.

.PARAMETER SkipDns
    Skip DNS log collection.

.PARAMETER SkipDhcp
    Skip DHCP log collection.

.PARAMETER MaxDebugLogSizeMB
    Maximum size of DNS debug log to copy (in MB). Copies the tail if exceeded.
    Default: 50 MB.

.EXAMPLE
    .\Collect-DnsDhcpFromDomain.ps1
    Auto-discovers all DCs and collects DNS/DHCP logs to Desktop.

.EXAMPLE
    .\Collect-DnsDhcpFromDomain.ps1 -DomainControllers DC1,DC2,DNS3
    Collects from specific servers only.

.EXAMPLE
    .\Collect-DnsDhcpFromDomain.ps1 -OutputRoot C:\Evidence\dns-collection
    Collects to a custom output directory.
#>
[CmdletBinding()]
param(
    [string]$OutputRoot = (Join-Path ([Environment]::GetFolderPath('Desktop')) 'DnsDhcpCollection'),
    [string[]]$DomainControllers,
    [switch]$SkipDns,
    [switch]$SkipDhcp,
    [int]$MaxDebugLogSizeMB = 50
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Step {
    param([Parameter(Mandatory)] [string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([Parameter(Mandatory)] [string]$Message)
    Write-Host "    [+] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([Parameter(Mandatory)] [string]$Message)
    Write-Host "    [!] $Message" -ForegroundColor Yellow
}

function Write-Skip {
    param([Parameter(Mandatory)] [string]$Message)
    Write-Host "    [-] $Message" -ForegroundColor DarkGray
}

function Initialize-Directory {
    param([Parameter(Mandatory)] [string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Get-UtcTimestamp {
    return (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function Test-UncAccess {
    param([Parameter(Mandatory)] [string]$Server)
    $sharePath = "\\$Server\C$"
    try {
        return Test-Path -LiteralPath $sharePath -ErrorAction Stop
    }
    catch {
        return $false
    }
}

# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

function Get-DomainControllerList {
    Write-Step 'Discovering domain controllers from Active Directory'

    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $dcs = $domain.DomainControllers | ForEach-Object { $_.Name }

        if ($dcs.Count -eq 0) {
            throw 'No domain controllers found in the current domain.'
        }

        Write-Ok "Domain: $($domain.Name)"
        Write-Ok "Found $($dcs.Count) domain controller(s): $($dcs -join ', ')"
        return $dcs
    }
    catch {
        throw "Failed to discover domain controllers: $_. Ensure this machine is domain-joined."
    }
}

# ---------------------------------------------------------------------------
# Per-Server Collectors
# ---------------------------------------------------------------------------

function Collect-DnsFromServer {
    param(
        [Parameter(Mandatory)] [string]$Server,
        [Parameter(Mandatory)] [string]$DestDir
    )

    Write-Step "Collecting DNS logs from $Server"

    $basePath = "\\$Server\C$\Windows\System32"

    # --- DNS debug log ---
    $debugLogCandidates = @(
        "$basePath\dns\dns.log"
        "$basePath\dns\DNSServer_debug.log"
    )

    # Also check registry for custom log path
    try {
        $regPath = "\\$Server\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters"
        # Can't read remote registry this way easily; fall back to file checks
    }
    catch { }

    $debugLogFound = $false
    foreach ($logPath in $debugLogCandidates) {
        if (Test-Path -LiteralPath $logPath -ErrorAction SilentlyContinue) {
            $fileSize = (Get-Item -LiteralPath $logPath).Length
            $fileSizeMB = [math]::Round($fileSize / 1MB, 1)
            $destFile = Join-Path $DestDir "dns-debug.log"

            if ($fileSizeMB -gt $MaxDebugLogSizeMB) {
                Write-Warn "DNS debug log is $fileSizeMB MB, copying last $MaxDebugLogSizeMB MB"
                $bytes = [IO.File]::ReadAllBytes($logPath)
                $maxBytes = $MaxDebugLogSizeMB * 1MB
                $offset = $bytes.Length - $maxBytes
                if ($offset -lt 0) { $offset = 0 }
                $tail = New-Object byte[] ($bytes.Length - $offset)
                [Array]::Copy($bytes, $offset, $tail, 0, $tail.Length)
                [IO.File]::WriteAllBytes($destFile, $tail)
            }
            else {
                Copy-Item -LiteralPath $logPath -Destination $destFile -Force
            }

            Write-Ok "DNS debug log ($fileSizeMB MB) -> $destFile"
            $debugLogFound = $true
            break
        }
    }

    if (-not $debugLogFound) {
        Write-Warn "No DNS debug log found on $Server (debug logging may not be enabled)"
    }

    # --- DNS audit EVTX ---
    $evtxCandidates = @(
        "$basePath\winevt\Logs\Microsoft-Windows-DNSServer%4Audit.evtx"
        "$basePath\winevt\Logs\DNS Server.evtx"
    )

    foreach ($evtxPath in $evtxCandidates) {
        if (Test-Path -LiteralPath $evtxPath -ErrorAction SilentlyContinue) {
            $fileSize = (Get-Item -LiteralPath $evtxPath).Length
            $fileSizeMB = [math]::Round($fileSize / 1MB, 1)
            $fileName = Split-Path -Leaf $evtxPath
            $destFile = Join-Path $DestDir $fileName

            Copy-Item -LiteralPath $evtxPath -Destination $destFile -Force
            Write-Ok "DNS audit EVTX ($fileSizeMB MB) -> $destFile"
        }
    }
}

function Collect-DhcpFromServer {
    param(
        [Parameter(Mandatory)] [string]$Server,
        [Parameter(Mandatory)] [string]$DestDir
    )

    Write-Step "Collecting DHCP logs from $Server"

    $dhcpDir = "\\$Server\C$\Windows\System32\dhcp"

    if (-not (Test-Path -LiteralPath $dhcpDir -ErrorAction SilentlyContinue)) {
        Write-Skip "No DHCP log directory on $Server (DHCP Server may not be installed)"
        return
    }

    $logFiles = Get-ChildItem -LiteralPath $dhcpDir -Filter 'DhcpSrvLog-*.log' -ErrorAction SilentlyContinue
    $v6Files = Get-ChildItem -LiteralPath $dhcpDir -Filter 'DhcpV6SrvLog-*.log' -ErrorAction SilentlyContinue

    $allFiles = @()
    if ($logFiles) { $allFiles += $logFiles }
    if ($v6Files) { $allFiles += $v6Files }

    if ($allFiles.Count -eq 0) {
        Write-Skip "No DHCP log files found in $dhcpDir"
        return
    }

    $dhcpDestDir = Join-Path $DestDir 'dhcp'
    Initialize-Directory -Path $dhcpDestDir

    $totalSize = 0
    foreach ($file in $allFiles) {
        $destFile = Join-Path $dhcpDestDir $file.Name
        Copy-Item -LiteralPath $file.FullName -Destination $destFile -Force
        $totalSize += $file.Length
    }

    $totalSizeMB = [math]::Round($totalSize / 1MB, 1)
    Write-Ok "$($allFiles.Count) DHCP log file(s) ($totalSizeMB MB) -> $dhcpDestDir"
}

function Collect-ServerMetadata {
    param(
        [Parameter(Mandatory)] [string]$Server,
        [Parameter(Mandatory)] [string]$DestDir
    )

    $meta = [ordered]@{
        collectedAt   = Get-UtcTimestamp
        collectedFrom = $env:COMPUTERNAME
        targetServer  = $Server
    }

    $destFile = Join-Path $DestDir 'server-metadata.json'
    $meta | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $destFile -Encoding UTF8
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '  CMTrace Open - DNS/DHCP Domain Collection' -ForegroundColor White
Write-Host '  ===========================================' -ForegroundColor DarkGray
Write-Host ''

# Discover or use provided DC list
if ($DomainControllers -and $DomainControllers.Count -gt 0) {
    $servers = $DomainControllers
    Write-Step "Using provided server list: $($servers -join ', ')"
}
else {
    $servers = Get-DomainControllerList
}

# Create output directory
$timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$bundleDir = Join-Path $OutputRoot "dns-dhcp-$timestamp"
Initialize-Directory -Path $bundleDir

Write-Host ''
Write-Step "Output directory: $bundleDir"
Write-Host ''

# Collect from each server
$serverResults = @()

foreach ($server in $servers) {
    Write-Host ''
    Write-Host "  --- $server ---" -ForegroundColor White

    # Test connectivity
    if (-not (Test-UncAccess -Server $server)) {
        Write-Warn "Cannot access \\$server\C$ - skipping (check admin share access)"
        $serverResults += [ordered]@{
            server = $server
            status = 'unreachable'
        }
        continue
    }

    $serverDir = Join-Path $bundleDir $server
    Initialize-Directory -Path $serverDir

    # Collect metadata
    Collect-ServerMetadata -Server $server -DestDir $serverDir

    # Collect DNS
    if (-not $SkipDns) {
        try {
            Collect-DnsFromServer -Server $server -DestDir $serverDir
        }
        catch {
            Write-Warn "DNS collection failed for $server : $_"
        }
    }
    else {
        Write-Skip "Skipping DNS collection (-SkipDns)"
    }

    # Collect DHCP
    if (-not $SkipDhcp) {
        try {
            Collect-DhcpFromServer -Server $server -DestDir $serverDir
        }
        catch {
            Write-Warn "DHCP collection failed for $server : $_"
        }
    }
    else {
        Write-Skip "Skipping DHCP collection (-SkipDhcp)"
    }

    $serverResults += [ordered]@{
        server = $server
        status = 'collected'
    }
}

# Write collection manifest
$manifest = [ordered]@{
    collectedAt    = Get-UtcTimestamp
    collectedBy    = "$env:USERDOMAIN\$env:USERNAME"
    collectedFrom  = $env:COMPUTERNAME
    domainServers  = $serverResults
    skipDns        = [bool]$SkipDns
    skipDhcp       = [bool]$SkipDhcp
}

$manifestPath = Join-Path $bundleDir 'collection-manifest.json'
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

# Summary
Write-Host ''
Write-Host ''
Write-Host '  Collection complete.' -ForegroundColor Green
Write-Host ''

$collected = ($serverResults | Where-Object { $_.status -eq 'collected' }).Count
$skipped = ($serverResults | Where-Object { $_.status -eq 'unreachable' }).Count

Write-Host "  Servers collected: $collected" -ForegroundColor White
if ($skipped -gt 0) {
    Write-Host "  Servers skipped:   $skipped" -ForegroundColor Yellow
}

# List collected files
$allFiles = Get-ChildItem -LiteralPath $bundleDir -Recurse -File
Write-Host "  Total files:       $($allFiles.Count)" -ForegroundColor White
$totalMB = [math]::Round(($allFiles | Measure-Object -Property Length -Sum).Sum / 1MB, 1)
Write-Host "  Total size:        $totalMB MB" -ForegroundColor White
Write-Host ''
Write-Host "  Bundle: $bundleDir" -ForegroundColor White
Write-Host ''
Write-Host '  Open this folder in CMTrace Open DNS/DHCP workspace to analyze.' -ForegroundColor DarkGray
Write-Host ''
