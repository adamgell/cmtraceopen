[CmdletBinding()]
param(
    [string]$OutputRoot = (Join-Path $env:ProgramData 'CmtraceOpen\Evidence'),
    [string]$BundleLabel = 'intune-endpoint-evidence',
    [string]$CaseReference = '',
    [string]$CollectorProfilePath,
    [string]$SasUrl,
    [string]$BlobName,
    [string]$OperatorName = 'SYSTEM',
    [string]$OperatorTeam = 'Intune',
    [string]$OperatorContact = '',
    [switch]$LocalOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($CollectorProfilePath)) {
    $CollectorProfilePath = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'intune-evidence-profile.json'
}

$script:CollectorVersion = '1.1.0'
$script:ArtifactCounters = @{}
$script:CollectorRunLogPath = $null
$script:CollectorTranscriptStarted = $false

function Protect-SecretText {
    param(
        [AllowNull()]
        [string]$Text
    )

    if ($null -eq $Text) {
        return $null
    }

    return [System.Text.RegularExpressions.Regex]::Replace(
        $Text,
        '(https?://[^\s''""<>]+)\?[^\s''""<>]+',
        '$1?<redacted>'
    )
}

function Write-Step {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $sanitizedMessage = Protect-SecretText -Text $Message
    Write-Host "==> $sanitizedMessage" -ForegroundColor Cyan
}

function Get-UtcTimestamp {
    return (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function Initialize-Directory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Initialize-ParentDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $parentPath = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parentPath)) {
        Initialize-Directory -Path $parentPath
    }
}

function ConvertTo-SafeFileName {
    param(
        [AllowEmptyString()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return 'unknown'
    }

    $safeValue = $Value.Trim()
    foreach ($character in [System.IO.Path]::GetInvalidFileNameChars()) {
        $safeValue = $safeValue.Replace($character, '-')
    }

    $safeValue = $safeValue -replace '\s+', '-'
    $safeValue = $safeValue.Trim('-')

    if ([string]::IsNullOrWhiteSpace($safeValue)) {
        return 'unknown'
    }

    return $safeValue
}

function Join-RelativePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Left,
        [Parameter(Mandatory = $true)]
        [string]$Right
    )

    return (($Left.TrimEnd('/')) + '/' + ($Right.TrimStart('/')))
}

function ConvertTo-PhysicalPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,
        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    $normalizedRelativePath = $RelativePath -replace '/', '\\'
    return Join-Path $Root $normalizedRelativePath
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject,
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    Initialize-ParentDirectory -Path $Path
    $utf8Encoding = New-Object System.Text.UTF8Encoding($false)
    $json = $InputObject | ConvertTo-Json -Depth 12
    [System.IO.File]::WriteAllText($Path, $json, $utf8Encoding)
}

function Write-TextFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content,
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    Initialize-ParentDirectory -Path $Path
    $utf8Encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8Encoding)
}

function Start-CollectorTranscript {
    $logRoot = Join-Path $env:ProgramData 'CmtraceOpen\Logs\Collection'
    $logFileName = 'collector-{0}-{1}-{2}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), (ConvertTo-SafeFileName -Value $env:COMPUTERNAME), $PID
    $script:CollectorRunLogPath = Join-Path $logRoot $logFileName

    Initialize-Directory -Path $logRoot

    try {
        $null = Start-Transcript -LiteralPath $script:CollectorRunLogPath -Force -UseMinimalHeader -IncludeInvocationHeader -ErrorAction Stop
        $script:CollectorTranscriptStarted = $true
        Write-Step ('Collector run log: {0}' -f $script:CollectorRunLogPath)
    }
    catch {
        $script:CollectorTranscriptStarted = $false
        Write-Warning ('Collector transcript could not be started at {0}: {1}' -f $script:CollectorRunLogPath, (Protect-SecretText -Text $_.Exception.Message))
    }
}

function Stop-CollectorTranscript {
    if (-not $script:CollectorTranscriptStarted) {
        return
    }

    try {
        $null = Stop-Transcript -ErrorAction Stop
    }
    catch {
        Write-Warning ('Collector transcript could not be stopped cleanly: {0}' -f (Protect-SecretText -Text $_.Exception.Message))
    }
    finally {
        $script:CollectorTranscriptStarted = $false
    }
}

function Get-FileSha256 {
    param(
        [AllowNull()]
        [string]$Path
    )

    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Expand-EnvironmentPath {
    param(
        [AllowEmptyString()]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }

    return [System.Environment]::ExpandEnvironmentVariables($Path)
}

function Get-ObjectPropertyValue {
    param(
        [AllowNull()]
        [object]$InputObject,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [AllowNull()]
        [object]$DefaultValue = $null
    )

    if ($null -eq $InputObject) {
        return $DefaultValue
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $DefaultValue
    }

    return $property.Value
}

function Test-ArrayValue {
    param(
        [AllowNull()]
        [object]$Value
    )

    return ($Value -is [System.Array]) -or ($Value -is [System.Collections.IList])
}

function Assert-ProfileRequiredString {
    param(
        [AllowNull()]
        [object]$InputObject,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Context,
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $value = Get-ObjectPropertyValue -InputObject $InputObject -Name $Name
    if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$value)) {
        throw ('Collector profile is invalid: {0}. {1}.{2} must be a non-empty string.' -f $Path, $Context, $Name)
    }
}

function Assert-ProfileRequiredArray {
    param(
        [AllowNull()]
        [object]$InputObject,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $property = $null
    if ($null -ne $InputObject) {
        $property = $InputObject.PSObject.Properties[$Name]
    }

    if ($null -eq $property) {
        throw ('Collector profile is invalid: {0}. Top-level section "{1}" is missing.' -f $Path, $Name)
    }

    if (-not (Test-ArrayValue -Value $property.Value)) {
        throw ('Collector profile is invalid: {0}. Top-level section "{1}" must be an array.' -f $Path, $Name)
    }
}

function Assert-CollectorProfileShape {
    param(
        [Parameter(Mandatory = $true)]
        [object]$CollectorProfile,
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    Assert-ProfileRequiredString -InputObject $CollectorProfile -Name 'profileName' -Context 'profile' -Path $Path
    Assert-ProfileRequiredString -InputObject $CollectorProfile -Name 'profileVersion' -Context 'profile' -Path $Path

    foreach ($sectionName in @('logs', 'registry', 'eventLogs', 'exports', 'commands')) {
        Assert-ProfileRequiredArray -InputObject $CollectorProfile -Name $sectionName -Path $Path
    }

    $sectionDefinitions = @(
        @{
            name            = 'logs'
            requiredStrings = @('id', 'family', 'sourcePattern', 'destinationFolder')
            optionalArrays  = @('parseHints')
        },
        @{
            name            = 'registry'
            requiredStrings = @('id', 'family', 'path', 'fileName')
            optionalArrays  = @()
        },
        @{
            name            = 'eventLogs'
            requiredStrings = @('id', 'family', 'channel', 'fileName')
            optionalArrays  = @()
        },
        @{
            name            = 'exports'
            requiredStrings = @('id', 'family', 'sourcePath')
            optionalArrays  = @('parseHints')
        },
        @{
            name            = 'commands'
            requiredStrings = @('id', 'family', 'command', 'fileName')
            optionalArrays  = @('arguments')
        }
    )

    foreach ($sectionDefinition in $sectionDefinitions) {
        $sectionName = [string]$sectionDefinition.name
        $sectionItems = @(Get-ObjectPropertyValue -InputObject $CollectorProfile -Name $sectionName -DefaultValue @())

        for ($index = 0; $index -lt $sectionItems.Count; $index++) {
            $item = $sectionItems[$index]
            $itemContext = '{0}[{1}]' -f $sectionName, $index

            if ($null -eq $item) {
                throw ('Collector profile is invalid: {0}. {1} must be an object.' -f $Path, $itemContext)
            }

            foreach ($propertyName in @($sectionDefinition.requiredStrings)) {
                Assert-ProfileRequiredString -InputObject $item -Name $propertyName -Context $itemContext -Path $Path
            }

            foreach ($propertyName in @($sectionDefinition.optionalArrays)) {
                $propertyValue = Get-ObjectPropertyValue -InputObject $item -Name $propertyName
                if ($null -ne $propertyValue -and -not (Test-ArrayValue -Value $propertyValue)) {
                    throw ('Collector profile is invalid: {0}. {1}.{2} must be an array when present.' -f $Path, $itemContext, $propertyName)
                }
            }
        }
    }
}

function Read-CollectorProfile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw ('Collector profile file was not found: {0}' -f $Path)
    }

    try {
        $rawProfile = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    }
    catch {
        throw ('Collector profile file could not be read: {0}. Error: {1}' -f $Path, $_.Exception.Message)
    }

    if ([string]::IsNullOrWhiteSpace($rawProfile)) {
        throw ('Collector profile file is empty: {0}' -f $Path)
    }

    try {
        $collectorProfile = $rawProfile | ConvertFrom-Json -Depth 20 -ErrorAction Stop
    }
    catch {
        throw ('Collector profile contains invalid JSON: {0}. Error: {1}' -f $Path, $_.Exception.Message)
    }

    Assert-CollectorProfileShape -CollectorProfile $collectorProfile -Path $Path
    return $collectorProfile
}

function New-ArtifactId {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Category
    )

    $prefix = switch ($Category) {
        'event-log' { 'event' }
        'command-output' { 'command' }
        default { $Category }
    }

    if (-not $script:ArtifactCounters.ContainsKey($prefix)) {
        $script:ArtifactCounters[$prefix] = 0
    }

    $script:ArtifactCounters[$prefix] += 1
    return ('{0}-{1:D3}' -f $prefix, $script:ArtifactCounters[$prefix])
}

function New-ArtifactRecord {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Category,
        [Parameter(Mandatory = $true)]
        [string]$Family,
        [Parameter(Mandatory = $true)]
        [string]$RelativePath,
        [Parameter(Mandatory = $true)]
        [string]$OriginPath,
        [Parameter(Mandatory = $true)]
        [ValidateSet('collected', 'missing', 'failed', 'skipped')]
        [string]$Status,
        [string[]]$ParseHints = @(),
        [AllowNull()]
        [string]$FilePath,
        [AllowNull()]
        [string]$Notes,
        [AllowNull()]
        [string]$StartUtc,
        [AllowNull()]
        [string]$EndUtc
    )

    return [ordered]@{
        artifactId   = New-ArtifactId -Category $Category
        category     = $Category
        family       = $Family
        relativePath = $RelativePath
        originPath   = $OriginPath
        collectedUtc = Get-UtcTimestamp
        status       = $Status
        parseHints   = @($ParseHints)
        timeCoverage = [ordered]@{
            startUtc = $StartUtc
            endUtc   = $EndUtc
        }
        hashes       = [ordered]@{
            sha256 = (Get-FileSha256 -Path $FilePath)
        }
        notes        = $Notes
    }
}

function ConvertTo-RegistryProviderPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath
    )

    return ('Registry::{0}' -f $RegistryPath)
}

function Test-RegistryKeyExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath
    )

    return (Test-Path -LiteralPath (ConvertTo-RegistryProviderPath -RegistryPath $RegistryPath))
}

function Invoke-ExternalCommandCapture {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,
        [string[]]$Arguments = @()
    )

    $commandInfo = Get-Command $Command -ErrorAction SilentlyContinue
    if (-not $commandInfo) {
        return [ordered]@{
            found    = $false
            exitCode = $null
            output   = ''
            error    = ('Command not found: {0}' -f $Command)
        }
    }

    $output = & $commandInfo.Source @Arguments 2>&1 | Out-String
    $exitCode = $LASTEXITCODE

    return [ordered]@{
        found    = $true
        exitCode = $exitCode
        output   = $output.TrimEnd()
        error    = $null
    }
}

function Get-CommandInvocationText {
    param(
        [Parameter(Mandatory = $true)]
        [object]$CommandItem
    )

    return ('{0} {1}' -f $CommandItem.command, (@($CommandItem.arguments) -join ' ')).Trim()
}

function Add-GeneratedCommandArtifacts {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Artifacts,
        [Parameter(Mandatory = $true)]
        [object]$ObservedGaps,
        [Parameter(Mandatory = $true)]
        [object]$CommandItem,
        [Parameter(Mandatory = $true)]
        [string]$BundleRoot
    )

    $generatedOutputs = @(Get-ObjectPropertyValue -InputObject $CommandItem -Name 'generatedOutputs' -DefaultValue @())

    foreach ($outputItem in $generatedOutputs) {
        $resolvedSourcePath = Expand-EnvironmentPath -Path (Get-ObjectPropertyValue -InputObject $outputItem -Name 'sourcePath')
        $destinationFolder = Get-ObjectPropertyValue -InputObject $outputItem -Name 'destinationFolder' -DefaultValue 'evidence/exports'
        $outputFileName = Get-ObjectPropertyValue -InputObject $outputItem -Name 'fileName'

        if ([string]::IsNullOrWhiteSpace($outputFileName) -and -not [string]::IsNullOrWhiteSpace($resolvedSourcePath)) {
            $outputFileName = Split-Path -Leaf $resolvedSourcePath
        }

        $relativePath = Join-RelativePath -Left $destinationFolder -Right $outputFileName
        $destinationPath = ConvertTo-PhysicalPath -Root $BundleRoot -RelativePath $relativePath
        $family = Get-ObjectPropertyValue -InputObject $outputItem -Name 'family' -DefaultValue $CommandItem.family
        $parseHints = @(Get-ObjectPropertyValue -InputObject $outputItem -Name 'parseHints' -DefaultValue @())
        $notes = Get-ObjectPropertyValue -InputObject $outputItem -Name 'notes'

        if ([string]::IsNullOrWhiteSpace($resolvedSourcePath) -or -not (Test-Path -LiteralPath $resolvedSourcePath -PathType Leaf)) {
            $artifact = New-ArtifactRecord -Category 'export' -Family $family -RelativePath $relativePath -OriginPath $resolvedSourcePath -Status 'missing' -ParseHints $parseHints -Notes $notes
            $Artifacts.Add($artifact)
            Add-ObservedGap -ObservedGaps $ObservedGaps -Status 'missing' -Origin $resolvedSourcePath -Reason $null
            continue
        }

        try {
            Initialize-ParentDirectory -Path $destinationPath
            Copy-Item -LiteralPath $resolvedSourcePath -Destination $destinationPath -Force
            $sourceFile = Get-Item -LiteralPath $resolvedSourcePath -ErrorAction Stop
            $artifact = New-ArtifactRecord -Category 'export' -Family $family -RelativePath $relativePath -OriginPath $resolvedSourcePath -Status 'collected' -ParseHints $parseHints -FilePath $destinationPath -Notes $notes -StartUtc $sourceFile.CreationTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ') -EndUtc $sourceFile.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        }
        catch {
            $artifact = New-ArtifactRecord -Category 'export' -Family $family -RelativePath $relativePath -OriginPath $resolvedSourcePath -Status 'failed' -ParseHints $parseHints -Notes $_.Exception.Message
            Add-ObservedGap -ObservedGaps $ObservedGaps -Status 'failed' -Origin $resolvedSourcePath -Reason $_.Exception.Message
        }

        $Artifacts.Add($artifact)
    }
}

function New-MdmDiagnosticsCommandItem {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BundleId
    )

    $stagingRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('CmtraceOpen-{0}' -f $BundleId)
    Initialize-Directory -Path $stagingRoot

    $zipPath = Join-Path $stagingRoot 'MDMDiagReport.zip'

    return [pscustomobject]@{
        id               = 'mdm-diagnostics-report'
        family           = 'diagnostic-command'
        command          = 'MdmDiagnosticsTool.exe'
        arguments        = @('-area', 'DeviceEnrollment;DeviceProvisioning;Autopilot', '-zip', $zipPath)
        fileName         = 'mdmdiagnosticstool.txt'
        notes            = 'Captures a fresh MDM diagnostics report during bundle collection.'
        generatedOutputs = @(
            [pscustomobject]@{
                family            = 'mdm-diagnostics-report'
                sourcePath        = $zipPath
                destinationFolder = 'evidence/exports'
                fileName          = 'MDMDiagReport.zip'
                parseHints        = @('zip', 'mdm')
                notes             = 'Fresh MDM diagnostics ZIP captured during bundle collection.'
            }
        )
    }
}

function Get-DsRegStatusSummary {
    $capture = Invoke-ExternalCommandCapture -Command 'dsregcmd.exe' -Arguments @('/status')

    $summary = [ordered]@{
        capture          = $capture
        azureAdJoined    = $null
        domainJoined     = $null
        enterpriseJoined = $null
        tenantId         = $null
        tenantName       = $null
        deviceId         = $null
    }

    if (-not $capture.found -or $capture.exitCode -ne 0 -or [string]::IsNullOrWhiteSpace($capture.output)) {
        return $summary
    }

    foreach ($line in ($capture.output -split "`r?`n")) {
        if ($line -match '^\s*AzureAdJoined\s*:\s*(.+?)\s*$') {
            $summary.azureAdJoined = $Matches[1].Trim()
            continue
        }

        if ($line -match '^\s*DomainJoined\s*:\s*(.+?)\s*$') {
            $summary.domainJoined = $Matches[1].Trim()
            continue
        }

        if ($line -match '^\s*EnterpriseJoined\s*:\s*(.+?)\s*$') {
            $summary.enterpriseJoined = $Matches[1].Trim()
            continue
        }

        if ($line -match '^\s*TenantId\s*:\s*(.+?)\s*$') {
            $summary.tenantId = $Matches[1].Trim()
            continue
        }

        if ($line -match '^\s*TenantName\s*:\s*(.+?)\s*$') {
            $summary.tenantName = $Matches[1].Trim()
            continue
        }

        if ($line -match '^\s*DeviceId\s*:\s*(.+?)\s*$') {
            $summary.deviceId = $Matches[1].Trim()
        }
    }

    return $summary
}

function Get-LastLoggedOnUser {
    try {
        $properties = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -ErrorAction Stop
        if ($properties.LastLoggedOnUser) {
            return $properties.LastLoggedOnUser
        }
    }
    catch {
    }

    return $null
}

function Get-DeviceContext {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
    $bios = Get-CimInstance -ClassName Win32_BIOS
    $dsregStatus = Get-DsRegStatusSummary

    $primaryUser = $computerSystem.UserName
    if (-not $primaryUser) {
        $primaryUser = Get-LastLoggedOnUser
    }

    return [ordered]@{
        device      = [ordered]@{
            deviceName       = $env:COMPUTERNAME
            primaryUser      = $primaryUser
            serialNumber     = $bios.SerialNumber
            manufacturer     = $computerSystem.Manufacturer
            model            = $computerSystem.Model
            platform         = 'Windows'
            osVersion        = ('{0} {1} (Build {2})' -f $operatingSystem.Caption, $operatingSystem.Version, $operatingSystem.BuildNumber)
            tenant           = if ($dsregStatus.tenantName) { $dsregStatus.tenantName } elseif ($dsregStatus.tenantId) { $dsregStatus.tenantId } else { $null }
            azureAdJoined    = $dsregStatus.azureAdJoined
            domainJoined     = $dsregStatus.domainJoined
            enterpriseJoined = $dsregStatus.enterpriseJoined
            deviceId         = $dsregStatus.deviceId
        }
        dsregStatus = $dsregStatus
    }
}

function Test-EventChannelExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Channel
    )

    try {
        $null = Get-WinEvent -ListLog $Channel -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Get-RedactedUploadUrl {
    param(
        [AllowEmptyString()]
        [string]$Url
    )

    if ([string]::IsNullOrWhiteSpace($Url)) {
        return $null
    }

    $uriBuilder = New-Object System.UriBuilder($Url)
    $uriBuilder.Query = ''
    return $uriBuilder.Uri.AbsoluteUri.TrimEnd('?')
}

function Resolve-BlobUploadUrl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,
        [Parameter(Mandatory = $true)]
        [string]$DefaultBlobName,
        [AllowNull()]
        [string]$RequestedBlobName
    )

    $uri = New-Object System.Uri($Url)
    if ($uri.Scheme -ne 'https') {
        throw 'SAS uploads require an https URL.'
    }

    $effectiveBlobName = if ([string]::IsNullOrWhiteSpace($RequestedBlobName)) {
        $DefaultBlobName
    }
    else {
        $RequestedBlobName
    }

    $uriBuilder = New-Object System.UriBuilder($uri)
    $path = $uriBuilder.Path

    if ([string]::IsNullOrWhiteSpace($RequestedBlobName) -and $path -match '\.zip$') {
        return [ordered]@{
            uploadUrl   = $uri.AbsoluteUri
            blobName    = [System.IO.Path]::GetFileName($path)
            redactedUrl = (Get-RedactedUploadUrl -Url $uri.AbsoluteUri)
        }
    }

    $escapedBlobName = ($effectiveBlobName -split '/') | ForEach-Object { [System.Uri]::EscapeDataString($_) }
    $blobPath = [string]::Join('/', $escapedBlobName)
    $trimmedPath = $path.TrimEnd('/')
    $uriBuilder.Path = ('{0}/{1}' -f $trimmedPath, $blobPath)

    return [ordered]@{
        uploadUrl   = $uriBuilder.Uri.AbsoluteUri
        blobName    = $effectiveBlobName
        redactedUrl = (Get-RedactedUploadUrl -Url $uriBuilder.Uri.AbsoluteUri)
    }
}

function Invoke-BlobUpload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZipPath,
        [Parameter(Mandatory = $true)]
        [string]$UploadUrl
    )

    $headers = @{
        'x-ms-blob-type' = 'BlockBlob'
        'x-ms-version'   = '2021-12-02'
    }

    $response = Invoke-WebRequest -Uri $UploadUrl -Method Put -InFile $ZipPath -Headers $headers -ContentType 'application/zip' -UseBasicParsing

    return [ordered]@{
        statusCode        = $response.StatusCode
        statusDescription = $response.StatusDescription
    }
}

function Add-ObservedGap {
    param(
        [Parameter(Mandatory = $true)]
        [object]$ObservedGaps,
        [Parameter(Mandatory = $true)]
        [string]$Status,
        [Parameter(Mandatory = $true)]
        [string]$Origin,
        [AllowNull()]
        [string]$Reason
    )

    if ($Status -eq 'missing') {
        $ObservedGaps.Add(('Missing expected artifact: {0}' -f $Origin))
        return
    }

    if ($Status -eq 'failed') {
        if ($Reason) {
            $ObservedGaps.Add(('Collection failed for {0}: {1}' -f ($Origin, $Reason)))
        }
        else {
            $ObservedGaps.Add(('Collection failed for {0}' -f $Origin))
        }
    }
}

Start-CollectorTranscript

try {
    Write-Step 'Loading collector profile'
    $collectorProfile = Read-CollectorProfile -Path $CollectorProfilePath

    Write-Step 'Gathering device metadata'
    $deviceContext = Get-DeviceContext
    $bundleId = 'CMTRACE-{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), (ConvertTo-SafeFileName -Value $deviceContext.device.deviceName)
    $bundleRoot = Join-Path $OutputRoot $bundleId
    $evidenceRoot = Join-Path $bundleRoot 'evidence'

    $logRoot = Join-Path $evidenceRoot 'logs'
    $registryRoot = Join-Path $evidenceRoot 'registry'
    $eventLogRoot = Join-Path $evidenceRoot 'event-logs'
    $exportRoot = Join-Path $evidenceRoot 'exports'
    $screenshotRoot = Join-Path $evidenceRoot 'screenshots'
    $commandOutputRoot = Join-Path $evidenceRoot 'command-output'

    Write-Step 'Creating bundle structure'
    foreach ($path in @($bundleRoot, $evidenceRoot, $logRoot, $registryRoot, $eventLogRoot, $exportRoot, $screenshotRoot, $commandOutputRoot)) {
        Initialize-Directory -Path $path
    }

    $commandItems = New-Object System.Collections.Generic.List[object]
    foreach ($commandItem in @($collectorProfile.commands)) {
        $commandItems.Add($commandItem)
    }

    if (-not @($commandItems | Where-Object { $_.command -ieq 'MdmDiagnosticsTool.exe' })) {
        $commandItems.Add((New-MdmDiagnosticsCommandItem -BundleId $bundleId))
    }

    $artifacts = New-Object System.Collections.Generic.List[object]
    $observedGaps = New-Object System.Collections.Generic.List[string]

    Write-Step 'Collecting curated IME logs'
    foreach ($logItem in @($collectorProfile.logs)) {
        $matchedFiles = @(Get-ChildItem -Path $logItem.sourcePattern -File -ErrorAction SilentlyContinue | Sort-Object FullName)

        if ($matchedFiles.Count -eq 0) {
            $relativePath = Join-RelativePath -Left $logItem.destinationFolder -Right (Split-Path -Leaf $logItem.sourcePattern)
            $artifact = New-ArtifactRecord -Category 'log' -Family $logItem.family -RelativePath $relativePath -OriginPath $logItem.sourcePattern -Status 'missing' -ParseHints $logItem.parseHints -Notes $logItem.notes
            $artifacts.Add($artifact)
            Add-ObservedGap -ObservedGaps $observedGaps -Status 'missing' -Origin $logItem.sourcePattern -Reason $null
            continue
        }

        foreach ($sourceFile in $matchedFiles) {
            $relativePath = Join-RelativePath -Left $logItem.destinationFolder -Right $sourceFile.Name
            $destinationPath = ConvertTo-PhysicalPath -Root $bundleRoot -RelativePath $relativePath

            try {
                Initialize-ParentDirectory -Path $destinationPath
                Copy-Item -LiteralPath $sourceFile.FullName -Destination $destinationPath -Force
                $artifact = New-ArtifactRecord -Category 'log' -Family $logItem.family -RelativePath $relativePath -OriginPath $sourceFile.FullName -Status 'collected' -ParseHints $logItem.parseHints -FilePath $destinationPath -Notes $logItem.notes -StartUtc $sourceFile.CreationTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ') -EndUtc $sourceFile.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
            }
            catch {
                $artifact = New-ArtifactRecord -Category 'log' -Family $logItem.family -RelativePath $relativePath -OriginPath $sourceFile.FullName -Status 'failed' -ParseHints $logItem.parseHints -Notes (Protect-SecretText -Text $_.Exception.Message)
                Add-ObservedGap -ObservedGaps $observedGaps -Status 'failed' -Origin $sourceFile.FullName -Reason (Protect-SecretText -Text $_.Exception.Message)
            }

            $artifacts.Add($artifact)
        }
    }

    Write-Step 'Exporting curated registry paths'
    foreach ($registryItem in @($collectorProfile.registry)) {
        $relativePath = Join-RelativePath -Left 'evidence/registry' -Right $registryItem.fileName
        $destinationPath = ConvertTo-PhysicalPath -Root $bundleRoot -RelativePath $relativePath

        if (-not (Test-RegistryKeyExists -RegistryPath $registryItem.path)) {
            $artifact = New-ArtifactRecord -Category 'registry' -Family $registryItem.family -RelativePath $relativePath -OriginPath $registryItem.path -Status 'missing' -ParseHints @('reg') -Notes $registryItem.notes
            $artifacts.Add($artifact)
            Add-ObservedGap -ObservedGaps $observedGaps -Status 'missing' -Origin $registryItem.path -Reason $null
            continue
        }

        Initialize-ParentDirectory -Path $destinationPath
        & reg.exe export $registryItem.path $destinationPath /y | Out-Null
        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0 -and (Test-Path -LiteralPath $destinationPath)) {
            $artifact = New-ArtifactRecord -Category 'registry' -Family $registryItem.family -RelativePath $relativePath -OriginPath $registryItem.path -Status 'collected' -ParseHints @('reg') -FilePath $destinationPath -Notes $registryItem.notes
        }
        else {
            $notes = 'reg.exe export failed with exit code {0}.' -f $exitCode
            $artifact = New-ArtifactRecord -Category 'registry' -Family $registryItem.family -RelativePath $relativePath -OriginPath $registryItem.path -Status 'failed' -ParseHints @('reg') -Notes $notes
            Add-ObservedGap -ObservedGaps $observedGaps -Status 'failed' -Origin $registryItem.path -Reason $notes
        }

        $artifacts.Add($artifact)
    }

    Write-Step 'Exporting curated event channels'
    foreach ($eventItem in @($collectorProfile.eventLogs)) {
        $relativePath = Join-RelativePath -Left 'evidence/event-logs' -Right $eventItem.fileName
        $destinationPath = ConvertTo-PhysicalPath -Root $bundleRoot -RelativePath $relativePath

        if (-not (Test-EventChannelExists -Channel $eventItem.channel)) {
            $artifact = New-ArtifactRecord -Category 'event-log' -Family $eventItem.family -RelativePath $relativePath -OriginPath $eventItem.channel -Status 'missing' -ParseHints @('evtx') -Notes $eventItem.notes
            $artifacts.Add($artifact)
            Add-ObservedGap -ObservedGaps $observedGaps -Status 'missing' -Origin $eventItem.channel -Reason $null
            continue
        }

        Initialize-ParentDirectory -Path $destinationPath
        & wevtutil.exe epl $eventItem.channel $destinationPath /ow:true | Out-Null
        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0 -and (Test-Path -LiteralPath $destinationPath)) {
            $artifact = New-ArtifactRecord -Category 'event-log' -Family $eventItem.family -RelativePath $relativePath -OriginPath $eventItem.channel -Status 'collected' -ParseHints @('evtx') -FilePath $destinationPath -Notes $eventItem.notes
        }
        else {
            $notes = 'wevtutil.exe epl failed with exit code {0}.' -f $exitCode
            $artifact = New-ArtifactRecord -Category 'event-log' -Family $eventItem.family -RelativePath $relativePath -OriginPath $eventItem.channel -Status 'failed' -ParseHints @('evtx') -Notes $notes
            Add-ObservedGap -ObservedGaps $observedGaps -Status 'failed' -Origin $eventItem.channel -Reason $notes
        }

        $artifacts.Add($artifact)
    }

    Write-Step 'Collecting exported file artifacts'
    foreach ($exportItem in @($collectorProfile.exports)) {
        $resolvedSourcePath = Expand-EnvironmentPath -Path $exportItem.sourcePath
        $destinationFolder = if ([string]::IsNullOrWhiteSpace($exportItem.destinationFolder)) { 'evidence/exports' } else { $exportItem.destinationFolder }
        $exportFileName = if ([string]::IsNullOrWhiteSpace($exportItem.fileName)) { Split-Path -Leaf $resolvedSourcePath } else { $exportItem.fileName }
        $relativePath = Join-RelativePath -Left $destinationFolder -Right $exportFileName
        $destinationPath = ConvertTo-PhysicalPath -Root $bundleRoot -RelativePath $relativePath

        if ([string]::IsNullOrWhiteSpace($resolvedSourcePath) -or -not (Test-Path -LiteralPath $resolvedSourcePath -PathType Leaf)) {
            $artifact = New-ArtifactRecord -Category 'export' -Family $exportItem.family -RelativePath $relativePath -OriginPath $resolvedSourcePath -Status 'missing' -ParseHints $exportItem.parseHints -Notes $exportItem.notes
            $artifacts.Add($artifact)
            Add-ObservedGap -ObservedGaps $observedGaps -Status 'missing' -Origin $resolvedSourcePath -Reason $null
            continue
        }

        try {
            Initialize-ParentDirectory -Path $destinationPath
            Copy-Item -LiteralPath $resolvedSourcePath -Destination $destinationPath -Force
            $sourceFile = Get-Item -LiteralPath $resolvedSourcePath -ErrorAction Stop
            $artifact = New-ArtifactRecord -Category 'export' -Family $exportItem.family -RelativePath $relativePath -OriginPath $resolvedSourcePath -Status 'collected' -ParseHints $exportItem.parseHints -FilePath $destinationPath -Notes $exportItem.notes -StartUtc $sourceFile.CreationTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ') -EndUtc $sourceFile.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        }
        catch {
            $artifact = New-ArtifactRecord -Category 'export' -Family $exportItem.family -RelativePath $relativePath -OriginPath $resolvedSourcePath -Status 'failed' -ParseHints $exportItem.parseHints -Notes (Protect-SecretText -Text $_.Exception.Message)
            Add-ObservedGap -ObservedGaps $observedGaps -Status 'failed' -Origin $resolvedSourcePath -Reason (Protect-SecretText -Text $_.Exception.Message)
        }

        $artifacts.Add($artifact)
    }

    Write-Step 'Collecting command outputs'
    foreach ($commandItem in $commandItems) {
        $relativePath = Join-RelativePath -Left 'evidence/command-output' -Right $commandItem.fileName
        $destinationPath = ConvertTo-PhysicalPath -Root $bundleRoot -RelativePath $relativePath
        $commandInvocationText = Get-CommandInvocationText -CommandItem $commandItem

        if ($commandItem.id -eq 'dsregcmd-status') {
            $capture = $deviceContext.dsregStatus.capture
        }
        else {
            $capture = Invoke-ExternalCommandCapture -Command $commandItem.command -Arguments @($commandItem.arguments)
        }

        if (-not $capture.found) {
            $artifact = New-ArtifactRecord -Category 'command-output' -Family $commandItem.family -RelativePath $relativePath -OriginPath $commandInvocationText -Status 'missing' -ParseHints @('plain-text') -Notes $capture.error
            $artifacts.Add($artifact)
            Add-ObservedGap -ObservedGaps $observedGaps -Status 'missing' -Origin $commandItem.command -Reason $capture.error
            continue
        }

        $commandText = if ([string]::IsNullOrWhiteSpace($capture.output)) { '[no output returned]' } else { $capture.output }
        Write-TextFile -Content $commandText -Path $destinationPath

        if ($capture.exitCode -eq 0) {
            $artifact = New-ArtifactRecord -Category 'command-output' -Family $commandItem.family -RelativePath $relativePath -OriginPath $commandInvocationText -Status 'collected' -ParseHints @('plain-text') -FilePath $destinationPath -Notes $commandItem.notes
        }
        else {
            $notes = '{0} exited with code {1}.' -f $commandItem.command, $capture.exitCode
            $artifact = New-ArtifactRecord -Category 'command-output' -Family $commandItem.family -RelativePath $relativePath -OriginPath $commandInvocationText -Status 'failed' -ParseHints @('plain-text') -FilePath $destinationPath -Notes $notes
            Add-ObservedGap -ObservedGaps $observedGaps -Status 'failed' -Origin $commandItem.command -Reason $notes
        }

        $artifacts.Add($artifact)
        Add-GeneratedCommandArtifacts -Artifacts $artifacts -ObservedGaps $observedGaps -CommandItem $commandItem -BundleRoot $bundleRoot
    }

    $notesPath = Join-Path $bundleRoot 'notes.md'
    $manifestPath = Join-Path $bundleRoot 'manifest.json'

    $statusCounts = [ordered]@{
        collected = @($artifacts | Where-Object { $_.status -eq 'collected' }).Count
        missing   = @($artifacts | Where-Object { $_.status -eq 'missing' }).Count
        failed    = @($artifacts | Where-Object { $_.status -eq 'failed' }).Count
        skipped   = @($artifacts | Where-Object { $_.status -eq 'skipped' }).Count
    }

    $uploadRequested = (-not $LocalOnly) -and (-not [string]::IsNullOrWhiteSpace($SasUrl))
    $sanitizedBundleLabel = ConvertTo-SafeFileName -Value $BundleLabel
    $zipFileName = ('{0}.zip' -f $bundleId)
    $zipPath = Join-Path $OutputRoot $zipFileName

    $uploadInfo = [ordered]@{
        requested           = $uploadRequested
        destination         = (Get-RedactedUploadUrl -Url $SasUrl)
        blobName            = $null
        collectorRunLogPath = $script:CollectorRunLogPath
    }

    if ($uploadRequested) {
        $resolvedUpload = Resolve-BlobUploadUrl -Url $SasUrl -DefaultBlobName $zipFileName -RequestedBlobName $BlobName
        $uploadInfo.destination = $resolvedUpload.redactedUrl
        $uploadInfo.blobName = $resolvedUpload.blobName
    }

    Write-Step 'Writing notes and manifest'
    $manifestCreatedUtc = Get-UtcTimestamp
    $manifestCaseReference = if ([string]::IsNullOrWhiteSpace($CaseReference)) { $bundleId } else { $CaseReference }
    $operatorContactValue = if ([string]::IsNullOrWhiteSpace($OperatorContact)) { $null } else { $OperatorContact }
    $analysisObservedGaps = if ($observedGaps.Count -gt 0) { @($observedGaps) } else { @('No collection gaps were recorded during bundle creation.') }
    $observedGapSummary = [string]::Join('; ', @($analysisObservedGaps | ForEach-Object { [string]$_ }))
    $artifactArray = @($artifacts.ToArray())
    $primaryEntryPoints = @(
        'evidence/logs',
        'evidence/registry',
        'evidence/event-logs',
        'evidence/exports',
        'evidence/screenshots',
        'evidence/command-output'
    )
    $expectedEvidence = @(
        [ordered]@{
            category     = 'log'
            relativePath = 'evidence/logs'
            required     = $true
            reason       = 'Primary troubleshooting timeline and parser input.'
        },
        [ordered]@{
            category     = 'registry'
            relativePath = 'evidence/registry'
            required     = $false
            reason       = 'Useful for enrollment, policy, and IME state.'
        },
        [ordered]@{
            category     = 'event-log'
            relativePath = 'evidence/event-logs'
            required     = $false
            reason       = 'Curated adjacent evidence for MDM, enrollment, and Autopilot.'
        },
        [ordered]@{
            category     = 'export'
            relativePath = 'evidence/exports'
            required     = $false
            reason       = 'Exported supporting artifacts such as live Autopilot JSON state.'
        },
        [ordered]@{
            category     = 'command-output'
            relativePath = 'evidence/command-output'
            required     = $false
            reason       = 'Point-in-time command output for device join and identity state.'
        }
    )

    $notesContent = @"
# Investigation Notes

## Case Summary

- Case reference: $CaseReference
- Operator: $OperatorName
- Started: $(Get-UtcTimestamp)
- Device: $($deviceContext.device.deviceName)
- Scope: Curated Intune evidence collection generated by Invoke-CmtraceEvidenceCollection.ps1.
- Collector run log: $($script:CollectorRunLogPath)

## Collection Notes

| Time | Action | Result |
| --- | --- | --- |
| $(Get-UtcTimestamp) | Created evidence bundle structure | Bundle root: $bundleRoot |
| $(Get-UtcTimestamp) | Collected curated artifacts and exports | Collected=$($statusCounts.collected), Missing=$($statusCounts.missing), Failed=$($statusCounts.failed) |

## Intake Notes

- Lead artifact: evidence/logs
- Supporting exports: evidence/exports
- Known gaps: $observedGapSummary
- Upload requested: $uploadRequested
- Upload destination: $($uploadInfo.destination)
"@
    Write-TextFile -Content $notesContent.Trim() -Path $notesPath

    $manifest = [ordered]@{
        schemaVersion    = '1.0'
        bundle           = [ordered]@{
            bundleId      = $bundleId
            bundleLabel   = $sanitizedBundleLabel
            createdUtc    = $manifestCreatedUtc
            caseReference = $manifestCaseReference
            summary       = 'Curated endpoint evidence bundle collected for Intune and adjacent Windows diagnostics.'
            operator      = [ordered]@{
                name    = $OperatorName
                team    = $OperatorTeam
                contact = $operatorContactValue
            }
            device        = $deviceContext.device
        }
        collection       = [ordered]@{
            method              = 'intune-powershell-script'
            collectorProfile    = $collectorProfile.profileName
            collectorVersion    = $script:CollectorVersion
            sourceRoot          = $OutputRoot
            collectedBy         = $OperatorName
            collectedUtc        = $manifestCreatedUtc
            chainOfCustodyNotes = 'Collected locally with built-in PowerShell and native Windows tools. Missing or failed artifacts are retained in this manifest.'
            results             = [ordered]@{
                artifactCounts = $statusCounts
                zipFileName    = $zipFileName
                upload         = $uploadInfo
            }
        }
        intakeHints      = [ordered]@{
            manifestPath       = 'manifest.json'
            notesPath          = 'notes.md'
            evidenceRoot       = 'evidence'
            primaryEntryPoints = $primaryEntryPoints
        }
        artifacts        = $artifactArray
        expectedEvidence = $expectedEvidence
        analysis         = [ordered]@{
            status            = 'not-started'
            priorityQuestions = @(
                'What failed, and when was it first observed?',
                'Which expected artifacts are missing or incomplete?',
                'Which collected artifact should be treated as the lead source?'
            )
            observedGaps      = $analysisObservedGaps
            handoffSummary    = 'Start with evidence/logs, evidence/exports, and dsregcmd-status.txt, then use the manifest to review missing or failed collections.'
        }
    }

    Write-JsonFile -InputObject $manifest -Path $manifestPath

    Write-Step 'Compressing evidence bundle'
    if (Test-Path -LiteralPath $zipPath) {
        Remove-Item -LiteralPath $zipPath -Force
    }
    Compress-Archive -LiteralPath $bundleRoot -DestinationPath $zipPath -CompressionLevel Optimal -Force

    $uploadStatus = [ordered]@{
        attempted   = $uploadRequested
        uploaded    = $false
        destination = $uploadInfo.destination
        statusCode  = $null
        error       = $null
    }

    if ($uploadRequested) {
        Write-Step 'Uploading zip to Azure Blob Storage'
        try {
            $uploadResult = Invoke-BlobUpload -ZipPath $zipPath -UploadUrl $resolvedUpload.uploadUrl
            $uploadStatus.uploaded = $true
            $uploadStatus.statusCode = $uploadResult.statusCode
        }
        catch {
            $uploadStatus.error = Protect-SecretText -Text $_.Exception.Message
            Write-Warning ('Upload failed: {0}' -f $uploadStatus.error)
        }
    }
    else {
        Write-Step 'Skipping upload because no SAS destination was provided'
    }

    $result = [pscustomobject]@{
        BundleId         = $bundleId
        BundleRoot       = $bundleRoot
        ManifestPath     = $manifestPath
        NotesPath        = $notesPath
        ZipPath          = $zipPath
        CollectorLogPath = $script:CollectorRunLogPath
        ArtifactCounts   = $statusCounts
        UploadStatus     = $uploadStatus
    }

    Write-Step 'Collection complete'
    $result
}
catch {
    $sanitizedMessage = Protect-SecretText -Text $_.Exception.Message
    Write-Error ('Collector failed: {0}' -f $sanitizedMessage)
    throw $sanitizedMessage
}
finally {
    Stop-CollectorTranscript
}