<#
Intune Remediations uploads the selected script content rather than a repo-relative file path.
This entrypoint intentionally mirrors Invoke-CmtraceEvidenceBootstrap.ps1 so it can be
uploaded directly while the original bootstrap remains the reusable repo-side engine.
Keep parameters and behavior aligned with Invoke-CmtraceEvidenceBootstrap.ps1.
#>

[CmdletBinding()]
param(
    [string]$StagingRoot = (Join-Path $env:ProgramData 'CmtraceOpen\Staging'),
    [string]$StateRoot = (Join-Path $env:ProgramData 'CmtraceOpen\State'),
    [string]$OutputRoot = (Join-Path $env:ProgramData 'CmtraceOpen\Evidence'),
    [string]$TaskName = 'CmtraceOpen-EvidenceCollection-Once',
    [int]$DelayMinutes = 2,
    [int]$ThrottleHours = 24,
    [version]$RequiredPowerShellVersion = [version]'7.5.4',
    [string]$PowerShellMsiUrl = 'https://github.com/PowerShell/PowerShell/releases/download/v7.5.4/PowerShell-7.5.4-win-x64.msi',
    [string]$CollectorProfileUrl = '', #fill out
    [string]$CollectorScriptUrl = '', #fill out
    [string]$SasUrl = '', #fill out
    [string]$BundleLabel = 'intune-endpoint-evidence',
    [string]$CaseReference = '',
    [string]$BlobName = '',
    [string]$OperatorName = 'SYSTEM',
    [string]$OperatorTeam = 'Intune',
    [string]$OperatorContact = '',
    [switch]$LocalOnly,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ForwardedArgumentList {
    $argumentList = New-Object System.Collections.Generic.List[string]

    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        $argumentList.Add('-{0}' -f $entry.Key)

        if ($entry.Value -is [System.Management.Automation.SwitchParameter]) {
            if (-not $entry.Value.IsPresent) {
                $argumentList.RemoveAt($argumentList.Count - 1)
                continue
            }

            continue
        }

        if (($entry.Value -is [System.Collections.IEnumerable]) -and (-not ($entry.Value -is [string]))) {
            foreach ($item in $entry.Value) {
                $argumentList.Add([string]$item)
            }

            continue
        }

        $argumentList.Add([string]$entry.Value)
    }

    return $argumentList
}

function Invoke-In64BitPowerShell {
    if (-not [Environment]::Is64BitOperatingSystem) {
        return
    }

    if ([Environment]::Is64BitProcess) {
        return
    }

    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        return
    }

    $sysNativePowerShell = Join-Path $env:WINDIR 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $sysNativePowerShell -PathType Leaf)) {
        return
    }

    # Re-enter through 64-bit PowerShell so transcript creation and Task Scheduler calls stay in the expected view.
    & $sysNativePowerShell -NoLogo -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @(Get-ForwardedArgumentList)
    exit $LASTEXITCODE
}

Invoke-In64BitPowerShell

$script:BootstrapTranscriptDirectory = Join-Path $env:ProgramData 'CmtraceOpen\Logs'
$script:BootstrapTranscriptPath = Join-Path $script:BootstrapTranscriptDirectory ('Remediate-CmtraceEvidenceBootstrap-{0}.log' -f (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))
$script:BootstrapTranscriptStarted = $false
$script:BootstrapTranscriptFilePresent = $false
$script:BootstrapTranscriptStartError = $null
$script:BootstrapTranscriptDiagnostics = $null
$script:BootstrapStage = 'startup'
$script:ConvertFromJsonSupportsDepth = $null
$script:BootstrapPayloadPath = if ([string]::IsNullOrWhiteSpace($PSCommandPath)) { $MyInvocation.MyCommand.Path } else { $PSCommandPath }
$script:BootstrapPayloadFingerprint = $null

function Protect-SecretText {
    param(
        [AllowEmptyString()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Value
    }

    return [System.Text.RegularExpressions.Regex]::Replace($Value, 'https?://[^\s''""<>]+', {
            param($Match)

            $uri = $null
            if (-not [System.Uri]::TryCreate($Match.Value, [System.UriKind]::Absolute, [ref]$uri)) {
                return $Match.Value
            }

            if ([string]::IsNullOrWhiteSpace($uri.Query)) {
                return $Match.Value
            }

            return ('{0} [query redacted]' -f $uri.GetLeftPart([System.UriPartial]::Path))
        })
}

function Format-StatusValue {
    param(
        [AllowEmptyString()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return '[not set]'
    }

    $normalizedValue = (Protect-SecretText -Value $Value) -replace '\r?\n', ' '
    $normalizedValue = ($normalizedValue -replace ';', ',').Trim()

    if ([string]::IsNullOrWhiteSpace($normalizedValue)) {
        return '[not set]'
    }

    return $normalizedValue
}

function Write-Step {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Verbose $Message
}

function Get-UtcTimestamp {
    return (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function Get-ContentFingerprint {
    param(
        [AllowEmptyString()]
        [string]$Path
    )

    $fingerprint = [ordered]@{
        Algorithm  = 'sha256'
        Hash       = $null
        Identifier = 'unavailable'
        Path       = $Path
    }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject]$fingerprint
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]$fingerprint
    }

    try {
        $fileHash = Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop
        $hashValue = $fileHash.Hash.ToLowerInvariant()
        $fingerprint.Algorithm = $fileHash.Algorithm.ToLowerInvariant()
        $fingerprint.Hash = $hashValue
        $fingerprint.Identifier = '{0}:{1}' -f $fingerprint.Algorithm, $hashValue.Substring(0, 16)
    }
    catch {
        $fingerprint.Identifier = 'unavailable'
    }

    return [pscustomobject]$fingerprint
}

$script:BootstrapPayloadFingerprint = Get-ContentFingerprint -Path $script:BootstrapPayloadPath

function Write-StageStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Stage,
        [Parameter(Mandatory = $true)]
        [string]$Status,
        [hashtable]$Details
    )

    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add('stage={0}' -f $Stage)
    $parts.Add('status={0}' -f $Status)
    $parts.Add('payloadId={0}' -f (Format-StatusValue -Value ([string]$script:BootstrapPayloadFingerprint.Identifier)))

    if ($null -ne $Details) {
        foreach ($entry in ($Details.GetEnumerator() | Sort-Object Key)) {
            $parts.Add(('{0}={1}' -f $entry.Key, (Format-StatusValue -Value ([string]$entry.Value))))
        }
    }

    Write-Output ($parts -join '; ')
}

function Get-ProcessArchitectureLabel {
    if ([Environment]::Is64BitProcess) {
        return 'x64'
    }

    return 'x86'
}

function Get-TranscriptStatusDetails {
    param(
        [AllowEmptyString()]
        [string]$ErrorMessage
    )

    $details = [ordered]@{
        host                 = $Host.Name
        processArch          = Get-ProcessArchitectureLabel
        transcript           = $script:BootstrapTranscriptPath
        transcriptDirExists  = (Test-Path -LiteralPath $script:BootstrapTranscriptDirectory -PathType Container)
        transcriptFileExists = (Test-Path -LiteralPath $script:BootstrapTranscriptPath -PathType Leaf)
    }

    if (-not [string]::IsNullOrWhiteSpace($ErrorMessage)) {
        $details.error = (Format-StatusValue -Value $ErrorMessage)
    }

    return $details
}

function Get-TranscriptStatus {
    if (-not $script:BootstrapTranscriptStarted) {
        return 'unavailable'
    }

    if (-not $script:BootstrapTranscriptFilePresent) {
        return 'file-missing'
    }

    return 'enabled'
}

function Initialize-BootstrapTranscript {
    try {
        [System.IO.Directory]::CreateDirectory($script:BootstrapTranscriptDirectory) | Out-Null
        $startTranscriptParameters = @{
            LiteralPath = $script:BootstrapTranscriptPath
            Force       = $true
        }

        $startTranscriptCommand = Get-Command -Name Start-Transcript -ErrorAction Stop
        if ($startTranscriptCommand.Parameters.ContainsKey('UseMinimalHeader')) {
            $startTranscriptParameters.UseMinimalHeader = $true
        }

        Start-Transcript @startTranscriptParameters | Out-Null
        $script:BootstrapTranscriptStarted = $true
        $script:BootstrapTranscriptFilePresent = (Test-Path -LiteralPath $script:BootstrapTranscriptPath -PathType Leaf)

        if (-not $script:BootstrapTranscriptFilePresent) {
            $script:BootstrapTranscriptStartError = 'Start-Transcript returned without creating the expected transcript file.'
        }
    }
    catch {
        $script:BootstrapTranscriptStartError = $_.Exception.Message
        $script:BootstrapTranscriptFilePresent = (Test-Path -LiteralPath $script:BootstrapTranscriptPath -PathType Leaf)
    }

    $script:BootstrapTranscriptDiagnostics = Get-TranscriptStatusDetails -ErrorMessage $script:BootstrapTranscriptStartError
}

Initialize-BootstrapTranscript

function Initialize-Directory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject,
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $utf8Encoding = New-Object System.Text.UTF8Encoding($false)
    $json = $InputObject | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($Path, $json, $utf8Encoding)
}

function Read-JsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-JsonCompat -Depth 10)
}

function ConvertFrom-JsonCompat {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [string]$InputObject,
        [int]$Depth = 10
    )

    process {
        if ($null -eq $script:ConvertFromJsonSupportsDepth) {
            $convertFromJsonCommand = Get-Command -Name ConvertFrom-Json -ErrorAction Stop
            $script:ConvertFromJsonSupportsDepth = $convertFromJsonCommand.Parameters.ContainsKey('Depth')
        }

        $convertFromJsonParameters = @{
            ErrorAction = 'Stop'
        }

        if ($script:ConvertFromJsonSupportsDepth) {
            $convertFromJsonParameters.Depth = $Depth
        }

        return ($InputObject | ConvertFrom-Json @convertFromJsonParameters)
    }
}

function Format-TaskArgument {
    param(
        [AllowEmptyString()]
        [string]$Value
    )

    return '"{0}"' -f ($Value -replace '"', '\"')
}

function Test-HttpsUrl {
    param(
        [AllowEmptyString()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }

    $uri = $null
    if (-not [System.Uri]::TryCreate($Value, [System.UriKind]::Absolute, [ref]$uri)) {
        return $false
    }

    return $uri.Scheme -eq 'https'
}

function Test-PlaceholderUrl {
    param(
        [AllowEmptyString()]
        [string]$Value
    )

    return $Value -like 'https://example.invalid/*'
}

function Get-File {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    if (-not (Test-HttpsUrl -Value $Url)) {
        throw ('Only HTTPS URLs are allowed: {0}' -f (Get-RedactedUrl -Value $Url))
    }

    Invoke-WebRequest -Uri $Url -OutFile $DestinationPath -UseBasicParsing
}

function Get-CommandExecutablePath {
    param(
        [AllowEmptyString()]
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $null
    }

    $command = Get-Command -Name $Name -CommandType Application -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        return $null
    }

    foreach ($propertyName in @('Path', 'Source', 'Definition')) {
        $property = $command.PSObject.Properties[$propertyName]
        if ($null -eq $property) {
            continue
        }

        $propertyValue = [string]$property.Value
        if ([string]::IsNullOrWhiteSpace($propertyValue)) {
            continue
        }

        return $propertyValue
    }

    return $null
}

function Get-PowerShellExecutableCandidates {
    $candidatePaths = New-Object System.Collections.Generic.List[string]
    $resolvedPwshPath = Get-CommandExecutablePath -Name 'pwsh.exe'

    foreach ($preferredPath in @(
            (Join-Path ${env:ProgramFiles} 'PowerShell\7\pwsh.exe'),
            $resolvedPwshPath,
            (Join-Path ${env:ProgramFiles(x86)} 'PowerShell\7\pwsh.exe')
        )) {
        if ([string]::IsNullOrWhiteSpace($preferredPath)) {
            continue
        }

        if (-not $candidatePaths.Contains($preferredPath)) {
            $candidatePaths.Add($preferredPath)
        }
    }

    return $candidatePaths
}

function Get-PowerShellExecutableVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $versionOutput = & $Path -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>$null
        if ($LASTEXITCODE -ne 0) {
            return $null
        }

        $versionText = [string]($versionOutput | Select-Object -First 1)
        if ([string]::IsNullOrWhiteSpace($versionText)) {
            return $null
        }

        $parsedVersion = $null
        if ([version]::TryParse($versionText.Trim(), [ref]$parsedVersion)) {
            return $parsedVersion
        }
    }
    catch {
        return $null
    }

    return $null
}

function Resolve-PowerShellExecutable {
    param(
        [Parameter(Mandatory = $true)]
        [version]$MinimumVersion
    )

    $fallbackCandidate = $null

    foreach ($candidatePath in (Get-PowerShellExecutableCandidates)) {
        if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
            continue
        }

        $candidateVersion = Get-PowerShellExecutableVersion -Path $candidatePath
        if ($null -eq $candidateVersion) {
            continue
        }

        $source = if ($candidatePath -eq (Join-Path ${env:ProgramFiles} 'PowerShell\7\pwsh.exe')) {
            'programfiles-x64'
        }
        elseif ($candidatePath -eq (Join-Path ${env:ProgramFiles(x86)} 'PowerShell\7\pwsh.exe')) {
            'programfiles-x86'
        }
        else {
            'command-path'
        }

        $candidate = [ordered]@{
            Found      = $true
            Acceptable = ($candidateVersion -ge $MinimumVersion)
            Path       = $candidatePath
            Version    = $candidateVersion
            Source     = $source
        }

        if ($candidate.Acceptable) {
            return [pscustomobject]$candidate
        }

        if ($null -eq $fallbackCandidate) {
            $fallbackCandidate = [pscustomobject]$candidate
        }
    }

    if ($null -ne $fallbackCandidate) {
        return $fallbackCandidate
    }

    return [pscustomobject]@{
        Found      = $false
        Acceptable = $false
        Path       = $null
        Version    = $null
        Source     = 'not-found'
    }
}

function Install-PowerShellMsi {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    if (-not (Test-HttpsUrl -Value $Url)) {
        throw "PowerShellMsiUrl must be an HTTPS URL: $Url"
    }

    Write-Step 'Downloading PowerShell MSI payload'
    Get-File -Url $Url -DestinationPath $DestinationPath

    Write-Step 'Installing PowerShell MSI payload'
    $installerProcess = Start-Process -FilePath 'msiexec.exe' -ArgumentList ('/i "{0}" /qn /norestart ALLUSERS=1' -f $DestinationPath) -Wait -PassThru -WindowStyle Hidden
    $restartRequired = $installerProcess.ExitCode -in @(3010, 1641)
    $installSucceeded = $installerProcess.ExitCode -in @(0, 3010, 1641)

    return [pscustomobject]@{
        StagedMsiPath     = $DestinationPath
        InstallerExitCode = $installerProcess.ExitCode
        RestartRequired   = $restartRequired
        InstallSucceeded  = $installSucceeded
    }
}

function Initialize-PowerShellExecutable {
    param(
        [Parameter(Mandatory = $true)]
        [version]$MinimumVersion,
        [Parameter(Mandatory = $true)]
        [string]$MsiUrl,
        [Parameter(Mandatory = $true)]
        [string]$MsiPath
    )

    $initialResolution = Resolve-PowerShellExecutable -MinimumVersion $MinimumVersion
    $details = [ordered]@{
        requiredVersion   = $MinimumVersion.ToString()
        msiUrl            = $MsiUrl
        action            = if ($initialResolution.Acceptable) { 'existing' } else { 'install-required' }
        installAttempted  = $false
        initialPath       = $initialResolution.Path
        initialVersion    = if ($null -ne $initialResolution.Version) { $initialResolution.Version.ToString() } else { $null }
        initialSource     = $initialResolution.Source
        stagedMsiPath     = $null
        installerExitCode = $null
        restartRequired   = $false
        finalPath         = $initialResolution.Path
        finalVersion      = if ($null -ne $initialResolution.Version) { $initialResolution.Version.ToString() } else { $null }
        finalSource       = $initialResolution.Source
    }

    if ($initialResolution.Acceptable) {
        return [pscustomobject]@{
            ExecutablePath = $initialResolution.Path
            Version        = $initialResolution.Version
            Details        = [pscustomobject]$details
        }
    }

    $details.installAttempted = $true
    $details.stagedMsiPath = $MsiPath

    $installResult = Install-PowerShellMsi -Url $MsiUrl -DestinationPath $MsiPath
    $details.action = 'installed'
    $details.installerExitCode = $installResult.InstallerExitCode
    $details.restartRequired = $installResult.RestartRequired
    $details.stagedMsiPath = $installResult.StagedMsiPath

    $finalResolution = Resolve-PowerShellExecutable -MinimumVersion $MinimumVersion
    $details.finalPath = $finalResolution.Path
    $details.finalVersion = if ($null -ne $finalResolution.Version) { $finalResolution.Version.ToString() } else { $null }
    $details.finalSource = $finalResolution.Source

    if (-not $finalResolution.Acceptable) {
        throw ('PowerShell {0} or later is required, but pwsh.exe could not be resolved after MSI install. Installer exit code: {1}. MSI path: {2}.' -f $MinimumVersion, $installResult.InstallerExitCode, $installResult.StagedMsiPath)
    }

    if (-not $installResult.InstallSucceeded) {
        throw ('PowerShell MSI install reported exit code {0} even though pwsh.exe resolved afterward. Treating this as a failure to avoid masking an incomplete installation.' -f $installResult.InstallerExitCode)
    }

    return [pscustomobject]@{
        ExecutablePath = $finalResolution.Path
        Version        = $finalResolution.Version
        Details        = [pscustomobject]$details
    }
}

function Test-PowerShellFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $parseErrors = $null
    $tokens = $null
    [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors) | Out-Null
    return ($parseErrors.Count -eq 0)
}

function Test-JsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        Get-Content -LiteralPath $Path -Raw | ConvertFrom-JsonCompat -Depth 20 | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Get-RedactedUrl {
    param(
        [AllowEmptyString()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return '[not provided]'
    }

    $uri = $null
    if (-not [System.Uri]::TryCreate($Value, [System.UriKind]::Absolute, [ref]$uri)) {
        return $Value
    }

    if ([string]::IsNullOrWhiteSpace($uri.Query)) {
        return $uri.AbsoluteUri
    }

    return ('{0} [query redacted]' -f $uri.GetLeftPart([System.UriPartial]::Path))
}

function Get-FilePreview {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $rawContent = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    }
    catch {
        return ('[preview unavailable: {0}]' -f $_.Exception.Message)
    }

    if ([string]::IsNullOrWhiteSpace($rawContent)) {
        return '[empty file]'
    }

    $normalizedPreview = (($rawContent -replace [char]0xFEFF, '') -replace '\r?\n', ' ')
    $normalizedPreview = ($normalizedPreview -replace '\s+', ' ').Trim()

    if ($normalizedPreview.Length -gt 200) {
        return ('{0}...' -f $normalizedPreview.Substring(0, 200))
    }

    return $normalizedPreview
}

function Get-JsonPayloadHint {
    param(
        [AllowEmptyString()]
        [string]$Preview
    )

    if ([string]::IsNullOrWhiteSpace($Preview) -or $Preview -eq '[empty file]') {
        return 'Payload is empty.'
    }

    $trimmedPreview = $Preview.TrimStart()
    if ($trimmedPreview.StartsWith('<')) {
        return 'Payload preview suggests HTML or XML content rather than JSON.'
    }

    if ((-not $trimmedPreview.StartsWith('{')) -and (-not $trimmedPreview.StartsWith('['))) {
        return 'Payload preview suggests plain text or another non-JSON format.'
    }

    return 'Payload could not be parsed as JSON.'
}

function Assert-ValidJsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$SourceContext
    )

    try {
        $rawContent = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    }
    catch {
        throw ('Downloaded profile payload could not be read. Staged path: {0}. Source: {1}. Error: {2}' -f $Path, (Get-RedactedUrl -Value $SourceContext), $_.Exception.Message)
    }

    if ([string]::IsNullOrWhiteSpace($rawContent)) {
        throw ('Downloaded profile payload is empty. Staged path: {0}. Source: {1}.' -f $Path, (Get-RedactedUrl -Value $SourceContext))
    }

    try {
        $rawContent | ConvertFrom-JsonCompat -Depth 20 | Out-Null
    }
    catch {
        $preview = Get-FilePreview -Path $Path
        $payloadHint = Get-JsonPayloadHint -Preview $preview
        throw ('Downloaded profile payload is not valid JSON. Staged path: {0}. Source: {1}. {2} Parse error: {3}. Payload preview: {4}' -f $Path, (Get-RedactedUrl -Value $SourceContext), $payloadHint, $_.Exception.Message, $preview)
    }
}

function Assert-StagedPayloads {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CollectorPath,
        [Parameter(Mandatory = $true)]
        [string]$ProfilePath,
        [Parameter(Mandatory = $true)]
        [string]$ProfileSource
    )

    if (-not (Test-PowerShellFile -Path $CollectorPath)) {
        throw "Downloaded collector payload is not valid PowerShell: $CollectorPath. Check CollectorScriptUrl."
    }

    Assert-ValidJsonFile -Path $ProfilePath -SourceContext $ProfileSource
}

function Get-Task {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
}

function Remove-TaskIfPresent {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $existingTask = Get-Task -Name $Name
    if ($existingTask) {
        Unregister-ScheduledTask -TaskName $Name -Confirm:$false
    }
}

function Assert-TaskRegistered {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Executable,
        [Parameter(Mandatory = $true)]
        [datetime]$TriggerTime,
        [AllowEmptyString()]
        [string]$Arguments
    )

    $registeredTask = Get-Task -Name $Name
    if ($registeredTask) {
        return $registeredTask
    }

    $detailParts = New-Object System.Collections.Generic.List[string]
    $detailParts.Add('taskName={0}' -f (Format-StatusValue -Value $Name))
    $detailParts.Add('execute={0}' -f (Format-StatusValue -Value $Executable))
    $detailParts.Add('processArch={0}' -f (Get-ProcessArchitectureLabel))
    $detailParts.Add('triggerUtc={0}' -f $TriggerTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))

    if (-not [string]::IsNullOrWhiteSpace($Arguments)) {
        $detailParts.Add('arguments={0}' -f (Format-StatusValue -Value $Arguments))
    }

    throw ('Scheduled task was not visible after Register-ScheduledTask. {0}' -f ($detailParts -join '; '))
}

function Get-ShouldThrottle {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StatePath,
        [Parameter(Mandatory = $true)]
        [int]$WindowHours,
        [switch]$IgnoreState
    )

    if ($IgnoreState) {
        return $false
    }

    $state = Read-JsonFile -Path $StatePath
    if ($null -eq $state) {
        return $false
    }

    if ([string]::IsNullOrWhiteSpace([string]$state.registeredUtc)) {
        return $false
    }

    $registeredUtc = [datetime]::Parse([string]$state.registeredUtc).ToUniversalTime()
    $expiresUtc = $registeredUtc.AddHours($WindowHours)
    return $expiresUtc -gt (Get-Date).ToUniversalTime()
}

function New-CollectorArgumentString {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CollectorPath,
        [Parameter(Mandatory = $true)]
        [string]$ProfilePath,
        [Parameter(Mandatory = $true)]
        [string]$CollectorOutputRoot,
        [Parameter(Mandatory = $true)]
        [string]$CollectorBundleLabel,
        [AllowEmptyString()]
        [string]$CollectorCaseReference,
        [AllowEmptyString()]
        [string]$CollectorBlobName,
        [AllowEmptyString()]
        [string]$CollectorOperatorName,
        [AllowEmptyString()]
        [string]$CollectorOperatorTeam,
        [AllowEmptyString()]
        [string]$CollectorOperatorContact,
        [AllowEmptyString()]
        [string]$ResolvedSasUrl,
        [switch]$RunLocalOnly
    )

    $arguments = New-Object System.Collections.Generic.List[string]
    $arguments.Add('-NoProfile')
    $arguments.Add('-ExecutionPolicy')
    $arguments.Add('Bypass')
    $arguments.Add('-File')
    $arguments.Add((Format-TaskArgument -Value $CollectorPath))
    $arguments.Add('-CollectorProfilePath')
    $arguments.Add((Format-TaskArgument -Value $ProfilePath))
    $arguments.Add('-OutputRoot')
    $arguments.Add((Format-TaskArgument -Value $CollectorOutputRoot))
    $arguments.Add('-BundleLabel')
    $arguments.Add((Format-TaskArgument -Value $CollectorBundleLabel))
    $arguments.Add('-OperatorName')
    $arguments.Add((Format-TaskArgument -Value $CollectorOperatorName))
    $arguments.Add('-OperatorTeam')
    $arguments.Add((Format-TaskArgument -Value $CollectorOperatorTeam))

    if (-not [string]::IsNullOrWhiteSpace($CollectorCaseReference)) {
        $arguments.Add('-CaseReference')
        $arguments.Add((Format-TaskArgument -Value $CollectorCaseReference))
    }

    if (-not [string]::IsNullOrWhiteSpace($CollectorBlobName)) {
        $arguments.Add('-BlobName')
        $arguments.Add((Format-TaskArgument -Value $CollectorBlobName))
    }

    if (-not [string]::IsNullOrWhiteSpace($CollectorOperatorContact)) {
        $arguments.Add('-OperatorContact')
        $arguments.Add((Format-TaskArgument -Value $CollectorOperatorContact))
    }

    if ($RunLocalOnly) {
        $arguments.Add('-LocalOnly')
    }
    elseif (-not [string]::IsNullOrWhiteSpace($ResolvedSasUrl)) {
        $arguments.Add('-SasUrl')
        $arguments.Add((Format-TaskArgument -Value $ResolvedSasUrl))
    }

    return ($arguments -join ' ')
}

function New-RunScopedStagedPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,
        [Parameter(Mandatory = $true)]
        [string]$LeafName,
        [Parameter(Mandatory = $true)]
        [string]$RunToken
    )

    $extension = [System.IO.Path]::GetExtension($LeafName)
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($LeafName)

    if ([string]::IsNullOrWhiteSpace($extension)) {
        return (Join-Path $Root ('{0}-{1}' -f $baseName, $RunToken))
    }

    return (Join-Path $Root ('{0}-{1}{2}' -f $baseName, $RunToken, $extension))
}

$stagingRunId = '{0}-{1}' -f (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'), [guid]::NewGuid().ToString('N')
$statePath = Join-Path $StateRoot 'collection-bootstrap.json'
$stagedCollectorPath = New-RunScopedStagedPath -Root $StagingRoot -LeafName 'Invoke-CmtraceEvidenceCollection.ps1' -RunToken $stagingRunId
$stagedProfilePath = New-RunScopedStagedPath -Root $StagingRoot -LeafName 'intune-evidence-profile.json' -RunToken $stagingRunId
$stagedPowerShellMsiPath = Join-Path $StagingRoot ('PowerShell-{0}-win-x64.msi' -f $RequiredPowerShellVersion)

try {
    Write-StageStatus -Stage 'bootstrap' -Status 'starting' -Details @{
        delayMinutes     = $DelayMinutes
        localOnly        = [bool]$LocalOnly
        processArch      = Get-ProcessArchitectureLabel
        stagedCollector  = $stagedCollectorPath
        stagedProfile    = $stagedProfilePath
        stagingRunId     = $stagingRunId
        throttleHours    = $ThrottleHours
        transcript       = $script:BootstrapTranscriptPath
        transcriptStatus = Get-TranscriptStatus
    }

    if ((Get-TranscriptStatus) -ne 'enabled') {
        Write-StageStatus -Stage 'transcript' -Status (Get-TranscriptStatus) -Details $script:BootstrapTranscriptDiagnostics
    }

    $script:BootstrapStage = 'prepare-directories'
    Write-Step 'Preparing bootstrap directories'
    Initialize-Directory -Path $StagingRoot
    Initialize-Directory -Path $StateRoot
    Initialize-Directory -Path $OutputRoot

    if (Test-PlaceholderUrl -Value $CollectorScriptUrl) {
        throw 'CollectorScriptUrl still points to the example.invalid placeholder. Provide a reachable HTTPS URL for the collector payload.'
    }

    if (Test-PlaceholderUrl -Value $CollectorProfileUrl) {
        throw 'CollectorProfileUrl still points to the example.invalid placeholder. Provide a reachable HTTPS URL for the collector profile.'
    }

    if ((-not $LocalOnly) -and [string]::IsNullOrWhiteSpace($SasUrl)) {
        throw 'SasUrl is required unless you use -LocalOnly.'
    }

    if ((-not $LocalOnly) -and (-not (Test-HttpsUrl -Value $SasUrl))) {
        throw 'SasUrl must be an HTTPS URL.'
    }

    if ((-not $LocalOnly) -and ($SasUrl -notmatch '\?')) {
        throw 'SasUrl does not appear to contain a query string.'
    }

    $script:BootstrapStage = 'throttle-check'
    if (Get-ShouldThrottle -StatePath $statePath -WindowHours $ThrottleHours -IgnoreState:$Force) {
        $existingTask = Get-Task -Name $TaskName
        $status = if ($existingTask) { 'skipped-throttled-task-present' } else { 'skipped-throttled' }
        Write-StageStatus -Stage 'bootstrap' -Status $status -Details @{
            state      = $statePath
            task       = $TaskName
            transcript = $script:BootstrapTranscriptPath
        }
        return
    }

    $script:BootstrapStage = 'stage-payloads'
    Write-Step 'Downloading staged collector payloads'
    Get-File -Url $CollectorScriptUrl -DestinationPath $stagedCollectorPath
    Get-File -Url $CollectorProfileUrl -DestinationPath $stagedProfilePath

    Write-Step 'Validating staged collector payloads'
    Assert-StagedPayloads -CollectorPath $stagedCollectorPath -ProfilePath $stagedProfilePath -ProfileSource $CollectorProfileUrl
    Write-StageStatus -Stage 'payloads' -Status 'ready' -Details @{
        collector  = $stagedCollectorPath
        profile    = $stagedProfilePath
        stagingRun = $stagingRunId
        transcript = $script:BootstrapTranscriptPath
    }

    $script:BootstrapStage = 'resolve-runtime'
    Write-Step 'Resolving PowerShell runtime'
    $powerShellResolution = Initialize-PowerShellExecutable -MinimumVersion $RequiredPowerShellVersion -MsiUrl $PowerShellMsiUrl -MsiPath $stagedPowerShellMsiPath
    Write-StageStatus -Stage 'runtime' -Status 'ready' -Details @{
        executable = $powerShellResolution.ExecutablePath
        transcript = $script:BootstrapTranscriptPath
        version    = $powerShellResolution.Version.ToString()
    }

    $resolvedSasUrl = $SasUrl

    $caseReferenceValue = if ([string]::IsNullOrWhiteSpace($CaseReference)) {
        'bootstrap-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss')
    }
    else {
        $CaseReference
    }

    $taskArguments = New-CollectorArgumentString -CollectorPath $stagedCollectorPath -ProfilePath $stagedProfilePath -CollectorOutputRoot $OutputRoot -CollectorBundleLabel $BundleLabel -CollectorCaseReference $caseReferenceValue -CollectorBlobName $BlobName -CollectorOperatorName $OperatorName -CollectorOperatorTeam $OperatorTeam -CollectorOperatorContact $OperatorContact -ResolvedSasUrl $resolvedSasUrl -RunLocalOnly:$LocalOnly
    $powerShellExecutable = $powerShellResolution.ExecutablePath

    $script:BootstrapStage = 'register-task'
    Write-Step 'Registering one-time SYSTEM scheduled task'
    if ($Force) {
        Remove-TaskIfPresent -Name $TaskName
    }
    elseif (Get-Task -Name $TaskName) {
        Remove-TaskIfPresent -Name $TaskName
    }

    $triggerTime = (Get-Date).AddMinutes($DelayMinutes)
    $taskAction = New-ScheduledTaskAction -Execute $powerShellExecutable -Argument $taskArguments
    $taskTrigger = New-ScheduledTaskTrigger -Once -At $triggerTime
    $taskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 8) -StartWhenAvailable

    Register-ScheduledTask -TaskName $TaskName -Action $taskAction -Trigger $taskTrigger -User 'SYSTEM' -RunLevel Highest -Settings $taskSettings -Force | Out-Null
    $registeredTask = Assert-TaskRegistered -Name $TaskName -Executable $powerShellExecutable -Arguments $taskArguments -TriggerTime $triggerTime

    $state = [ordered]@{
        registeredUtc               = Get-UtcTimestamp
        triggerUtc                  = $triggerTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        taskName                    = $TaskName
        remediationPayloadId        = $script:BootstrapPayloadFingerprint.Identifier
        remediationPayloadAlgorithm = $script:BootstrapPayloadFingerprint.Algorithm
        remediationPayloadHash      = $script:BootstrapPayloadFingerprint.Hash
        remediationPayloadPath      = $script:BootstrapPayloadFingerprint.Path
        stagingRoot                 = $StagingRoot
        stagingRunId                = $stagingRunId
        stagedCollectorPath         = $stagedCollectorPath
        stagedProfilePath           = $stagedProfilePath
        outputRoot                  = $OutputRoot
        collectorScriptUrl          = $CollectorScriptUrl
        collectorProfileUrl         = $CollectorProfileUrl
        powerShell                  = $powerShellResolution.Details
        powerShellExecutable        = $powerShellExecutable
        sasUrlConfigured            = (-not [string]::IsNullOrWhiteSpace($SasUrl))
        localOnly                   = [bool]$LocalOnly
        caseReference               = $caseReferenceValue
        transcriptPath              = $script:BootstrapTranscriptPath
    }

    Write-JsonFile -InputObject $state -Path $statePath

    $script:BootstrapStage = 'completed'
    Write-Step 'Bootstrap complete'
    Write-StageStatus -Stage 'bootstrap' -Status 'scheduled' -Details @{
        collector  = $stagedCollectorPath
        outputRoot = $OutputRoot
        profile    = $stagedProfilePath
        state      = $statePath
        task       = $TaskName
        taskPath   = [string]$registeredTask.TaskPath
        transcript = $script:BootstrapTranscriptPath
        triggerUtc = $triggerTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
}
catch {
    $redactedMessage = Format-StatusValue -Value $_.Exception.Message
    Write-StageStatus -Stage $script:BootstrapStage -Status 'failed' -Details @{
        collector  = $stagedCollectorPath
        message    = $redactedMessage
        profile    = $stagedProfilePath
        transcript = $script:BootstrapTranscriptPath
    }
    throw
}
finally {
    if ($script:BootstrapTranscriptStarted) {
        try {
            Stop-Transcript | Out-Null
        }
        catch {
            Write-StageStatus -Stage 'transcript' -Status 'stop-failed' -Details @{
                message    = $_.Exception.Message
                transcript = $script:BootstrapTranscriptPath
            }
        }
    }
}