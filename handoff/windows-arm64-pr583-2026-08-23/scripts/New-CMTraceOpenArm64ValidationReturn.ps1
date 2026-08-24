[CmdletBinding(DefaultParameterSetName = 'Production')]
param(
    [Parameter(Mandatory = $true)]
    [string]$EvidenceRoot,

    [Parameter(Mandatory = $true, ParameterSetName = 'Production')]
    [string]$OutputPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Production')]
    [string]$RepositoryPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'ContractOnly')]
    [switch]$ContractOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion -lt [version]'7.5.0') {
    throw 'The ARM64 validation return exporter requires PowerShell 7.5 or later.'
}

. (Join-Path $PSScriptRoot 'CMTraceOpenArm64Handoff.Common.ps1')

[void](Assert-CMTraceHandoffIntegrity)

function Assert-CMTraceNoReparsePath {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Label)

    $cursor = if (Test-Path -LiteralPath $Path -PathType Any) { [IO.Path]::GetFullPath($Path) } else { Split-Path -Parent ([IO.Path]::GetFullPath($Path)) }
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        if (Test-Path -LiteralPath $cursor -PathType Any) {
            $entry = Get-Item -LiteralPath $cursor -Force
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label cannot traverse a symlink, junction, or reparse point: $cursor"
            }
        }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) {
            break
        }
        $cursor = $parent
    }
}

function Test-CMTracePathWithin {
    param([string]$Path, [string]$Root)
    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd([char]'\', [char]'/')
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd([char]'\', [char]'/')
    $separator = [IO.Path]::DirectorySeparatorChar
    return $fullPath.Equals($fullRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith("$fullRoot$separator", [StringComparison]::OrdinalIgnoreCase)
}

function Assert-CMTraceSequence {
    param([object[]]$Actual, [object[]]$Expected, [string]$Label)
    if ($Actual.Count -ne $Expected.Count) {
        throw "$Label count mismatch."
    }
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        if ($Expected[$index] -is [string] -and $Actual[$index] -isnot [string]) {
            throw "$Label contains a non-string value at index $index."
        }
        if (-not [object]::Equals($Actual[$index], $Expected[$index])) {
            throw "$Label order or value mismatch at index $index."
        }
    }
}

function Assert-CMTraceReturnZipContract {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][DateTimeOffset]$FixedTimestamp,
        [Parameter(Mandatory = $true)][string[]]$ExpectedFiles
    )

    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $seenEntries = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $archiveFiles = [System.Collections.Generic.List[string]]::new()
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName.Replace('\', '/')
            if ($name.StartsWith('/') -or $name.StartsWith('../') -or $name.Contains('/../') -or $name -match '^[A-Za-z]:') {
                throw "Return ZIP contains an unsafe entry: $name"
            }
            if (-not $seenEntries.Add($name)) {
                throw "Return ZIP contains a duplicate entry: $name"
            }
            if ([string]::IsNullOrEmpty($entry.Name)) {
                throw "Return ZIP contains a directory entry: $name"
            }
            if ($entry.LastWriteTime.DateTime -ne $FixedTimestamp.DateTime) {
                throw "Return ZIP entry has a noncanonical timestamp: $name"
            }
            if ([int64]$entry.ExternalAttributes -ne 0) {
                throw "Return ZIP entry has noncanonical external attributes: $name"
            }
            $archiveFiles.Add($name)
        }
        Assert-CMTraceSequence -Actual @(Get-CMTraceOrdinalSortedString -Value @($archiveFiles)) `
            -Expected $ExpectedFiles -Label 'return ZIP entry inventory'
    }
    finally {
        $archive.Dispose()
    }
}

function Assert-CMTraceNoDuplicateJsonProperty {
    param([System.Text.Json.JsonElement]$Element, [string]$Label)

    if ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $seen.Add($property.Name)) {
                throw "$Label contains a duplicate or case-colliding JSON property: $($property.Name)."
            }
            Assert-CMTraceNoDuplicateJsonProperty -Element $property.Value -Label $Label
        }
    }
    elseif ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Element.EnumerateArray()) {
            Assert-CMTraceNoDuplicateJsonProperty -Element $item -Label $Label
        }
    }
}

function Read-CMTraceStrictJson {
    param([string]$Path, [int]$MaximumBytes, [string]$Label)

    $text = Read-CMTraceStrictUtf8Text -Path $Path -MaximumBytes $MaximumBytes
    $options = [System.Text.Json.JsonDocumentOptions]::new()
    $options.AllowTrailingCommas = $false
    $options.CommentHandling = [System.Text.Json.JsonCommentHandling]::Disallow
    $options.MaxDepth = 20
    try {
        $document = [System.Text.Json.JsonDocument]::Parse($text, $options)
        try {
            Assert-CMTraceNoDuplicateJsonProperty -Element $document.RootElement -Label $Label
            if ($document.RootElement.ValueKind -notin @([System.Text.Json.JsonValueKind]::Object, [System.Text.Json.JsonValueKind]::Array)) {
                throw "$Label must have an object or array root."
            }
        }
        finally {
            $document.Dispose()
        }
        $value = $text | ConvertFrom-Json -Depth 25 -DateKind String
    }
    catch {
        throw "$Label is malformed or violates the strict JSON contract: $($_.Exception.Message)"
    }
    return [pscustomobject]@{ Text = $text; Value = $value }
}

function Assert-CMTraceSha256Value {
    param([object]$Value, [string]$Label)
    if ($Value -isnot [string] -or $Value -cnotmatch '^[0-9a-f]{64}$') {
        throw "$Label must be a lowercase SHA-256 value."
    }
}

function ConvertTo-CMTraceBoundedInteger {
    param([object]$Value, [string]$Label, [switch]$Positive, [switch]$AllowNegative)
    if ($Value -isnot [int64]) {
        throw "$Label must be an integer."
    }
    $integer = [int64]$Value
    if (($Positive -and $integer -le 0) -or (-not $Positive -and -not $AllowNegative -and $integer -lt 0)) {
        throw "$Label is outside its allowed nonnegative range."
    }
    return $integer
}

function ConvertTo-CMTraceUtcTimestamp {
    param([object]$Value, [string]$Label)
    if ($Value -isnot [string] -or $Value -cnotmatch 'Z$') {
        throw "$Label must be an explicit UTC timestamp ending in Z."
    }
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed) -or $parsed.Offset -ne [TimeSpan]::Zero) {
        throw "$Label must be a valid UTC timestamp."
    }
    return $parsed
}

function Assert-CMTracePrivateLiteralsAbsent {
    param(
        [string]$Text,
        [object]$PrivacyLiterals,
        [string]$Label,
        [switch]$StrictSubstring
    )

    foreach ($property in $PrivacyLiterals.PSObject.Properties) {
        $literal = ([string]$property.Value).Normalize([Text.NormalizationForm]::FormC)
        if ([string]::IsNullOrWhiteSpace($literal)) {
            continue
        }
        $tokenBoundedProperties = @('computerName', 'userName', 'userDomain', 'homeDrive')
        $views = @(
            [pscustomobject]@{
                Text = $Text.Normalize([Text.NormalizationForm]::FormC)
                Literal = $literal
            },
            [pscustomobject]@{
                Text = ConvertTo-CMTracePrivacyReconstructionText -Text $Text
                Literal = ConvertTo-CMTracePrivacyReconstructionText -Text $literal
            }
        )
        foreach ($view in $views) {
            if ([string]::IsNullOrEmpty($view.Literal)) {
                continue
            }
            $pattern = if (-not $StrictSubstring -and $property.Name -cin $tokenBoundedProperties) {
                '(?<![A-Za-z0-9]){0}(?![A-Za-z0-9])' -f [regex]::Escape($view.Literal)
            }
            else {
                '{0}' -f [regex]::Escape($view.Literal)
            }
            $options = [Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
                [Text.RegularExpressions.RegexOptions]::CultureInvariant
            if ([regex]::IsMatch($view.Text, $pattern, $options)) {
                throw "Evidence privacy scan failed for ${Label}: detected target-private $($property.Name)."
            }
        }
    }
}

function Get-CMTracePrivateLiteralScanText {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$SanitizedGateBody
    )

    $trimmedBody = $SanitizedGateBody.TrimEnd([char]"`r", [char]"`n")
    foreach ($publicFallbackBody in @(
        "result=sanitized-log-body-withheld-after-size-limit`nThe complete raw log remains target-private.",
        "result=sanitized-log-withheld-after-privacy-validation-failure`nThe complete raw log remains target-private."
    )) {
        if ([string]::Equals($trimmedBody, $publicFallbackBody, [StringComparison]::Ordinal)) {
            return ''
        }
    }

    return ConvertTo-CMTracePrivacyCanonicalScanText -Text $SanitizedGateBody
}

function Assert-CMTraceSummaryContract {
    param([object]$Summary, [string]$StagingRoot, [string]$PrivateEvidenceRoot)

    Assert-CMTraceExactPropertySet -Value $Summary -Names @('schemaVersion', 'handoffId', 'sourceCommit', 'sourceTree', 'target', 'startedAtUtc', 'completedAtUtc', 'automaticStatus', 'gates', 'rawEvidenceReturned') -Label 'summary.json'
    $summarySchemaVersion = ConvertTo-CMTraceBoundedInteger -Value $Summary.schemaVersion -Label 'summary.json schemaVersion'
    if ($summarySchemaVersion -ne 1 -or $Summary.rawEvidenceReturned -isnot [bool] -or $Summary.rawEvidenceReturned -ne $false) {
        throw 'summary.json does not match the sealed automatic evidence coordinate.'
    }
    foreach ($coordinate in @(
        [pscustomobject]@{ Value = $Summary.handoffId; Expected = $script:CMTraceHandoffId; Label = 'summary handoffId' },
        [pscustomobject]@{ Value = $Summary.sourceCommit; Expected = $script:CMTraceExpectedSourceCommit; Label = 'summary sourceCommit' },
        [pscustomobject]@{ Value = $Summary.sourceTree; Expected = $script:CMTraceExpectedSourceTree; Label = 'summary sourceTree' },
        [pscustomobject]@{ Value = $Summary.target; Expected = $script:CMTraceRustTarget; Label = 'summary target' }
    )) {
        Assert-CMTraceExactStringValue -Value $coordinate.Value -Expected $coordinate.Expected -Label $coordinate.Label
    }
    $started = ConvertTo-CMTraceUtcTimestamp -Value $Summary.startedAtUtc -Label 'summary.json startedAtUtc'
    $completed = ConvertTo-CMTraceUtcTimestamp -Value $Summary.completedAtUtc -Label 'summary.json completedAtUtc'
    if ($completed -lt $started) {
        throw 'summary.json completedAtUtc precedes startedAtUtc.'
    }

    $gates = @($Summary.gates)
    if ($gates.Count -ne $script:CMTraceAutomaticGateIds.Count) {
        throw "summary.json must contain exactly $($script:CMTraceAutomaticGateIds.Count) automatic gates."
    }
    $gateById = @{}
    for ($index = 0; $index -lt $script:CMTraceAutomaticGateIds.Count; $index++) {
        $expectedId = $script:CMTraceAutomaticGateIds[$index]
        $gate = $gates[$index]
        Assert-CMTraceExactPropertySet -Value $gate -Names @('id', 'class', 'status', 'exitCode', 'startedAtUtc', 'durationMilliseconds', 'command', 'rawLogSha256', 'sanitizedLog', 'sanitizedLogSha256', 'blockedBy') -Label "summary gate $expectedId"
        Assert-CMTraceExactStringValue -Value $gate.id -Expected $expectedId -Label "summary gate $expectedId id"
        if ($gateById.ContainsKey($gate.id)) {
            throw "summary.json automatic gate order or uniqueness failed at $expectedId."
        }
        $gateById[$gate.id] = $gate
        $contract = $script:CMTraceAutomaticGateContracts[$gate.id]
        Assert-CMTraceExactStringValue -Value $gate.class -Expected $contract.class -Label "summary gate $expectedId class"
        Assert-CMTraceStringInSet -Value $gate.status -Allowed @('passed', 'failed', 'blocked') -Label "summary gate $expectedId status"
        [void](ConvertTo-CMTraceBoundedInteger -Value $gate.durationMilliseconds -Label "$expectedId durationMilliseconds")
        Assert-CMTraceSha256Value -Value $gate.rawLogSha256 -Label "$expectedId rawLogSha256"
        Assert-CMTraceSha256Value -Value $gate.sanitizedLogSha256 -Label "$expectedId sanitizedLogSha256"
        $expectedLog = "sanitized-logs/$expectedId.log"
        Assert-CMTraceExactStringValue -Value $gate.sanitizedLog -Expected $expectedLog -Label "summary gate $expectedId sanitizedLog"
        $expectedCommand = if ($expectedId -in @('source-integrity', 'arm64-pe-verification', 'source-clean-after')) {
            '<internal handoff gate>'
        }
        elseif ($expectedId -in @('installer-pester', 'collector-pester')) {
            'pwsh -EncodedCommand <redacted>'
        }
        else {
            "gate:$expectedId"
        }

        if ($gate.status -eq 'blocked') {
            if ($null -ne $gate.exitCode -or $null -ne $gate.startedAtUtc -or $null -ne $gate.command -or
                (ConvertTo-CMTraceBoundedInteger -Value $gate.durationMilliseconds -Label "$expectedId durationMilliseconds") -ne 0) {
                throw "Blocked gate $expectedId contains execution fields."
            }
        }
        else {
            [void](ConvertTo-CMTraceUtcTimestamp -Value $gate.startedAtUtc -Label "$expectedId startedAtUtc")
            Assert-CMTraceExactStringValue -Value $gate.command -Expected $expectedCommand -Label "summary gate $expectedId command"
            $validatedExitCode = if ($null -eq $gate.exitCode) { $null } else {
                ConvertTo-CMTraceBoundedInteger -Value $gate.exitCode -Label "$expectedId exitCode" -AllowNegative
            }
            if ($null -ne $validatedExitCode -and
                ($validatedExitCode -lt [int]::MinValue -or $validatedExitCode -gt [int]::MaxValue)) {
                throw "Gate $expectedId exitCode is outside the native Int32 process-exit range."
            }
            if (Test-CMTraceOwnedProcessWrapperFailureExitCode -ExitCode $validatedExitCode) {
                throw "Gate $expectedId cannot retain reserved wrapper infrastructure exit code $script:CMTraceOwnedProcessWrapperFailureExitCode; use null because no trustworthy native exit exists."
            }
            if ($gate.status -eq 'passed' -and $validatedExitCode -ne 0) {
                throw "Passed gate $expectedId must have exitCode 0."
            }
            if ($gate.status -eq 'failed' -and $null -ne $validatedExitCode -and $validatedExitCode -eq 0) {
                throw "Failed gate $expectedId cannot have exitCode 0."
            }
        }
    }

    foreach ($gate in $gates) {
        $contract = $script:CMTraceAutomaticGateContracts[$gate.id]
        $expectedBlockedBy = @($contract.dependsOn | Where-Object { $gateById[$_].status -ne 'passed' })
        if ($gate.blockedBy -isnot [System.Array]) {
            throw "summary gate $($gate.id) blockedBy must be a JSON array."
        }
        $actualBlockedBy = @($gate.blockedBy)
        if ($gate.status -eq 'blocked') {
            Assert-CMTraceSequence -Actual $actualBlockedBy -Expected $expectedBlockedBy -Label "$($gate.id) blockedBy"
            if ($expectedBlockedBy.Count -eq 0) {
                throw "Blocked gate $($gate.id) has no failed or blocked dependency."
            }
        }
        else {
            if ($actualBlockedBy.Count -ne 0) {
                throw "Executed gate $($gate.id) cannot contain blockedBy entries."
            }
            if ($expectedBlockedBy.Count -ne 0) {
                throw "Executed gate $($gate.id) has a failed or blocked dependency and must be blocked."
            }
        }

        $logPath = Join-Path $StagingRoot $gate.sanitizedLog
        if ((Get-CMTraceSha256 -Path $logPath) -ne $gate.sanitizedLogSha256) {
            throw "Sanitized log hash mismatch for gate $($gate.id)."
        }
        $logText = Read-CMTraceStrictUtf8Text -Path $logPath -MaximumBytes 1048576
        $canonicalEnvelopePattern = '\Agate=' + [regex]::Escape($gate.id) +
            '\r?\nstatus=' + [regex]::Escape($gate.status) + '(?:\r?\n|\z)'
        if ($logText -cnotmatch $canonicalEnvelopePattern) {
            throw "Sanitized log envelope does not match summary gate $($gate.id)."
        }
        $normalizedLogText = [regex]::Replace(
            $logText.TrimEnd([char]"`r", [char]"`n"),
            '\r\n?',
            "`n"
        )
        $privacyFailureResultLine = 'result=sanitized-log-withheld-after-privacy-validation-failure'
        if ($normalizedLogText -match ('(?m)^' + [regex]::Escape($privacyFailureResultLine) + '$')) {
            $expectedPrivacyFailureLog = "gate=$($gate.id)`nstatus=failed`n$privacyFailureResultLine`nThe complete raw log remains target-private."
            if ($gate.status -cne 'failed' -or
                -not [string]::Equals($normalizedLogText, $expectedPrivacyFailureLog, [StringComparison]::Ordinal)) {
                throw "Sanitized privacy-withheld fallback is not canonical failed-gate evidence for $($gate.id)."
            }
        }

        $rawLogPath = Join-Path $PrivateEvidenceRoot "raw-logs/$($gate.id).log"
        Assert-CMTraceNoReparsePath -Path $rawLogPath -Label "raw log $($gate.id)"
        if (-not (Test-Path -LiteralPath $rawLogPath -PathType Leaf)) {
            throw "Private raw log is missing for gate $($gate.id)."
        }
        $rawLogEntry = Get-Item -LiteralPath $rawLogPath -Force
        if (($rawLogEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            (Get-CMTraceSha256 -Path $rawLogPath) -cne $gate.rawLogSha256) {
            throw "Private raw log hash mismatch for gate $($gate.id)."
        }
    }

    $derivedStatus = if (@($gates | Where-Object { $_.status -eq 'failed' }).Count -gt 0) {
        'FAILED'
    }
    elseif (@($gates | Where-Object { $_.status -eq 'blocked' }).Count -gt 0) {
        'BLOCKED'
    }
    else {
        'PASSED'
    }
    Assert-CMTraceExactStringValue -Value $Summary.automaticStatus -Expected $derivedStatus -Label 'summary automaticStatus'
    return $gateById
}

function Assert-CMTraceMachineContract {
    param([object]$Machine)

    $properties = @(
        'schemaVersion', 'handoffId', 'sourceCommit', 'sourceTree', 'target',
        'os', 'osVersion', 'osBuild', 'osArchitecture', 'processArchitecture',
        'processorArchitecture', 'logicalProcessorCount', 'cpuClass', 'physicalMemoryBytes',
        'powerShellVersion', 'gitVersion', 'nodeVersion', 'nodeArchitecture', 'npmVersion',
        'rustVersion', 'rustHost', 'pesterVersion', 'cargoDenyVersion', 'cargoAuditVersion',
        'clangVersion', 'visualStudioVersion', 'windowsSdkVersion', 'webView2Version',
        'sourceVolumeFileSystem', 'sourceVolumeDriveType', 'sourceOutsideKnownSyncRoots',
        'identityFieldsIntentionallyOmitted'
    )
    Assert-CMTraceExactPropertySet -Value $Machine -Names $properties -Label 'machine.json'
    $machineSchemaVersion = ConvertTo-CMTraceBoundedInteger -Value $Machine.schemaVersion -Label 'machine.json schemaVersion'
    if ($machineSchemaVersion -ne 2 -or $Machine.sourceOutsideKnownSyncRoots -isnot [bool] -or $Machine.sourceOutsideKnownSyncRoots -ne $true) {
        throw 'machine.json does not prove the sealed native Windows 11 ARM64 environment.'
    }
    foreach ($coordinate in @(
        [pscustomobject]@{ Value = $Machine.handoffId; Expected = $script:CMTraceHandoffId; Label = 'machine handoffId' },
        [pscustomobject]@{ Value = $Machine.sourceCommit; Expected = $script:CMTraceExpectedSourceCommit; Label = 'machine sourceCommit' },
        [pscustomobject]@{ Value = $Machine.sourceTree; Expected = $script:CMTraceExpectedSourceTree; Label = 'machine sourceTree' },
        [pscustomobject]@{ Value = $Machine.target; Expected = $script:CMTraceRustTarget; Label = 'machine target' },
        [pscustomobject]@{ Value = $Machine.os; Expected = 'Windows 11'; Label = 'machine os' },
        [pscustomobject]@{ Value = $Machine.osArchitecture; Expected = 'Arm64'; Label = 'machine osArchitecture' },
        [pscustomobject]@{ Value = $Machine.processArchitecture; Expected = 'Arm64'; Label = 'machine processArchitecture' },
        [pscustomobject]@{ Value = $Machine.processorArchitecture; Expected = 'ARM64'; Label = 'machine processorArchitecture' },
        [pscustomobject]@{ Value = $Machine.nodeArchitecture; Expected = 'arm64'; Label = 'machine nodeArchitecture' },
        [pscustomobject]@{ Value = $Machine.rustHost; Expected = $script:CMTraceRustTarget; Label = 'machine rustHost' },
        [pscustomobject]@{ Value = $Machine.sourceVolumeFileSystem; Expected = 'NTFS'; Label = 'machine sourceVolumeFileSystem' },
        [pscustomobject]@{ Value = $Machine.sourceVolumeDriveType; Expected = 'Fixed'; Label = 'machine sourceVolumeDriveType' }
    )) {
        Assert-CMTraceExactStringValue -Value $coordinate.Value -Expected $coordinate.Expected -Label $coordinate.Label
    }
    if ($Machine.osVersion -isnot [string] -or $Machine.osVersion -notmatch '^\d+\.\d+\.\d+(?:\.\d+)?$') {
        throw 'machine.json osVersion must be dotted numeric Windows version evidence.'
    }
    $versionParts = @($Machine.osVersion.Split('.') | ForEach-Object { [int64]$_ })
    $osBuild = ConvertTo-CMTraceBoundedInteger -Value $Machine.osBuild -Label 'machine osBuild'
    if ($osBuild -lt 22000 -or $versionParts.Count -lt 3 -or $versionParts[2] -ne $osBuild) {
        throw 'machine.json does not identify a Windows 11 build.'
    }
    $versionComponent = '(?:0|[1-9]\d{0,5})'
    $threePartPattern = "^$versionComponent(?:\.$versionComponent){2}$"
    $fourPartPattern = "^$versionComponent(?:\.$versionComponent){3}$"
    if ($Machine.nodeVersion -isnot [string] -or $Machine.nodeVersion -cnotmatch "^v22\.$versionComponent\.$versionComponent$") {
        throw 'machine.json nodeVersion must identify normalized Node.js 22.'
    }
    if ($Machine.rustVersion -isnot [string] -or
        $Machine.rustVersion -cnotmatch "^rustc 1\.(?<minor>$versionComponent)\.$versionComponent$" -or
        [int]$Matches.minor -lt 88) {
        throw 'machine.json rustVersion must identify normalized Rust 1.88 or later.'
    }

    $versionContracts = @(
        [pscustomobject]@{ Name = 'powerShellVersion'; Pattern = $threePartPattern; Minimum = [version]'7.5.0'; Major = $null },
        [pscustomobject]@{ Name = 'npmVersion'; Pattern = $threePartPattern; Minimum = $null; Major = $null },
        [pscustomobject]@{ Name = 'pesterVersion'; Pattern = $threePartPattern; Minimum = [version]'5.0.0'; Major = $null },
        [pscustomobject]@{ Name = 'cargoDenyVersion'; Pattern = $threePartPattern; Minimum = $null; Major = $null },
        [pscustomobject]@{ Name = 'cargoAuditVersion'; Pattern = $threePartPattern; Minimum = $null; Major = $null },
        [pscustomobject]@{ Name = 'clangVersion'; Pattern = $threePartPattern; Minimum = $null; Major = $null },
        [pscustomobject]@{ Name = 'visualStudioVersion'; Pattern = $fourPartPattern; Minimum = $null; Major = 17 },
        [pscustomobject]@{ Name = 'windowsSdkVersion'; Pattern = $fourPartPattern; Minimum = [version]'10.0.26100.0'; Major = 10 },
        [pscustomobject]@{ Name = 'webView2Version'; Pattern = $fourPartPattern; Minimum = $null; Major = $null }
    )
    foreach ($contract in $versionContracts) {
        $value = $Machine.($contract.Name)
        if ($value -isnot [string] -or $value -cnotmatch $contract.Pattern) {
            throw "machine.json $($contract.Name) must be a normalized numeric version."
        }
        $parsed = [version]$value
        if (($parsed.Major -eq 0 -and $parsed.Minor -eq 0 -and $parsed.Build -eq 0) -or
            ($null -ne $contract.Minimum -and $parsed -lt $contract.Minimum) -or
            ($null -ne $contract.Major -and $parsed.Major -ne $contract.Major)) {
            throw "machine.json $($contract.Name) is outside the sealed toolchain requirement."
        }
    }
    if (([version]$Machine.windowsSdkVersion).Minor -ne 0) {
        throw 'machine.json windowsSdkVersion must identify the Windows 10/11 SDK version family.'
    }
    if ($Machine.gitVersion -isnot [string] -or
        $Machine.gitVersion -cnotmatch '^(?<core>(?:0|[1-9]\d{0,5})(?:\.(?:0|[1-9]\d{0,5})){2})\.windows\.(?:0|[1-9]\d{0,5})$') {
        throw 'machine.json gitVersion must be a normalized Git for Windows version.'
    }
    $gitCoreVersion = [version]$Matches.core
    if ($gitCoreVersion.Major -eq 0 -and $gitCoreVersion.Minor -eq 0 -and $gitCoreVersion.Build -eq 0) {
        throw 'machine.json gitVersion must be a nonzero Git for Windows version.'
    }
    $logicalProcessorCount = ConvertTo-CMTraceBoundedInteger -Value $Machine.logicalProcessorCount -Label 'machine logicalProcessorCount' -Positive
    if ($logicalProcessorCount -gt [int]::MaxValue) {
        throw 'machine.json logicalProcessorCount is outside the native Int32 processor-count range.'
    }
    [void](ConvertTo-CMTraceBoundedInteger -Value $Machine.physicalMemoryBytes -Label 'machine physicalMemoryBytes' -Positive)
    if ($Machine.cpuClass -isnot [string] -or [string]::IsNullOrWhiteSpace($Machine.cpuClass) -or
        $Machine.cpuClass -cne $Machine.cpuClass.Trim() -or
        $Machine.cpuClass.Equals('unknown', [StringComparison]::OrdinalIgnoreCase) -or
        $Machine.cpuClass -match '[\x00-\x1F\x7F-\x9F\p{Cf}\p{Zl}\p{Zp}]' -or
        ([Text.Encoding]::UTF8.GetByteCount($Machine.cpuClass) -gt 160)) {
        throw 'machine.json cpuClass must be a bounded nonempty hardware class.'
    }
    Assert-CMTracePrivacySafeText -Text $Machine.cpuClass -Label 'machine.json cpuClass'
    Assert-CMTraceSequence -Actual @($Machine.identityFieldsIntentionallyOmitted) -Expected @('computerName', 'userName', 'domain', 'deviceId', 'tenantId', 'ipAddress') -Label 'machine identityFieldsIntentionallyOmitted'
}

function Get-CMTraceMachinePrivacyScanText {
    param([Parameter(Mandatory = $true)][object]$Machine)

    # These exact fields have already passed the strict machine contract above.
    # Replace only their values before the generic dotted-quad scan so a valid
    # four-part version cannot be mistaken for an IP address. Every other
    # machine value remains subject to the unmodified privacy scanner.
    $normalizedVersionFields = @(
        'powerShellVersion', 'gitVersion', 'nodeVersion', 'npmVersion', 'rustVersion',
        'pesterVersion', 'cargoDenyVersion', 'cargoAuditVersion', 'clangVersion',
        'visualStudioVersion', 'windowsSdkVersion', 'webView2Version'
    )
    $privacyView = [ordered]@{}
    foreach ($property in $Machine.PSObject.Properties) {
        $privacyView[$property.Name] = if ($property.Name -cin $normalizedVersionFields) {
            '<validated:normalized:version>'
        }
        else {
            $property.Value
        }
    }
    # Preserve property boundaries for the line-wrapped payload detector.
    # Compressing this already strictly validated object makes unrelated public
    # hashes and platform labels appear to be one continuous encoded stream.
    return ($privacyView | ConvertTo-Json -Depth 10)
}

function Assert-CMTracePortableArtifact {
    param([object]$Item, [string]$Kind)
    Assert-CMTraceExactPropertySet -Value $Item -Names @('kind', 'bytes', 'sha256', 'peMachine', 'architecture', 'authenticodeStatus') -Label "artifact $Kind"
    foreach ($coordinate in @(
        [pscustomobject]@{ Value = $Item.kind; Expected = $Kind; Label = "$Kind kind" },
        [pscustomobject]@{ Value = $Item.peMachine; Expected = '0xAA64'; Label = "$Kind peMachine" },
        [pscustomobject]@{ Value = $Item.architecture; Expected = 'arm64'; Label = "$Kind architecture" },
        [pscustomobject]@{ Value = $Item.authenticodeStatus; Expected = 'NotSigned'; Label = "$Kind authenticodeStatus" }
    )) {
        Assert-CMTraceExactStringValue -Value $coordinate.Value -Expected $coordinate.Expected -Label $coordinate.Label
    }
    [void](ConvertTo-CMTraceBoundedInteger -Value $Item.bytes -Label "$Kind bytes" -Positive)
    Assert-CMTraceSha256Value -Value $Item.sha256 -Label "$Kind sha256"
}

function Assert-CMTraceWindowsProvenanceProjection {
    param(
        [Parameter(Mandatory = $true)][object]$Private,
        [Parameter(Mandatory = $true)][object]$Returned
    )

    Assert-CMTraceExactPropertySet -Value $Private -Names @(
        'schemaVersion', 'sourceCommit', 'buildCommit', 'target', 'packageVersion',
        'releaseExecutable', 'installers'
    ) -Label 'private windows-build-provenance.json'
    $privateSchema = ConvertTo-CMTraceBoundedInteger -Value $Private.schemaVersion -Label 'private provenance schemaVersion'
    if ($privateSchema -ne (ConvertTo-CMTraceBoundedInteger -Value $Returned.schemaVersion -Label 'returned provenance schemaVersion')) {
        throw 'Private Windows build provenance schema does not match artifacts.json.'
    }
    foreach ($name in @('sourceCommit', 'buildCommit', 'target', 'packageVersion')) {
        Assert-CMTraceExactStringValue -Value $Private.$name -Expected ([string]$Returned.$name) -Label "private provenance $name"
    }

    Assert-CMTraceExactPropertySet -Value $Private.releaseExecutable -Names @('path', 'bytes', 'sha256') -Label 'private provenance releaseExecutable'
    foreach ($name in @('path', 'sha256')) {
        Assert-CMTraceExactStringValue -Value $Private.releaseExecutable.$name -Expected ([string]$Returned.releaseExecutable.$name) -Label "private provenance releaseExecutable $name"
    }
    if ((ConvertTo-CMTraceBoundedInteger -Value $Private.releaseExecutable.bytes -Label 'private provenance release bytes' -Positive) -ne
        (ConvertTo-CMTraceBoundedInteger -Value $Returned.releaseExecutable.bytes -Label 'returned provenance release bytes' -Positive)) {
        throw 'Private Windows build provenance release bytes do not match artifacts.json.'
    }

    if ($Private.installers -isnot [System.Array] -or @($Private.installers).Count -ne 1) {
        throw 'Private Windows build provenance must contain exactly one installer array entry.'
    }
    $privateInstaller = @($Private.installers)[0]
    $returnedInstaller = @($Returned.installers)[0]
    Assert-CMTraceExactPropertySet -Value $privateInstaller -Names @('path', 'bytes', 'sha256', 'bundleType', 'expectedInstalledExecutable') -Label 'private provenance installer'
    foreach ($name in @('path', 'sha256', 'bundleType')) {
        Assert-CMTraceExactStringValue -Value $privateInstaller.$name -Expected ([string]$returnedInstaller.$name) -Label "private provenance installer $name"
    }
    if ((ConvertTo-CMTraceBoundedInteger -Value $privateInstaller.bytes -Label 'private provenance installer bytes' -Positive) -ne
        (ConvertTo-CMTraceBoundedInteger -Value $returnedInstaller.bytes -Label 'returned provenance installer bytes' -Positive)) {
        throw 'Private Windows build provenance installer bytes do not match artifacts.json.'
    }

    $privateInstalled = $privateInstaller.expectedInstalledExecutable
    $returnedInstalled = $returnedInstaller.expectedInstalledExecutable
    Assert-CMTraceExactPropertySet -Value $privateInstalled -Names @('path', 'bytes', 'sha256', 'derivation') -Label 'private provenance expectedInstalledExecutable'
    foreach ($name in @('path', 'sha256', 'derivation')) {
        Assert-CMTraceExactStringValue -Value $privateInstalled.$name -Expected ([string]$returnedInstalled.$name) -Label "private provenance expectedInstalledExecutable $name"
    }
    if ((ConvertTo-CMTraceBoundedInteger -Value $privateInstalled.bytes -Label 'private provenance installed bytes' -Positive) -ne
        (ConvertTo-CMTraceBoundedInteger -Value $returnedInstalled.bytes -Label 'returned provenance installed bytes' -Positive)) {
        throw 'Private Windows build provenance installed bytes do not match artifacts.json.'
    }
}

function Assert-CMTraceArtifactsContract {
    param([object]$Artifacts, [hashtable]$AutomaticGates, [string]$PrivateEvidenceRoot)

    Assert-CMTraceExactPropertySet -Value $Artifacts -Names @('schemaVersion', 'handoffId', 'sourceCommit', 'sourceTree', 'target', 'items') -Label 'artifacts.json'
    $artifactsSchemaVersion = ConvertTo-CMTraceBoundedInteger -Value $Artifacts.schemaVersion -Label 'artifacts.json schemaVersion'
    if ($artifactsSchemaVersion -ne 1) {
        throw 'artifacts.json does not match the sealed coordinate.'
    }
    foreach ($coordinate in @(
        [pscustomobject]@{ Value = $Artifacts.handoffId; Expected = $script:CMTraceHandoffId; Label = 'artifacts handoffId' },
        [pscustomobject]@{ Value = $Artifacts.sourceCommit; Expected = $script:CMTraceExpectedSourceCommit; Label = 'artifacts sourceCommit' },
        [pscustomobject]@{ Value = $Artifacts.sourceTree; Expected = $script:CMTraceExpectedSourceTree; Label = 'artifacts sourceTree' },
        [pscustomobject]@{ Value = $Artifacts.target; Expected = $script:CMTraceRustTarget; Label = 'artifacts target' }
    )) {
        Assert-CMTraceExactStringValue -Value $coordinate.Value -Expected $coordinate.Expected -Label $coordinate.Label
    }
    $items = @($Artifacts.items)
    if ($AutomaticGates['arm64-pe-verification'].status -ne 'passed') {
        if ($items.Count -ne 0) {
            throw 'Artifact evidence must be atomic and empty when ARM64 PE verification did not pass.'
        }
        return @{}
    }
    $expectedKinds = @('full-portable', 'lite-portable', 'nsis-installer', 'windows-build-provenance')
    Assert-CMTraceSequence -Actual @($items.kind) -Expected $expectedKinds -Label 'artifact kinds'
    Assert-CMTracePortableArtifact -Item $items[0] -Kind 'full-portable'
    Assert-CMTracePortableArtifact -Item $items[1] -Kind 'lite-portable'

    $nsis = $items[2]
    Assert-CMTraceExactPropertySet -Value $nsis -Names @('kind', 'bytes', 'sha256', 'peMachine', 'architecture', 'authenticodeStatus') -Label 'artifact nsis-installer'
    foreach ($coordinate in @(
        [pscustomobject]@{ Value = $nsis.kind; Expected = 'nsis-installer'; Label = 'NSIS kind' },
        [pscustomobject]@{ Value = $nsis.peMachine; Expected = '0x014C'; Label = 'NSIS peMachine' },
        [pscustomobject]@{ Value = $nsis.architecture; Expected = 'x86-bootstrapper'; Label = 'NSIS architecture' },
        [pscustomobject]@{ Value = $nsis.authenticodeStatus; Expected = 'NotSigned'; Label = 'NSIS authenticodeStatus' }
    )) {
        Assert-CMTraceExactStringValue -Value $coordinate.Value -Expected $coordinate.Expected -Label $coordinate.Label
    }
    [void](ConvertTo-CMTraceBoundedInteger -Value $nsis.bytes -Label 'nsis bytes' -Positive)
    Assert-CMTraceSha256Value -Value $nsis.sha256 -Label 'nsis sha256'

    $provenance = $items[3]
    Assert-CMTraceExactPropertySet -Value $provenance -Names @('kind', 'schemaVersion', 'sourceCommit', 'buildCommit', 'target', 'packageVersion', 'releaseExecutable', 'installers', 'manifestSha256') -Label 'artifact windows-build-provenance'
    $provenanceSchemaVersion = ConvertTo-CMTraceBoundedInteger -Value $provenance.schemaVersion -Label 'provenance schemaVersion'
    if ($provenanceSchemaVersion -ne 2) {
        throw 'Windows build provenance does not match the sealed coordinate.'
    }
    foreach ($coordinate in @(
        [pscustomobject]@{ Value = $provenance.kind; Expected = 'windows-build-provenance'; Label = 'provenance kind' },
        [pscustomobject]@{ Value = $provenance.sourceCommit; Expected = $script:CMTraceExpectedSourceCommit; Label = 'provenance sourceCommit' },
        [pscustomobject]@{ Value = $provenance.buildCommit; Expected = $script:CMTraceExpectedSourceCommit; Label = 'provenance buildCommit' },
        [pscustomobject]@{ Value = $provenance.target; Expected = $script:CMTraceRustTarget; Label = 'provenance target' },
        [pscustomobject]@{ Value = $provenance.packageVersion; Expected = '1.5.1'; Label = 'provenance packageVersion' }
    )) {
        Assert-CMTraceExactStringValue -Value $coordinate.Value -Expected $coordinate.Expected -Label $coordinate.Label
    }
    Assert-CMTraceSha256Value -Value $provenance.manifestSha256 -Label 'provenance manifestSha256'
    Assert-CMTraceExactPropertySet -Value $provenance.releaseExecutable -Names @('path', 'bytes', 'sha256') -Label 'provenance releaseExecutable'
    Assert-CMTraceExactStringValue -Value $provenance.releaseExecutable.path -Expected 'cmtrace-open.exe' -Label 'provenance releaseExecutable path'
    $releaseBytes = ConvertTo-CMTraceBoundedInteger -Value $provenance.releaseExecutable.bytes -Label 'provenance release bytes' -Positive
    Assert-CMTraceSha256Value -Value $provenance.releaseExecutable.sha256 -Label 'provenance release sha256'
    $fullBytes = ConvertTo-CMTraceBoundedInteger -Value $items[0].bytes -Label 'full artifact bytes' -Positive
    if ($fullBytes -ne $releaseBytes -or
        -not [string]::Equals($items[0].sha256, $provenance.releaseExecutable.sha256, [StringComparison]::Ordinal)) {
        throw 'Full portable artifact does not match standalone release-executable provenance.'
    }

    $installers = @($provenance.installers)
    if ($provenance.installers -isnot [System.Array] -or $installers.Count -ne 1) {
        throw 'Provenance must contain exactly one NSIS installer.'
    }
    $installer = $installers[0]
    Assert-CMTraceExactPropertySet -Value $installer -Names @('path', 'bytes', 'sha256', 'bundleType', 'expectedInstalledExecutable') -Label 'provenance NSIS installer'
    Assert-CMTraceExactStringValue -Value $installer.path -Expected 'nsis/CMTrace Open_1.5.1_arm64-setup.exe' -Label 'provenance NSIS installer path'
    Assert-CMTraceExactStringValue -Value $installer.bundleType -Expected 'nsis' -Label 'provenance installer bundleType'
    $installerBytes = ConvertTo-CMTraceBoundedInteger -Value $installer.bytes -Label 'provenance installer bytes' -Positive
    Assert-CMTraceSha256Value -Value $installer.sha256 -Label 'provenance installer sha256'
    $nsisBytes = ConvertTo-CMTraceBoundedInteger -Value $nsis.bytes -Label 'nsis bytes' -Positive
    if ($installerBytes -ne $nsisBytes -or -not [string]::Equals($installer.sha256, $nsis.sha256, [StringComparison]::Ordinal)) {
        throw 'NSIS artifact does not match its provenance installer entry.'
    }
    $installed = $installer.expectedInstalledExecutable
    Assert-CMTraceExactPropertySet -Value $installed -Names @('path', 'bytes', 'sha256', 'derivation') -Label 'provenance expectedInstalledExecutable'
    Assert-CMTraceExactStringValue -Value $installed.path -Expected 'cmtrace-open.exe' -Label 'installed executable path'
    Assert-CMTraceExactStringValue -Value $installed.derivation -Expected 'tauriBundleTypeMarkerV1' -Label 'installed executable derivation'
    $installedBytes = ConvertTo-CMTraceBoundedInteger -Value $installed.bytes -Label 'expected installed executable bytes' -Positive
    Assert-CMTraceSha256Value -Value $installed.sha256 -Label 'expected installed executable sha256'
    # The Tauri NSIS marker changes the installed image hash without changing its byte length.
    if ($installedBytes -ne $releaseBytes) {
        throw 'Expected installed executable evidence must be the same-length, distinct Tauri NSIS derivation of the standalone release executable; byte length differs.'
    }
    if ([string]::Equals($installed.sha256, $provenance.releaseExecutable.sha256, [StringComparison]::Ordinal)) {
        throw 'Expected installed executable evidence must be the same-length, distinct Tauri NSIS derivation of the standalone release executable; SHA-256 is not distinct.'
    }

    foreach ($privateArtifact in @(
        [pscustomobject]@{ Relative = 'raw-artifacts/full/cmtrace-open.exe'; Hash = $items[0].sha256; Bytes = $fullBytes },
        [pscustomobject]@{ Relative = 'raw-artifacts/lite/cmtrace-open.exe'; Hash = $items[1].sha256; Bytes = (ConvertTo-CMTraceBoundedInteger -Value $items[1].bytes -Label 'lite artifact bytes' -Positive) },
        [pscustomobject]@{ Relative = 'raw-artifacts/nsis/cmtrace-open-setup.exe'; Hash = $nsis.sha256; Bytes = $nsisBytes },
        [pscustomobject]@{ Relative = 'raw-artifacts/provenance/windows-build-provenance.json'; Hash = $provenance.manifestSha256; Bytes = $null }
    )) {
        $privatePath = Join-Path $PrivateEvidenceRoot $privateArtifact.Relative
        Assert-CMTraceNoReparsePath -Path $privatePath -Label $privateArtifact.Relative
        if (-not (Test-Path -LiteralPath $privatePath -PathType Leaf)) {
            throw "Private automatic artifact is missing: $($privateArtifact.Relative)"
        }
        $privateEntry = Get-Item -LiteralPath $privatePath -Force
        if (($privateEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            (Get-CMTraceSha256 -Path $privatePath) -cne $privateArtifact.Hash -or
            ($null -ne $privateArtifact.Bytes -and $privateEntry.Length -ne $privateArtifact.Bytes)) {
            throw "Private automatic artifact does not match artifacts.json: $($privateArtifact.Relative)"
        }
    }
    $privateProvenancePath = Join-Path $PrivateEvidenceRoot 'raw-artifacts/provenance/windows-build-provenance.json'
    $privateProvenance = Read-CMTraceStrictJson -Path $privateProvenancePath -MaximumBytes 131072 -Label 'private windows-build-provenance.json'
    Assert-CMTraceWindowsProvenanceProjection -Private $privateProvenance.Value -Returned $provenance
    return @{
        'full-portable' = $items[0].sha256
        'lite-portable' = $items[1].sha256
        'nsis-installer' = $nsis.sha256
        'installed-executable' = $installed.sha256
    }
}

function Assert-CMTraceManualContract {
    param([object]$Manual, [object]$Template, [string]$SummaryPath, [string]$ArtifactsPath, [hashtable]$ArtifactHashes, [string]$PrivateEvidenceRoot)

    $topProperties = @('schemaVersion', 'handoffId', 'sourceCommit', 'sourceTree', 'target', 'automaticSummarySha256', 'artifactsSha256', 'status', 'allowedGateStatuses', 'allowedDispositionCodes', 'privacyRule', 'measurements', 'gates')
    Assert-CMTraceExactPropertySet -Value $Manual -Names $topProperties -Label 'manual-results.json'
    $manualSchemaVersion = ConvertTo-CMTraceBoundedInteger -Value $Manual.schemaVersion -Label 'manual-results.json schemaVersion'
    if ($manualSchemaVersion -ne 3) {
        throw 'manual-results.json does not match the sealed manual contract.'
    }
    foreach ($coordinate in @(
        [pscustomobject]@{ Value = $Manual.handoffId; Expected = $script:CMTraceHandoffId; Label = 'manual handoffId' },
        [pscustomobject]@{ Value = $Manual.sourceCommit; Expected = $script:CMTraceExpectedSourceCommit; Label = 'manual sourceCommit' },
        [pscustomobject]@{ Value = $Manual.sourceTree; Expected = $script:CMTraceExpectedSourceTree; Label = 'manual sourceTree' },
        [pscustomobject]@{ Value = $Manual.target; Expected = $script:CMTraceRustTarget; Label = 'manual target' },
        [pscustomobject]@{ Value = $Manual.privacyRule; Expected = $Template.privacyRule; Label = 'manual privacyRule' }
    )) {
        Assert-CMTraceExactStringValue -Value $coordinate.Value -Expected $coordinate.Expected -Label $coordinate.Label
    }
    Assert-CMTraceSha256Value -Value $Manual.automaticSummarySha256 -Label 'manual automaticSummarySha256'
    Assert-CMTraceSha256Value -Value $Manual.artifactsSha256 -Label 'manual artifactsSha256'
    if ($Manual.automaticSummarySha256 -cne (Get-CMTraceSha256 -Path $SummaryPath) -or $Manual.artifactsSha256 -cne (Get-CMTraceSha256 -Path $ArtifactsPath)) {
        throw 'manual-results.json is not bound to the returned automatic summary and artifact evidence.'
    }
    Assert-CMTraceSequence -Actual @($Manual.allowedGateStatuses) -Expected @($Template.allowedGateStatuses) -Label 'manual allowedGateStatuses'
    Assert-CMTraceSequence -Actual @($Manual.allowedDispositionCodes) -Expected @($Template.allowedDispositionCodes) -Label 'manual allowedDispositionCodes'

    $measurementNames = @($Template.measurements.PSObject.Properties.Name)
    Assert-CMTraceExactPropertySet -Value $Manual.measurements -Names $measurementNames -Label 'manual measurements'
    foreach ($measurement in $Manual.measurements.PSObject.Properties) {
        if ($null -ne $measurement.Value) {
            [void](ConvertTo-CMTraceBoundedInteger -Value $measurement.Value -Label "manual measurement $($measurement.Name)")
        }
    }

    $gates = @($Manual.gates)
    $templateGates = @($Template.gates)
    if ($gates.Count -ne $templateGates.Count) {
        throw 'manual-results.json gate count does not match the sealed template.'
    }
    $gateProperties = @('id', 'requiredForFullAcceptance', 'status', 'dispositionCode', 'executedAtUtc', 'evidenceId', 'evidenceSha256', 'nativeArm64Observed', 'independentReadback', 'artifactSha256', 'requiredEvidence')
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $seenEvidenceIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $noArtifactGates = @(
        'clean-snapshot-version-isolation',
        'real-evtx-nonvacuous',
        'provider-native-capture', 'provider-retained-db-tests',
        'eventlog-filter-library-advanced-surface', 'eventlog-grouping-drag-pivot-surface', 'eventlog-filter-rule-color-surface',
        'performance-host-profile', 'performance-all-channels-seven-day',
        'production-signing-and-msi-boundary'
    )
    $artifactKindByGate = @{}
    foreach ($templateGate in $templateGates) {
        if ($templateGate.id -cnotin $noArtifactGates) {
            $artifactKindByGate[$templateGate.id] = 'full-portable'
        }
    }
    $artifactKindByGate['lite-portable-launch'] = 'lite-portable'
    $artifactKindByGate['nsis-clean-install'] = 'nsis-installer'
    $artifactKindByGate['provider-packaged-resource'] = 'nsis-installer'
    foreach ($installedGate in @(
        'nsis-installed-arm64-payload', 'default-apps-file-associations', 'nsis-uninstall-cleanup',
        'elevation-same-account', 'elevation-over-the-shoulder', 'genuine-upgrade-lifecycle'
    )) {
        $artifactKindByGate[$installedGate] = 'installed-executable'
    }
    if (($artifactKindByGate.Count + $noArtifactGates.Count) -ne $templateGates.Count) {
        throw 'The sealed manual gate-to-artifact map is incomplete.'
    }
    $allowedArtifactHashes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($hash in $ArtifactHashes.Values) {
        if ($hash -is [string]) { [void]$allowedArtifactHashes.Add($hash) }
    }
    for ($index = 0; $index -lt $templateGates.Count; $index++) {
        $gate = $gates[$index]
        $expected = $templateGates[$index]
        Assert-CMTraceExactPropertySet -Value $gate -Names $gateProperties -Label "manual gate $($expected.id)"
        Assert-CMTraceExactStringValue -Value $gate.id -Expected $expected.id -Label "manual gate $($expected.id) id"
        Assert-CMTraceExactStringValue -Value $gate.requiredEvidence -Expected $expected.requiredEvidence -Label "manual gate $($expected.id) requiredEvidence"
        if (-not $seen.Add($gate.id) -or $gate.requiredForFullAcceptance -ne $expected.requiredForFullAcceptance) {
            throw "Manual gate $($expected.id) does not match the sealed template."
        }
        if ($gate.requiredForFullAcceptance -isnot [bool] -or $gate.nativeArm64Observed -isnot [bool] -or $gate.independentReadback -isnot [bool]) {
            throw "Manual gate $($gate.id) contains a non-boolean contract field."
        }
        Assert-CMTraceStringInSet -Value $gate.status -Allowed @($Template.allowedGateStatuses) -Label "manual gate $($gate.id) status"
        Assert-CMTraceStringInSet -Value $gate.dispositionCode -Allowed @($Template.allowedDispositionCodes) -Label "manual gate $($gate.id) dispositionCode"
        if ($null -ne $gate.artifactSha256) {
            Assert-CMTraceSha256Value -Value $gate.artifactSha256 -Label "$($gate.id) artifactSha256"
            if (-not $allowedArtifactHashes.Contains($gate.artifactSha256)) {
                throw "Manual gate $($gate.id) artifactSha256 is not an automatic artifact hash."
            }
        }

        if ($gate.status -in @('PASS', 'FAIL', 'BLOCKED')) {
            $expectedDisposition = if ($gate.status -eq 'PASS') { 'CONFIRMED' } elseif ($gate.status -eq 'FAIL') { 'OBSERVED_FAILURE' } else { $null }
            if ($expectedDisposition -and $gate.dispositionCode -ne $expectedDisposition) {
                throw "Manual gate $($gate.id) disposition does not match status $($gate.status)."
            }
            if ($gate.status -eq 'BLOCKED' -and $gate.dispositionCode -notin @('APPROVAL_REQUIRED', 'APPROVAL_NOT_GRANTED', 'PREREQUISITE_MISSING', 'ENVIRONMENT_UNAVAILABLE', 'DEPENDENCY_FAILED', 'SAFETY_BOUNDARY', 'NONDETERMINISTIC_PATH')) {
                throw "Blocked manual gate $($gate.id) lacks a bounded blocker code."
            }
            [void](ConvertTo-CMTraceUtcTimestamp -Value $gate.executedAtUtc -Label "$($gate.id) executedAtUtc")
            if ($gate.evidenceId -isnot [string] -or $gate.evidenceId -cnotmatch '^[a-z0-9][a-z0-9._-]{0,63}$') {
                throw "Manual gate $($gate.id) evidenceId must be a privacy-safe target-local evidence slug."
            }
            if (-not $seenEvidenceIds.Add($gate.evidenceId)) {
                throw "Manual gate $($gate.id) reuses an evidenceId."
            }
            Assert-CMTraceSha256Value -Value $gate.evidenceSha256 -Label "$($gate.id) evidenceSha256"
            $proofPath = Join-Path $PrivateEvidenceRoot "raw-artifacts/manual-evidence/$($gate.evidenceId).proof"
            Assert-CMTraceNoReparsePath -Path $proofPath -Label "manual proof $($gate.evidenceId)"
            if (-not (Test-Path -LiteralPath $proofPath -PathType Leaf)) {
                throw "Manual gate $($gate.id) target-private proof file is missing."
            }
            $proofEntry = Get-Item -LiteralPath $proofPath -Force
            if (($proofEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                (Get-CMTraceSha256 -Path $proofPath) -cne $gate.evidenceSha256) {
                throw "Manual gate $($gate.id) proof file does not match evidenceSha256."
            }
            if ($gate.status -in @('PASS', 'FAIL') -and
                ($gate.nativeArm64Observed -ne $true -or $gate.independentReadback -ne $true)) {
                throw "Manual gate $($gate.id) PASS/FAIL must record native ARM64 observation and independent readback."
            }
            if ($gate.status -in @('PASS', 'FAIL') -and $artifactKindByGate.ContainsKey($gate.id) -and $null -eq $gate.artifactSha256) {
                throw "Manual gate $($gate.id) must bind the observed application or installer artifact hash."
            }
        }
        else {
            if ($gate.dispositionCode -in @('CONFIRMED', 'OBSERVED_FAILURE', 'DEPENDENCY_FAILED') -or
                $null -ne $gate.executedAtUtc -or $null -ne $gate.evidenceId -or $null -ne $gate.evidenceSha256 -or
                $gate.nativeArm64Observed -ne $false -or $gate.independentReadback -ne $false -or $null -ne $gate.artifactSha256) {
                throw "NOT_EXERCISED manual gate $($gate.id) contains observation evidence or an incompatible disposition."
            }
        }

        if ($gate.status -in @('PASS', 'FAIL', 'BLOCKED')) {
            $artifactKind = if ($artifactKindByGate.ContainsKey($gate.id)) {
                $artifactKindByGate[$gate.id]
            }
            else {
                $null
            }
            if ($null -eq $artifactKind -and $null -ne $gate.artifactSha256) {
                throw "Manual source-only gate $($gate.id) cannot bind an unrelated application artifact."
            }
            if ($null -ne $artifactKind -and $null -ne $gate.artifactSha256 -and
                $gate.artifactSha256 -cne $ArtifactHashes[$artifactKind]) {
                throw "Manual gate $($gate.id) does not bind to the expected automatic artifact hash."
            }
            if ($gate.status -eq 'PASS' -and $gate.id -eq 'production-signing-and-msi-boundary') {
                throw 'The production signing and MSI boundary cannot be marked PASS from this unsigned handoff.'
            }
        }
    }

    $byId = @{}
    foreach ($gate in $gates) { $byId[$gate.id] = $gate }

    $measurementGateMap = [ordered]@{
        localWideRecordCount = @('local-time-filter-strict')
        localNarrowRecordCount = @('local-time-filter-strict')
        localLevelRecordCount = @('local-level-filter-nonzero')
        realEvtxTestsExecuted = @('real-evtx-nonvacuous')
        providerCount = @('provider-native-capture', 'provider-retained-db-tests')
        mdmArchiveMemberCount = @('mdmdiag-real-nonvacuous', 'mdmdiag-member-accounting', 'mdmdiag-record-provenance')
        mdmParsedEvtxMemberCount = @('mdmdiag-real-nonvacuous', 'mdmdiag-member-accounting', 'mdmdiag-record-provenance')
        mdmRecordCount = @('mdmdiag-real-nonvacuous', 'mdmdiag-record-provenance')
        folderChildErrorCount = @('folder-child-errors-visible', 'folder-child-errors-display-bound')
        remoteHandleBaseline = @('remote-handle-cleanup')
        remoteHandleAfter = @('remote-handle-cleanup')
        remoteHandleIterations = @('remote-handle-cleanup')
        coldLaunchRun1Milliseconds = @('performance-cold-window-launch')
        coldLaunchRun2Milliseconds = @('performance-cold-window-launch')
        coldLaunchRun3Milliseconds = @('performance-cold-window-launch')
        coldLaunchMilliseconds = @('performance-cold-window-launch')
        coldLaunchRun1PeakWorkingSetBytes = @('performance-cold-window-launch')
        coldLaunchRun2PeakWorkingSetBytes = @('performance-cold-window-launch')
        coldLaunchRun3PeakWorkingSetBytes = @('performance-cold-window-launch')
        coldLaunchPeakWorkingSetBytes = @('performance-cold-window-launch')
        firstRowRun1Milliseconds = @('performance-cold-first-visible-row')
        firstRowRun2Milliseconds = @('performance-cold-first-visible-row')
        firstRowRun3Milliseconds = @('performance-cold-first-visible-row')
        firstRowMilliseconds = @('performance-cold-first-visible-row')
        sevenDayChannelsScanned = @('performance-all-channels-seven-day')
        sevenDayChannelsFailed = @('performance-all-channels-seven-day')
        sevenDayChannelsWithGaps = @('performance-all-channels-seven-day')
        sevenDayGapEntries = @('performance-all-channels-seven-day')
        sevenDayAllChannelScanMilliseconds = @('performance-all-channels-seven-day')
        sevenDayAllChannelRecordCount = @('performance-all-channels-seven-day')
        sevenDayPeakWorkingSetBytes = @('performance-all-channels-seven-day')
        renderRecordCount = @('performance-100k-render')
        render100000Milliseconds = @('performance-100k-render')
        renderPeakWorkingSetBytes = @('performance-100k-render')
        intuneDescriptionResolutionMilliseconds = @('performance-intune-description-resolution')
        intunePeakWorkingSetBytes = @('performance-intune-description-resolution')
        intuneDescriptionsResolved = @('performance-intune-description-resolution')
        intuneDescriptionsMissing = @('performance-intune-description-resolution')
    }
    Assert-CMTraceSequence -Actual @($measurementGateMap.Keys | Sort-Object) -Expected @($measurementNames | Sort-Object) -Label 'manual measurement-to-gate map'
    foreach ($measurementName in $measurementNames) {
        foreach ($ownerId in $measurementGateMap[$measurementName]) {
            if (-not $byId.ContainsKey($ownerId)) {
                throw "Manual measurement $measurementName references an unknown owning gate: $ownerId."
            }
        }
    }
    foreach ($measurementName in $measurementNames) {
        if ($null -ne $Manual.measurements.$measurementName) {
            $hasExercisedOwner = @($measurementGateMap[$measurementName] | Where-Object {
                $byId[$_].status -in @('PASS', 'FAIL', 'BLOCKED')
            }).Count -gt 0
            if (-not $hasExercisedOwner) {
                throw "Manual measurement $measurementName must be null until an owning gate is exercised."
            }
        }
    }

    if ($byId['local-time-filter-strict'].status -eq 'PASS') {
        $wide = ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.localWideRecordCount -Label 'localWideRecordCount' -Positive
        $narrow = ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.localNarrowRecordCount -Label 'localNarrowRecordCount'
        if ($narrow -ge $wide) { throw 'PASS local-time-filter-strict requires narrow count below wide count.' }
    }
    if ($byId['local-level-filter-nonzero'].status -eq 'PASS' -and (ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.localLevelRecordCount -Label 'localLevelRecordCount' -Positive) -le 0) {
        throw 'PASS local-level-filter-nonzero requires a nonzero count.'
    }
    if ($byId['real-evtx-nonvacuous'].status -eq 'PASS' -and (ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.realEvtxTestsExecuted -Label 'realEvtxTestsExecuted') -ne 7) {
        throw 'PASS real-evtx-nonvacuous requires exactly seven executed tests.'
    }
    if ($byId['provider-retained-db-tests'].status -eq 'PASS' -and (ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.providerCount -Label 'providerCount' -Positive) -le 100) {
        throw 'PASS provider-retained-db-tests requires more than 100 providers.'
    }
    $passedMdmMemberGate = @(
        'mdmdiag-real-nonvacuous',
        'mdmdiag-member-accounting',
        'mdmdiag-record-provenance'
    ) | Where-Object { $byId[$_].status -eq 'PASS' } | Select-Object -First 1
    if ($null -ne $passedMdmMemberGate -or
        $null -ne $Manual.measurements.mdmArchiveMemberCount -or
        $null -ne $Manual.measurements.mdmParsedEvtxMemberCount) {
        $mdmArchiveMemberCount = ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.mdmArchiveMemberCount -Label 'mdmArchiveMemberCount' -Positive
        $mdmParsedEvtxMemberCount = ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.mdmParsedEvtxMemberCount -Label 'mdmParsedEvtxMemberCount' -Positive
        if ($mdmArchiveMemberCount -gt 512 -or $mdmParsedEvtxMemberCount -gt $mdmArchiveMemberCount) {
            throw 'MDMDiag evidence requires 1..512 archive members and parsed EVTX members no greater than the archive member count.'
        }
    }
    if ($byId['mdmdiag-real-nonvacuous'].status -eq 'PASS' -or
        $byId['mdmdiag-record-provenance'].status -eq 'PASS') {
        [void](ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.mdmRecordCount -Label 'mdmRecordCount' -Positive)
    }
    if ($byId['folder-child-errors-visible'].status -eq 'PASS' -and (ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.folderChildErrorCount -Label 'folderChildErrorCount' -Positive) -ne 5) {
        throw 'PASS folder-child-errors-visible requires the exact five-child bounded fixture.'
    }
    if ($byId['folder-child-errors-display-bound'].status -eq 'PASS' -and (ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.folderChildErrorCount -Label 'folderChildErrorCount' -Positive) -ne 5) {
        throw 'PASS folder-child-errors-display-bound requires the exact five-child bounded fixture.'
    }
    if ($byId['remote-handle-cleanup'].status -eq 'PASS') {
        $handleBaseline = ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.remoteHandleBaseline -Label 'remoteHandleBaseline'
        $handleAfter = ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.remoteHandleAfter -Label 'remoteHandleAfter'
        $handleIterations = ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.remoteHandleIterations -Label 'remoteHandleIterations' -Positive
        if ($handleIterations -lt 20 -or $handleAfter -gt $handleBaseline) {
            throw 'PASS remote-handle-cleanup requires at least 20 repetitions and no net handle increase.'
        }
    }
    if ($byId['performance-cold-window-launch'].status -eq 'PASS') {
        $coldLaunchRuns = @('coldLaunchRun1Milliseconds', 'coldLaunchRun2Milliseconds', 'coldLaunchRun3Milliseconds') | ForEach-Object {
            ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.$_ -Label $_ -Positive
        }
        $coldLaunchPeaks = @('coldLaunchRun1PeakWorkingSetBytes', 'coldLaunchRun2PeakWorkingSetBytes', 'coldLaunchRun3PeakWorkingSetBytes') | ForEach-Object {
            ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.$_ -Label $_ -Positive
        }
        $coldLaunchMedian = ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.coldLaunchMilliseconds -Label 'coldLaunchMilliseconds' -Positive
        $coldPeakMedian = ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.coldLaunchPeakWorkingSetBytes -Label 'coldLaunchPeakWorkingSetBytes' -Positive
        if ($coldLaunchMedian -ne @($coldLaunchRuns | Sort-Object)[1] -or
            $coldPeakMedian -ne @($coldLaunchPeaks | Sort-Object)[1]) {
            throw 'PASS performance-cold-window-launch requires exact medians from three positive run values and peaks.'
        }
    }
    if ($byId['performance-cold-first-visible-row'].status -eq 'PASS') {
        $firstRowRuns = @('firstRowRun1Milliseconds', 'firstRowRun2Milliseconds', 'firstRowRun3Milliseconds') | ForEach-Object {
            ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.$_ -Label $_ -Positive
        }
        $firstRowMedian = ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.firstRowMilliseconds -Label 'firstRowMilliseconds' -Positive
        if ($firstRowMedian -ne @($firstRowRuns | Sort-Object)[1]) {
            throw 'PASS performance-cold-first-visible-row requires the exact median from three positive run values.'
        }
    }
    if ($byId['performance-all-channels-seven-day'].status -eq 'PASS') {
        foreach ($name in @('sevenDayChannelsScanned', 'sevenDayAllChannelScanMilliseconds', 'sevenDayAllChannelRecordCount', 'sevenDayPeakWorkingSetBytes')) { [void](ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.$name -Label $name -Positive) }
        foreach ($name in @('sevenDayChannelsFailed', 'sevenDayChannelsWithGaps', 'sevenDayGapEntries')) {
            if ((ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.$name -Label $name) -ne 0) {
                throw "PASS performance-all-channels-seven-day requires $name to be zero."
            }
        }
    }
    if ($byId['performance-100k-render'].status -eq 'PASS') {
        foreach ($name in @('render100000Milliseconds', 'renderPeakWorkingSetBytes')) { [void](ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.$name -Label $name -Positive) }
        $renderCount = ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.renderRecordCount -Label 'renderRecordCount' -Positive
        if ($renderCount -lt 100000) { throw 'PASS performance-100k-render requires at least 100000 real records.' }
    }
    if ($byId['performance-intune-description-resolution'].status -eq 'PASS') {
        foreach ($name in @('intuneDescriptionResolutionMilliseconds', 'intunePeakWorkingSetBytes', 'intuneDescriptionsResolved')) { [void](ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.$name -Label $name -Positive) }
        [void](ConvertTo-CMTraceBoundedInteger -Value $Manual.measurements.intuneDescriptionsMissing -Label 'intuneDescriptionsMissing')
    }
    foreach ($surfaceGap in @('eventlog-filter-library-advanced-surface', 'eventlog-grouping-drag-pivot-surface', 'eventlog-filter-rule-color-surface')) {
        if ($byId[$surfaceGap].status -eq 'PASS') {
            throw "Exact-head source evidence establishes that $surfaceGap cannot be marked PASS."
        }
    }

    $requiredIncomplete = @($gates | Where-Object { $_.requiredForFullAcceptance -and $_.status -ne 'PASS' })
    $derived = if (@($gates | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { 'MANUAL_FAILED' } elseif ($requiredIncomplete.Count -eq 0) { 'MANUAL_COMPLETE' } else { 'MANUAL_INCOMPLETE' }
    Assert-CMTraceExactStringValue -Value $Manual.status -Expected $derived -Label 'manual status'
}

$isProductionReturn = -not [bool]$ContractOnly
$fullOutput = if ($isProductionReturn) { [IO.Path]::GetFullPath($OutputPath) } else { $null }
$outputParent = if ($isProductionReturn) { Split-Path -Parent $fullOutput } else { $null }
if ($isProductionReturn) {
    $outputName = [IO.Path]::GetFileName($fullOutput)
    if ($outputName -cnotmatch '^pr583-arm64-[0-9]{3}\.zip$') {
        throw 'Return bundle OutputPath basename must match pr583-arm64-NNN.zip.'
    }
    Assert-CMTraceWindows11Arm64
}

$resolvedEvidence = (Resolve-Path -LiteralPath $EvidenceRoot).Path
$resolvedRepository = $null
Assert-CMTraceNoReparsePath -Path $resolvedEvidence -Label 'EvidenceRoot'
if ($isProductionReturn) {
    if ([IO.Path]::GetExtension($fullOutput) -cne '.zip') {
        throw 'Return bundle OutputPath must end in .zip.'
    }
    if (Test-Path -LiteralPath $fullOutput -PathType Any) {
        throw "Return bundle already exists and will not be overwritten: $fullOutput"
    }
    if (Test-Path -LiteralPath "$fullOutput.sha256" -PathType Any) {
        throw "Return checksum already exists and will not be overwritten: $fullOutput.sha256"
    }
    if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
        throw "Return bundle parent must already exist: $outputParent"
    }
    if ((Test-CMTracePathWithin -Path $fullOutput -Root $resolvedEvidence) -or (Test-CMTracePathWithin -Path $resolvedEvidence -Root $fullOutput)) {
        throw 'Return bundle must be outside and disjoint from EvidenceRoot.'
    }
    Assert-CMTraceNoReparsePath -Path $fullOutput -Label 'OutputPath'
    $resolvedRepository = (Resolve-Path -LiteralPath $RepositoryPath).Path
    [void](Assert-CMTraceFixedLocalNtfsPath -Path $resolvedRepository -Label 'RepositoryPath' -ForbiddenRoots @($resolvedEvidence, (Get-CMTraceHandoffRoot)))
    [void](Assert-CMTraceFixedLocalNtfsPath -Path $resolvedEvidence -Label 'EvidenceRoot' -ForbiddenRoots @((Get-CMTraceHandoffRoot)))
    [void](Assert-CMTraceFixedLocalNtfsPath -Path $fullOutput -Label 'OutputPath' -ForbiddenRoots @($resolvedEvidence, $resolvedRepository, (Get-CMTraceHandoffRoot)) -MustNotExist)
    [void](Assert-CMTraceSourceIntegrity -RepositoryPath $resolvedRepository)
    [void](Assert-CMTraceLivePullRequest)
}

$expectedRootFiles = @('summary.json', 'machine.json', 'artifacts.json', 'manual-results.json')
$expectedRootDirectories = @('raw-logs', 'raw-artifacts', 'sanitized-logs')
$actualRootFiles = @(Get-ChildItem -LiteralPath $resolvedEvidence -File -Force | Select-Object -ExpandProperty Name | Sort-Object)
$actualRootDirectories = @(Get-ChildItem -LiteralPath $resolvedEvidence -Directory -Force | Select-Object -ExpandProperty Name | Sort-Object)
Assert-CMTraceSequence -Actual $actualRootFiles -Expected @($expectedRootFiles | Sort-Object) -Label 'evidence root files'
Assert-CMTraceSequence -Actual $actualRootDirectories -Expected @($expectedRootDirectories | Sort-Object) -Label 'evidence root directories'
foreach ($directory in $expectedRootDirectories) {
    Assert-CMTraceNoReparsePath -Path (Join-Path $resolvedEvidence $directory) -Label $directory
}

$privacyLiteralsPath = Join-Path $resolvedEvidence 'raw-logs/privacy-literals.json'
$privacyDocument = Read-CMTraceStrictJson -Path $privacyLiteralsPath -MaximumBytes 32768 -Label 'privacy-literals.json'
$privacyProperties = @('computerName', 'userName', 'userDomain', 'userDnsDomain', 'logonServer', 'userProfile', 'homePath', 'homeDrive', 'oneDrive', 'oneDriveCommercial', 'oneDriveConsumer', 'repositoryPath', 'evidencePath', 'handoffPath')
Assert-CMTraceExactPropertySet -Value $privacyDocument.Value -Names $privacyProperties -Label 'privacy-literals.json'
foreach ($property in $privacyDocument.Value.PSObject.Properties) {
    if ($null -ne $property.Value -and $property.Value -isnot [string]) {
        throw 'privacy-literals.json values must be strings or null.'
    }
}

$sanitizedRoot = Join-Path $resolvedEvidence 'sanitized-logs'
Assert-CMTraceNoReparsePath -Path $sanitizedRoot -Label 'sanitized-logs'
if (Get-ChildItem -LiteralPath $sanitizedRoot -Directory -Force) {
    throw 'sanitized-logs cannot contain nested directories.'
}
$expectedLogNames = @($script:CMTraceAutomaticGateIds | ForEach-Object { "$_.log" } | Sort-Object)
$sanitizedFiles = @(Get-ChildItem -LiteralPath $sanitizedRoot -File -Force | Sort-Object Name)
Assert-CMTraceSequence -Actual @($sanitizedFiles.Name) -Expected $expectedLogNames -Label 'sanitized log files'

$returnFiles = [System.Collections.Generic.List[object]]::new()
foreach ($name in $expectedRootFiles) {
    $source = Join-Path $resolvedEvidence $name
    $entry = Get-Item -LiteralPath $source -Force
    if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Required root evidence cannot be a reparse point: $name"
    }
    $returnFiles.Add([pscustomobject]@{ Source = $source; Relative = $name })
}
foreach ($file in $sanitizedFiles) {
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Sanitized log cannot be a reparse point: $($file.Name)"
    }
    $returnFiles.Add([pscustomobject]@{ Source = $file.FullName; Relative = "sanitized-logs/$($file.Name)" })
}

$inputRoot = if ($isProductionReturn) {
    Join-Path ([IO.Path]::GetPathRoot($resolvedRepository)) 'cmtraceopen-input'
}
else {
    $null
}
$temporaryBase = if ($isProductionReturn) {
    Assert-CMTraceSafeTemporaryRoot -ForbiddenRoots @(
        $resolvedEvidence,
        $resolvedRepository,
        $inputRoot,
        (Get-CMTraceHandoffRoot),
        $outputParent
    )
}
else {
    [IO.Path]::GetTempPath()
}
$stagingRoot = Join-Path $temporaryBase ("cmtraceopen-arm64-return-stage-{0}" -f [guid]::NewGuid().ToString('N'))
$verifyRoot = Join-Path $temporaryBase ("cmtraceopen-arm64-return-verify-{0}" -f [guid]::NewGuid().ToString('N'))
$publicationRoot = if ($isProductionReturn) {
    Join-Path $outputParent ('.cmtraceopen-return-publish-{0}' -f [guid]::NewGuid().ToString('N'))
}
else {
    $null
}
$stagingRootOwned = $false
$verifyRootOwned = $false
$publicationRootOwned = $false
if ($isProductionReturn) {
    foreach ($temporaryRoot in @($stagingRoot, $verifyRoot)) {
        [void](Assert-CMTraceFixedLocalNtfsPath -Path $temporaryRoot -Label 'Return temporary path' -ForbiddenRoots @(
            $resolvedEvidence,
            $resolvedRepository,
            $inputRoot,
            (Get-CMTraceHandoffRoot),
            $outputParent
        ) -MustNotExist)
    }
    [void](Assert-CMTraceFixedLocalNtfsPath -Path $publicationRoot -Label 'Return publication staging path' -ForbiddenRoots @(
        $resolvedEvidence,
        $resolvedRepository,
        $inputRoot,
        (Get-CMTraceHandoffRoot)
    ) -MustNotExist)
}
New-Item -ItemType Directory -Path $stagingRoot -ErrorAction Stop | Out-Null
$stagingRootOwned = $true
$returnFailure = $null
$cleanupFailureText = $null

try {
    foreach ($file in $returnFiles) {
        $destination = Join-Path $stagingRoot $file.Relative
        $destinationParent = Split-Path -Parent $destination
        if (-not (Test-Path -LiteralPath $destinationParent -PathType Container)) {
            New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null
        }
        Copy-Item -LiteralPath $file.Source -Destination $destination
    }

    $totalSanitizedBytes = 0L
    foreach ($file in @($returnFiles | Where-Object { $_.Relative.StartsWith('sanitized-logs/', [StringComparison]::Ordinal) })) {
        $totalSanitizedBytes += (Get-Item -LiteralPath (Join-Path $stagingRoot $file.Relative)).Length
        if ($totalSanitizedBytes -gt 16777216) {
            throw 'Sanitized logs exceed the 16 MiB aggregate return limit.'
        }
    }

    $summaryDocument = Read-CMTraceStrictJson -Path (Join-Path $stagingRoot 'summary.json') -MaximumBytes 1048576 -Label 'summary.json'
    $machineDocument = Read-CMTraceStrictJson -Path (Join-Path $stagingRoot 'machine.json') -MaximumBytes 32768 -Label 'machine.json'
    $artifactsDocument = Read-CMTraceStrictJson -Path (Join-Path $stagingRoot 'artifacts.json') -MaximumBytes 131072 -Label 'artifacts.json'
    $manualDocument = Read-CMTraceStrictJson -Path (Join-Path $stagingRoot 'manual-results.json') -MaximumBytes 524288 -Label 'manual-results.json'
    $templateDocument = Read-CMTraceStrictJson -Path (Join-Path (Get-CMTraceHandoffRoot) 'manual-results.template.json') -MaximumBytes 524288 -Label 'sealed manual template'

    $automaticGates = Assert-CMTraceSummaryContract -Summary $summaryDocument.Value -StagingRoot $stagingRoot -PrivateEvidenceRoot $resolvedEvidence
    Assert-CMTraceMachineContract -Machine $machineDocument.Value
    $artifactHashes = Assert-CMTraceArtifactsContract -Artifacts $artifactsDocument.Value -AutomaticGates $automaticGates -PrivateEvidenceRoot $resolvedEvidence
    Assert-CMTraceManualContract -Manual $manualDocument.Value -Template $templateDocument.Value -SummaryPath (Join-Path $stagingRoot 'summary.json') -ArtifactsPath (Join-Path $stagingRoot 'artifacts.json') -ArtifactHashes $artifactHashes -PrivateEvidenceRoot $resolvedEvidence

    foreach ($candidate in @($returnFiles | ForEach-Object { Join-Path $stagingRoot $_.Relative })) {
        $relative = Get-CMTraceRelativePath -Root $stagingRoot -Path $candidate
        $text = Read-CMTraceStrictUtf8Text -Path $candidate -MaximumBytes 1048576
        $privacyScanText = if ($relative -ceq 'machine.json') {
            Get-CMTraceMachinePrivacyScanText -Machine $machineDocument.Value
        }
        else {
            $text
        }
        Assert-CMTracePrivacySafeText -Text $privacyScanText -Label $relative
        if ($relative.StartsWith('sanitized-logs/', [StringComparison]::Ordinal)) {
            $privateLiteralScanText = [regex]::Replace(
                $text,
                '\Agate=[a-z0-9][a-z0-9-]{0,63}\r?\nstatus=(?:passed|failed|blocked)(?:\r?\n|\z)',
                '',
                1
            )
            $privateLiteralScanText = Get-CMTracePrivateLiteralScanText -SanitizedGateBody $privateLiteralScanText
            Assert-CMTracePrivateLiteralsAbsent -Text $privateLiteralScanText -PrivacyLiterals $privacyDocument.Value -Label $relative
        }
    }
    Assert-CMTracePrivateLiteralsAbsent -Text ([string]$machineDocument.Value.cpuClass) -PrivacyLiterals $privacyDocument.Value -Label 'machine.json cpuClass' -StrictSubstring
    foreach ($gate in @($manualDocument.Value.gates | Where-Object { $null -ne $_.evidenceId })) {
        Assert-CMTracePrivateLiteralsAbsent -Text ([string]$gate.evidenceId) -PrivacyLiterals $privacyDocument.Value -Label "manual-results.json evidenceId for $($gate.id)" -StrictSubstring
    }
    $checksumRelativePaths = @(Get-CMTraceOrdinalSortedString -Value @(
        Get-ChildItem -LiteralPath $stagingRoot -File -Recurse |
            ForEach-Object { Get-CMTraceRelativePath -Root $stagingRoot -Path $_.FullName }
    ))
    $checksumLines = @($checksumRelativePaths | ForEach-Object {
        "$(Get-CMTraceSha256 -Path (Join-Path $stagingRoot $_))  $_"
    })
    Set-Content -LiteralPath (Join-Path $stagingRoot 'SHA256SUMS.txt') -Value $checksumLines -Encoding ascii
    [void](Assert-CMTraceChecksumInventory -Root $stagingRoot -Context 'Staged return')
    $stagedChecksumSha256 = Get-CMTraceSha256 -Path (Join-Path $stagingRoot 'SHA256SUMS.txt')
    $expectedArchiveFiles = @(Get-CMTraceOrdinalSortedString -Value @(
        $checksumRelativePaths + 'SHA256SUMS.txt'
    ))

    if ($isProductionReturn) {
        [void](Assert-CMTraceSourceIntegrity -RepositoryPath $resolvedRepository)
        [void](Assert-CMTraceLivePullRequest)

        New-Item -ItemType Directory -Path $publicationRoot -ErrorAction Stop | Out-Null
        $publicationRootOwned = $true
        Assert-CMTraceNoReparsePath -Path $publicationRoot -Label 'Return publication staging path'
        $archiveCandidate = Join-Path $publicationRoot 'return.zip'
        $sidecarCandidate = Join-Path $publicationRoot 'return.zip.sha256'
        $fixedZipTimestamp = New-CMTraceDeterministicZip -SourceRoot $stagingRoot -DestinationPath $archiveCandidate
        $outerHash = Get-CMTraceSha256 -Path $archiveCandidate
        Assert-CMTraceNoReparsePath -Path $archiveCandidate -Label 'Return ZIP candidate'
        Assert-CMTraceReturnZipContract -Path $archiveCandidate -FixedTimestamp $fixedZipTimestamp `
            -ExpectedFiles $expectedArchiveFiles

        New-Item -ItemType Directory -Path $verifyRoot -ErrorAction Stop | Out-Null
        $verifyRootOwned = $true
        Expand-Archive -LiteralPath $archiveCandidate -DestinationPath $verifyRoot
        $verifiedFiles = @(Get-CMTraceOrdinalSortedString -Value @(
            Get-ChildItem -LiteralPath $verifyRoot -File -Recurse |
                ForEach-Object { Get-CMTraceRelativePath -Root $verifyRoot -Path $_.FullName }
        ))
        Assert-CMTraceSequence -Actual $verifiedFiles -Expected $expectedArchiveFiles -Label 'freshly extracted return inventory'
        if ((Get-CMTraceSha256 -Path (Join-Path $verifyRoot 'SHA256SUMS.txt')) -cne $stagedChecksumSha256) {
            throw 'Freshly extracted return checksum manifest does not match the validated staged manifest.'
        }
        [void](Assert-CMTraceChecksumInventory -Root $verifyRoot -Context 'Freshly extracted return')
        if ((Get-CMTraceSha256 -Path $archiveCandidate) -cne $outerHash) {
            throw 'Return ZIP candidate changed during fresh-extraction verification.'
        }

        [void](Assert-CMTraceSourceIntegrity -RepositoryPath $resolvedRepository)
        [void](Assert-CMTraceLivePullRequest)

        $sidecarOwnedText = "$outerHash  $([IO.Path]::GetFileName($fullOutput))$([Environment]::NewLine)"
        Write-CMTraceNewText -Text $sidecarOwnedText -Path $sidecarCandidate -Encoding ascii
        if ((Get-CMTraceSha256 -Path $archiveCandidate) -cne $outerHash) {
            throw 'Return ZIP candidate changed before publication.'
        }

        [IO.File]::Move($archiveCandidate, $fullOutput, $false)
        Assert-CMTraceNoReparsePath -Path $fullOutput -Label 'Published return ZIP'
        if ((Get-CMTraceSha256 -Path $fullOutput) -cne $outerHash) {
            throw 'Published return ZIP does not match the validated candidate.'
        }
        [IO.File]::Move($sidecarCandidate, "$fullOutput.sha256", $false)
        # The sidecar move creates a new replacement interval. Recheck the ZIP
        # namespace before the final paired-content readback.
        Assert-CMTraceNoReparsePath -Path $fullOutput -Label 'Published return ZIP'
        Assert-CMTraceNoReparsePath -Path "$fullOutput.sha256" -Label 'Published return checksum'
        if ((Get-CMTraceSha256 -Path $fullOutput) -cne $outerHash -or
            [IO.File]::ReadAllText("$fullOutput.sha256", [Text.Encoding]::ASCII) -cne $sidecarOwnedText) {
            throw 'Published return ZIP or checksum changed during final publication.'
        }
    }
}
catch {
    $returnFailure = $_
}
finally {
    $cleanupFailures = [System.Collections.Generic.List[string]]::new()
    foreach ($temporary in @(
        [pscustomobject]@{ Path = $stagingRoot; Owned = $stagingRootOwned; Parent = $temporaryBase }
        [pscustomobject]@{ Path = $verifyRoot; Owned = $verifyRootOwned; Parent = $temporaryBase }
        [pscustomobject]@{ Path = $publicationRoot; Owned = $publicationRootOwned; Parent = $outputParent }
    )) {
        if (-not $temporary.Owned) {
            continue
        }
        try {
            if (Test-Path -LiteralPath $temporary.Path -PathType Container) {
                $fullTemporary = [IO.Path]::GetFullPath($temporary.Path)
                $allowedPrefix = [IO.Path]::GetFullPath($temporary.Parent).TrimEnd([char]'\', [char]'/') + [IO.Path]::DirectorySeparatorChar
                $rootEntry = Get-Item -LiteralPath $fullTemporary -Force
                $reparseDescendants = @(Get-ChildItem -LiteralPath $fullTemporary -Recurse -Force | Where-Object {
                    ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
                })
                if (-not $fullTemporary.StartsWith($allowedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
                    ($rootEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                    $reparseDescendants.Count -gt 0) {
                    throw "unsafe owned temporary path $fullTemporary"
                }
                else {
                    Remove-Item -LiteralPath $fullTemporary -Recurse -Force
                }
            }
        }
        catch {
            $cleanupFailures.Add("$($temporary.Path): $($_.Exception.Message)")
        }
    }
    if ($cleanupFailures.Count -gt 0) {
        $cleanupFailureText = $cleanupFailures -join '; '
    }
}

if ($null -ne $returnFailure -and $null -ne $cleanupFailureText) {
    $aggregateMessage = "Primary return failure: $($returnFailure.Exception.Message) Cleanup also failed: $cleanupFailureText"
    $cleanupException = [InvalidOperationException]::new("Return temporary cleanup failed: $cleanupFailureText")
    throw [AggregateException]::new($aggregateMessage, [Exception[]]@($returnFailure.Exception, $cleanupException))
}
elseif ($null -ne $returnFailure) {
    throw $returnFailure
}
elseif ($null -ne $cleanupFailureText) {
    throw "Return temporary cleanup failed: $cleanupFailureText"
}

if ($isProductionReturn) {
    Write-Output "RETURN_BUNDLE_OK $fullOutput"
}
else {
    Write-Output 'RETURN_CONTRACT_OK'
}
