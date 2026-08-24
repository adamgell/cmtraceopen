Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-CMTraceSymbolicLinkSupport {
    $probeRoot = Join-Path ([IO.Path]::GetTempPath()) ("cmtraceopen-symlink-probe-{0}" -f [guid]::NewGuid().ToString('N'))
    try {
        New-Item -ItemType Directory -Path $probeRoot | Out-Null
        $target = Join-Path $probeRoot 'target.txt'
        $link = Join-Path $probeRoot 'link.txt'
        Set-Content -LiteralPath $target -Value 'probe' -Encoding ascii
        New-Item -ItemType SymbolicLink -Path $link -Target $target -ErrorAction Stop | Out-Null
        return Test-Path -LiteralPath $link -PathType Leaf
    }
    catch {
        return $false
    }
    finally {
        if (Test-Path -LiteralPath $probeRoot -PathType Container) {
            Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

$script:CMTraceSymbolicLinkSupported = Test-CMTraceSymbolicLinkSupport

BeforeAll {
    $script:HandoffRoot = Split-Path -Parent $PSScriptRoot
    $script:ScriptsRoot = Join-Path $script:HandoffRoot 'scripts'
    $script:PwshPath = Join-Path $PSHOME $(if ($IsWindows) { 'pwsh.exe' } else { 'pwsh' })
    . (Join-Path $script:ScriptsRoot 'CMTraceOpenArm64Handoff.Common.ps1')

    function Invoke-HandoffScript {
        param([Parameter(Mandatory = $true)][string]$Path, [string[]]$Arguments = @())
        $output = & $script:PwshPath -NoLogo -NoProfile -NonInteractive -File $Path @Arguments 2>&1 | Out-String
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
    }

    function Invoke-ReturnContractValidation {
        param([Parameter(Mandatory = $true)][string]$EvidenceRoot)
        return Invoke-HandoffScript -Path (Join-Path $script:ScriptsRoot 'New-CMTraceOpenArm64ValidationReturn.ps1') -Arguments @(
            '-EvidenceRoot', $EvidenceRoot,
            '-ContractOnly'
        )
    }

    function Write-TestJson {
        param([object]$Value, [string]$Path)
        $Value | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $Path -Encoding utf8NoBOM
    }

    function Get-PowerShellFunctionBodyText {
        param(
            [Parameter(Mandatory = $true)]
            [object[]]$Ast,

            [Parameter(Mandatory = $true)]
            [string]$Name,

            [Parameter(Mandatory = $true)]
            [string]$SourceLabel
        )

        $definitions = [Collections.Generic.List[object]]::new()
        foreach ($root in $Ast) {
            foreach ($definition in @($root.FindAll({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $Name
            }, $true))) {
                $definitions.Add($definition)
            }
        }
        if ($definitions.Count -ne 1) {
            throw "Expected exactly one PowerShell function named $Name in $SourceLabel."
        }
        $body = $definitions[0].Body.Extent.Text
        return $body.Substring(1, $body.Length - 2)
    }

    function Get-DocumentedPowerShellFunctionText {
        param(
            [Parameter(Mandatory = $true)]
            [string]$DocumentPath,

            [Parameter(Mandatory = $true)]
            [string]$Name
        )

        $document = Get-Content -LiteralPath $DocumentPath -Raw
        $blocks = @([regex]::Matches(
            $document,
            '(?ms)^```powershell\s*\r?\n(?<code>.*?)^```\s*$',
            [Text.RegularExpressions.RegexOptions]::CultureInvariant
        ))
        if ($blocks.Count -eq 0) {
            throw "Cannot extract $Name because $DocumentPath contains no PowerShell code fence."
        }
        $asts = [Collections.Generic.List[object]]::new()
        foreach ($block in $blocks) {
            $tokens = $null
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseInput(
                $block.Groups['code'].Value,
                [ref]$tokens,
                [ref]$errors
            )
            if (@($errors).Count -ne 0) {
                throw "Cannot extract $Name because a PowerShell code fence in $DocumentPath does not parse."
            }
            $asts.Add($ast)
        }
        return Get-PowerShellFunctionBodyText -Ast $asts.ToArray() -Name $Name -SourceLabel $DocumentPath
    }

    function Get-ScriptPowerShellFunctionText {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ScriptPath,

            [Parameter(Mandatory = $true)]
            [string]$Name
        )

        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile(
            $ScriptPath,
            [ref]$tokens,
            [ref]$errors
        )
        if (@($errors).Count -ne 0) {
            throw "Cannot extract $Name because $ScriptPath does not parse."
        }
        return Get-PowerShellFunctionBodyText -Ast @($ast) -Name $Name -SourceLabel $ScriptPath
    }

    function Get-OrderedTextMarkerIndex {
        param(
            [Parameter(Mandatory = $true)][string]$Text,
            [Parameter(Mandatory = $true)][string]$Marker,
            [ValidateRange(-1, [int]::MaxValue)][int]$AfterIndex = -1
        )

        $index = $Text.IndexOf($Marker, ($AfterIndex + 1), [StringComparison]::Ordinal)
        if ($index -lt 0) {
            throw "Required ordered text marker is missing: $Marker"
        }
        return $index
    }

    function Write-EvidenceFixture {
        param([Parameter(Mandatory = $true)][string]$Root)

        New-Item -ItemType Directory -Force -Path (Join-Path $Root 'raw-logs'), (Join-Path $Root 'raw-artifacts'), (Join-Path $Root 'sanitized-logs') | Out-Null
        $privacy = [ordered]@{
            computerName = 'PRIVATE-LAB-PC'
            userName = 'PrivateLabUser'
            userDomain = 'PRIVATEWORKGROUP'
            userDnsDomain = $null
            logonServer = $null
            userProfile = 'C:\Users\PrivateLabUser'
            homePath = '\Users\PrivateLabUser'
            homeDrive = 'C:'
            oneDrive = $null
            oneDriveCommercial = $null
            oneDriveConsumer = $null
            repositoryPath = 'C:\private\source'
            evidencePath = 'C:\private\evidence'
            handoffPath = 'C:\private\handoff'
        }
        Write-TestJson -Value $privacy -Path (Join-Path $Root 'raw-logs/privacy-literals.json')

        $timestamp = '2026-08-23T16:00:00.0000000Z'
        $gates = [System.Collections.Generic.List[object]]::new()
        foreach ($id in $script:CMTraceAutomaticGateIds) {
            $rawLogPath = Join-Path $Root "raw-logs/$id.log"
            Set-Content -LiteralPath $rawLogPath -Value "gate=$id`nstatus=passed`nprivateResult=bounded-test-evidence" -Encoding utf8NoBOM
            $logPath = Join-Path $Root "sanitized-logs/$id.log"
            Set-Content -LiteralPath $logPath -Value "gate=$id`nstatus=passed`nresult=bounded-test-evidence" -Encoding utf8NoBOM
            $command = if ($id -in @('source-integrity', 'arm64-pe-verification', 'source-clean-after')) {
                '<internal handoff gate>'
            }
            elseif ($id -in @('installer-pester', 'collector-pester')) {
                'pwsh -EncodedCommand <redacted>'
            }
            else {
                "gate:$id"
            }
            $gates.Add([ordered]@{
                id = $id
                class = $script:CMTraceAutomaticGateContracts[$id].class
                status = 'passed'
                exitCode = 0
                startedAtUtc = $timestamp
                durationMilliseconds = 1
                command = $command
                rawLogSha256 = Get-CMTraceSha256 -Path $rawLogPath
                sanitizedLog = "sanitized-logs/$id.log"
                sanitizedLogSha256 = Get-CMTraceSha256 -Path $logPath
                blockedBy = @()
            })
        }
        $summary = [ordered]@{
            schemaVersion = 1
            handoffId = $script:CMTraceHandoffId
            sourceCommit = $script:CMTraceExpectedSourceCommit
            sourceTree = $script:CMTraceExpectedSourceTree
            target = $script:CMTraceRustTarget
            startedAtUtc = $timestamp
            completedAtUtc = '2026-08-23T16:01:00.0000000Z'
            automaticStatus = 'PASSED'
            gates = @($gates)
            rawEvidenceReturned = $false
        }
        Write-TestJson -Value $summary -Path (Join-Path $Root 'summary.json')

        $machine = [ordered]@{
            schemaVersion = 2
            handoffId = $script:CMTraceHandoffId
            sourceCommit = $script:CMTraceExpectedSourceCommit
            sourceTree = $script:CMTraceExpectedSourceTree
            target = $script:CMTraceRustTarget
            os = 'Windows 11'
            osVersion = '10.0.26100.0'
            osBuild = 26100
            osArchitecture = 'Arm64'
            processArchitecture = 'Arm64'
            processorArchitecture = 'ARM64'
            logicalProcessorCount = 12
            cpuClass = 'Qualcomm ARM64 validation class'
            physicalMemoryBytes = 17179869184
            powerShellVersion = '7.6.5'
            gitVersion = '2.51.0.windows.1'
            nodeVersion = 'v22.18.0'
            nodeArchitecture = 'arm64'
            npmVersion = '11.6.2'
            rustVersion = 'rustc 1.89.0'
            rustHost = $script:CMTraceRustTarget
            pesterVersion = '5.7.1'
            cargoDenyVersion = '0.19.0'
            cargoAuditVersion = '0.22.2'
            clangVersion = '21.1.8'
            visualStudioVersion = '17.14.36310.24'
            windowsSdkVersion = '10.0.26100.0'
            webView2Version = '139.0.3405.86'
            sourceVolumeFileSystem = 'NTFS'
            sourceVolumeDriveType = 'Fixed'
            sourceOutsideKnownSyncRoots = $true
            identityFieldsIntentionallyOmitted = @('computerName', 'userName', 'domain', 'deviceId', 'tenantId', 'ipAddress')
        }
        Write-TestJson -Value $machine -Path (Join-Path $Root 'machine.json')

        $fullArtifact = Join-Path $Root 'raw-artifacts/full/cmtrace-open.exe'
        $liteArtifact = Join-Path $Root 'raw-artifacts/lite/cmtrace-open.exe'
        $nsisArtifact = Join-Path $Root 'raw-artifacts/nsis/cmtrace-open-setup.exe'
        $provenancePath = Join-Path $Root 'raw-artifacts/provenance/windows-build-provenance.json'
        foreach ($artifactPath in @($fullArtifact, $liteArtifact, $nsisArtifact, $provenancePath)) {
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $artifactPath) | Out-Null
        }
        [IO.File]::WriteAllBytes($fullArtifact, [byte[]]@(0x4D, 0x5A, 0x64, 0x75, 0x6D, 0x6D, 0x79, 0x01))
        [IO.File]::WriteAllBytes($liteArtifact, [byte[]]@(0x4D, 0x5A, 0x64, 0x75, 0x6D, 0x6D, 0x79, 0x02))
        [IO.File]::WriteAllBytes($nsisArtifact, [byte[]]@(0x4D, 0x5A, 0x64, 0x75, 0x6D, 0x6D, 0x79, 0x03))
        $fullHash = Get-CMTraceSha256 -Path $fullArtifact
        $liteHash = Get-CMTraceSha256 -Path $liteArtifact
        $nsisHash = Get-CMTraceSha256 -Path $nsisArtifact
        $installedBytes = [byte[]]@(0x4D, 0x5A, 0x64, 0x75, 0x6D, 0x6D, 0x79, 0x04)
        $installedHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($installedBytes)).ToLowerInvariant()
        $provenance = [ordered]@{
            schemaVersion = 2
            sourceCommit = $script:CMTraceExpectedSourceCommit
            buildCommit = $script:CMTraceExpectedSourceCommit
            target = $script:CMTraceRustTarget
            packageVersion = '1.5.1'
            releaseExecutable = [ordered]@{
                path = 'cmtrace-open.exe'
                bytes = (Get-Item -LiteralPath $fullArtifact).Length
                sha256 = $fullHash
            }
            installers = @([ordered]@{
                path = 'nsis/CMTrace Open_1.5.1_arm64-setup.exe'
                bytes = (Get-Item -LiteralPath $nsisArtifact).Length
                sha256 = $nsisHash
                bundleType = 'nsis'
                expectedInstalledExecutable = [ordered]@{
                    path = 'cmtrace-open.exe'
                    bytes = $installedBytes.Length
                    sha256 = $installedHash
                    derivation = 'tauriBundleTypeMarkerV1'
                }
            })
        }
        Write-TestJson -Value $provenance -Path $provenancePath
        $provenanceHash = Get-CMTraceSha256 -Path $provenancePath
        $artifacts = [ordered]@{
            schemaVersion = 1
            handoffId = $script:CMTraceHandoffId
            sourceCommit = $script:CMTraceExpectedSourceCommit
            sourceTree = $script:CMTraceExpectedSourceTree
            target = $script:CMTraceRustTarget
            items = @(
                [ordered]@{ kind = 'full-portable'; bytes = (Get-Item -LiteralPath $fullArtifact).Length; sha256 = $fullHash; peMachine = '0xAA64'; architecture = 'arm64'; authenticodeStatus = 'NotSigned' },
                [ordered]@{ kind = 'lite-portable'; bytes = (Get-Item -LiteralPath $liteArtifact).Length; sha256 = $liteHash; peMachine = '0xAA64'; architecture = 'arm64'; authenticodeStatus = 'NotSigned' },
                [ordered]@{ kind = 'nsis-installer'; bytes = (Get-Item -LiteralPath $nsisArtifact).Length; sha256 = $nsisHash; peMachine = '0x014C'; architecture = 'x86-bootstrapper'; authenticodeStatus = 'NotSigned' },
                [ordered]@{
                    kind = 'windows-build-provenance'
                    schemaVersion = $provenance.schemaVersion
                    sourceCommit = $provenance.sourceCommit
                    buildCommit = $provenance.buildCommit
                    target = $provenance.target
                    packageVersion = $provenance.packageVersion
                    releaseExecutable = $provenance.releaseExecutable
                    installers = $provenance.installers
                    manifestSha256 = $provenanceHash
                }
            )
        }
        Write-TestJson -Value $artifacts -Path (Join-Path $Root 'artifacts.json')

        $manual = Get-Content -LiteralPath (Join-Path $script:HandoffRoot 'manual-results.template.json') -Raw | ConvertFrom-Json
        $manual.automaticSummarySha256 = Get-CMTraceSha256 -Path (Join-Path $Root 'summary.json')
        $manual.artifactsSha256 = Get-CMTraceSha256 -Path (Join-Path $Root 'artifacts.json')
        Write-TestJson -Value $manual -Path (Join-Path $Root 'manual-results.json')
    }

    function Write-ManualBinding {
        param([string]$Root)
        $path = Join-Path $Root 'manual-results.json'
        $manual = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $manual.automaticSummarySha256 = Get-CMTraceSha256 -Path (Join-Path $Root 'summary.json')
        $manual.artifactsSha256 = Get-CMTraceSha256 -Path (Join-Path $Root 'artifacts.json')
        Write-TestJson -Value $manual -Path $path
    }

    function Write-ManualEvidenceProof {
        param([string]$Root, [string]$EvidenceId)
        $proofRoot = Join-Path $Root 'raw-artifacts/manual-evidence'
        New-Item -ItemType Directory -Force -Path $proofRoot | Out-Null
        $proofPath = Join-Path $proofRoot "$EvidenceId.proof"
        Set-Content -LiteralPath $proofPath -Value "evidence=$EvidenceId`nresult=bounded-target-local-proof" -Encoding utf8NoBOM
        return Get-CMTraceSha256 -Path $proofPath
    }

    function Write-SummaryLogHash {
        param([string]$Root, [string]$GateId)
        $summaryPath = Join-Path $Root 'summary.json'
        $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
        $gate = @($summary.gates | Where-Object { $_.id -eq $GateId })[0]
        $gate.sanitizedLogSha256 = Get-CMTraceSha256 -Path (Join-Path $Root "sanitized-logs/$GateId.log")
        Write-TestJson -Value $summary -Path $summaryPath
        Write-ManualBinding -Root $Root
    }

    function Write-PackageChecksum {
        param([string]$Root, [string]$RelativePath)
        $checksumPath = Join-Path $Root 'SHA256SUMS.txt'
        $hash = (Get-FileHash -LiteralPath (Join-Path $Root $RelativePath) -Algorithm SHA256).Hash.ToLowerInvariant()
        $lines = Get-Content -LiteralPath $checksumPath | ForEach-Object {
            if ($_ -match '^([0-9a-fA-F]{64})  (.+)$' -and $Matches[2] -eq $RelativePath) { "$hash  $RelativePath" } else { $_ }
        }
        Set-Content -LiteralPath $checksumPath -Value $lines -Encoding ascii
    }
}

Describe 'sealed handoff integrity' {
    It 'accepts the untouched package and rejects a changed payload file' {
        $verifier = Join-Path $script:ScriptsRoot 'Test-CMTraceOpenArm64Handoff.ps1'
        $valid = Invoke-HandoffScript -Path $verifier -Arguments @('-HandoffRoot', $script:HandoffRoot)
        $valid.ExitCode | Should -Be 0 -Because $valid.Output
        $valid.Output | Should -Match 'HANDOFF_INTEGRITY_OK'

        $copyRoot = Join-Path $TestDrive 'handoff-copy'
        Copy-Item -LiteralPath $script:HandoffRoot -Destination $copyRoot -Recurse
        Add-Content -LiteralPath (Join-Path $copyRoot 'README.md') -Value 'unexpected mutation'
        $changed = Invoke-HandoffScript -Path (Join-Path $copyRoot 'scripts/Test-CMTraceOpenArm64Handoff.ps1') -Arguments @('-HandoffRoot', $copyRoot)
        $changed.ExitCode | Should -Not -Be 0
        $changed.Output | Should -Match 'checksum mismatch'
    }

    It 'rejects missing, unexpected, traversal, and case-colliding inventory entries' {
        $verifierName = 'scripts/Test-CMTraceOpenArm64Handoff.ps1'
        $missingRoot = Join-Path $TestDrive 'missing-file'
        Copy-Item -LiteralPath $script:HandoffRoot -Destination $missingRoot -Recurse
        Remove-Item -LiteralPath (Join-Path $missingRoot 'README.md')
        (Invoke-HandoffScript -Path (Join-Path $missingRoot $verifierName) -Arguments @('-HandoffRoot', $missingRoot)).Output | Should -Match 'inventory'

        $extraRoot = Join-Path $TestDrive 'extra-file'
        Copy-Item -LiteralPath $script:HandoffRoot -Destination $extraRoot -Recurse
        Set-Content -LiteralPath (Join-Path $extraRoot 'unexpected.txt') -Value 'not checksummed'
        (Invoke-HandoffScript -Path (Join-Path $extraRoot $verifierName) -Arguments @('-HandoffRoot', $extraRoot)).Output | Should -Match 'inventory'

        $traversalRoot = Join-Path $TestDrive 'traversal'
        Copy-Item -LiteralPath $script:HandoffRoot -Destination $traversalRoot -Recurse
        $checksumPath = Join-Path $traversalRoot 'SHA256SUMS.txt'
        $lines = @(Get-Content -LiteralPath $checksumPath)
        $lines[0] = $lines[0] -replace '  .+$', '  ../escape'
        Set-Content -LiteralPath $checksumPath -Value $lines -Encoding ascii
        (Invoke-HandoffScript -Path (Join-Path $traversalRoot $verifierName) -Arguments @('-HandoffRoot', $traversalRoot)).Output | Should -Match 'Unsafe checksum path'

        $duplicateRoot = Join-Path $TestDrive 'duplicate'
        Copy-Item -LiteralPath $script:HandoffRoot -Destination $duplicateRoot -Recurse
        $readmeLine = Get-Content -LiteralPath (Join-Path $duplicateRoot 'SHA256SUMS.txt') | Where-Object { $_ -match '  README\.md$' }
        Add-Content -LiteralPath (Join-Path $duplicateRoot 'SHA256SUMS.txt') -Value ($readmeLine -replace 'README\.md$', 'readme.md')
        (Invoke-HandoffScript -Path (Join-Path $duplicateRoot $verifierName) -Arguments @('-HandoffRoot', $duplicateRoot)).Output | Should -Match 'Duplicate checksum path'
    }

    It 'rejects an unexpected empty directory outside the checksummed inventory' {
        $copyRoot = Join-Path $TestDrive 'unexpected-empty-directory'
        Copy-Item -LiteralPath $script:HandoffRoot -Destination $copyRoot -Recurse
        New-Item -ItemType Directory -Path (Join-Path $copyRoot 'not-in-sealed-inventory') | Out-Null

        $result = Invoke-HandoffScript -Path (Join-Path $copyRoot 'scripts/Test-CMTraceOpenArm64Handoff.ps1') -Arguments @(
            '-HandoffRoot', $copyRoot
        )
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'directory inventory'
    }

    It 'rejects reparse payloads' -Skip:(-not $script:CMTraceSymbolicLinkSupported) {
        $verifierName = 'scripts/Test-CMTraceOpenArm64Handoff.ps1'
        $linkRoot = Join-Path $TestDrive 'reparse'
        Copy-Item -LiteralPath $script:HandoffRoot -Destination $linkRoot -Recurse
        Remove-Item -LiteralPath (Join-Path $linkRoot 'README.md')
        New-Item -ItemType SymbolicLink -Path (Join-Path $linkRoot 'README.md') -Target (Join-Path $script:HandoffRoot 'README.md') | Out-Null
        (Invoke-HandoffScript -Path (Join-Path $linkRoot $verifierName) -Arguments @('-HandoffRoot', $linkRoot)).Output | Should -Match 'reparse'
    }

    It 'rejects a handoff reached through a reparse ancestor' -Skip:(-not $script:CMTraceSymbolicLinkSupported) {
        $physicalParent = Join-Path $TestDrive 'physical-parent'
        $physicalRoot = Join-Path $physicalParent 'package'
        New-Item -ItemType Directory -Path $physicalParent | Out-Null
        Copy-Item -LiteralPath $script:HandoffRoot -Destination $physicalRoot -Recurse
        $linkedParent = Join-Path $TestDrive 'linked-parent'
        New-Item -ItemType SymbolicLink -Path $linkedParent -Target $physicalParent | Out-Null

        { Assert-CMTraceHandoffIntegrity -HandoffRoot (Join-Path $linkedParent 'package') } |
            Should -Throw '*reparse*'
    }

    It 'rejects changed coordinates and an extra signer key' {
        $verifierName = 'scripts/Test-CMTraceOpenArm64Handoff.ps1'
        $manifestRoot = Join-Path $TestDrive 'bad-manifest'
        Copy-Item -LiteralPath $script:HandoffRoot -Destination $manifestRoot -Recurse
        $manifestPath = Join-Path $manifestRoot 'MANIFEST.json'
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $manifest.validationTarget.sourceCommit = '39ee0b4f'
        Write-TestJson -Value $manifest -Path $manifestPath
        Write-PackageChecksum -Root $manifestRoot -RelativePath 'MANIFEST.json'
        (Invoke-HandoffScript -Path (Join-Path $manifestRoot $verifierName) -Arguments @('-HandoffRoot', $manifestRoot)).Output | Should -Match 'sourceCommit'

        $signerRoot = Join-Path $TestDrive 'extra-signer'
        Copy-Item -LiteralPath $script:HandoffRoot -Destination $signerRoot -Recurse
        Add-Content -LiteralPath (Join-Path $signerRoot 'PUBLIC_ALLOWED_SIGNERS') -Value 'extra@example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnlyPublicMaterial'
        Write-PackageChecksum -Root $signerRoot -RelativePath 'PUBLIC_ALLOWED_SIGNERS'
        (Invoke-HandoffScript -Path (Join-Path $signerRoot $verifierName) -Arguments @('-HandoffRoot', $signerRoot)).Output | Should -Match 'only the sealed public'
    }

    It 'accepts only Int32 and Int64 manifest integer coordinates' {
        $script:typedManifestJson = Get-Content -LiteralPath (Join-Path $script:HandoffRoot 'MANIFEST.json') -Raw
        $script:realConvertFromJson = Get-Command Microsoft.PowerShell.Utility\ConvertFrom-Json
        $baseManifest = $script:typedManifestJson | & $script:realConvertFromJson
        Mock -CommandName ConvertFrom-Json -MockWith {
            $InputObject | & $script:realConvertFromJson
        }
        Mock -CommandName ConvertFrom-Json -ParameterFilter {
            $InputObject -is [string] -and $InputObject -ceq $script:typedManifestJson
        } -MockWith { return $script:typedManifest }
        ('{"probe":1}' | ConvertFrom-Json).probe | Should -Be 1

        foreach ($case in @(
            [pscustomobject]@{ Schema = [int32]1; PullRequest = [int32]583; Throws = $false },
            [pscustomobject]@{ Schema = [int64]1; PullRequest = [int64]583; Throws = $false },
            [pscustomobject]@{ Schema = [double]1; PullRequest = [int64]583; Throws = $true },
            [pscustomobject]@{ Schema = [int64]1; PullRequest = [double]583; Throws = $true }
        )) {
            $script:typedManifest = $baseManifest.PSObject.Copy()
            $script:typedManifest.validationTarget = $baseManifest.validationTarget.PSObject.Copy()
            $script:typedManifest.schemaVersion = $case.Schema
            $script:typedManifest.validationTarget.pullRequest = $case.PullRequest
            if ($case.Throws) {
                { Assert-CMTraceHandoffManifest -HandoffRoot $script:HandoffRoot } | Should -Throw
            }
            else {
                { Assert-CMTraceHandoffManifest -HandoffRoot $script:HandoffRoot } | Should -Not -Throw
            }
        }
    }

    It 'creates deterministic file-only ZIPs with fixed metadata' {
        $sourceRoot = Join-Path $TestDrive 'deterministic-zip-source'
        $nestedRoot = Join-Path $sourceRoot 'nested'
        New-Item -ItemType Directory -Path $nestedRoot -Force | Out-Null
        $nestedFile = Join-Path $nestedRoot 'alpha.txt'
        $rootFile = Join-Path $sourceRoot 'zeta.txt'
        Set-Content -LiteralPath $nestedFile -Value 'alpha payload' -Encoding utf8NoBOM
        Set-Content -LiteralPath $rootFile -Value 'zeta payload' -Encoding utf8NoBOM
        [IO.File]::SetLastWriteTimeUtc($nestedFile, [datetime]'2024-01-02T03:04:05Z')
        [IO.File]::SetLastWriteTimeUtc($rootFile, [datetime]'2025-06-07T08:09:10Z')

        $firstZip = Join-Path $TestDrive 'deterministic-first.zip'
        $secondZip = Join-Path $TestDrive 'deterministic-second.zip'
        $firstTimestamp = New-CMTraceDeterministicZip -SourceRoot $sourceRoot -DestinationPath $firstZip
        $secondTimestamp = New-CMTraceDeterministicZip -SourceRoot $sourceRoot -DestinationPath $secondZip

        $firstTimestamp.Offset | Should -Be ([TimeSpan]::Zero)
        $secondTimestamp.Offset | Should -Be ([TimeSpan]::Zero)
        $firstTimestamp.UtcDateTime.ToString('O') | Should -BeExactly '1980-01-01T00:00:00.0000000Z'
        $secondTimestamp | Should -Be $firstTimestamp
        (Get-CMTraceSha256 -Path $firstZip) | Should -BeExactly (Get-CMTraceSha256 -Path $secondZip)
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($firstZip)) |
            Should -BeExactly ([Convert]::ToBase64String([IO.File]::ReadAllBytes($secondZip)))

        $archive = [IO.Compression.ZipFile]::OpenRead($firstZip)
        try {
            $entries = @($archive.Entries)
            @($entries.FullName) | Should -Be @('nested/alpha.txt', 'zeta.txt')
            @($entries | Where-Object { [string]::IsNullOrEmpty($_.Name) }).Count | Should -Be 0
            foreach ($entry in $entries) {
                $entry.LastWriteTime.DateTime | Should -Be ([datetime]'1980-01-01T00:00:00')
                [int64]$entry.ExternalAttributes | Should -Be 0
            }
        }
        finally {
            $archive.Dispose()
        }
    }

    It 'rejects unsafe and noncanonical return ZIP central-directory entries' {
        $returnScript = Join-Path $script:ScriptsRoot 'New-CMTraceOpenArm64ValidationReturn.ps1'
        $sequenceFunction = Get-ScriptPowerShellFunctionText -ScriptPath $returnScript -Name 'Assert-CMTraceSequence'
        $zipContractFunction = Get-ScriptPowerShellFunctionText -ScriptPath $returnScript -Name 'Assert-CMTraceReturnZipContract'
        $fixedTimestamp = [DateTimeOffset]'1980-01-01T00:00:00Z'
        $writeArchive = {
            param([string]$Path, [object[]]$Entries)

            $fileStream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            $archive = [IO.Compression.ZipArchive]::new($fileStream, [IO.Compression.ZipArchiveMode]::Create, $false)
            try {
                foreach ($specification in $Entries) {
                    $entry = $archive.CreateEntry([string]$specification.Name)
                    $entry.LastWriteTime = [DateTimeOffset]$specification.Timestamp
                    $entry.ExternalAttributes = [int]$specification.ExternalAttributes
                    if (-not [string]::IsNullOrEmpty($entry.Name)) {
                        $entryStream = $entry.Open()
                        try { $entryStream.WriteByte(0x41) }
                        finally { $entryStream.Dispose() }
                    }
                }
            }
            finally {
                $archive.Dispose()
            }
        }

        try {
            Set-Item -LiteralPath Function:\Assert-CMTraceSequence -Value ([scriptblock]::Create($sequenceFunction))
            Set-Item -LiteralPath Function:\Assert-CMTraceReturnZipContract -Value ([scriptblock]::Create($zipContractFunction))

            $canonicalPath = Join-Path $TestDrive 'canonical-return.zip'
            & $writeArchive -Path $canonicalPath -Entries @(
                [pscustomobject]@{ Name = 'safe.txt'; Timestamp = $fixedTimestamp; ExternalAttributes = 0 }
            )
            {
                Assert-CMTraceReturnZipContract -Path $canonicalPath -FixedTimestamp $fixedTimestamp `
                    -ExpectedFiles @('safe.txt')
            } | Should -Not -Throw

            foreach ($case in @(
                [pscustomobject]@{
                    Name = 'unsafe'; Match = 'unsafe entry'; Expected = @('safe.txt')
                    Entries = @([pscustomobject]@{ Name = '../escape.txt'; Timestamp = $fixedTimestamp; ExternalAttributes = 0 })
                },
                [pscustomobject]@{
                    Name = 'duplicate'; Match = 'duplicate entry'; Expected = @('safe.txt', 'SAFE.txt')
                    Entries = @(
                        [pscustomobject]@{ Name = 'safe.txt'; Timestamp = $fixedTimestamp; ExternalAttributes = 0 },
                        [pscustomobject]@{ Name = 'SAFE.txt'; Timestamp = $fixedTimestamp; ExternalAttributes = 0 }
                    )
                },
                [pscustomobject]@{
                    Name = 'directory'; Match = 'directory entry'; Expected = @('folder/')
                    Entries = @([pscustomobject]@{ Name = 'folder/'; Timestamp = $fixedTimestamp; ExternalAttributes = 0 })
                },
                [pscustomobject]@{
                    Name = 'timestamp'; Match = 'noncanonical timestamp'; Expected = @('safe.txt')
                    Entries = @([pscustomobject]@{ Name = 'safe.txt'; Timestamp = [DateTimeOffset]'1981-01-01T00:00:00Z'; ExternalAttributes = 0 })
                },
                [pscustomobject]@{
                    Name = 'attributes'; Match = 'noncanonical external attributes'; Expected = @('safe.txt')
                    Entries = @([pscustomobject]@{ Name = 'safe.txt'; Timestamp = $fixedTimestamp; ExternalAttributes = 1 })
                }
            )) {
                $path = Join-Path $TestDrive "$($case.Name)-return.zip"
                & $writeArchive -Path $path -Entries $case.Entries
                {
                    Assert-CMTraceReturnZipContract -Path $path -FixedTimestamp $fixedTimestamp `
                        -ExpectedFiles $case.Expected
                } | Should -Throw "*$($case.Match)*"
            }
        }
        finally {
            Remove-Item -LiteralPath Function:\Assert-CMTraceReturnZipContract -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath Function:\Assert-CMTraceSequence -ErrorAction SilentlyContinue
        }
    }

    It 'preserves a destination created during deterministic ZIP publication' {
        $sourceRoot = Join-Path $TestDrive 'zip-race-source'
        New-Item -ItemType Directory -Path $sourceRoot | Out-Null
        Set-Content -LiteralPath (Join-Path $sourceRoot 'payload.txt') -Value 'sealed payload' -Encoding utf8NoBOM
        $script:zipRaceDestination = Join-Path $TestDrive 'zip-race-destination.zip'
        $script:zipRaceInjected = $false

        $originalOrdinalSorter = ${function:Get-CMTraceOrdinalSortedString}
        Mock -CommandName Get-CMTraceOrdinalSortedString -MockWith {
            if (-not $script:zipRaceInjected) {
                [IO.File]::WriteAllText($script:zipRaceDestination, 'FOREIGN-CONTENT')
                $script:zipRaceInjected = $true
            }
            & $originalOrdinalSorter -Value $Value
        }

        { New-CMTraceDeterministicZip -SourceRoot $sourceRoot -DestinationPath $script:zipRaceDestination } |
            Should -Throw '*already exists*'
        [IO.File]::ReadAllText($script:zipRaceDestination) | Should -BeExactly 'FOREIGN-CONTENT'
        @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $TestDrive -Filter '.cmtraceopen-zip-*.tmp' -Force).Count | Should -Be 0
    }

    It 'creates new JSON without overwriting a competing destination' {
        $outputPath = Join-Path $TestDrive 'new-json-output.json'
        [IO.File]::WriteAllText($outputPath, 'FOREIGN-CONTENT')
        { Write-CMTraceNewJson -Value @{ value = 'sealed' } -Path $outputPath } |
            Should -Throw
        [IO.File]::ReadAllText($outputPath) | Should -BeExactly 'FOREIGN-CONTENT'
    }

    It 'preserves text publication and temporary cleanup failures together' {
        $outputPath = Join-Path $TestDrive 'text-cleanup-race.txt'
        [IO.File]::WriteAllText($outputPath, 'FOREIGN-CONTENT')
        Mock -CommandName Remove-Item -MockWith {
            throw [UnauthorizedAccessException]::new('TEXT-CLEANUP-MARKER')
        } -ParameterFilter {
            [IO.Path]::GetFileName([string]$LiteralPath) -like '.cmtraceopen-text-*.tmp'
        }

        $caught = $null
        try {
            Write-CMTraceNewText -Text 'sealed payload' -Path $outputPath
        }
        catch {
            $caught = $_
        }

        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception | Should -BeOfType [AggregateException]
        $innerMessages = @($caught.Exception.InnerExceptions | ForEach-Object Message)
        ($innerMessages -join "`n") | Should -Match '(?i)exist'
        ($innerMessages -join "`n") | Should -Match 'TEXT-CLEANUP-MARKER'
        [IO.File]::ReadAllText($outputPath) | Should -BeExactly 'FOREIGN-CONTENT'
        @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $TestDrive -Filter '.cmtraceopen-text-*.tmp' -Force).Count | Should -Be 1
    }

    It 'preserves ZIP publication and temporary cleanup failures together' {
        $sourceRoot = Join-Path $TestDrive 'zip-cleanup-race-source'
        New-Item -ItemType Directory -Path $sourceRoot | Out-Null
        Set-Content -LiteralPath (Join-Path $sourceRoot 'payload.txt') -Value 'sealed payload' -Encoding utf8NoBOM
        $script:zipCleanupRaceDestination = Join-Path $TestDrive 'zip-cleanup-race-destination.zip'
        $script:zipCleanupRaceInjected = $false

        $originalOrdinalSorter = ${function:Get-CMTraceOrdinalSortedString}
        Mock -CommandName Get-CMTraceOrdinalSortedString -MockWith {
            if (-not $script:zipCleanupRaceInjected) {
                [IO.File]::WriteAllText($script:zipCleanupRaceDestination, 'FOREIGN-CONTENT')
                $script:zipCleanupRaceInjected = $true
            }
            & $originalOrdinalSorter -Value $Value
        }
        Mock -CommandName Remove-Item -MockWith {
            throw [UnauthorizedAccessException]::new('ZIP-CLEANUP-MARKER')
        } -ParameterFilter {
            [IO.Path]::GetFileName([string]$LiteralPath) -like '.cmtraceopen-zip-*.tmp'
        }

        $caught = $null
        try {
            New-CMTraceDeterministicZip -SourceRoot $sourceRoot -DestinationPath $script:zipCleanupRaceDestination
        }
        catch {
            $caught = $_
        }

        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception | Should -BeOfType [AggregateException]
        $innerMessages = @($caught.Exception.InnerExceptions | ForEach-Object Message)
        ($innerMessages -join "`n") | Should -Match '(?i)exist'
        ($innerMessages -join "`n") | Should -Match 'ZIP-CLEANUP-MARKER'
        [IO.File]::ReadAllText($script:zipCleanupRaceDestination) | Should -BeExactly 'FOREIGN-CONTENT'
        @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $TestDrive -Filter '.cmtraceopen-zip-*.tmp' -Force).Count | Should -Be 1
    }

    It 'rejects a self-consistent candidate replacement before public ZIP publication' {
        $stagingRoot = Join-Path $TestDrive 'candidate-safe-stage'
        $stagingLogRoot = Join-Path $stagingRoot 'sanitized-logs'
        New-Item -ItemType Directory -Path $stagingLogRoot -Force | Out-Null
        $stagedLog = Join-Path $stagingLogRoot 'gate.log'
        Set-Content -LiteralPath $stagedLog -Value 'result=safe' -Encoding utf8NoBOM
        $relativeLog = 'sanitized-logs/gate.log'
        $stagedChecksum = "$(Get-CMTraceSha256 -Path $stagedLog)  $relativeLog$([Environment]::NewLine)"
        [IO.File]::WriteAllText((Join-Path $stagingRoot 'SHA256SUMS.txt'), $stagedChecksum, [Text.Encoding]::ASCII)
        $stagedChecksumSha256 = Get-CMTraceSha256 -Path (Join-Path $stagingRoot 'SHA256SUMS.txt')

        $candidate = Join-Path $TestDrive 'candidate.zip'
        [void](New-CMTraceDeterministicZip -SourceRoot $stagingRoot -DestinationPath $candidate)

        $attackerRoot = Join-Path $TestDrive 'candidate-attacker-stage'
        Copy-Item -LiteralPath $stagingRoot -Destination $attackerRoot -Recurse
        $attackerLog = Join-Path $attackerRoot $relativeLog
        Set-Content -LiteralPath $attackerLog -Value 'password=ATTACKER-CONTENT' -Encoding utf8NoBOM
        $attackerChecksum = "$(Get-CMTraceSha256 -Path $attackerLog)  $relativeLog$([Environment]::NewLine)"
        [IO.File]::WriteAllText((Join-Path $attackerRoot 'SHA256SUMS.txt'), $attackerChecksum, [Text.Encoding]::ASCII)
        $attackerCandidate = Join-Path $TestDrive 'attacker-candidate.zip'
        [void](New-CMTraceDeterministicZip -SourceRoot $attackerRoot -DestinationPath $attackerCandidate)
        [IO.File]::Delete($candidate)
        [IO.File]::Move($attackerCandidate, $candidate)

        $verifyRoot = Join-Path $TestDrive 'candidate-verify'
        $publicOutput = Join-Path $TestDrive 'pr583-arm64-001.zip'
        $caught = $null
        try {
            $outerHash = Get-CMTraceSha256 -Path $candidate
            Expand-Archive -LiteralPath $candidate -DestinationPath $verifyRoot
            [void](Assert-CMTraceChecksumInventory -Root $verifyRoot -Context 'Injected candidate')
            if ((Get-CMTraceSha256 -Path (Join-Path $verifyRoot 'SHA256SUMS.txt')) -cne $stagedChecksumSha256) {
                throw 'Freshly extracted return checksum manifest does not match the validated staged manifest.'
            }
            if ((Get-CMTraceSha256 -Path $candidate) -cne $outerHash) {
                throw 'Return ZIP candidate changed during fresh-extraction verification.'
            }
            [IO.File]::Move($candidate, $publicOutput, $false)
        }
        catch {
            $caught = $_
        }

        $caught.Exception.Message | Should -BeExactly 'Freshly extracted return checksum manifest does not match the validated staged manifest.'
        Test-Path -LiteralPath $publicOutput -PathType Any | Should -BeFalse
    }

    It 'sorts deterministic inventories with ordinal semantics under every culture' {
        $values = @('zeta', 'machine.json', 'manual-results.json', 'esp-native.log', 'bundle-output-clean.log')
        $expected = @('bundle-output-clean.log', 'esp-native.log', 'machine.json', 'manual-results.json', 'zeta')
        $originalCulture = [Globalization.CultureInfo]::CurrentCulture
        try {
            foreach ($cultureName in @('en-US', 'haw-US', 'om-ET')) {
                [Globalization.CultureInfo]::CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo($cultureName)
                @(Get-CMTraceOrdinalSortedString -Value $values) | Should -Be $expected
            }
        }
        finally {
            [Globalization.CultureInfo]::CurrentCulture = $originalCulture
        }
    }
}

Describe 'source and platform safety' {
    It 'refuses an existing source destination before Git or platform mutation' {
        $destination = Join-Path $TestDrive 'existing-source'
        New-Item -ItemType Directory -Path $destination | Out-Null
        Set-Content -LiteralPath (Join-Path $destination 'keep.txt') -Value 'preserve me'
        $result = Invoke-HandoffScript -Path (Join-Path $script:ScriptsRoot 'Initialize-CMTraceOpenArm64Source.ps1') -Arguments @('-DestinationPath', $destination)
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'already exists'
        (Get-Content -LiteralPath (Join-Path $destination 'keep.txt') -Raw).Trim() | Should -Be 'preserve me'
    }

    It 'fails closed on a non-Windows host' -Skip:$IsWindows {
        $result = Invoke-HandoffScript -Path (Join-Path $script:ScriptsRoot 'Test-CMTraceOpenArm64Preflight.ps1') -Arguments @('-RepositoryPath', $TestDrive)
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'Windows 11 ARM64'
    }

    It 'rejects target-qualified build, path, npm, and MSVC controls' {
        $rejectedNames = @(
            'HOME', 'PREFIX', 'NPM_CONFIG_USERCONFIG',
            'AZURE_STORAGE_CONNECTION_STRING', 'DATABASE_URL', 'DOCKER_AUTH_CONFIG',
            'AWS_SHARED_CREDENTIALS_FILE', 'KUBECONFIG', 'CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE',
            'SQLCONNSTR_APP', 'SQLAZURECONNSTR_APP', 'CUSTOMCONNSTR_SERVICE', 'IDENTITY_HEADER',
            'PGPASSWORD', 'PGPASSFILE', 'MYSQL_PWD', 'POSTGRES_URL', 'REDIS_URL', 'MONGODB_URI',
            'PIP_INDEX_URL', 'PIP_EXTRA_INDEX_URL', 'KRB5_CLIENT_KTNAME', 'KRB5CCNAME', 'OCI_CLI_KEY_FILE',
            'LINK', '_LINK_',
            'CC_aarch64-pc-windows-msvc', 'CC_aarch64_pc_windows_msvc',
            'CXX_aarch64-pc-windows-msvc', 'AR_aarch64_pc_windows_msvc',
            'RANLIB_aarch64-pc-windows-msvc', 'CFLAGS_aarch64_pc_windows_msvc',
            'CXXFLAGS_aarch64-pc-windows-msvc', 'ARFLAGS_aarch64_pc_windows_msvc',
            'HOST_CC', 'TARGET_CXX', 'HOST_ARFLAGS',
            'BINDGEN_EXTRA_CLANG_ARGS', 'BINDGEN_EXTRA_CLANG_ARGS_aarch64_pc_windows_msvc',
            'CMAKE', 'CMAKE_TOOLCHAIN_FILE', 'CMAKE_GENERATOR', 'CMAKE_PREFIX_PATH'
        )
        foreach ($name in $rejectedNames) {
            (Test-CMTraceSensitiveEnvironmentName -Name $name) | Should -BeTrue -Because "$name controls validation inputs or config paths"
        }
        foreach ($name in @('PATH', 'TEMP', 'PROCESSOR_ARCHITECTURE', 'ProgramFiles', 'SystemRoot', 'COMPUTERNAME')) {
            (Test-CMTraceSensitiveEnvironmentName -Name $name) | Should -BeFalse -Because "$name is required ordinary process context"
        }
        (Test-CMTraceAllowedInheritedEnvironmentName -Name 'COMPUTERNAME') | Should -BeTrue
        (Test-CMTraceAllowedInheritedEnvironmentName -Name 'UNLISTED_CREDENTIAL_CARRIER') | Should -BeFalse
        (Test-CMTraceAllowedSessionEnvironmentName -Name 'UNLISTED_CREDENTIAL_CARRIER') | Should -BeFalse
    }

    It 'constructs every automatic and private child environment from the sealed allowlist' {
        $runner = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'Invoke-CMTraceOpenArm64Validation.ps1') -Raw
        $provider = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'New-CMTraceOpenPrivateProviderDatabase.ps1') -Raw
        $common = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'CMTraceOpenArm64Handoff.Common.ps1') -Raw
        $readme = Get-Content -LiteralPath (Join-Path $script:HandoffRoot 'README.md') -Raw
        $matrix = Get-Content -LiteralPath (Join-Path $script:HandoffRoot 'VALIDATION-MATRIX.md') -Raw

        foreach ($text in @($runner, $provider, $readme)) {
            $text | Should -Match ([regex]::Escape('Initialize-CMTraceChildEnvironment -StartInfo'))
        }
        $runner | Should -Not -Match 'Test-CMTraceSensitiveEnvironmentName -Name \(\[string\]\$environmentName\)'
        $provider | Should -Match ([regex]::Escape('-Environment @{'))
        $provider | Should -Match ([regex]::Escape('CMTRACEOPEN_PROVIDER_DB = $providerDb'))
        $readme | Should -Match ([regex]::Escape('-Environment $PortableEnvironment'))
        $readme | Should -Match ([regex]::Escape('CMTRACE_EVTX_FIXTURE = $CleanEvtx'))
        $matrix | Should -Match ([regex]::Escape('-Environment $PortableEnvironment'))
        foreach ($text in @($provider, $readme, $matrix)) {
            $text | Should -Not -Match '(?m)^\s*\$env:(?:CMTRACEOPEN_PROVIDER_DB|CMTRACEOPEN_DISABLE_UPDATE_CHECKS|CMTRACE_EVTX_FIXTURE)\s*='
        }
        $common | Should -Match ([regex]::Escape("'COMPUTERNAME'"))
        $common | Should -Match ([regex]::Escape('Child environment override is not in the sealed allowlist'))
    }

    It 'keeps source initialization bounded and preserves Git environment isolation' {
        $initializer = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'Initialize-CMTraceOpenArm64Source.ps1') -Raw
        $initializer | Should -Match "(?s)Exact-SHA checkout.*?-TimeoutSeconds 300"
        $initializer | Should -Not -Match ([regex]::Escape('--filter=blob:none'))
        $initializer | Should -Match 'complete shallow clone was preserved for inspection'
        $initializer | Should -Match 'checkout was preserved for inspection'
        $initializer | Should -Match '\$advertisedMatch\s*=\s*\[regex\]::Match'
        $initializer | Should -Not -Match '\$Matches\[1\]'
        $initializer | Should -Match ([regex]::Escape('-Operation $command.Operation'))
        $initializer | Should -Not -Match ([regex]::Escape('-Operation $command.Failure'))
        $readme = Get-Content -LiteralPath (Join-Path $script:HandoffRoot 'README.md') -Raw
        $readme | Should -Match ([regex]::Escape('Do not delete or reuse it for a retry.'))
        $readme | Should -Match ([regex]::Escape('C:\src\cmtraceopen-pr583-arm64-002'))
        $ownedDestinationIndex = $initializer.IndexOf('New-Item -ItemType Directory -Path $fullDestination -ErrorAction Stop', [StringComparison]::Ordinal)
        $cloneIndex = $initializer.IndexOf('$clone = Invoke-CMTraceInitializerGit', [StringComparison]::Ordinal)
        $ownedDestinationIndex | Should -BeGreaterThan -1
        $cloneIndex | Should -BeGreaterThan $ownedDestinationIndex

        $provider = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'New-CMTraceOpenPrivateProviderDatabase.ps1') -Raw
        $provider | Should -Not -Match '(?m)^\s*\$env:(?:GIT_CONFIG_NOSYSTEM|GIT_CONFIG_GLOBAL|GIT_TERMINAL_PROMPT|GCM_INTERACTIVE|GIT_ASKPASS|SSH_ASKPASS)\s*='
        $provider | Should -Match '\$gitEnvironment\s*=\s*\[ordered\]@\{'
        $provider | Should -Match ([regex]::Escape("GIT_NO_REPLACE_OBJECTS = '1'"))
        $initializer | Should -Match ([regex]::Escape("GIT_NO_REPLACE_OBJECTS = '1'"))

        $common = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'CMTraceOpenArm64Handoff.Common.ps1') -Raw
        $common | Should -Match ([regex]::Escape('normal isolated clone with a .git directory; linked worktrees are not accepted'))
        $common | Should -Match ([regex]::Escape("rev-parse', '--absolute-git-dir"))
        $common | Should -Match ([regex]::Escape("rev-parse', '--git-common-dir"))
        $common | Should -Match ([regex]::Escape('$stdout = $capture.StdOut.Trim()'))
        $common | Should -Match ([regex]::Escape("throw 'Git emitted unexpected stderr while verifying the isolated source.'"))
        $common | Should -Match ([regex]::Escape('-ExpectedStdErrPattern ''\AGood "git" signature for me@adamgell\.com'))
        $common | Should -Not -Match ([regex]::Escape('@($capture.StdOut, $capture.StdErr)'))
        $common | Should -Match ([regex]::Escape("GIT_NO_REPLACE_OBJECTS = '1'"))
        $common | Should -Match ([regex]::Escape("@('--no-replace-objects'"))
        $common | Should -Match ([regex]::Escape("'refs/replace/'"))
        $common | Should -Match ([regex]::Escape('if ($topLevel -notin $approvedTopLevels)'))
        $common | Should -Not -Match ([regex]::Escape('if ($topLevel -cnotin $approvedTopLevels)'))
        $initializer | Should -Match ([regex]::Escape('Assert-CMTraceSafeTemporaryRoot'))
    }

    It 'rejects every relevant npmrc location and custom npm config controls' {
        $preflight = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'Test-CMTraceOpenArm64Preflight.ps1') -Raw
        foreach ($marker in @(
            "Join-Path `$resolvedRepository '.npmrc'",
            "Join-Path `$env:USERPROFILE '.npmrc'",
            "Join-Path `$env:APPDATA 'npm\etc\npmrc'",
            "Join-Path `$env:ProgramData 'npm\etc\npmrc'",
            "Join-Path `$nodeRoot 'etc\npmrc'",
            "Join-Path `$npmPrefix 'etc\npmrc'"
        )) {
            $preflight | Should -Match ([regex]::Escape($marker))
        }
        foreach ($marker in @('--location=global', '--update-notifier=false', '.cmtraceopen-absent-user.npmrc', '.cmtraceopen-absent-global.npmrc')) {
            $preflight | Should -Match ([regex]::Escape($marker))
        }
        $preflight | Should -Match ([regex]::Escape('$emptyNpmUserConfig = Join-Path $preflightTemporaryRoot'))
        $preflight | Should -Match ([regex]::Escape('$emptyNpmGlobalConfig = Join-Path $preflightTemporaryRoot'))
        $preflight | Should -Not -Match ([regex]::Escape("`$emptyNpmUserConfig = Join-Path `$resolvedRepository"))
        $preflight | Should -Not -Match ([regex]::Escape("`$emptyNpmGlobalConfig = Join-Path `$resolvedRepository"))
        $preflight | Should -Match ([regex]::Escape('Remove repository, user, and global npmrc files before validation.'))
        foreach ($name in @('HOME', 'PREFIX', 'NPM_CONFIG_USERCONFIG')) {
            (Test-CMTraceSensitiveEnvironmentName -Name $name) | Should -BeTrue
        }
    }

    It 'uses only successful stdout as authoritative preflight evidence' {
        $preflight = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'Test-CMTraceOpenArm64Preflight.ps1') -Raw
        $preflight | Should -Match ([regex]::Escape('if (-not [string]::IsNullOrWhiteSpace($capture.StdErr))'))
        $preflight | Should -Match ([regex]::Escape('throw "$Command wrote to stderr despite exit code 0."'))
        $preflight | Should -Match ([regex]::Escape('return ConvertTo-CMTraceNormalizedNativeOutput -Text $capture.StdOut'))
        $preflight | Should -Not -Match ([regex]::Escape('@($capture.StdOut, $capture.StdErr)'))
        $preflight | Should -Match ([regex]::Escape('handoffId = $script:CMTraceHandoffId'))
        $preflight | Should -Not -Match ([regex]::Escape("handoffId = 'cmtraceopen-pr583-windows11-arm64-2026-08-23'"))
    }

    It 'accepts only the exact missing-global-Git-config failure as clean' {
        $missing = "fatal: unable to read config file 'C:/Users/Lab/.gitconfig': No such file or directory`n"
        (Test-CMTraceMissingGlobalGitConfigResult -ExitCode 128 -StdOut '' -StdErr $missing) | Should -BeTrue
        foreach ($case in @(
            [pscustomobject]@{ ExitCode = 1; StdOut = ''; StdErr = $missing },
            [pscustomobject]@{ ExitCode = 128; StdOut = 'unexpected'; StdErr = $missing },
            [pscustomobject]@{ ExitCode = 128; StdOut = ''; StdErr = "fatal: unable to read config file 'C:/Users/Lab/.gitconfig': Permission denied`n" },
            [pscustomobject]@{ ExitCode = 128; StdOut = ''; StdErr = "$missing`nfatal: extra diagnostic" }
        )) {
            (Test-CMTraceMissingGlobalGitConfigResult -ExitCode $case.ExitCode -StdOut $case.StdOut -StdErr $case.StdErr) | Should -BeFalse
        }
        $preflight = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'Test-CMTraceOpenArm64Preflight.ps1') -Raw
        $preflight | Should -Not -Match '\$gitConfigCapture\.ExitCode -eq 1'
        $preflight | Should -Match '\$missingGlobalGitConfig'
        $gitResolutionIndex = $preflight.IndexOf('$gitPath = (Get-Command git.exe -CommandType Application -ErrorAction Stop).Source', [StringComparison]::Ordinal)
        $gitCaptureIndex = $preflight.IndexOf('Invoke-CMTraceOwnedProcessCapture -FilePath $gitPath', [StringComparison]::Ordinal)
        $gitResolutionIndex | Should -BeGreaterThan -1
        $gitCaptureIndex | Should -BeGreaterThan $gitResolutionIndex
    }

    It 'accepts only JSON integer representations for the exact live PR number' {
        $script:livePullRequestNumber = [int64]583
        Mock -CommandName Invoke-RestMethod -MockWith {
            return [pscustomobject]@{
                number = $script:livePullRequestNumber
                merged = $false
                state = 'open'
                head = [pscustomobject]@{
                    ref = $script:CMTraceExpectedSourceBranch
                    sha = $script:CMTraceExpectedSourceCommit
                }
                base = [pscustomobject]@{
                    ref = 'main'
                    sha = $script:CMTraceExpectedBaseCommit
                }
            }
        }

        foreach ($number in @([int32]583, [int64]583)) {
            $script:livePullRequestNumber = $number
            Assert-CMTraceLivePullRequest | Should -BeTrue
        }
        $script:livePullRequestNumber = [double]583
        { Assert-CMTraceLivePullRequest } | Should -Throw '*sealed open head/base coordinate*'
    }
}

Describe 'validation contract and private helpers' {
    It 'exposes the exact 33-gate automatic plan without repository mutation' {
        $repositoryPath = Join-Path $TestDrive 'plan-source'
        New-Item -ItemType Directory -Path $repositoryPath | Out-Null
        $planPath = Join-Path $TestDrive 'plan.json'
        $result = Invoke-HandoffScript -Path (Join-Path $script:ScriptsRoot 'Invoke-CMTraceOpenArm64Validation.ps1') -Arguments @(
            '-PlanOnly', '-PlanOutputPath', $planPath, '-RepositoryPath', $repositoryPath
        )
        $result.ExitCode | Should -Be 0 -Because $result.Output
        $plan = Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
        $plan.handoffId | Should -BeExactly $script:CMTraceHandoffId
        @($plan.gates.id) | Should -Be $script:CMTraceAutomaticGateIds

        $insideRepository = Join-Path $repositoryPath 'plan.json'
        $insideResult = Invoke-HandoffScript -Path (Join-Path $script:ScriptsRoot 'Invoke-CMTraceOpenArm64Validation.ps1') -Arguments @(
            '-PlanOnly', '-PlanOutputPath', $insideRepository, '-RepositoryPath', $repositoryPath
        )
        $insideResult.ExitCode | Should -Not -Be 0
        $insideResult.Output | Should -Match 'inside the supplied repository'
        Test-Path -LiteralPath $insideRepository | Should -BeFalse
    }

    It 'refuses PlanOnly output from a package whose sealed inventory is stale' {
        $tamperedRoot = Join-Path $TestDrive 'tampered-plan-package'
        Copy-Item -LiteralPath $script:HandoffRoot -Destination $tamperedRoot -Recurse
        Add-Content -LiteralPath (Join-Path $tamperedRoot 'README.md') -Value 'tampered'
        $planPath = Join-Path $TestDrive 'tampered-plan.json'
        $result = Invoke-HandoffScript -Path (Join-Path $tamperedRoot 'scripts/Invoke-CMTraceOpenArm64Validation.ps1') -Arguments @('-PlanOnly', '-PlanOutputPath', $planPath)
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'checksum mismatch'
        Test-Path -LiteralPath $planPath | Should -BeFalse
    }

    It 'ships deterministic private recovery, provider, folder-error, and archive-boundary helpers' {
        $fixtureScript = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'New-CMTraceOpenPrivateEvtxFixtures.ps1') -Raw
        foreach ($name in @('clean.evtx', 'tail-truncated.evtx', 'internal-missing-chunk.evtx', 'malformed-file-header.evtx', 'malformed-chunk-header.evtx', 'malformed-record-size.evtx', 'malformed-binxml.evtx')) {
            $fixtureScript | Should -Match ([regex]::Escape($name))
        }
        $fixtureScript | Should -Match '\$EvidenceRoot'
        $fixtureScript | Should -Not -Match '\$OutputDirectory'
        $fixtureScript | Should -Match ([regex]::Escape("if (`$originalBinXmlToken -eq 0xFF) { 0xFE } else { 0xFF }"))
        $fixtureScript | Should -Match ([regex]::Escape('changed from $originalBinXmlToken to $malformedBinXmlToken'))
        $fixtureScript | Should -Match ([regex]::Escape("elseif (`$fixtureHash -ceq `$sourceHashBefore)"))
        $fixtureScript | Should -Match ([regex]::Escape('Every EVTX recovery fixture must have unique bytes.'))
        $fixtureScript | Should -Not -Match ([regex]::Escape('$source.Length'))
        foreach ($marker in @(
            '[IO.FileShare]::Read',
            '$sourceStream.ReadExactly($sourceBytes, 0, $sourceBytes.Length)',
            '[Security.Cryptography.SHA256]::HashData($sourceBytes)',
            '(($sourceBytes.Length - $headerBytes) / $chunkBytes)',
            '[IO.FileMode]::CreateNew',
            '[IO.FileShare]::None',
            '$fixtureStream.Write($sourceBytes, 0, $sourceBytes.Length)',
            '$fixtureStream.Flush($true)'
        )) {
            $fixtureScript | Should -Match ([regex]::Escape($marker))
        }
        $fixtureScript | Should -Not -Match ([regex]::Escape('Copy-Item -LiteralPath $source.FullName'))
        $sourceReadIndex = $fixtureScript.IndexOf('$sourceStream.ReadExactly($sourceBytes, 0, $sourceBytes.Length)', [StringComparison]::Ordinal)
        $sourceHashIndex = $fixtureScript.IndexOf('[Security.Cryptography.SHA256]::HashData($sourceBytes)', [StringComparison]::Ordinal)
        $signatureIndex = $fixtureScript.IndexOf('[Text.Encoding]::ASCII.GetString($sourceBytes, 0, 8)', [StringComparison]::Ordinal)
        $sourceHashIndex | Should -BeGreaterThan $sourceReadIndex
        $signatureIndex | Should -BeGreaterThan $sourceHashIndex

        $providerScript = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'New-CMTraceOpenPrivateProviderDatabase.ps1') -Raw
        @($providerScript -split "`n" | Where-Object { $_ -match "^\s+'event_log::(?:provider_db|parser)::" }).Count | Should -Be 6
        $providerScript | Should -Match 'windows_provider_walk_writes_named_rows_with_composite_keys'
        $providerScript | Should -Match 'CMTRACEOPEN_PROVIDER_DB'
        $providerScript | Should -Match 'providerCount'
        $providerScript | Should -Match ([regex]::Escape("-Id 'provider-publication-test'"))
        $providerScript | Should -Match ([regex]::Escape("'tests::publish_no_replace_preserves_existing_destination', '--', '--exact'"))
        $providerScript | Should -Match 'target-native provider publication no-overwrite regression failed'
        $providerScript | Should -Match ([regex]::Escape('Select-String -LiteralPath $captureResult.StandardOutputPath -CaseSensitive'))
        $providerScript | Should -Match ([regex]::Escape('if (-not $providerCountMatch.Success)'))
        $providerScript | Should -Match ([regex]::Escape('if (-not $process.WaitForExit(5000))'))
        $providerScript | Should -Match ([regex]::Escape('if ($process.HasExited)'))
        $providerScript | Should -Match ([regex]::Escape('Start-Sleep -Milliseconds 50'))
        $providerScript | Should -Match ([regex]::Escape('if (-not [Threading.Tasks.Task]::WaitAll'))
        $providerScript | Should -Match ([regex]::Escape('Job activity query failed:'))
        (Get-ScriptPowerShellFunctionText -ScriptPath (Join-Path $script:ScriptsRoot 'New-CMTraceOpenPrivateProviderDatabase.ps1') `
            -Name 'Invoke-CMTracePrivateCargoProcess') | Should -Match ([regex]::Escape('Wait-CMTraceOwnedTargetStarted'))
        $providerScript | Should -Match ([regex]::Escape('-ContentBindings $publicationBindings'))
        $providerScript | Should -Match ([regex]::Escape('-ContentBindings $captureBindings'))
        $providerScript | Should -Match ([regex]::Escape('-ContentBindings @($providerDbBinding)'))
        $providerScript | Should -Match ([regex]::Escape('Open-CMTraceGuardedReadFile -Path $cargo -Label "Private Cargo target $Id"'))
        $providerReadIndex = Get-OrderedTextMarkerIndex -Text $providerScript -Marker '$stdoutReadTask = $process.StandardOutput.BaseStream.ReadAsync'
        $providerReadyIndex = Get-OrderedTextMarkerIndex -Text $providerScript -Marker '[void]$ownedLaunch.ReadyEvent.Set()' -AfterIndex $providerReadIndex
        $providerTargetWaitIndex = Get-OrderedTextMarkerIndex -Text $providerScript -Marker 'Wait-CMTraceOwnedTargetStarted -OwnedLaunch $ownedLaunch -WrapperProcess $process' -AfterIndex $providerReadyIndex
        $providerTargetCatchIndex = Get-OrderedTextMarkerIndex -Text $providerScript -Marker '$targetStartFailure = $_.Exception.Message' -AfterIndex $providerTargetWaitIndex
        $providerGuardReleaseIndex = Get-OrderedTextMarkerIndex -Text $providerScript -Marker '$targetGuard.Stream.Dispose()' -AfterIndex $providerTargetWaitIndex
        $providerClassifierIndex = Get-OrderedTextMarkerIndex -Text $providerScript -Marker 'Private cargo owned-process wrapper failed before a trustworthy native child result' -AfterIndex $providerGuardReleaseIndex
        $providerReadIndex | Should -BeGreaterThan -1
        $providerReadyIndex | Should -BeGreaterThan $providerReadIndex
        $providerTargetWaitIndex | Should -BeGreaterThan $providerReadyIndex
        $providerTargetCatchIndex | Should -BeGreaterThan $providerTargetWaitIndex
        $providerGuardReleaseIndex | Should -BeGreaterThan $providerTargetWaitIndex
        $providerClassifierIndex | Should -BeGreaterThan $providerGuardReleaseIndex
        $providerScript | Should -Not -Match ([regex]::Escape('[void][Threading.Tasks.Task]::WaitAll'))
        $providerAsset = Get-Content -LiteralPath (Join-Path $script:HandoffRoot 'assets/provider_capture.rs') -Raw
        $providerAsset | Should -Match ([regex]::Escape('.tempdir_in(destination_parent)'))
        $providerAsset | Should -Match ([regex]::Escape('capture_providers_to_db(&capture_path)'))
        $providerAsset | Should -Match ([regex]::Escape('drop(connection)'))
        $providerAsset | Should -Match ([regex]::Escape('publish_no_replace(&capture_path, &destination)'))
        $providerAsset | Should -Match 'fn publish_no_replace_preserves_existing_destination\(\)'
        $providerAsset | Should -Match ([regex]::Escape('expect_err("publication must refuse an existing destination")'))
        $providerAsset | Should -Match ([regex]::Escape('staging_directory.close()'))
        $providerAsset | Should -Match ([regex]::Escape('PROVIDER_CAPTURE_STAGING_RESIDUE cannot remove staging directory: {error}'))
        $providerAsset | Should -Not -Match ([regex]::Escape('PROVIDER_CAPTURE_FAILED cannot remove staging directory'))
        $providerAsset | Should -Match '(?s)if let Err\(error\) = staging_directory\.close\(\) \{.*?PROVIDER_CAPTURE_STAGING_RESIDUE.*?\}\s*match capture_result \{.*?println!\("PROVIDER_CAPTURE_OK'
        $providerAsset | Should -Match ([regex]::Escape('MOVEFILE_WRITE_THROUGH'))
        $providerAsset | Should -Not -Match ([regex]::Escape('MOVEFILE_REPLACE_EXISTING'))
        $providerAsset | Should -Not -Match ([regex]::Escape('OpenOptionsExt'))
        $providerAsset | Should -Not -Match ([regex]::Escape('share_mode('))
        $providerAsset | Should -Not -Match ([regex]::Escape('destination.exists()'))
        $providerAsset | Should -Match 'SELECT COUNT\(\*\) FROM ProviderDetails'
        $providerAsset | Should -Match 'provider_count <= 100'

        $sourceFixtureScript = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'New-CMTraceOpenPrivateSourceFixtures.ps1') -Raw
        $sourceFixtureScript | Should -Match 'blocked-\{0\}\.evtx'
        $sourceFixtureScript | Should -Match '\.\./escape\.bin'
        $sourceFixtureScript | Should -Match '0\.\.512'
        $sourceFixtureScript | Should -Not -Match 'Add-Type -AssemblyName System\.IO\.Compression'
        $commonScript = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'CMTraceOpenArm64Handoff.Common.ps1') -Raw
        $commonScript | Should -Not -Match 'Add-Type -AssemblyName System\.IO\.Compression'

        $runner = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'Invoke-CMTraceOpenArm64Validation.ps1') -Raw
        $runner | Should -Match ([regex]::Escape('$stream.ReadExactly($head, 0, $head.Length)'))
        $runner | Should -Match ([regex]::Escape('$stream.ReadExactly($tail, 0, $tail.Length)'))
        $runner | Should -Not -Match ([regex]::Escape('$stream.Read($head'))
        $runner | Should -Not -Match ([regex]::Escape('$stream.Read($tail'))
        $runner | Should -Match ([regex]::Escape('function Join-CMTraceFailureMessage'))
        $runner | Should -Not -Match ([regex]::Escape('$failureMessage = "$failureMessage`n'))

        $tokens = $null
        $parseErrors = $null
        $runnerAst = [Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $script:ScriptsRoot 'Invoke-CMTraceOpenArm64Validation.ps1'),
            [ref]$tokens,
            [ref]$parseErrors
        )
        @($parseErrors).Count | Should -Be 0
        $excerptFunction = @($runnerAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'Read-CMTraceProcessCaptureExcerpt'
        }, $true))
        $excerptFunction.Count | Should -Be 1
        . ([scriptblock]::Create($excerptFunction[0].Extent.Text))
        $capturePath = Join-Path $TestDrive 'process-capture.txt'
        $captureText = ('H' * 512) + ('M' * 1024) + ('T' * 512)
        [IO.File]::WriteAllBytes($capturePath, [Text.Encoding]::ASCII.GetBytes($captureText))
        (Read-CMTraceProcessCaptureExcerpt -Path $capturePath -MaximumBytes 1024) | Should -BeExactly (
            ('H' * 512) + "`n<process-output-excerpted; complete stream retained target-private>`n" + ('T' * 512)
        )
    }

    It 'binds Full release provenance while preserving the distinct NSIS payload derivation' {
        $runner = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'Invoke-CMTraceOpenArm64Validation.ps1') -Raw
        $return = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'New-CMTraceOpenArm64ValidationReturn.ps1') -Raw
        foreach ($text in @($runner, $return)) {
            $text | Should -Match ([regex]::Escape('standalone release-executable provenance'))
            $text | Should -Match ([regex]::Escape('same-length, distinct Tauri NSIS derivation'))
            $text | Should -Match ([regex]::Escape("-Expected 'nsis/CMTrace Open_1.5.1_arm64-setup.exe'"))
        }
        $runner | Should -Match ([regex]::Escape("`$fullPortableEvidence[0].sha256 -cne `$provenance.releaseExecutable.sha256"))
        $return | Should -Match ([regex]::Escape("[string]::Equals(`$items[0].sha256, `$provenance.releaseExecutable.sha256, [StringComparison]::Ordinal)"))
        $runner | Should -Match ([regex]::Escape('Null is intentional when no trustworthy native exit code exists'))
        $runner | Should -Match ([regex]::Escape('if ($null -ne $exitCode -and $exitCode -eq 0) { $exitCode = 1 }'))
    }

    It 'keeps the complete vswhere candidate pipeline array-wrapped in preflight and the runner' {
        foreach ($name in @('Test-CMTraceOpenArm64Preflight.ps1', 'Invoke-CMTraceOpenArm64Validation.ps1')) {
            $tokens = $null
            $parseErrors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile(
                (Join-Path $script:ScriptsRoot $name),
                [ref]$tokens,
                [ref]$parseErrors
            )
            @($parseErrors).Count | Should -Be 0
            $assignment = @($ast.FindAll({
                param($node)
                $node -is [Management.Automation.Language.AssignmentStatementAst] -and
                    $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
                    $node.Left.VariablePath.UserPath -eq 'vswhereCandidates'
            }, $true))
            $assignment.Count | Should -Be 1 -Because "$name must have one authoritative vswhere candidate assignment"
            $assignment[0].Right.Extent.Text | Should -Match '^@\(\s*@\('
        }
    }

    It 'parses every shipped PowerShell script and documented PowerShell procedure' {
        foreach ($scriptPath in @(Get-ChildItem -LiteralPath $script:ScriptsRoot -Filter '*.ps1' -File -Recurse)) {
            $tokens = $null
            $parseErrors = $null
            [void][Management.Automation.Language.Parser]::ParseFile(
                $scriptPath.FullName,
                [ref]$tokens,
                [ref]$parseErrors
            )
            @($parseErrors).Count | Should -Be 0 -Because "$($scriptPath.Name) must parse"
        }

        foreach ($documentName in @('README.md', 'VALIDATION-MATRIX.md')) {
            $document = Get-Content -LiteralPath (Join-Path $script:HandoffRoot $documentName) -Raw
            $blocks = [regex]::Matches(
                $document,
                '(?ms)^```powershell\s*\r?\n(?<code>.*?)^```\s*$',
                [Text.RegularExpressions.RegexOptions]::CultureInvariant
            )
            $blocks.Count | Should -BeGreaterThan 0 -Because "$documentName must contain executable procedures"
            for ($index = 0; $index -lt $blocks.Count; $index++) {
                $tokens = $null
                $parseErrors = $null
                [void][Management.Automation.Language.Parser]::ParseInput(
                    $blocks[$index].Groups['code'].Value,
                    "$documentName#powershell-$($index + 1)",
                    [ref]$tokens,
                    [ref]$parseErrors
                )
                @($parseErrors).Count | Should -Be 0 -Because "$documentName PowerShell block $($index + 1) must parse"
            }
        }
        $noFencePath = Join-Path $TestDrive 'no-powershell-fence.md'
        Set-Content -LiteralPath $noFencePath -Value '# No executable procedure' -Encoding utf8NoBOM
        { Get-DocumentedPowerShellFunctionText -DocumentPath $noFencePath -Name 'Missing' } |
            Should -Throw '*contains no PowerShell code fence*'
    }

    It 'validates fixed NTFS non-reparse bootstrap ancestry before extraction and execution' {
        $readme = Get-Content -LiteralPath (Join-Path $script:HandoffRoot 'README.md') -Raw
        $helperIndex = Get-OrderedTextMarkerIndex -Text $readme -Marker 'function Assert-BootstrapPathBoundary'
        $zipBoundaryIndex = Get-OrderedTextMarkerIndex -Text $readme -Marker '$Zip = Assert-BootstrapPathBoundary' -AfterIndex $helperIndex
        $placeholderGuardIndex = Get-OrderedTextMarkerIndex -Text $readme -Marker "if (`$TrustedSha256.StartsWith('<')" -AfterIndex $zipBoundaryIndex
        $zipGuardIndex = Get-OrderedTextMarkerIndex -Text $readme -Marker '$ZipGuard = [IO.File]::Open($Zip, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)' -AfterIndex $placeholderGuardIndex
        $postOpenZipBoundaryIndex = Get-OrderedTextMarkerIndex -Text $readme -Marker '$Zip = Assert-BootstrapPathBoundary' -AfterIndex $zipGuardIndex
        $hashIndex = Get-OrderedTextMarkerIndex -Text $readme -Marker '$Actual = (Get-FileHash -InputStream $ZipGuard -Algorithm SHA256)' -AfterIndex $postOpenZipBoundaryIndex
        $ownedExtractionIndex = Get-OrderedTextMarkerIndex -Text $readme -Marker 'New-Item -ItemType Directory -Path $Handoff -ErrorAction Stop' -AfterIndex $hashIndex
        $rewindIndex = Get-OrderedTextMarkerIndex -Text $readme -Marker '$ZipGuard.Position = 0' -AfterIndex $ownedExtractionIndex
        $extractIndex = Get-OrderedTextMarkerIndex -Text $readme -Marker '[IO.Compression.ZipFile]::ExtractToDirectory($ZipGuard, $Handoff, $false)' -AfterIndex $rewindIndex
        $postExtractBoundaryIndex = Get-OrderedTextMarkerIndex -Text $readme -Marker '$Handoff = Assert-BootstrapPathBoundary' -AfterIndex $extractIndex
        $finallyIndex = Get-OrderedTextMarkerIndex -Text $readme -Marker 'finally {' -AfterIndex $postExtractBoundaryIndex
        $zipGuardDisposeIndex = Get-OrderedTextMarkerIndex -Text $readme -Marker '$ZipGuard.Dispose()' -AfterIndex $finallyIndex
        $executeIndex = Get-OrderedTextMarkerIndex -Text $readme -Marker 'pwsh.exe -NoProfile -ExecutionPolicy RemoteSigned -File "$Handoff\scripts\Test-CMTraceOpenArm64Handoff.ps1"' -AfterIndex $zipGuardDisposeIndex

        $helperIndex | Should -BeGreaterThan -1
        $zipBoundaryIndex | Should -BeGreaterThan $helperIndex
        $placeholderGuardIndex | Should -BeGreaterThan $zipBoundaryIndex
        $zipGuardIndex | Should -BeGreaterThan $placeholderGuardIndex
        $postOpenZipBoundaryIndex | Should -BeGreaterThan $zipGuardIndex
        $hashIndex | Should -BeGreaterThan $postOpenZipBoundaryIndex
        $ownedExtractionIndex | Should -BeGreaterThan $hashIndex
        $rewindIndex | Should -BeGreaterThan $ownedExtractionIndex
        $extractIndex | Should -BeGreaterThan $rewindIndex
        $postExtractBoundaryIndex | Should -BeGreaterThan $extractIndex
        $finallyIndex | Should -BeGreaterThan $postExtractBoundaryIndex
        $zipGuardDisposeIndex | Should -BeGreaterThan $finallyIndex
        $executeIndex | Should -BeGreaterThan $zipGuardDisposeIndex
        $readme | Should -Match ([regex]::Escape('$Volume.DriveType -ne ''Fixed'' -or $Volume.FileSystem -ne ''NTFS'''))
        $readme | Should -Match ([regex]::Escape('$Entry.Attributes -band [IO.FileAttributes]::ReparsePoint'))
        $readme | Should -Match ([regex]::Escape('Set $TrustedSha256 to the lowercase SHA-256 received out of band before continuing.'))
        $readme | Should -Match ([regex]::Escape('under the CMTraceOpen-Handoff top-level directory on its fixed NTFS volume'))
        $readme | Should -Not -Match ([regex]::Escape('must remain under C:\CMTraceOpen-Handoff'))
        $readme | Should -Not -Match ([regex]::Escape('$Actual = (Get-FileHash -LiteralPath $Zip'))
    }

    It 'captures the default-app baseline before the approved installer executes' {
        $matrix = Get-Content -LiteralPath (Join-Path $script:HandoffRoot 'VALIDATION-MATRIX.md') -Raw
        $helperMarker = 'function Get-PrivateDefaultAppChoices'
        $baselineMarker = '$DefaultAppsBefore = Get-PrivateDefaultAppChoices'
        $installerMarker = '$InstallResult = Invoke-PrivateProcess -Id ''nsis-current-user-install'''
        $defaultAppsApprovalMarker = '$DefaultAppsApprovalToken = Read-Host'
        $exerciseMarker = 'privately exercise `.log`, `.log_`, `.lo_`, and `.cmtlog`'
        $defaultAppsExerciseMarker = '$DefaultAppsExerciseToken = Read-Host'
        $restorationMarker = '$DefaultAppRestorationMatched = $true'
        $uninstallApprovalMarker = '$UninstallApprovalToken = Read-Host'
        $uninstallDeniedMarker = 'if (-not $UninstallApproved)'
        $uninstallerMarker = '$UninstallResult = Invoke-PrivateProcess -Id ''nsis-current-user-uninstall'''
        $cleanupFinallyMarker = 'finally {'
        $policyGuardMarker = 'if (Test-PrivateRegistryValue -Path $UpdatePolicyPath -Name ''DisableUpdateChecks'')'
        $policyRemovalMarker = 'Remove-ItemProperty -LiteralPath $UpdatePolicyPath -Name DisableUpdateChecks -ErrorAction Stop'
        $cleanupResultMarker = 'if ($NsisLifecycleFailures.Count -eq 0)'
        $helperIndex = $matrix.IndexOf($helperMarker, [StringComparison]::Ordinal)
        $baselineIndex = $matrix.IndexOf($baselineMarker, [StringComparison]::Ordinal)
        $installerIndex = $matrix.IndexOf($installerMarker, [StringComparison]::Ordinal)
        $defaultAppsApprovalIndex = $matrix.IndexOf($defaultAppsApprovalMarker, [StringComparison]::Ordinal)
        $exerciseIndex = $matrix.IndexOf($exerciseMarker, [StringComparison]::Ordinal)
        $defaultAppsExerciseIndex = $matrix.IndexOf($defaultAppsExerciseMarker, [StringComparison]::Ordinal)
        $restorationIndex = $matrix.IndexOf($restorationMarker, [StringComparison]::Ordinal)
        $uninstallApprovalIndex = $matrix.IndexOf($uninstallApprovalMarker, [StringComparison]::Ordinal)
        $uninstallDeniedIndex = $matrix.IndexOf($uninstallDeniedMarker, [StringComparison]::Ordinal)
        $uninstallerIndex = $matrix.IndexOf($uninstallerMarker, [StringComparison]::Ordinal)
        $helperIndex | Should -BeGreaterThan -1
        $baselineIndex | Should -BeGreaterThan $helperIndex
        $installerIndex | Should -BeGreaterThan $baselineIndex
        $defaultAppsApprovalIndex | Should -BeGreaterThan $installerIndex
        $exerciseIndex | Should -BeGreaterThan $defaultAppsApprovalIndex
        $defaultAppsExerciseIndex | Should -BeGreaterThan $exerciseIndex
        $restorationIndex | Should -BeGreaterThan $defaultAppsExerciseIndex
        $uninstallApprovalIndex | Should -BeGreaterThan $restorationIndex
        $uninstallDeniedIndex | Should -BeGreaterThan $uninstallApprovalIndex
        $uninstallerIndex | Should -BeGreaterThan $uninstallDeniedIndex
        $cleanupFinallyIndex = $matrix.IndexOf($cleanupFinallyMarker, $uninstallerIndex, [StringComparison]::Ordinal)
        $cleanupFinallyIndex | Should -BeGreaterThan $uninstallerIndex
        $policyGuardIndex = $matrix.IndexOf($policyGuardMarker, $cleanupFinallyIndex, [StringComparison]::Ordinal)
        $policyGuardIndex | Should -BeGreaterThan $cleanupFinallyIndex
        $policyRemovalIndex = $matrix.IndexOf($policyRemovalMarker, $cleanupFinallyIndex, [StringComparison]::Ordinal)
        $policyRemovalIndex | Should -BeGreaterThan $policyGuardIndex
        $policyReadbackGuardIndex = $matrix.IndexOf($policyGuardMarker, $policyRemovalIndex, [StringComparison]::Ordinal)
        $policyReadbackGuardIndex | Should -BeGreaterThan $policyRemovalIndex
        $cleanupResultIndex = $matrix.IndexOf($cleanupResultMarker, $policyRemovalIndex, [StringComparison]::Ordinal)
        $cleanupResultIndex | Should -BeGreaterThan $policyRemovalIndex
        ([regex]::Matches($matrix, [regex]::Escape($baselineMarker))).Count | Should -Be 1
        ([regex]::Matches($matrix, [regex]::Escape($exerciseMarker))).Count | Should -Be 1
        $matrix | Should -Match ([regex]::Escape('$DefaultAppsApprovalToken = Read-Host ''Type APPROVE-DEFAULT-APPS only after separate human approval; otherwise press Enter'''))
        $matrix | Should -Match ([regex]::Escape('$DefaultAppsExerciseToken = Read-Host ''Type DEFAULT-APPS-EXERCISED-AND-RESTORED only after all four Explorer actions and Windows Settings restorations are complete'''))
        $matrix | Should -Match ([regex]::Escape("'DEFAULT-APPS-EXERCISED-AND-RESTORED',"))
        $matrix | Should -Match ([regex]::Escape('Default Apps activation and restoration were not directly confirmed; no restoration readback was accepted.'))
        $matrix | Should -Match ([regex]::Escape('$UninstallApprovalToken = Read-Host ''Type APPROVE-UNINSTALL only after separate human approval; otherwise press Enter'''))
        $matrix | Should -Match ([regex]::Escape('APPROVAL_NOT_GRANTED: default-apps-file-associations was not authorized and no Default Apps action was performed.'))
        $matrix | Should -Match ([regex]::Escape('APPROVAL_NOT_GRANTED: ordinary uninstall was not authorized and was not run.'))
        $matrix | Should -Match ([regex]::Escape('if ($DefaultAppsApproved -and $NsisLifecycleReady)'))
        $matrix | Should -Match ([regex]::Escape('if ($DefaultAppRestorationMatched -and -not $DefaultAppsRemainRestored)'))
        $matrix | Should -Not -Match ([regex]::Escape('throw "The prior default-app choice for $Extension was not restored."'))
        $registryHelperIndex = $matrix.IndexOf('function Test-PrivateRegistryValue', [StringComparison]::Ordinal)
        $policyBaselineIndex = $matrix.IndexOf('$UpdatePolicyKeyExisted = Test-Path -LiteralPath $UpdatePolicyPath -ErrorAction Stop', [StringComparison]::Ordinal)
        $registryHelperIndex | Should -BeGreaterThan -1
        $policyBaselineIndex | Should -BeGreaterThan $registryHelperIndex
        ([regex]::Matches($matrix, '(?m)^function Test-PrivateRegistryValue \{')).Count | Should -Be 1
        $matrix | Should -Match ([regex]::Escape('$Key = Get-Item -LiteralPath $Path -ErrorAction Stop'))
        $matrix | Should -Match ([regex]::Escape('[string]::Equals($ValueName, $Name, [StringComparison]::OrdinalIgnoreCase)'))
        $matrix | Should -Not -Match ([regex]::Escape('$Key.GetValueNames() -ccontains $Name'))
        $matrix | Should -Not -Match ([regex]::Escape('Get-ItemProperty -LiteralPath $UpdatePolicyPath -Name DisableUpdateChecks -ErrorAction SilentlyContinue'))
        $matrix | Should -Not -Match ([regex]::Escape('Get-ItemProperty -LiteralPath $UserChoicePath -Name ProgId -ErrorAction SilentlyContinue'))
        $matrix | Should -Match ([regex]::Escape('Get-ItemPropertyValue -LiteralPath $UserChoicePath -Name ProgId -ErrorAction Stop'))
        $matrix | Should -Match ([regex]::Escape('$InstallDirectory = $ExpectedInstallDirectory'))
        $matrix | Should -Match ([regex]::Escape('elseif (-not $InstalledExecutableVerified)'))
        $matrix | Should -Match ([regex]::Escape('it was not stopped'))
        $matrix | Should -Match ([regex]::Escape('deliberately does not throw at the end so failure evidence can still be sealed and accepted'))
        $matrix | Should -Not -Match '(?i)(?:fail|cancel)[^\r\n]{0,80}revert(?: the)? snapshot'
        $readme = Get-Content -LiteralPath (Join-Path $script:HandoffRoot 'README.md') -Raw
        $readme | Should -Not -Match '(?i)fail[^\r\n]{0,80}revert(?: the)? snapshot'
        $readme | Should -Match ([regex]::Escape('Seal, transport, verify, and obtain acceptance for the privacy-bounded return before separately requesting approval to revert the snapshot.'))
    }

    It 'uses Windows registry name semantics and fails closed on default-app read errors' {
        $matrixPath = Join-Path $script:HandoffRoot 'VALIDATION-MATRIX.md'
        $registryValueFunction = [scriptblock]::Create(
            (Get-DocumentedPowerShellFunctionText -DocumentPath $matrixPath -Name 'Test-PrivateRegistryValue')
        )
        $defaultAppFunction = [scriptblock]::Create(
            (Get-DocumentedPowerShellFunctionText -DocumentPath $matrixPath -Name 'Get-PrivateDefaultAppChoices')
        )
        $defaultAppEqualityFunction = [scriptblock]::Create(
            (Get-DocumentedPowerShellFunctionText -DocumentPath $matrixPath -Name 'Test-PrivateDefaultAppChoiceEqual')
        )

        $script:FakeRegistryKey = [pscustomobject]@{}
        $script:FakeRegistryKey | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value { @('disableupdatechecks') }
        Mock -CommandName Test-Path -MockWith { return $true }
        Mock -CommandName Get-Item -MockWith { return $script:FakeRegistryKey }
        (& $registryValueFunction -Path 'HKCU:\Software\CMTrace Open' -Name 'DisableUpdateChecks') | Should -BeTrue

        Mock -CommandName Test-Path -MockWith { throw 'forced registry provider read failure' }
        { & $defaultAppFunction } | Should -Throw '*forced registry provider read failure*'

        $absent = [pscustomobject]@{ present = $false; progId = $null }
        $presentEmpty = [pscustomobject]@{ present = $true; progId = '' }
        $mixedCase = [pscustomobject]@{ present = $true; progId = 'CMTraceOpen.LogFile' }
        $lowerCase = [pscustomobject]@{ present = $true; progId = 'cmtraceopen.logfile' }
        (& $defaultAppEqualityFunction -Expected $absent -Actual $absent) | Should -BeTrue
        (& $defaultAppEqualityFunction -Expected $absent -Actual $presentEmpty) | Should -BeFalse
        (& $defaultAppEqualityFunction -Expected $mixedCase -Actual $lowerCase) | Should -BeTrue
        {
            & $defaultAppEqualityFunction -Expected ([pscustomobject]@{ present = 0; progId = $null }) -Actual $absent
        } | Should -Throw '*invalid presence discriminator*'
    }

    It 'validates isolated Git configuration before binding working-tree lockfiles' {
        $common = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'CMTraceOpenArm64Handoff.Common.ps1') -Raw
        $sourceIntegrityIndex = $common.IndexOf('function Assert-CMTraceSourceIntegrity', [StringComparison]::Ordinal)
        $configurationIndex = $common.IndexOf("`$autocrlf = Invoke-CMTraceSourceGit", $sourceIntegrityIndex, [StringComparison]::Ordinal)
        $unsafeConfigurationIndex = $common.IndexOf("`$unsafeLocalConfig = Invoke-CMTraceSourceGit", $configurationIndex, [StringComparison]::Ordinal)
        $indexTreeIndex = $common.IndexOf("@('write-tree')", $unsafeConfigurationIndex, [StringComparison]::Ordinal)
        $trackedHashIndex = $common.IndexOf("@('hash-object', '--stdin-paths')", $indexTreeIndex, [StringComparison]::Ordinal)
        $lockfileIndex = $common.IndexOf("@('hash-object', `$lock.Path)", $trackedHashIndex, [StringComparison]::Ordinal)
        $sourceIntegrityIndex | Should -BeGreaterThan -1
        $configurationIndex | Should -BeGreaterThan $sourceIntegrityIndex
        $unsafeConfigurationIndex | Should -BeGreaterThan $configurationIndex
        $indexTreeIndex | Should -BeGreaterThan $unsafeConfigurationIndex
        $trackedHashIndex | Should -BeGreaterThan $indexTreeIndex
        $lockfileIndex | Should -BeGreaterThan $trackedHashIndex
        foreach ($message in @(
            'Source worktree status exceeded the bounded capture limit and is not accepted as clean',
            'Tracked source worktree status exceeded the bounded capture limit and is not accepted as clean',
            'Ignored source file inventory exceeded the bounded capture limit and is not accepted'
        )) {
            $common | Should -Match ([regex]::Escape($message))
        }
        $common | Should -Match ([regex]::Escape('$_.Exception.Message -ceq "Owned process output exceeded the strict $MaximumCaptureBytes-byte aggregate capture limit."'))
        $common | Should -Match ([regex]::Escape('-MaximumCaptureBytes 1048576'))
        $common | Should -Match ([regex]::Escape("'ls-files', '--stage', '-z', '--cached'"))
        $common | Should -Match ([regex]::Escape('-StandardInputText $trackedHashPlan.StandardInputText'))
    }

    It 'rejects hidden index state, source controls, and external Cargo configuration' {
        { Assert-CMTraceGitIndexVisibility -Inventory ("H first" + [char]0 + "H second" + [char]0) } | Should -Not -Throw
        foreach ($tag in @('h', 'S', 's', 'M', '?')) {
            { Assert-CMTraceGitIndexVisibility -Inventory ("$tag unsafe" + [char]0) } | Should -Throw '*nonordinary*'
        }

        Mock -CommandName Assert-CMTraceNoReparseAncestor -MockWith { return $true }
        $boundaryRoot = Join-Path $TestDrive 'cargo-boundary'
        $sourceRoot = Join-Path $boundaryRoot 'source'
        $workingDirectory = Join-Path $sourceRoot 'src-tauri'
        $sourceCargoDirectory = Join-Path $sourceRoot '.cargo'
        $sourceCargoConfiguration = Join-Path $sourceCargoDirectory 'config.toml'
        New-Item -ItemType Directory -Force -Path $workingDirectory, $sourceCargoDirectory | Out-Null
        Set-Content -LiteralPath $sourceCargoConfiguration -Value '[build]' -Encoding utf8NoBOM
        {
            Assert-CMTraceCargoConfigurationBoundary -WorkingDirectory $workingDirectory `
                -AllowedConfigurationPaths @($sourceCargoConfiguration)
        } | Should -Not -Throw

        $externalCargoDirectory = Join-Path $boundaryRoot '.cargo'
        New-Item -ItemType Directory -Path $externalCargoDirectory | Out-Null
        Set-Content -LiteralPath (Join-Path $externalCargoDirectory 'config.toml') -Value '[build]' -Encoding utf8NoBOM
        {
            Assert-CMTraceCargoConfigurationBoundary -WorkingDirectory $workingDirectory `
                -AllowedConfigurationPaths @($sourceCargoConfiguration)
        } | Should -Throw '*outside the authenticated*'
        Remove-Item -LiteralPath $externalCargoDirectory -Recurse -Force
        Set-Content -LiteralPath (Join-Path $boundaryRoot 'rust-toolchain.toml') -Value '[toolchain]' -Encoding utf8NoBOM
        {
            Assert-CMTraceCargoConfigurationBoundary -WorkingDirectory $workingDirectory `
                -AllowedConfigurationPaths @($sourceCargoConfiguration)
        } | Should -Throw '*toolchain override*'
        Remove-Item -LiteralPath (Join-Path $boundaryRoot 'rust-toolchain.toml') -Force

        $gitMetadata = Join-Path $sourceRoot '.git'
        $gitInfo = Join-Path $gitMetadata 'info'
        New-Item -ItemType Directory -Force -Path $gitInfo | Out-Null
        Set-Content -LiteralPath (Join-Path $gitInfo 'exclude') -Value '# comments only' -Encoding utf8NoBOM
        Set-Content -LiteralPath (Join-Path $sourceRoot '.env.example') -Value 'SEALED_EXAMPLE=1' -Encoding utf8NoBOM
        { Assert-CMTraceRepositoryControlBoundary -RepositoryPath $sourceRoot -GitMetadataPath $gitMetadata } | Should -Not -Throw
        Set-Content -LiteralPath (Join-Path $sourceRoot '.env.local') -Value 'VITE_UNSEALED=1' -Encoding utf8NoBOM
        { Assert-CMTraceRepositoryControlBoundary -RepositoryPath $sourceRoot -GitMetadataPath $gitMetadata } | Should -Throw '*unsealed environment*'
        Remove-Item -LiteralPath (Join-Path $sourceRoot '.env.local') -Force
        Set-Content -LiteralPath (Join-Path $gitInfo 'exclude') -Value '.env.local' -Encoding utf8NoBOM
        { Assert-CMTraceRepositoryControlBoundary -RepositoryPath $sourceRoot -GitMetadataPath $gitMetadata } | Should -Throw '*active local*'
        Set-Content -LiteralPath (Join-Path $gitInfo 'exclude') -Value '# comments only' -Encoding utf8NoBOM
        Set-Content -LiteralPath (Join-Path $gitMetadata 'config.worktree') -Value '[core]' -Encoding utf8NoBOM
        { Assert-CMTraceRepositoryControlBoundary -RepositoryPath $sourceRoot -GitMetadataPath $gitMetadata } | Should -Throw '*worktree-specific*'
    }

    It 'authenticates every tracked worktree byte independently of stat metadata' `
        -Skip:(-not (Get-Command git -CommandType Application -ErrorAction SilentlyContinue)) {
        $firstHash = '1111111111111111111111111111111111111111'
        $secondHash = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        $inventory = "100644 $firstHash 0`tfirst file.txt" + [char]0 +
            "100755 $secondHash 0`tscripts/second.ps1" + [char]0
        $plan = Get-CMTraceTrackedHashPlan -StageInventory $inventory
        @($plan.Paths) | Should -Be @('first file.txt', 'scripts/second.ps1')
        @($plan.ExpectedHashes) | Should -Be @($firstHash, $secondHash)
        $plan.StandardInputText | Should -BeExactly "first file.txt`nscripts/second.ps1`n"
        (Assert-CMTraceTrackedHashOutput -ExpectedHashes $plan.ExpectedHashes -ActualOutput "$firstHash`n$secondHash") | Should -Be 2
        { Assert-CMTraceTrackedHashOutput -ExpectedHashes $plan.ExpectedHashes -ActualOutput "$firstHash`n$firstHash" } |
            Should -Throw '*does not hash to its exact index blob*'
        { Assert-CMTraceTrackedHashOutput -ExpectedHashes $plan.ExpectedHashes -ActualOutput "$firstHash`n$($secondHash.ToUpperInvariant())" } |
            Should -Throw '*does not hash to its exact index blob*'
        { Assert-CMTraceTrackedHashOutput -ExpectedHashes $plan.ExpectedHashes -ActualOutput $firstHash } |
            Should -Throw '*incomplete or extra*'
        { Get-CMTraceTrackedHashPlan -StageInventory ("100644 $firstHash 1`tunmerged.txt" + [char]0) } |
            Should -Throw '*unsupported mode, stage, hash, or path*'
        { Get-CMTraceTrackedHashPlan -StageInventory ("100600 $firstHash 0`tunsupported.txt" + [char]0) } |
            Should -Throw '*unsupported mode, stage, hash, or path*'

        $repository = Join-Path $TestDrive 'stat-metadata-source'
        New-Item -ItemType Directory -Path $repository | Out-Null
        $git = @(Get-Command git -CommandType Application -ErrorAction Stop)[0].Source
        $emptyTemplate = Join-Path $TestDrive 'empty-git-template'
        New-Item -ItemType Directory -Path $emptyTemplate | Out-Null
        $gitEnvironmentNames = @(
            'GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG_GLOBAL',
            'GIT_CONFIG_COUNT', 'GIT_ATTR_NOSYSTEM', 'GIT_TEMPLATE_DIR'
        )
        $priorGitEnvironment = @{}
        foreach ($name in $gitEnvironmentNames) {
            $priorGitEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, [EnvironmentVariableTarget]::Process)
        }
        try {
            $nullDevice = if ($IsWindows) { 'NUL' } else { '/dev/null' }
            $env:GIT_CONFIG_NOSYSTEM = '1'
            $env:GIT_CONFIG_SYSTEM = $nullDevice
            $env:GIT_CONFIG_GLOBAL = $nullDevice
            $env:GIT_CONFIG_COUNT = '0'
            $env:GIT_ATTR_NOSYSTEM = '1'
            $env:GIT_TEMPLATE_DIR = $emptyTemplate
        & $git -C $repository init --quiet
        $LASTEXITCODE | Should -Be 0
        & $git -C $repository config core.autocrlf false
        $LASTEXITCODE | Should -Be 0
        $payload = Join-Path $repository 'payload.txt'
        $utf8 = [Text.UTF8Encoding]::new($false)
        [IO.File]::WriteAllText($payload, "trusted`n", $utf8)
        & $git -C $repository add -- payload.txt
        $LASTEXITCODE | Should -Be 0
        $stageInventory = [string](& $git -C $repository ls-files --stage -z --cached)
        $hashPlan = Get-CMTraceTrackedHashPlan -StageInventory $stageInventory
        $trustedLength = (Get-Item -LiteralPath $payload).Length
        $trustedTimestamp = (Get-Item -LiteralPath $payload).LastWriteTimeUtc
        & $git -C $repository config core.trustctime false
        $LASTEXITCODE | Should -Be 0
        [IO.File]::WriteAllText($payload, "hostile`n", $utf8)
        [IO.File]::SetLastWriteTimeUtc($payload, $trustedTimestamp)
        (Get-Item -LiteralPath $payload).Length | Should -Be $trustedLength
        $actualHash = ([string](& $git -C $repository hash-object -- payload.txt)).Trim()
        $LASTEXITCODE | Should -Be 0
        { Assert-CMTraceTrackedHashOutput -ExpectedHashes $hashPlan.ExpectedHashes -ActualOutput $actualHash } |
            Should -Throw '*does not hash to its exact index blob*'
        }
        finally {
            foreach ($name in $gitEnvironmentNames) {
                [Environment]::SetEnvironmentVariable(
                    $name,
                    $priorGitEnvironment[$name],
                    [EnvironmentVariableTarget]::Process
                )
            }
        }
    }

    It 'rechecks source controls before every automatic process gate and protects source-script preflight execution' {
        $runner = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'Invoke-CMTraceOpenArm64Validation.ps1') -Raw
        $processGateIndex = $runner.IndexOf('function Invoke-CMTraceProcessGate', [StringComparison]::Ordinal)
        $freshSourceIndex = $runner.IndexOf('[void](Assert-CMTraceSourceIntegrity -RepositoryPath $resolvedRepository)', $processGateIndex, [StringComparison]::Ordinal)
        $freshCargoIndex = $runner.IndexOf('[void](Assert-CMTraceCargoConfigurationBoundary -WorkingDirectory $WorkingDirectory', $freshSourceIndex, [StringComparison]::Ordinal)
        $activeToolchainIndex = $runner.IndexOf('[void](Assert-CMTraceActiveRustToolchain -WorkingDirectory $WorkingDirectory)', $freshCargoIndex, [StringComparison]::Ordinal)
        $commandResolutionIndex = $runner.IndexOf('$resolvedCommand = (Get-Command $FilePath', $processGateIndex, [StringComparison]::Ordinal)
        $freshSourceIndex | Should -BeGreaterThan $processGateIndex
        $freshCargoIndex | Should -BeGreaterThan $freshSourceIndex
        $activeToolchainIndex | Should -BeGreaterThan $freshCargoIndex
        $commandResolutionIndex | Should -BeGreaterThan $activeToolchainIndex

        $preflight = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'Test-CMTraceOpenArm64Preflight.ps1') -Raw
        $sdkGateIndex = $preflight.IndexOf("Add-PreflightCheck -Id 'windows-sdk-mt'", [StringComparison]::Ordinal)
        $exactSourceGuardIndex = $preflight.IndexOf("`$exactSourceCheck = @(`$checks | Where-Object { `$_.id -ceq 'exact-source' })", $sdkGateIndex, [StringComparison]::Ordinal)
        $resolverIndex = $preflight.IndexOf("`$resolver = Join-Path `$resolvedRepository 'scripts/resolve-windows-sdk-mt.ps1'", $sdkGateIndex, [StringComparison]::Ordinal)
        $sdkGateIndex | Should -BeGreaterThan -1
        $exactSourceGuardIndex | Should -BeGreaterThan $sdkGateIndex
        $resolverIndex | Should -BeGreaterThan $exactSourceGuardIndex

        $provider = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'New-CMTraceOpenPrivateProviderDatabase.ps1') -Raw
        $providerSourceIndex = $provider.IndexOf('[void](Assert-CMTraceSourceIntegrity -RepositoryPath $resolvedRepository)', [StringComparison]::Ordinal)
        $providerCargoIndex = $provider.IndexOf('Assert-CMTraceCargoConfigurationBoundary -WorkingDirectory $resolvedWorkingDirectory', $providerSourceIndex, [StringComparison]::Ordinal)
        $providerToolchainIndex = $provider.IndexOf('Assert-CMTraceActiveRustToolchain -WorkingDirectory $resolvedWorkingDirectory', $providerCargoIndex, [StringComparison]::Ordinal)
        $providerWorkingDirectoryIndex = $provider.IndexOf('$startInfo.WorkingDirectory = $resolvedWorkingDirectory', $providerToolchainIndex, [StringComparison]::Ordinal)
        $providerSourceIndex | Should -BeGreaterThan -1
        $providerCargoIndex | Should -BeGreaterThan $providerSourceIndex
        $providerToolchainIndex | Should -BeGreaterThan $providerCargoIndex
        $providerWorkingDirectoryIndex | Should -BeGreaterThan $providerToolchainIndex
        $provider | Should -Match ([regex]::Escape('The archived Cargo configuration does not match the immutable source checkout.'))
        $common = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'CMTraceOpenArm64Handoff.Common.ps1') -Raw
        $common | Should -Match ([regex]::Escape("foreach (`$name in @('config', 'config.toml', 'credentials', 'credentials.toml'))"))

        $readmePath = Join-Path $script:HandoffRoot 'README.md'
        $manualHelper = Get-DocumentedPowerShellFunctionText -DocumentPath $readmePath -Name 'Invoke-PrivateProcess'
        $manualSourceIndex = $manualHelper.IndexOf('[void](Assert-CMTraceSourceIntegrity -RepositoryPath $Source)', [StringComparison]::Ordinal)
        $manualCargoIndex = $manualHelper.IndexOf('Assert-CMTraceCargoConfigurationBoundary -WorkingDirectory $Source', $manualSourceIndex, [StringComparison]::Ordinal)
        $manualToolchainIndex = $manualHelper.IndexOf('Assert-CMTraceActiveRustToolchain -WorkingDirectory $Source', $manualCargoIndex, [StringComparison]::Ordinal)
        $manualStartIndex = $manualHelper.IndexOf('$StartInfo = [Diagnostics.ProcessStartInfo]::new()', $manualToolchainIndex, [StringComparison]::Ordinal)
        $manualGuardIndex = $manualHelper.IndexOf('$TargetGuard = Open-CMTraceGuardedReadFile', $manualStartIndex, [StringComparison]::Ordinal)
        $manualOutputCreateIndex = $manualHelper.IndexOf('$StdoutStream = [IO.File]::Open($StdoutPath', $manualGuardIndex, [StringComparison]::Ordinal)
        $manualReadyIndex = $manualHelper.IndexOf('[void]$OwnedLaunch.ReadyEvent.Set()', $manualOutputCreateIndex, [StringComparison]::Ordinal)
        $manualTargetStartedIndex = $manualHelper.IndexOf('Wait-CMTraceOwnedTargetStarted', $manualReadyIndex, [StringComparison]::Ordinal)
        $manualGuardReleaseIndex = $manualHelper.IndexOf('$TargetGuard.Stream.Dispose()', $manualTargetStartedIndex, [StringComparison]::Ordinal)
        $manualSourceIndex | Should -BeGreaterThan -1
        $manualCargoIndex | Should -BeGreaterThan $manualSourceIndex
        $manualToolchainIndex | Should -BeGreaterThan $manualCargoIndex
        $manualStartIndex | Should -BeGreaterThan $manualToolchainIndex
        $manualGuardIndex | Should -BeGreaterThan $manualStartIndex
        $manualOutputCreateIndex | Should -BeGreaterThan $manualGuardIndex
        $manualReadyIndex | Should -BeGreaterThan $manualOutputCreateIndex
        $manualTargetStartedIndex | Should -BeGreaterThan $manualReadyIndex
        $manualGuardReleaseIndex | Should -BeGreaterThan $manualTargetStartedIndex
        $manualHelper | Should -Match ([regex]::Escape('[AllowEmptyString()][string]$ExpectedSha256'))
        $manualHelper | Should -Match ([regex]::Escape('[int64]$ExpectedBytes = -1'))
        $manualHelper | Should -Match ([regex]::Escape('$OwnedLaunch.TargetStartedEvent.Dispose()'))
        $manualHelper | Should -Match ([regex]::Escape("`$ChildEnvironment.GIT_NO_REPLACE_OBJECTS = '1'"))
    }

    It 'defines privacy-bounded three-run Intune medians' {
        $manual = Get-Content -LiteralPath (Join-Path $script:HandoffRoot 'manual-results.template.json') -Raw | ConvertFrom-Json
        $matrix = Get-Content -LiteralPath (Join-Path $script:HandoffRoot 'VALIDATION-MATRIX.md') -Raw
        $gate = @($manual.gates | Where-Object { $_.id -ceq 'performance-intune-description-resolution' })
        $gate.Count | Should -Be 1
        $gate[0].requiredEvidence | Should -Match ([regex]::Escape('exact medians'))
        $gate[0].requiredEvidence | Should -Match ([regex]::Escape('target-local proof'))
        foreach ($name in @('intuneDescriptionResolutionMilliseconds', 'intunePeakWorkingSetBytes', 'intuneDescriptionsResolved', 'intuneDescriptionsMissing')) {
            $matrix | Should -Match ([regex]::Escape($name))
        }
        $matrix | Should -Match ([regex]::Escape('exact median of each corresponding three-value series'))
        $matrix | Should -Match ([regex]::Escape('all three per-run values and private output hashes'))
        $matrix | Should -Match ([regex]::Escape('only the four medians return'))
    }

    It 'documents fail-closed private recovery and exact evidence discriminators' {
        $readme = Get-Content -LiteralPath (Join-Path $script:HandoffRoot 'README.md') -Raw
        $privateEvtxMarker = '$PrivateEvtx = Join-Path $Evidence ''raw-artifacts\private-evtx'''
        $privateEvtxIndex = $readme.IndexOf($privateEvtxMarker, [StringComparison]::Ordinal)
        $privateEvtxIndex | Should -BeGreaterThan -1
        $privateEvtxGuardIndex = $readme.IndexOf('if (Test-Path -LiteralPath $PrivateEvtx -PathType Any)', $privateEvtxIndex, [StringComparison]::Ordinal)
        $privateEvtxGuardIndex | Should -BeGreaterThan $privateEvtxIndex
        $privateEvtxCreateIndex = $readme.IndexOf('New-Item -ItemType Directory -Path $PrivateEvtx', $privateEvtxGuardIndex, [StringComparison]::Ordinal)
        $privateEvtxCreateIndex | Should -BeGreaterThan $privateEvtxGuardIndex
        $readme | Should -Match ([regex]::Escape("'Application', `$Export, '/ow:false'"))
        $readme | Should -Not -Match ([regex]::Escape("'Application', `$Export, '/ow:true'"))
        $readme | Should -Match ([regex]::Escape('if ($Process.HasExited) { Start-Sleep -Milliseconds 100 }'))
        $readme | Should -Match ([regex]::Escape("`$Preflight = 'C:\cmtraceopen-validation\preflight-pr583-arm64-001.json'"))
        $readme | Should -Match ([regex]::Escape('preflight-pr583-arm64-002.json'))

        $matrix = Get-Content -LiteralPath (Join-Path $script:HandoffRoot 'VALIDATION-MATRIX.md') -Raw
        $matrix | Should -Match ([regex]::Escape("`$InputRoot = Join-Path ([IO.Path]::GetPathRoot(`$Source)) 'cmtraceopen-input'"))
        $matrix | Should -Match ([regex]::Escape("`$AuthorizedMdmBundle = Join-Path `$InputRoot 'MDMDiagReport.zip'"))
        $matrix | Should -Match ([regex]::Escape('regular, non-reparse file at `cmtraceopen-input\MDMDiagReport.zip` on the same fixed local NTFS volume as `$Source`'))
        $mdmFixedPathIndex = $matrix.IndexOf('$AuthorizedMdmPath = Assert-CMTraceFixedLocalNtfsPath', [StringComparison]::Ordinal)
        $mdmContainmentIndex = $matrix.IndexOf('$AuthorizedMdmPath = Assert-CMTracePathWithinRoot', [StringComparison]::Ordinal)
        $mdmGetItemIndex = $matrix.IndexOf('$AuthorizedMdmEntry = Get-Item', [StringComparison]::Ordinal)
        $mdmFixedPathIndex | Should -BeGreaterThan -1
        $mdmContainmentIndex | Should -BeGreaterThan $mdmFixedPathIndex
        $mdmGetItemIndex | Should -BeGreaterThan $mdmContainmentIndex
        $matrix | Should -Match ([regex]::Escape('-Root $InputRoot -Label ''Authorized MDMDiagReport.zip'''))
        $matrix | Should -Match ([regex]::Escape("Where-Object { `$_.kind -ceq 'windows-build-provenance' }"))
        $matrix | Should -Match ([regex]::Escape("Where-Object { `$_.kind -ceq 'nsis-installer' }"))
        $matrix | Should -Match ([regex]::Escape("Where-Object { `$_.bundleType -ceq 'nsis' }"))
        $readme | Should -Match ([regex]::Escape("`$PrivateCliRoot = Join-Path `$Evidence 'raw-artifacts\private-event-log-export'"))
        $readme | Should -Match ([regex]::Escape("'--target-dir', `$CliTargetDir"))
        $readme | Should -Match ([regex]::Escape('Get-CMTraceVerifiedArm64Executable -Path $CliPath -Root $PrivateCliRoot'))
        $readme | Should -Match ([regex]::Escape('-ExpectedSha256 $FullArtifact.Sha256 -ExpectedBytes $FullArtifact.Bytes'))
        $readme | Should -Match ([regex]::Escape('-ExpectedSha256 $LiteArtifact.Sha256 -ExpectedBytes $LiteArtifact.Bytes'))
        $readme | Should -Match ([regex]::Escape('-FilePath $CliBinding.Path -ExpectedSha256 $CliBinding.Sha256 -ExpectedBytes $CliBinding.Bytes'))
        $common = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'CMTraceOpenArm64Handoff.Common.ps1') -Raw
        $common | Should -Match ([regex]::Escape('function Get-CMTraceContentBinding'))
        $readme | Should -Match ([regex]::Escape('-ContentBindings $FixtureBindings'))
        $readme | Should -Match ([regex]::Escape('-ContentBindings @($CleanEvtxBinding)'))
        $readme | Should -Match ([regex]::Escape('-ContentBindings @($FixtureBinding)'))
        $readme | Should -Match ([regex]::Escape("if (`$RecoveryEntries.Count -ne 7) { throw 'Expected exactly seven private recovery EVTX files.' }"))
        $readme | Should -Match ([regex]::Escape('-ContentBindings $RecoveryBindings'))
        $readme | Should -Match ([regex]::Escape("Invoke-PrivateProcess -Id 'private-recovery-full-ui'"))
        $readme | Should -Match ([regex]::Escape('-ContentBindings @($ProviderScriptBinding)'))
        $matrix | Should -Match ([regex]::Escape('Reuse its `$PrivateEventLogExport` binding and `$PrivateCliRoot`'))
        $matrix | Should -Match ([regex]::Escape('Get-CMTraceVerifiedArm64Executable -Path $ResolvedPrivateCliPath -Root $ResolvedPrivateCliRoot'))
        $matrix | Should -Match ([regex]::Escape('-FilePath $MdmCliBinding.Path'))
        $matrix | Should -Match ([regex]::Escape('-ExpectedSha256 $MdmCliBinding.Sha256 -ExpectedBytes $MdmCliBinding.Bytes'))
        $matrix | Should -Match ([regex]::Escape('-ContentBindings @($MdmBundleBinding)'))
        $matrix | Should -Match ([regex]::Escape("Invoke-PrivateProcess -Id 'private-mdmdiag-full-ui'"))
        $matrix | Should -Match ([regex]::Escape('-ContentBindings @($SourceFixtureBinding)'))
        $matrix | Should -Match ([regex]::Escape("Invoke-PrivateProcess -Id 'private-structural-full-ui'"))
        $matrix | Should -Match ([regex]::Escape('-ContentBindings $StructuralFixtureBindings'))
        $matrix | Should -Match ([regex]::Escape("Get-CMTraceContentBinding -Path `$UnsafeStructuralZip -Label 'Private unsafe duplicate structural ZIP'"))
        $matrix | Should -Match ([regex]::Escape("Get-CMTraceContentBinding -Path `$MemberLimitStructuralZip -Label 'Private 513-member structural ZIP'"))
        $matrix | Should -Match ([regex]::Escape("if (`$Junctions.Count -ne 5) { throw 'Expected exactly five structural child-error junctions.' }"))
        $matrix | Should -Match ([regex]::Escape('-ExpectedSha256 $PrivateNsisSha256 -ExpectedBytes $PrivateNsisEntry.Length'))
        $matrix | Should -Match ([regex]::Escape('-ContentBindings $InstalledProviderContentBindings'))
        $matrix | Should -Match ([regex]::Escape('-ExpectedSha256 $Expected.sha256 -ExpectedBytes $Expected.bytes'))
        $matrix | Should -Match ([regex]::Escape('-FilePath $ScanBinding.Path -ExpectedSha256 $ScanBinding.Sha256 -ExpectedBytes $ScanBinding.Bytes'))
        $matrix | Should -Match ([regex]::Escape('-ExpectedSha256 $FullArtifact.Sha256 -ExpectedBytes $FullArtifact.Bytes'))
        foreach ($document in @($readme, $matrix)) {
            $document | Should -Not -Match ([regex]::Escape("`$Source 'src-tauri\target\aarch64-pc-windows-msvc\debug\event-log-export.exe'"))
        }

        $cliRootIndex = $readme.IndexOf("`$PrivateCliRoot = Join-Path `$Evidence 'raw-artifacts\private-event-log-export'", [StringComparison]::Ordinal)
        $cliMustNotExistIndex = $readme.IndexOf('-MustNotExist', $cliRootIndex, [StringComparison]::Ordinal)
        $cliRootCreateIndex = $readme.IndexOf('New-Item -ItemType Directory -Path $PrivateCliRoot -ErrorAction Stop', $cliMustNotExistIndex, [StringComparison]::Ordinal)
        $cliTargetCreateIndex = $readme.IndexOf('New-Item -ItemType Directory -Path $CliTargetDir -ErrorAction Stop', $cliRootCreateIndex, [StringComparison]::Ordinal)
        $preBuildSourceIndex = $readme.IndexOf('[void](Assert-CMTraceSourceIntegrity -RepositoryPath $Source)', $cliTargetCreateIndex, [StringComparison]::Ordinal)
        $cliBuildIndex = $readme.IndexOf("`$CliBuild = Invoke-PrivateProcess -Id 'event-log-export-build'", $preBuildSourceIndex, [StringComparison]::Ordinal)
        $cliTargetArgumentIndex = $readme.IndexOf("'--target-dir', `$CliTargetDir", $cliBuildIndex, [StringComparison]::Ordinal)
        $postBuildSourceIndex = $readme.IndexOf('[void](Assert-CMTraceSourceIntegrity -RepositoryPath $Source)', $cliTargetArgumentIndex, [StringComparison]::Ordinal)
        $cliBindingIndex = $readme.IndexOf('$PrivateEventLogExport = Get-CMTraceVerifiedArm64Executable', $postBuildSourceIndex, [StringComparison]::Ordinal)
        $recoveryLoopIndex = $readme.IndexOf('foreach ($Fixture in Get-ChildItem -LiteralPath $Recovery', $cliBindingIndex, [StringComparison]::Ordinal)
        $recoveryRecheckIndex = $readme.IndexOf('Get-CMTraceVerifiedArm64Executable -Path $PrivateEventLogExport.Path', $recoveryLoopIndex, [StringComparison]::Ordinal)
        $recoveryLaunchIndex = $readme.IndexOf('$CliResult = Invoke-PrivateProcess', $recoveryRecheckIndex, [StringComparison]::Ordinal)
        $cliRootIndex | Should -BeGreaterThan -1
        $cliMustNotExistIndex | Should -BeGreaterThan $cliRootIndex
        $cliRootCreateIndex | Should -BeGreaterThan $cliMustNotExistIndex
        $cliTargetCreateIndex | Should -BeGreaterThan $cliRootCreateIndex
        $preBuildSourceIndex | Should -BeGreaterThan $cliTargetCreateIndex
        $cliBuildIndex | Should -BeGreaterThan $preBuildSourceIndex
        $cliTargetArgumentIndex | Should -BeGreaterThan $cliBuildIndex
        $postBuildSourceIndex | Should -BeGreaterThan $cliTargetArgumentIndex
        $cliBindingIndex | Should -BeGreaterThan $postBuildSourceIndex
        $recoveryLoopIndex | Should -BeGreaterThan $cliBindingIndex
        $recoveryRecheckIndex | Should -BeGreaterThan $recoveryLoopIndex
        $recoveryLaunchIndex | Should -BeGreaterThan $recoveryRecheckIndex

        $mdmExpectedRootIndex = $matrix.IndexOf("`$ExpectedPrivateCliRoot = [IO.Path]::GetFullPath((Join-Path `$Evidence 'raw-artifacts\private-event-log-export'))", [StringComparison]::Ordinal)
        $mdmResolvedRootIndex = $matrix.IndexOf('$ResolvedPrivateCliRoot = (Resolve-Path -LiteralPath $PrivateCliRoot).Path', $mdmExpectedRootIndex, [StringComparison]::Ordinal)
        $mdmContainmentIndex = $matrix.IndexOf('Assert-CMTracePathWithinRoot -Path $ResolvedPrivateCliPath -Root $ResolvedPrivateCliRoot', $mdmResolvedRootIndex, [StringComparison]::Ordinal)
        $mdmBindingIndex = $matrix.IndexOf('$MdmCliBinding = Get-CMTraceVerifiedArm64Executable', $mdmContainmentIndex, [StringComparison]::Ordinal)
        $mdmLaunchIndex = $matrix.IndexOf("`$MdmResult = Invoke-PrivateProcess -Id 'private-mdmdiag-cli'", [StringComparison]::Ordinal)
        $mdmExpectedRootIndex | Should -BeGreaterThan -1
        $mdmResolvedRootIndex | Should -BeGreaterThan $mdmExpectedRootIndex
        $mdmContainmentIndex | Should -BeGreaterThan $mdmResolvedRootIndex
        $mdmBindingIndex | Should -BeGreaterThan $mdmContainmentIndex
        $mdmLaunchIndex | Should -BeGreaterThan $mdmBindingIndex

        $scanRootIndex = $matrix.IndexOf("`$PrivateScanRoot = Join-Path `$Evidence 'raw-artifacts\private-evtx-scan'", [StringComparison]::Ordinal)
        $scanMustNotExistIndex = $matrix.IndexOf('-MustNotExist', $scanRootIndex, [StringComparison]::Ordinal)
        $scanTargetCreateIndex = $matrix.IndexOf('New-Item -ItemType Directory -Path $ScanTargetDir -ErrorAction Stop', $scanMustNotExistIndex, [StringComparison]::Ordinal)
        $scanPreBuildSourceIndex = $matrix.IndexOf('[void](Assert-CMTraceSourceIntegrity -RepositoryPath $Source)', $scanTargetCreateIndex, [StringComparison]::Ordinal)
        $scanBuildIndex = $matrix.IndexOf("`$ScanBuild = Invoke-PrivateProcess -Id 'evtx-scan-build'", $scanPreBuildSourceIndex, [StringComparison]::Ordinal)
        $scanTargetArgumentIndex = $matrix.IndexOf("'--target-dir', `$ScanTargetDir", $scanBuildIndex, [StringComparison]::Ordinal)
        $scanPostBuildSourceIndex = $matrix.IndexOf('[void](Assert-CMTraceSourceIntegrity -RepositoryPath $Source)', $scanTargetArgumentIndex, [StringComparison]::Ordinal)
        $scanBindingIndex = $matrix.IndexOf('$PrivateEvtxScan = Get-CMTraceVerifiedArm64Executable', $scanPostBuildSourceIndex, [StringComparison]::Ordinal)
        $scanLoopIndex = $matrix.IndexOf('for ($Run = 1; $Run -le 3; $Run++)', $scanBindingIndex, [StringComparison]::Ordinal)
        $scanRecheckIndex = $matrix.IndexOf('Get-CMTraceVerifiedArm64Executable -Path $PrivateEvtxScan.Path', $scanLoopIndex, [StringComparison]::Ordinal)
        $scanLaunchIndex = $matrix.IndexOf('$Result = Invoke-PrivateProcess', $scanRecheckIndex, [StringComparison]::Ordinal)
        $scanRootIndex | Should -BeGreaterThan -1
        $scanMustNotExistIndex | Should -BeGreaterThan $scanRootIndex
        $scanTargetCreateIndex | Should -BeGreaterThan $scanMustNotExistIndex
        $scanPreBuildSourceIndex | Should -BeGreaterThan $scanTargetCreateIndex
        $scanBuildIndex | Should -BeGreaterThan $scanPreBuildSourceIndex
        $scanTargetArgumentIndex | Should -BeGreaterThan $scanBuildIndex
        $scanPostBuildSourceIndex | Should -BeGreaterThan $scanTargetArgumentIndex
        $scanBindingIndex | Should -BeGreaterThan $scanPostBuildSourceIndex
        $scanLoopIndex | Should -BeGreaterThan $scanBindingIndex
        $scanRecheckIndex | Should -BeGreaterThan $scanLoopIndex
        $scanLaunchIndex | Should -BeGreaterThan $scanRecheckIndex
        $matrix | Should -Not -Match ([regex]::Escape("Join-Path `$Source 'src-tauri\target\aarch64-pc-windows-msvc\release\examples\evtx_scan.exe'"))

        $common = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'CMTraceOpenArm64Handoff.Common.ps1') -Raw
        $runner = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'Invoke-CMTraceOpenArm64Validation.ps1') -Raw
        ([regex]::Matches($common, '(?m)^function Get-CMTracePEMachine \{')).Count | Should -Be 1
        $runner | Should -Not -Match '(?m)^function Get-CMTracePEMachine \{'
        $runner | Should -Match ([regex]::Escape('Get-CMTracePEMachine -Path $artifact.Path'))
        foreach ($artifactKind in @('installDirectory', 'arpRecord', 'startMenuShortcut', 'desktopShortcut')) {
            $matrix | Should -Match ([regex]::Escape("$artifactKind = [int](Test-Path"))
        }
        $matrix | Should -Match ([regex]::Escape('Owned Full artifacts remain after ordinary uninstall by kind and count:'))
        $providerObservationIndex = $matrix.IndexOf('The next command blocks until the installed Full process exits.', [StringComparison]::Ordinal)
        $providerLaunchIndex = $matrix.IndexOf("`$ProviderResourceResult = Invoke-PrivateProcess -Id 'installed-provider-packaged-resource'", [StringComparison]::Ordinal)
        $providerObservationIndex | Should -BeGreaterThan -1
        $providerLaunchIndex | Should -BeGreaterThan $providerObservationIndex
    }

    It 'reestablishes session state before source and preflight execution' {
        $readme = Get-Content -LiteralPath (Join-Path $script:HandoffRoot 'README.md') -Raw
        $codexPrompt = Get-Content -LiteralPath (Join-Path $script:HandoffRoot 'CODEX-PROMPT.txt') -Raw
        $securityNotes = Get-Content -LiteralPath (Join-Path $script:HandoffRoot 'SECURITY-NOTES.md') -Raw
        $readme | Should -Match ([regex]::Escape('prerequisite installation or elevation'))
        $readme | Should -Match ([regex]::Escape('If Git is absent, stop for approval before installing it'))
        $codexPrompt | Should -Match ([regex]::Escape('Stop for prerequisite installation or elevation'))
        $securityNotes | Should -Match ([regex]::Escape('prerequisite installation or elevation'))
        $sourceSectionStart = $readme.IndexOf('## 3. Initialize the exact source', [StringComparison]::Ordinal)
        $sourceSectionEnd = $readme.IndexOf('## 4. Install prerequisites after approval', [StringComparison]::Ordinal)
        $sourceSectionStart | Should -BeGreaterThan -1
        $sourceSectionEnd | Should -BeGreaterThan $sourceSectionStart
        $sourceSection = $readme.Substring($sourceSectionStart, $sourceSectionEnd - $sourceSectionStart)
        $sourceHandoffIndex = $sourceSection.IndexOf("`$Handoff = 'C:\CMTraceOpen-Handoff\pr583-arm64'", [StringComparison]::Ordinal)
        $sourcePathIndex = $sourceSection.IndexOf("`$Source = 'C:\src\cmtraceopen-pr583-arm64'", [StringComparison]::Ordinal)
        $sourceTempIndex = $sourceSection.IndexOf("`$env:TEMP = 'C:\cmtraceopen-validation\temp'", [StringComparison]::Ordinal)
        $initializerIndex = $sourceSection.IndexOf('Initialize-CMTraceOpenArm64Source.ps1', [StringComparison]::Ordinal)
        $sourceHandoffIndex | Should -BeGreaterThan -1
        $sourcePathIndex | Should -BeGreaterThan $sourceHandoffIndex
        $sourceTempIndex | Should -BeGreaterThan $sourcePathIndex
        $initializerIndex | Should -BeGreaterThan $sourceTempIndex

        $preflightSectionStart = $readme.IndexOf('## 5. Run preflight', [StringComparison]::Ordinal)
        $preflightSectionEnd = $readme.IndexOf('## 6. Run the automatic plan', [StringComparison]::Ordinal)
        $preflightSectionStart | Should -BeGreaterThan -1
        $preflightSectionEnd | Should -BeGreaterThan $preflightSectionStart
        $readme | Should -Match ([regex]::Escape("Invoke-WebRequest -Uri 'https://www.powershellgallery.com/api/v2/package/Pester/5.7.1'"))
        $readme | Should -Match ([regex]::Escape("if (`$PesterPackageGuard.Length -ne 325233)"))
        $readme | Should -Match ([regex]::Escape("'4a27904c6814a5fbe4758f8e49861f6a1994aee77b71165a5c43c0371ba6c580'"))
        $readme | Should -Match ([regex]::Escape('[IO.Compression.ZipFile]::ExtractToDirectory($PesterPackageGuard, $PesterModuleRoot, $false)'))
        $readme | Should -Match ([regex]::Escape("'https://www.powershellgallery.com/api/v2'"))
        $readme | Should -Not -Match ([regex]::Escape('Install-Module Pester'))
        $readme | Should -Not -Match ([regex]::Escape('Save-Module Pester'))
        $common = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'CMTraceOpenArm64Handoff.Common.ps1') -Raw
        $preflight = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'Test-CMTraceOpenArm64Preflight.ps1') -Raw
        $runner = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'Invoke-CMTraceOpenArm64Validation.ps1') -Raw
        $common | Should -Match ([regex]::Escape('function Get-CMTraceTrustedPesterModule'))
        $common | Should -Match ([regex]::Escape("`$script:CMTraceExpectedPesterPackageBytes = 325233L"))
        $common | Should -Match ([regex]::Escape("`$script:CMTraceExpectedPesterPackageSha256 = '4a27904c6814a5fbe4758f8e49861f6a1994aee77b71165a5c43c0371ba6c580'"))
        $common | Should -Match ([regex]::Escape('[IO.Compression.ZipArchive]::new('))
        $common | Should -Match ([regex]::Escape('Test-ModuleManifest -Path $manifestPath'))
        $common | Should -Match ([regex]::Escape('ContentBindings = [object[]]$contentBindings.ToArray()'))
        $preflight | Should -Match ([regex]::Escape('-ContentBindings $trustedPester.ContentBindings'))
        $preflight | Should -Match ([regex]::Escape('-ContentBindings $pesterContentBindings'))
        $runner | Should -Match ([regex]::Escape('-ContentBindings $installerPester.ContentBindings'))
        $runner | Should -Match ([regex]::Escape('-ContentBindings $collectorPester.ContentBindings'))
        $runner | Should -Match ([regex]::Escape('-ContentBindings $trustedPester.ContentBindings -Label ''Pester'''))
        $runner | Should -Match ([regex]::Escape("`$unsignedConfigBinding = Get-CMTraceContentBinding -Path `$unsignedConfig -Label 'Sealed unsigned Tauri validation configuration'"))
        $runner | Should -Match ([regex]::Escape('-ContentBindings @($unsignedConfigBinding)'))
        $common | Should -Not -Match ([regex]::Escape('Get-InstalledModule -Name Pester'))
        foreach ($consumer in @($preflight, $runner)) {
            $consumer | Should -Match ([regex]::Escape("Import-Module -Name '"))
            $consumer | Should -Match ([regex]::Escape('-RequiredVersion ''$($trustedPester.Version)'''))
            $consumer | Should -Not -Match ([regex]::Escape('Import-Module Pester -MinimumVersion'))
        }
        $preflightSection = $readme.Substring($preflightSectionStart, $preflightSectionEnd - $preflightSectionStart)
        $requiredMarkers = @(
            "`$Handoff = 'C:\CMTraceOpen-Handoff\pr583-arm64'",
            "`$Source = 'C:\src\cmtraceopen-pr583-arm64'",
            "`$Evidence = 'C:\cmtraceopen-validation\runs\pr583-arm64-001'",
            "`$Preflight = 'C:\cmtraceopen-validation\preflight-pr583-arm64-001.json'",
            "`$env:TEMP = 'C:\cmtraceopen-validation\temp'",
            '$env:TMP = $env:TEMP',
            'Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force',
            'Test-CMTraceOpenArm64Preflight.ps1'
        )
        $previousIndex = -1
        foreach ($marker in $requiredMarkers) {
            $currentIndex = $preflightSection.IndexOf($marker, [StringComparison]::Ordinal)
            $currentIndex | Should -BeGreaterThan $previousIndex -Because "$marker must be initialized in execution order"
            $previousIndex = $currentIndex
        }
    }

    It 'requires PowerShell 7.5 and enforces owned disjoint deterministic return paths' {
        $returnScript = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'New-CMTraceOpenArm64ValidationReturn.ps1') -Raw
        $common = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'CMTraceOpenArm64Handoff.Common.ps1') -Raw
        $versionGuardIndex = $returnScript.IndexOf("if (`$PSVersionTable.PSVersion -lt [version]'7.5.0')", [StringComparison]::Ordinal)
        $dateKindIndex = $returnScript.IndexOf('ConvertFrom-Json -Depth 25 -DateKind String', [StringComparison]::Ordinal)
        $versionGuardIndex | Should -BeGreaterThan -1
        $dateKindIndex | Should -BeGreaterThan $versionGuardIndex
        $returnScript | Should -Match '\$script:CMTraceAutomaticGateIds\.Count\) automatic gates'
        foreach ($marker in @(
            '$stagingRootOwned = $false',
            '$verifyRootOwned = $false',
            '$publicationRootOwned = $false',
            'Assert-CMTraceSafeTemporaryRoot -ForbiddenRoots',
            '$resolvedRepository',
            '$inputRoot',
            'Get-CMTraceOrdinalSortedString',
            'Write-CMTraceNewText -Text $sidecarOwnedText -Path $sidecarCandidate',
            '[IO.File]::Move($archiveCandidate, $fullOutput, $false)',
            '[IO.File]::Move($sidecarCandidate, "$fullOutput.sha256", $false)',
            '$returnFailure = $null',
            '$returnFailure = $_',
            'Cleanup also failed:',
            '[AggregateException]::new',
            'throw $returnFailure'
        )) {
            $returnScript | Should -Match ([regex]::Escape($marker))
        }
        $returnScript | Should -Not -Match 'Set-Content -LiteralPath "\$fullOutput\.sha256"'
        $returnScript | Should -Not -Match 'New-CMTraceDeterministicZip[^\r\n]+-DestinationPath \$fullOutput'
        $returnScript | Should -Not -Match 'Remove-Item -LiteralPath "?\$fullOutput'
        ([regex]::Matches($returnScript, [regex]::Escape("Assert-CMTraceNoReparsePath -Path `$fullOutput -Label 'Published return ZIP'"))).Count | Should -Be 2

        $candidateBuildIndex = $returnScript.IndexOf('New-CMTraceDeterministicZip -SourceRoot $stagingRoot -DestinationPath $archiveCandidate', [StringComparison]::Ordinal)
        $candidateHashIndex = $returnScript.IndexOf('$outerHash = Get-CMTraceSha256 -Path $archiveCandidate', [StringComparison]::Ordinal)
        $candidateAuditIndex = $returnScript.IndexOf('Assert-CMTraceReturnZipContract -Path $archiveCandidate', [StringComparison]::Ordinal)
        $manifestBindingIndex = $returnScript.IndexOf("Get-CMTraceSha256 -Path (Join-Path `$verifyRoot 'SHA256SUMS.txt')", [StringComparison]::Ordinal)
        $freshChecksumIndex = $returnScript.IndexOf("Assert-CMTraceChecksumInventory -Root `$verifyRoot -Context 'Freshly extracted return'", [StringComparison]::Ordinal)
        $candidateVerificationHashIndex = $returnScript.IndexOf('Get-CMTraceSha256 -Path $archiveCandidate', $freshChecksumIndex, [StringComparison]::Ordinal)
        $finalSourceIndex = $returnScript.LastIndexOf('Assert-CMTraceSourceIntegrity -RepositoryPath $resolvedRepository', [StringComparison]::Ordinal)
        $finalLiveIndex = $returnScript.LastIndexOf('Assert-CMTraceLivePullRequest', [StringComparison]::Ordinal)
        $candidatePrePublicationHashIndex = $returnScript.IndexOf('Get-CMTraceSha256 -Path $archiveCandidate', $finalLiveIndex, [StringComparison]::Ordinal)
        $publishIndex = $returnScript.IndexOf('[IO.File]::Move($archiveCandidate, $fullOutput, $false)', [StringComparison]::Ordinal)
        $sidecarPublishIndex = $returnScript.IndexOf('[IO.File]::Move($sidecarCandidate, "$fullOutput.sha256", $false)', [StringComparison]::Ordinal)
        $publicZipReadbackIndex = $returnScript.IndexOf('Get-CMTraceSha256 -Path $fullOutput', $publishIndex, [StringComparison]::Ordinal)
        $publicSidecarReadbackIndex = $returnScript.IndexOf('[IO.File]::ReadAllText("$fullOutput.sha256", [Text.Encoding]::ASCII)', $sidecarPublishIndex, [StringComparison]::Ordinal)
        $candidateBuildIndex | Should -BeGreaterThan -1
        $candidateHashIndex | Should -BeGreaterThan $candidateBuildIndex
        $candidateAuditIndex | Should -BeGreaterThan $candidateHashIndex
        $manifestBindingIndex | Should -BeGreaterThan $candidateAuditIndex
        $freshChecksumIndex | Should -BeGreaterThan $candidateAuditIndex
        $candidateVerificationHashIndex | Should -BeGreaterThan $freshChecksumIndex
        $finalSourceIndex | Should -BeGreaterThan $freshChecksumIndex
        $finalLiveIndex | Should -BeGreaterThan $finalSourceIndex
        $candidatePrePublicationHashIndex | Should -BeGreaterThan $finalLiveIndex
        $publishIndex | Should -BeGreaterThan $candidatePrePublicationHashIndex
        $publicZipReadbackIndex | Should -BeGreaterThan $publishIndex
        $sidecarPublishIndex | Should -BeGreaterThan $publicZipReadbackIndex
        $publicSidecarReadbackIndex | Should -BeGreaterThan $sidecarPublishIndex
        $returnScript | Should -Match ([regex]::Escape('[IO.Compression.ZipFile]::OpenRead($Path)'))
        $common | Should -Match ([regex]::Escape("`$script:CMTraceExpectedTemporaryRoot = 'C:\cmtraceopen-validation\temp'"))
        $common | Should -Not -Match '\$underTemporaryRoot'
    }

    It 'normalizes supported tool versions and rejects ambiguous or unsupported producer output' {
        $valid = @(
            [pscustomobject]@{ Tool = 'PowerShell'; Text = '7.5.0'; Expected = '7.5.0' },
            [pscustomobject]@{ Tool = 'Git'; Text = 'git version 2.51.0.windows.1'; Expected = '2.51.0.windows.1' },
            [pscustomobject]@{ Tool = 'Node'; Text = 'v22.18.0'; Expected = 'v22.18.0' },
            [pscustomobject]@{ Tool = 'Npm'; Text = '11.6.2'; Expected = '11.6.2' },
            [pscustomobject]@{ Tool = 'Rust'; Text = "rustc 1.89.0 (abc1234 2026-08-01)`nhost: aarch64-pc-windows-msvc"; Expected = 'rustc 1.89.0' },
            [pscustomobject]@{ Tool = 'Rustup'; Text = 'rustup 1.28.1 (abc1234 2025-03-05)'; Expected = '1.28.1' },
            [pscustomobject]@{ Tool = 'Rustup'; Text = 'rustup 1.29.0 (28d1352db 2026-03-05)'; Expected = '1.29.0' },
            [pscustomobject]@{ Tool = 'Rustup'; Text = 'rustup 1.29.0 :: 1.28.2+486 (732af7663 2026-02-02)'; Expected = '1.29.0' },
            [pscustomobject]@{ Tool = 'Pester'; Text = '5.7.1'; Expected = '5.7.1' },
            [pscustomobject]@{ Tool = 'CargoDeny'; Text = 'cargo-deny 0.19.0'; Expected = '0.19.0' },
            [pscustomobject]@{ Tool = 'CargoAudit'; Text = 'cargo-audit 0.22.2'; Expected = '0.22.2' },
            [pscustomobject]@{ Tool = 'Clang'; Text = "clang version 21.1.8`nTarget: aarch64-pc-windows-msvc"; Expected = '21.1.8' },
            [pscustomobject]@{ Tool = 'VisualStudio'; Text = '17.14.36310.24'; Expected = '17.14.36310.24' },
            [pscustomobject]@{ Tool = 'WindowsSdk'; Text = '10.0.26100.0'; Expected = '10.0.26100.0' },
            [pscustomobject]@{ Tool = 'WebView2'; Text = '139.0.3405.86'; Expected = '139.0.3405.86' }
        )
        foreach ($case in $valid) {
            ConvertTo-CMTraceNormalizedToolVersion -Tool $case.Tool -Text $case.Text | Should -BeExactly $case.Expected
        }

        foreach ($case in @(
            [pscustomobject]@{ Tool = 'Git'; Text = "git version 2.51.0.windows.1`nextra" },
            [pscustomobject]@{ Tool = 'Node'; Text = 'v23.0.0' },
            [pscustomobject]@{ Tool = 'PowerShell'; Text = '7.4.9' },
            [pscustomobject]@{ Tool = 'Rustup'; Text = 'rustup 1.28.0 (6e19fbec7 2025-03-02)' },
            [pscustomobject]@{ Tool = 'Rustup'; Text = 'rustup 1.29.0' },
            [pscustomobject]@{ Tool = 'Rustup'; Text = 'rustup 1.29.0 :: 1.28.2 (732af7663 2026-02-02)' },
            [pscustomobject]@{ Tool = 'Pester'; Text = '4.10.1' },
            [pscustomobject]@{ Tool = 'VisualStudio'; Text = '16.11.99999.1' },
            [pscustomobject]@{ Tool = 'WindowsSdk'; Text = '10.0.22621.0' },
            [pscustomobject]@{ Tool = 'WebView2'; Text = '139.0.3405.86 beta' }
        )) {
            { ConvertTo-CMTraceNormalizedToolVersion -Tool $case.Tool -Text $case.Text } | Should -Throw
        }
    }

    It 'normalizes Windows command output and checks supported rustup before active-toolchain' {
        (ConvertTo-CMTraceNormalizedNativeOutput -Text "first`r`nsecond`r`n") | Should -BeExactly "first`nsecond"
        $targetOutput = ConvertTo-CMTraceNormalizedNativeOutput -Text "aarch64-pc-windows-msvc`r`nwasm32-unknown-unknown`r`n"
        @($targetOutput -split "`n") | Should -Contain 'aarch64-pc-windows-msvc'
        @($targetOutput -split "`n") | Should -Contain 'wasm32-unknown-unknown'
        $rustVerboseOutput = ConvertTo-CMTraceNormalizedNativeOutput -Text "rustc 1.88.0`r`nhost: aarch64-pc-windows-msvc`r`n"
        $rustVerboseOutput | Should -Match '(?m)^host: aarch64-pc-windows-msvc$'

        $rustupStdout = "rustup 1.29.0 (28d1352db 2026-03-05)`r`n"
        $rustupStderr = "info: This is the version for the rustup toolchain manager, not the rustc compiler.`r`ninfo: the currently active ``rustc`` version is ``rustc 1.92.0 (ded5c06cf 2025-12-08)```r`n"
        ConvertTo-CMTraceNormalizedRustupVersionEvidence -ExitCode 0 -StdOut $rustupStdout -StdErr $rustupStderr | Should -BeExactly '1.29.0'
        $rustupDevelopmentStdout = "rustup 1.29.0 :: 1.28.2+486 (732af7663 2026-02-02)`r`n"
        ConvertTo-CMTraceNormalizedRustupVersionEvidence -ExitCode 0 -StdOut $rustupDevelopmentStdout -StdErr $rustupStderr | Should -BeExactly '1.29.0'
        $rustup128Stdout = "rustup 1.28.1 (f9edccde0 2025-03-05)`r`n"
        $rustup128Stderr = "info: This is the version for the rustup toolchain manager, not the rustc compiler.`r`ninfo: The currently active ``rustc`` version is ``rustc 1.85.0 (4d91de4e4 2025-02-17)```r`n"
        ConvertTo-CMTraceNormalizedRustupVersionEvidence -ExitCode 0 -StdOut $rustup128Stdout -StdErr $rustup128Stderr | Should -BeExactly '1.28.1'
        $rustupNightlyStderr = "info: This is the version for the rustup toolchain manager, not the rustc compiler.`ninfo: The currently active ``rustc`` version is ``rustc 1.96.0-nightly (80d0e4be6 2026-03-25)```n"
        ConvertTo-CMTraceNormalizedRustupVersionEvidence -ExitCode 0 -StdOut $rustupStdout -StdErr $rustupNightlyStderr | Should -BeExactly '1.29.0'
        foreach ($rustcReadFailure in @('(timeout reading rustc version)', '(error reading rustc version)', '(rustc does not exist)')) {
            $failureStderr = "info: This is the version for the rustup toolchain manager, not the rustc compiler.`ninfo: the currently active ``rustc`` version is ``$rustcReadFailure```n"
            ConvertTo-CMTraceNormalizedRustupVersionEvidence -ExitCode 0 -StdOut $rustupStdout -StdErr $failureStderr | Should -BeExactly '1.29.0'
        }
        { ConvertTo-CMTraceNormalizedRustupVersionEvidence -ExitCode 0 -StdOut $rustupStdout -StdErr '' } | Should -Throw
        { ConvertTo-CMTraceNormalizedRustupVersionEvidence -ExitCode 0 -StdOut $rustupStdout -StdErr "$rustupStderr`nextra" } | Should -Throw
        { ConvertTo-CMTraceNormalizedRustupVersionEvidence -ExitCode 0 -StdOut $rustupStdout -StdErr "info: This is the version for the rustup toolchain manager, not the rustc compiler.`nwarning: unrelated" } | Should -Throw
        { ConvertTo-CMTraceNormalizedRustupVersionEvidence -ExitCode 1 -StdOut $rustupStdout -StdErr $rustupStderr } | Should -Throw

        $preflight = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'Test-CMTraceOpenArm64Preflight.ps1') -Raw
        $rustupVersionIndex = $preflight.IndexOf('ConvertTo-CMTraceNormalizedRustupVersionEvidence -ExitCode $rustupCapture.ExitCode', [StringComparison]::Ordinal)
        $activeToolchainIndex = $preflight.IndexOf("@('show', 'active-toolchain')", [StringComparison]::Ordinal)
        $rustupVersionIndex | Should -BeGreaterThan -1
        $activeToolchainIndex | Should -BeGreaterThan $rustupVersionIndex
        $preflight | Should -Match ([regex]::Escape('return ConvertTo-CMTraceNormalizedNativeOutput -Text $capture.StdOut'))
        $preflight | Should -Match ([regex]::Escape("'*returns the reserved wrapper failure exit for a target-start failure*'"))
        $preflight | Should -Match ([regex]::Escape("'*drains and classifies documented private-helper target-start failure*'"))
        $preflight | Should -Match ([regex]::Escape("'*drains and classifies private provider Cargo target-start failure*'"))
        $preflight | Should -Match ([regex]::Escape("'*delivers bounded standard input to an owned native child*'"))
        $preflight | Should -Match ([regex]::Escape("'*holds a guarded launch file against replacement until target-start release*'"))
        $preflight | Should -Match ([regex]::Escape('if (`$summary.selected -ne 7 -or `$summary.passed -ne 7'))
    }

    It 'requires exact child containment for reserved input paths' {
        $root = Join-Path $TestDrive 'cmtraceopen-input'
        $child = Join-Path $root 'MDMDiagReport.zip'
        $sibling = Join-Path $TestDrive 'CMTraceOpen-Return/MDMDiagReport.zip'
        $prefixCollision = "$root-other/MDMDiagReport.zip"
        Assert-CMTracePathWithinRoot -Path $child -Root $root -Label 'MDMDiag input' | Should -BeExactly ([IO.Path]::GetFullPath($child))
        { Assert-CMTracePathWithinRoot -Path $sibling -Root $root -Label 'MDMDiag input' } | Should -Throw
        { Assert-CMTracePathWithinRoot -Path $prefixCollision -Root $root -Label 'MDMDiag input' } | Should -Throw
        { Assert-CMTracePathWithinRoot -Path $root -Root $root -Label 'MDMDiag input' } | Should -Throw
    }

    It 'binds only contained native ARM64 PE files and detects byte replacement' {
        $testRoot = (Resolve-Path -LiteralPath $TestDrive).Path
        $root = Join-Path $testRoot 'arm64-pe-root'
        New-Item -ItemType Directory -Path $root | Out-Null

        function Write-SyntheticPe {
            param([string]$Path, [uint16]$Machine)
            $bytes = [byte[]]::new(128)
            $bytes[0] = 0x4D
            $bytes[1] = 0x5A
            [BitConverter]::GetBytes([int32]64).CopyTo($bytes, 0x3C)
            $bytes[64] = 0x50
            $bytes[65] = 0x45
            [BitConverter]::GetBytes($Machine).CopyTo($bytes, 68)
            [IO.File]::WriteAllBytes($Path, $bytes)
        }

        $arm64Path = Join-Path $root 'event-log-export.exe'
        Write-SyntheticPe -Path $arm64Path -Machine 0xAA64
        $binding = Get-CMTraceVerifiedArm64Executable -Path $arm64Path -Root $root
        $binding.PeMachine | Should -BeExactly '0xAA64'
        $binding.Bytes | Should -Be 128
        $binding.Sha256 | Should -BeExactly (Get-CMTraceSha256 -Path $arm64Path)
        { Get-CMTraceVerifiedArm64Executable -Path $arm64Path -Root $root -ExpectedSha256 $binding.Sha256 -ExpectedBytes $binding.Bytes } |
            Should -Not -Throw

        $mutated = [IO.File]::ReadAllBytes($arm64Path)
        $mutated[100] = 1
        [IO.File]::WriteAllBytes($arm64Path, $mutated)
        { Get-CMTraceVerifiedArm64Executable -Path $arm64Path -Root $root -ExpectedSha256 $binding.Sha256 -ExpectedBytes $binding.Bytes } |
            Should -Throw '*no longer matches*'

        $x64Path = Join-Path $root 'x64.exe'
        Write-SyntheticPe -Path $x64Path -Machine 0x8664
        { Get-CMTraceVerifiedArm64Executable -Path $x64Path -Root $root } | Should -Throw '*0x8664*'
        $shortPath = Join-Path $root 'short.exe'
        [IO.File]::WriteAllBytes($shortPath, [byte[]]@(0x4D, 0x5A))
        { Get-CMTraceVerifiedArm64Executable -Path $shortPath -Root $root } | Should -Throw '*too short*'

        $overlapPath = Join-Path $root 'overlapping-header.exe'
        $overlapBytes = [byte[]]::new(128)
        $overlapBytes[0] = 0x4D
        $overlapBytes[1] = 0x5A
        [BitConverter]::GetBytes([int32]2).CopyTo($overlapBytes, 0x3C)
        $overlapBytes[2] = 0x50
        $overlapBytes[3] = 0x45
        [BitConverter]::GetBytes([uint16]0xAA64).CopyTo($overlapBytes, 6)
        [IO.File]::WriteAllBytes($overlapPath, $overlapBytes)
        { Get-CMTraceVerifiedArm64Executable -Path $overlapPath -Root $root } | Should -Throw '*outside the file*'

        $outsidePath = Join-Path $testRoot 'outside-arm64.exe'
        Write-SyntheticPe -Path $outsidePath -Machine 0xAA64
        { Get-CMTraceVerifiedArm64Executable -Path $outsidePath -Root $root } | Should -Throw '*child*'
    }

    It 'rejects an ARM64 executable reached through a reparse ancestor' -Skip:(-not $script:CMTraceSymbolicLinkSupported) {
        $testRoot = (Resolve-Path -LiteralPath $TestDrive).Path
        $physicalRoot = Join-Path $testRoot 'physical-pe-root'
        New-Item -ItemType Directory -Path $physicalRoot | Out-Null
        $pePath = Join-Path $physicalRoot 'event-log-export.exe'
        $bytes = [byte[]]::new(128)
        $bytes[0] = 0x4D
        $bytes[1] = 0x5A
        [BitConverter]::GetBytes([int32]64).CopyTo($bytes, 0x3C)
        $bytes[64] = 0x50
        $bytes[65] = 0x45
        [BitConverter]::GetBytes([uint16]0xAA64).CopyTo($bytes, 68)
        [IO.File]::WriteAllBytes($pePath, $bytes)
        $linkedRoot = Join-Path $testRoot 'linked-pe-root'
        New-Item -ItemType SymbolicLink -Path $linkedRoot -Target $physicalRoot | Out-Null

        { Get-CMTraceVerifiedArm64Executable -Path (Join-Path $linkedRoot 'event-log-export.exe') -Root $linkedRoot } |
            Should -Throw '*reparse*'
    }

    It 'reserves owned-process wrapper failure without claiming a native exit' {
        $script:CMTraceOwnedProcessWrapperFailureExitCode | Should -Be 253
        (Test-CMTraceOwnedProcessWrapperFailureExitCode -ExitCode 253) | Should -BeTrue
        foreach ($exitCode in @(0, 1, 252, 254, $null)) {
            (Test-CMTraceOwnedProcessWrapperFailureExitCode -ExitCode $exitCode) | Should -BeFalse
        }

        $common = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'CMTraceOpenArm64Handoff.Common.ps1') -Raw
        $runner = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'Invoke-CMTraceOpenArm64Validation.ps1') -Raw
        $provider = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot 'New-CMTraceOpenPrivateProviderDatabase.ps1') -Raw
        $readme = Get-Content -LiteralPath (Join-Path $script:HandoffRoot 'README.md') -Raw

        $common | Should -Match ([regex]::Escape('exit $wrapperFailureExitCode'))
        $common | Should -Match ([regex]::Escape('Test-CMTraceOwnedProcessWrapperFailureExitCode -ExitCode $exitCode'))
        $captureHelperIndex = Get-OrderedTextMarkerIndex -Text $common -Marker 'function Invoke-CMTraceOwnedProcessCapture'
        $captureReadIndex = Get-OrderedTextMarkerIndex -Text $common -Marker '$stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdoutStream)' -AfterIndex $captureHelperIndex
        $captureReadyIndex = Get-OrderedTextMarkerIndex -Text $common -Marker '[void]$ownedLaunch.ReadyEvent.Set()' -AfterIndex $captureReadIndex
        $captureTargetWaitIndex = Get-OrderedTextMarkerIndex -Text $common -Marker 'Wait-CMTraceOwnedTargetStarted -OwnedLaunch $ownedLaunch -WrapperProcess $process' -AfterIndex $captureReadyIndex
        $captureInputIndex = Get-OrderedTextMarkerIndex -Text $common -Marker '$inputTask = $process.StandardInput.WriteAsync($StandardInputText)' -AfterIndex $captureTargetWaitIndex
        $captureReadIndex | Should -BeGreaterThan $captureHelperIndex
        $captureReadyIndex | Should -BeGreaterThan $captureReadIndex
        $captureTargetWaitIndex | Should -BeGreaterThan $captureReadyIndex
        $captureInputIndex | Should -BeGreaterThan $captureTargetWaitIndex
        $runnerReadIndex = Get-OrderedTextMarkerIndex -Text $runner -Marker '$stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdoutStream)'
        $runnerReadyIndex = Get-OrderedTextMarkerIndex -Text $runner -Marker '[void]$ownedLaunch.ReadyEvent.Set()' -AfterIndex $runnerReadIndex
        $runnerTargetWaitIndex = Get-OrderedTextMarkerIndex -Text $runner -Marker 'Wait-CMTraceOwnedTargetStarted -OwnedLaunch $ownedLaunch -WrapperProcess $process' -AfterIndex $runnerReadyIndex
        $runnerGuardReleaseIndex = Get-OrderedTextMarkerIndex -Text $runner -Marker '$targetGuard.Stream.Dispose()' -AfterIndex $runnerTargetWaitIndex
        $runnerReadIndex | Should -BeGreaterThan -1
        $runnerReadyIndex | Should -BeGreaterThan $runnerReadIndex
        $runnerTargetWaitIndex | Should -BeGreaterThan $runnerReadyIndex
        $runnerGuardReleaseIndex | Should -BeGreaterThan $runnerTargetWaitIndex
        $childStartIndex = $common.IndexOf('if (-not `$child.Start())', [StringComparison]::Ordinal)
        $targetStartedSignalIndex = $common.IndexOf('[void]`$targetStartedEvent.Set()', $childStartIndex, [StringComparison]::Ordinal)
        $childWaitIndex = $common.IndexOf('`$child.WaitForExit()', $targetStartedSignalIndex, [StringComparison]::Ordinal)
        $childStartIndex | Should -BeGreaterThan -1
        $targetStartedSignalIndex | Should -BeGreaterThan $childStartIndex
        $childWaitIndex | Should -BeGreaterThan $targetStartedSignalIndex
        $provider | Should -Match ([regex]::Escape('Test-CMTraceOwnedProcessWrapperFailureExitCode -ExitCode $exitCode'))

        $runnerRejectIndex = $runner.IndexOf('if (Test-CMTraceOwnedProcessWrapperFailureExitCode -ExitCode $exitCode)', [StringComparison]::Ordinal)
        $runnerRecordIndex = $runner.IndexOf('$rawText = @"', [StringComparison]::Ordinal)
        $runnerRejectIndex | Should -BeGreaterThan -1
        $runnerRecordIndex | Should -BeGreaterThan $runnerRejectIndex

        $privateHelperIndex = $readme.IndexOf('function Invoke-PrivateProcess', [StringComparison]::Ordinal)
        $readmeRejectIndex = $readme.IndexOf('(Test-CMTraceOwnedProcessWrapperFailureExitCode -ExitCode $ExitCode)', $privateHelperIndex, [StringComparison]::Ordinal)
        $readmeReturnIndex = $readme.IndexOf('return [pscustomobject]@{', $readmeRejectIndex, [StringComparison]::Ordinal)
        $privateStdoutReadIndex = $readme.IndexOf('$StdoutReadTask = $Process.StandardOutput.BaseStream.ReadAsync', $privateHelperIndex, [StringComparison]::Ordinal)
        $privateReadyIndex = $readme.IndexOf('[void]$OwnedLaunch.ReadyEvent.Set()', $privateStdoutReadIndex, [StringComparison]::Ordinal)
        $privateTargetWaitIndex = $readme.IndexOf('Wait-CMTraceOwnedTargetStarted -OwnedLaunch $OwnedLaunch -WrapperProcess $Process', $privateReadyIndex, [StringComparison]::Ordinal)
        $privateHelperIndex | Should -BeGreaterThan -1
        $privateStdoutReadIndex | Should -BeGreaterThan $privateHelperIndex
        $privateReadyIndex | Should -BeGreaterThan $privateStdoutReadIndex
        $privateTargetWaitIndex | Should -BeGreaterThan $privateReadyIndex
        $readmeRejectIndex | Should -BeGreaterThan $privateHelperIndex
        $readmeReturnIndex | Should -BeGreaterThan $readmeRejectIndex
        $readme | Should -Match ([regex]::Escape('BLOCKED with dispositionCode ENVIRONMENT_UNAVAILABLE; never record FAIL or OBSERVED_FAILURE'))
    }

    It 'returns the reserved wrapper failure exit for a target-start failure' -Skip:(-not $IsWindows) {
        Initialize-CMTraceOwnedProcessType
        $targetStartInfo = [Diagnostics.ProcessStartInfo]::new()
        $targetStartInfo.FileName = Join-Path $script:HandoffRoot 'missing-owned-process-target.exe'
        $targetStartInfo.WorkingDirectory = $script:HandoffRoot
        $targetStartInfo.UseShellExecute = $false
        $targetStartInfo.CreateNoWindow = $true

        $launch = Get-CMTraceOwnedProcessLaunch -TargetStartInfo $targetStartInfo
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $launch.StartInfo
        $job = [CMTraceOpen.Validation.OwnedProcessJob]::new()
        $processStarted = $false
        try {
            $process.Start() | Should -BeTrue
            $processStarted = $true
            $job.Assign($process)
            @($job.ActiveProcessIds) | Should -Be @($process.Id)
            [void]$launch.ReadyEvent.Set()
            $stdoutTask = $process.StandardOutput.ReadToEndAsync()
            $stderrTask = $process.StandardError.ReadToEndAsync()
            $process.WaitForExit(5000) | Should -BeTrue
            [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdoutTask, $stderrTask), 5000) | Should -BeTrue
            $process.ExitCode | Should -Be $script:CMTraceOwnedProcessWrapperFailureExitCode
            $launch.TargetStartedEvent.WaitOne(0) | Should -BeFalse
            $stdoutTask.GetAwaiter().GetResult() | Should -BeNullOrEmpty
            $stderrTask.GetAwaiter().GetResult() | Should -Not -BeNullOrEmpty
            $job.ActiveProcessCount | Should -Be 0

            $pwsh = Join-Path $PSHOME 'pwsh.exe'
            $ordinary = Invoke-CMTraceOwnedProcessCapture -FilePath $pwsh -WorkingDirectory $script:HandoffRoot `
                -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'exit 1')
            $ordinary.ExitCode | Should -Be 1
            $invalidTarget = Join-Path $TestDrive 'invalid-owned-capture-target.exe'
            [IO.File]::WriteAllBytes($invalidTarget, [Text.Encoding]::UTF8.GetBytes('not a Windows executable'))
            {
                Invoke-CMTraceOwnedProcessCapture -FilePath $invalidTarget -WorkingDirectory $TestDrive
            } | Should -Throw '*Owned-process wrapper failed before a trustworthy native child result*'
            {
                Invoke-CMTraceOwnedProcessCapture -FilePath $pwsh -WorkingDirectory $script:HandoffRoot `
                    -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'exit 253')
            } | Should -Throw '*reserved infrastructure exit code 253*'
        }
        finally {
            if ($processStarted -and -not $process.HasExited) { $job.Terminate(1) }
            $job.Dispose()
            $launch.TargetStartedEvent.Dispose()
            $launch.ReadyEvent.Dispose()
            $process.Dispose()
        }
    }

    It 'drains and classifies documented private-helper target-start failure' -Skip:(-not $IsWindows) {
        Mock Assert-CMTraceHandoffIntegrity { return $true }
        Mock Assert-CMTraceSourceIntegrity { return $true }
        Mock Assert-CMTraceCargoConfigurationBoundary { return $true }
        Mock Assert-CMTraceActiveRustToolchain { return $true }

        $readmePath = Join-Path $script:HandoffRoot 'README.md'
        $privateHelper = Get-DocumentedPowerShellFunctionText -DocumentPath $readmePath -Name 'Invoke-PrivateProcess'
        $workingSetHelper = Get-DocumentedPowerShellFunctionText -DocumentPath $readmePath -Name 'Get-PrivateJobWorkingSetBytes'
        $privateOutput = Join-Path $TestDrive 'documented-private-helper-output'
        New-Item -ItemType Directory -Path $privateOutput | Out-Null
        $invalidTarget = Join-Path $TestDrive 'invalid-private-target.exe'
        [IO.File]::WriteAllBytes($invalidTarget, [Text.Encoding]::UTF8.GetBytes('not a Windows executable'))
        $targetBytes = (Get-Item -LiteralPath $invalidTarget).Length
        $targetSha256 = (Get-FileHash -LiteralPath $invalidTarget -Algorithm SHA256).Hash.ToLowerInvariant()

        Set-Variable -Name Source -Scope Script -Value $TestDrive
        Set-Variable -Name Handoff -Scope Script -Value $script:HandoffRoot
        Set-Variable -Name PrivateCommandOutput -Scope Script -Value $privateOutput
        try {
            Set-Item -LiteralPath Function:\Get-PrivateJobWorkingSetBytes -Value ([scriptblock]::Create($workingSetHelper))
            Set-Item -LiteralPath Function:\Invoke-PrivateProcess -Value ([scriptblock]::Create($privateHelper))
            {
                Invoke-PrivateProcess -Id 'invalid-target-start' -FilePath $invalidTarget `
                    -ArgumentList @() -WorkingDirectory $TestDrive `
                    -ExpectedSha256 $targetSha256 -ExpectedBytes $targetBytes
            } | Should -Throw '*BLOCKED*ENVIRONMENT_UNAVAILABLE*'

            $stderrPath = Join-Path $privateOutput 'invalid-target-start.stderr.log'
            Test-Path -LiteralPath $stderrPath -PathType Leaf | Should -BeTrue
            (Get-Item -LiteralPath $stderrPath).Length | Should -BeGreaterThan 0
            (Get-Content -LiteralPath $stderrPath -Raw) | Should -Match 'Exception'
        }
        finally {
            Remove-Item -LiteralPath Function:\Invoke-PrivateProcess -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath Function:\Get-PrivateJobWorkingSetBytes -ErrorAction SilentlyContinue
            Remove-Variable -Name PrivateCommandOutput -Scope Script -ErrorAction SilentlyContinue
            Remove-Variable -Name Handoff -Scope Script -ErrorAction SilentlyContinue
            Remove-Variable -Name Source -Scope Script -ErrorAction SilentlyContinue
        }
    }

    It 'drains and classifies private provider Cargo target-start failure' -Skip:(-not $IsWindows) {
        Mock Assert-CMTraceSourceIntegrity { return $TestDrive }
        Mock Assert-CMTraceCargoConfigurationBoundary { return $true }
        Mock Assert-CMTraceActiveRustToolchain { return $true }
        Mock Get-CMTraceOwnedProcessLaunch {
            param($TargetStartInfo)
            $null = $TargetStartInfo
            $readyName = 'Local\CMTraceOpenProviderReady-' + [guid]::NewGuid().ToString('N')
            $targetName = 'Local\CMTraceOpenProviderTarget-' + [guid]::NewGuid().ToString('N')
            $readyEvent = [Threading.EventWaitHandle]::new(
                $false,
                [Threading.EventResetMode]::ManualReset,
                $readyName
            )
            $targetStartedEvent = [Threading.EventWaitHandle]::new(
                $false,
                [Threading.EventResetMode]::ManualReset,
                $targetName
            )
            $pwshPath = Join-Path $PSHOME 'pwsh.exe'
            $sleepToken = [Convert]::ToBase64String(
                [Text.Encoding]::Unicode.GetBytes('[Threading.Thread]::Sleep(30000)')
            )
            $escapedPwshPath = $pwshPath.Replace("'", "''")
            $wrapperCommand = @"
`$ready = [Threading.EventWaitHandle]::OpenExisting('$readyName')
try {
  [void]`$ready.WaitOne()
  `$start = [Diagnostics.ProcessStartInfo]::new()
  `$start.FileName = '$escapedPwshPath'
  `$start.UseShellExecute = `$false
  `$start.CreateNoWindow = `$true
  [void]`$start.ArgumentList.Add('-NoLogo')
  [void]`$start.ArgumentList.Add('-NoProfile')
  [void]`$start.ArgumentList.Add('-NonInteractive')
  [void]`$start.ArgumentList.Add('-EncodedCommand')
  [void]`$start.ArgumentList.Add('$sleepToken')
  `$child = [Diagnostics.Process]::Start(`$start)
  [Console]::Out.WriteLine(`$child.Id)
  [Console]::Out.Flush()
}
finally {
  `$ready.Dispose()
}
exit 253
"@
            $wrapperToken = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($wrapperCommand))
            $startInfo = [Diagnostics.ProcessStartInfo]::new()
            $startInfo.FileName = $pwshPath
            $startInfo.UseShellExecute = $false
            $startInfo.CreateNoWindow = $true
            $startInfo.RedirectStandardOutput = $true
            $startInfo.RedirectStandardError = $true
            foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $wrapperToken)) {
                [void]$startInfo.ArgumentList.Add($argument)
            }
            return [pscustomobject]@{
                StartInfo = $startInfo
                ReadyEvent = $readyEvent
                TargetStartedEvent = $targetStartedEvent
            }
        }

        Initialize-CMTraceOwnedProcessType
        $providerPath = Join-Path $script:ScriptsRoot 'New-CMTraceOpenPrivateProviderDatabase.ps1'
        $providerHelper = Get-ScriptPowerShellFunctionText -ScriptPath $providerPath -Name 'Invoke-CMTracePrivateCargoProcess'
        $privateOutput = Join-Path $TestDrive 'provider-target-start-output'
        New-Item -ItemType Directory -Path $privateOutput | Out-Null
        $invalidCargo = Join-Path $TestDrive 'invalid-provider-cargo.exe'
        [IO.File]::WriteAllBytes($invalidCargo, [Text.Encoding]::UTF8.GetBytes('not a Windows executable'))

        Set-Variable -Name resolvedRepository -Scope Script -Value $TestDrive
        Set-Variable -Name archiveSource -Scope Script -Value (Join-Path $TestDrive 'archive-source')
        Set-Variable -Name sourceCargoConfiguration -Scope Script -Value (Join-Path $TestDrive '.cargo/config.toml')
        Set-Variable -Name archiveCargoConfiguration -Scope Script -Value (Join-Path $TestDrive 'archive-source/.cargo/config.toml')
        Set-Variable -Name cargo -Scope Script -Value $invalidCargo
        Set-Variable -Name providerRoot -Scope Script -Value $privateOutput
        Set-Variable -Name privateCargoTimeout -Scope Script -Value ([TimeSpan]::FromSeconds(10))
        Set-Variable -Name privateCargoOutputLimitBytes -Scope Script -Value 33554432L
        Set-Variable -Name privateCargoBufferBytes -Scope Script -Value 8192
        try {
            Set-Item -LiteralPath Function:\Invoke-CMTracePrivateCargoProcess -Value ([scriptblock]::Create($providerHelper))
            {
                Invoke-CMTracePrivateCargoProcess -Id 'invalid-provider-target' -ArgumentList @() `
                    -WorkingDirectory $TestDrive
            } | Should -Throw '*owned-process wrapper failed before a trustworthy native child result*'

            $stderrPath = Join-Path $privateOutput 'invalid-provider-target.stderr.private.log'
            $stdoutPath = Join-Path $privateOutput 'invalid-provider-target.stdout.private.log'
            Test-Path -LiteralPath $stderrPath -PathType Leaf | Should -BeTrue
            Test-Path -LiteralPath $stdoutPath -PathType Leaf | Should -BeTrue
            $spawnedChildId = [int](@(Get-Content -LiteralPath $stdoutPath)[0])
            $spawnedChildId | Should -BeGreaterThan 0
            Get-Process -Id $spawnedChildId -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }
        finally {
            Remove-Item -LiteralPath Function:\Invoke-CMTracePrivateCargoProcess -ErrorAction SilentlyContinue
            foreach ($name in @(
                'privateCargoBufferBytes', 'privateCargoOutputLimitBytes', 'privateCargoTimeout',
                'providerRoot', 'cargo', 'archiveCargoConfiguration', 'sourceCargoConfiguration',
                'archiveSource', 'resolvedRepository'
            )) {
                Remove-Variable -Name $name -Scope Script -ErrorAction SilentlyContinue
            }
        }
    }

    It 'terminates an inherited-stdio descendant after its root process exits' -Skip:(-not $IsWindows) {
        Initialize-CMTraceOwnedProcessType
        $pwsh = Join-Path $PSHOME 'pwsh.exe'
        $targetStartInfo = [Diagnostics.ProcessStartInfo]::new()
        $targetStartInfo.FileName = $pwsh
        $targetStartInfo.UseShellExecute = $false
        $targetStartInfo.CreateNoWindow = $true
        foreach ($argument in @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
            '$start = [Diagnostics.ProcessStartInfo]::new(); $start.FileName = (Get-Command pwsh.exe).Source; $start.UseShellExecute = $false; [void]$start.ArgumentList.Add(''-NoLogo''); [void]$start.ArgumentList.Add(''-NoProfile''); [void]$start.ArgumentList.Add(''-Command''); [void]$start.ArgumentList.Add(''[Threading.Thread]::Sleep(30000)''); $child = [Diagnostics.Process]::Start($start); [Console]::Out.WriteLine($child.Id)'
        )) {
            [void]$targetStartInfo.ArgumentList.Add($argument)
        }

        $launch = Get-CMTraceOwnedProcessLaunch -TargetStartInfo $targetStartInfo
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $launch.StartInfo
        $job = [CMTraceOpen.Validation.OwnedProcessJob]::new()
        $processStarted = $false
        try {
            $process.Start() | Should -BeTrue
            $processStarted = $true
            $job.Assign($process)
            [void]$launch.ReadyEvent.Set()
            Wait-CMTraceOwnedTargetStarted -OwnedLaunch $launch -WrapperProcess $process
            $childProcessId = [int]$process.StandardOutput.ReadLine()
            $process.WaitForExit(5000) | Should -BeTrue
            { Get-Process -Id $childProcessId -ErrorAction Stop } | Should -Not -Throw
            $job.ActiveProcessCount | Should -BeGreaterThan 0
            @($job.ActiveProcessIds) | Should -Contain $childProcessId

            $job.Terminate(1)

            $deadline = [DateTimeOffset]::UtcNow.AddSeconds(5)
            do {
                $child = Get-Process -Id $childProcessId -ErrorAction SilentlyContinue
                if ($null -eq $child) { break }
                Start-Sleep -Milliseconds 50
            } while ([DateTimeOffset]::UtcNow -lt $deadline)
            $child | Should -BeNullOrEmpty
            $job.ActiveProcessCount | Should -Be 0
            @($job.ActiveProcessIds).Count | Should -Be 0
        }
        finally {
            $job.Dispose()
            $launch.TargetStartedEvent.Dispose()
            $launch.ReadyEvent.Dispose()
            if ($processStarted -and -not $process.HasExited) { $process.Kill($true) }
            $process.Dispose()
        }
    }

    It 'delivers bounded standard input to an owned native child' -Skip:(-not $IsWindows) {
        $pwsh = Join-Path $PSHOME 'pwsh.exe'
        $payload = "first tracked path`nsecond tracked path`n"
        $capture = Invoke-CMTraceOwnedProcessCapture -FilePath $pwsh -WorkingDirectory $script:HandoffRoot `
            -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '[Console]::Out.Write([Console]::In.ReadToEnd())') `
            -StandardInputText $payload
        $capture.ExitCode | Should -Be 0
        $capture.StdErr | Should -BeNullOrEmpty
        $capture.StdOut | Should -BeExactly $payload
    }

    It 'holds a guarded launch file against replacement until target-start release' -Skip:(-not $IsWindows) {
        $path = Join-Path $TestDrive 'guarded-launch-target.exe'
        $movedPath = Join-Path $TestDrive 'guarded-launch-target.moved.exe'
        Copy-Item -LiteralPath (Get-Command cmd.exe -CommandType Application -ErrorAction Stop).Source -Destination $path
        $bytes = (Get-Item -LiteralPath $path).Length
        $sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        $guard = Open-CMTraceGuardedReadFile -Path $path -Label 'Target-native guarded launch regression' `
            -ExpectedSha256 $sha256 -ExpectedBytes $bytes
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $guard.Path
        $startInfo.WorkingDirectory = $TestDrive
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        foreach ($argument in @('/d', '/s', '/c', 'exit 0')) { [void]$startInfo.ArgumentList.Add($argument) }
        $launch = Get-CMTraceOwnedProcessLaunch -TargetStartInfo $startInfo
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $launch.StartInfo
        $job = [CMTraceOpen.Validation.OwnedProcessJob]::new()
        $processStarted = $false
        try {
            $guard.Bytes | Should -Be $bytes
            $guard.Sha256 | Should -BeExactly $sha256
            {
                $writer = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
                $writer.Dispose()
            } | Should -Throw
            { [IO.File]::Move($path, $movedPath) } | Should -Throw
            $process.Start() | Should -BeTrue
            $processStarted = $true
            $job.Assign($process)
            $launch.TargetStartedEvent.WaitOne(0) | Should -BeFalse
            { [IO.File]::Move($path, $movedPath) } | Should -Throw
            [void]$launch.ReadyEvent.Set()
            Wait-CMTraceOwnedTargetStarted -OwnedLaunch $launch -WrapperProcess $process
            $launch.TargetStartedEvent.WaitOne(0) | Should -BeTrue
            { [IO.File]::Move($path, $movedPath) } | Should -Throw
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() | Should -BeExactly $sha256
            $guard.Stream.Dispose()
            $guard = $null
            $process.WaitForExit(5000) | Should -BeTrue
            $process.ExitCode | Should -Be 0
            $job.ActiveProcessCount | Should -Be 0
        }
        finally {
            if ($null -ne $guard) { $guard.Stream.Dispose() }
            if ($processStarted -and -not $process.HasExited) { $job.Terminate(1) }
            $job.Dispose()
            $launch.TargetStartedEvent.Dispose()
            $launch.ReadyEvent.Dispose()
            $process.Dispose()
        }
        { [IO.File]::Move($path, $movedPath) } | Should -Not -Throw
        [IO.File]::WriteAllText($movedPath, 'replacement allowed after release')
        (Get-FileHash -LiteralPath $movedPath -Algorithm SHA256).Hash.ToLowerInvariant() | Should -Not -BeExactly $sha256
    }

    It 'holds verified content bindings until the consuming child exits' -Skip:(-not $IsWindows) {
        $contentPath = Join-Path $TestDrive 'guarded-content.txt'
        [IO.File]::WriteAllText($contentPath, 'authenticated content')
        $contentEntry = Get-Item -LiteralPath $contentPath
        $contentSha256 = (Get-FileHash -LiteralPath $contentPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $binding = [pscustomobject][ordered]@{
            Path = $contentEntry.FullName
            Sha256 = $contentSha256
            Bytes = [int64]$contentEntry.Length
            Label = 'Owned-process content guard regression'
        }
        $escapedContentPath = $contentPath.Replace("'", "''")
        $command = @"
try {
    [IO.File]::WriteAllText('$escapedContentPath', 'replacement')
    exit 1
}
catch [IO.IOException] {
    [Console]::Out.Write('guarded')
    exit 0
}
"@
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        $capture = Invoke-CMTraceOwnedProcessCapture -FilePath (Join-Path $PSHOME 'pwsh.exe') `
            -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedCommand) `
            -WorkingDirectory $TestDrive -ContentBindings @($binding)
        $capture.ExitCode | Should -Be 0
        $capture.StdErr | Should -BeNullOrEmpty
        $capture.StdOut | Should -BeExactly 'guarded'
        (Get-FileHash -LiteralPath $contentPath -Algorithm SHA256).Hash.ToLowerInvariant() |
            Should -BeExactly $contentSha256
        { [IO.File]::WriteAllText($contentPath, 'replacement allowed after child exit') } | Should -Not -Throw
    }

    It 'contains 68 unique structured manual gates with no freeform observation field' {
        $manual = Get-Content -LiteralPath (Join-Path $script:HandoffRoot 'manual-results.template.json') -Raw | ConvertFrom-Json
        $manual.schemaVersion | Should -Be 3
        @($manual.gates).Count | Should -Be 68
        @($manual.gates.id | Sort-Object -Unique).Count | Should -Be 68
        @($manual.gates | Where-Object { $_.PSObject.Properties.Name -contains 'observation' }).Count | Should -Be 0
        @($manual.gates | Where-Object { $_.PSObject.Properties.Name -notcontains 'evidenceSha256' }).Count | Should -Be 0
        foreach ($name in @(
            'coldLaunchRun1Milliseconds', 'coldLaunchRun2Milliseconds', 'coldLaunchRun3Milliseconds',
            'coldLaunchRun1PeakWorkingSetBytes', 'coldLaunchRun2PeakWorkingSetBytes', 'coldLaunchRun3PeakWorkingSetBytes',
            'firstRowRun1Milliseconds', 'firstRowRun2Milliseconds', 'firstRowRun3Milliseconds'
        )) {
            $manual.measurements.PSObject.Properties.Name | Should -Contain $name
        }
    }

    It 'defines cross-section manual gates in exactly one authoritative matrix row' {
        $matrix = Get-Content -LiteralPath (Join-Path $script:HandoffRoot 'VALIDATION-MATRIX.md') -Raw
        foreach ($gateId in @('unified-timeline-provenance', 'mdmdiag-structural-bounds')) {
            ([regex]::Matches($matrix, "(?m)^\| ``$([regex]::Escape($gateId))`` \|")).Count | Should -Be 1
            $matrix | Should -Match ([regex]::Escape("The ``$gateId`` acceptance boundary is defined once"))
        }
    }
}

Describe 'privacy-bounded return archive' {
    It 'accepts only Int64 values for bounded JSON integer fields' {
        $returnScript = Join-Path $script:ScriptsRoot 'New-CMTraceOpenArm64ValidationReturn.ps1'
        $integerFunction = Get-ScriptPowerShellFunctionText -ScriptPath $returnScript -Name 'ConvertTo-CMTraceBoundedInteger'
        try {
            Set-Item -LiteralPath Function:\ConvertTo-CMTraceBoundedInteger -Value ([scriptblock]::Create($integerFunction))
            (ConvertTo-CMTraceBoundedInteger -Value ([int64]1) -Label 'integer') | Should -Be 1
            (ConvertTo-CMTraceBoundedInteger -Value ([int64]::MaxValue) -Label 'positive integer' -Positive) |
                Should -Be ([int64]::MaxValue)
            (ConvertTo-CMTraceBoundedInteger -Value ([int64]::MinValue) -Label 'signed integer' -AllowNegative) |
                Should -Be ([int64]::MinValue)
            foreach ($nonInteger in @(
                [double]1.0,
                [single]1.0,
                [decimal]1,
                [System.Numerics.BigInteger]::Parse('9223372036854775808'),
                [System.Numerics.BigInteger]::Parse('-9223372036854775809')
            )) {
                { ConvertTo-CMTraceBoundedInteger -Value $nonInteger -Label 'integer' } |
                    Should -Throw '*must be an integer*'
            }
            { ConvertTo-CMTraceBoundedInteger -Value ([int64]-1) -Label 'nonnegative integer' } |
                Should -Throw '*outside its allowed nonnegative range*'
            { ConvertTo-CMTraceBoundedInteger -Value ([int64]0) -Label 'positive integer' -Positive } |
                Should -Throw '*outside its allowed nonnegative range*'
        }
        finally {
            Remove-Item -LiteralPath Function:\ConvertTo-CMTraceBoundedInteger -ErrorAction SilentlyContinue
        }
    }

    It 'sanitizes and rejects every documented generic privacy class' {
        $private = [ordered]@{ 'C:\Users\Ada\src\cmtraceopen' = '%REPOSITORY%'; 'ADA-LAPTOP' = '%COMPUTERNAME%'; 'Ada' = '%USERNAME%' }
        $text = 'C:\Users\Ada\src\cmtraceopen ADA-LAPTOP Ada user@example.com S-1-5-21-111111111-222222222-333333333-1001 S-1-12-1-111111111-222222222-333333333-444444444 S-1-15-2-111111111-222222222-333333333-444444444 token=abc https://example.invalid/a?sig=abc 10.20.30.40 2001:db8:abcd:: :: HOST01.corp.local 11111111-2222-4333-8333-555555555555 \\server01\share\private.log ghp_abcdefghijklmnopqrstuvwxyz123456'
        $sanitized = ConvertTo-CMTraceSanitizedText -Text $text -LiteralReplacements $private
        { Assert-CMTracePrivacySafeText -Text $sanitized -Label 'sanitized test log' } | Should -Not -Throw
        foreach ($unsafe in @('10.20.30.40', 'fe80::1234', '2001:db8:abcd::', '::', '00-11-22-33-44-55', 'HOST01.corp.local', 'S-1-5-21-111111111-222222222-333333333-1001', 'S-1-12-1-111111111-222222222-333333333-444444444', 'S-1-15-2-111111111-222222222-333333333-444444444', 'tenantId=11111111-2222-4333-8333-555555555555', '\\server01\share\private.log', 'C:/Users/Ada/private.log', '{"token":"supersecret"}', 'ghp_abcdefghijklmnopqrstuvwxyz123456', ('QUJD' * 80), ('ab' * 300))) {
            { Assert-CMTracePrivacySafeText -Text $unsafe -Label 'unsafe text' } | Should -Throw
        }
        $wrappedBase64 = ((@((('A' * 64) -join '')) * 4) -join "`n")
        $wrappedBase64Wide = ((@((('B' * 128) -join '')) * 2) -join "`r`n")
        $wrappedBase64Narrow = ((@((('C' * 32) -join '')) * 8) -join "`n")
        $wrappedBase64Whitespace = ((@("  $((('D' * 64) -join ''))  ") * 4) -join "`n")
        $wrappedBase64Url = ((@((('E' * 63) + '_')) * 4) -join "`n")
        $wrappedBase64UrlHyphen = ((@((('F' * 63) + '-')) * 4) -join "`n")
        $wrappedBase64CarriageReturn = ((@((('G' * 64) -join '')) * 4) -join "`r")
        $base64InternalWhitespaceLine = ((1..16 | ForEach-Object { 'SElK' }) -join "`t")
        $wrappedBase64InternalWhitespace = ((@($base64InternalWhitespaceLine) * 4) -join "`n")
        $wrappedBase64BlankLines = ((@((('I' * 64) -join '')) * 4) -join "`n`n")
        $wrappedBase64WhitespaceOnlyLines = ((@((('J' * 64) -join '')) * 4) -join "`r`n `t`r`n")
        foreach ($encodedCase in @(
            [pscustomobject]@{ Input = ('QUJD' * 80); Marker = '<redacted-base64-payload>'; ForbiddenPattern = 'QUJD' },
            [pscustomobject]@{ Input = $wrappedBase64; Marker = '<redacted-line-wrapped-payload>'; ForbiddenPattern = 'A{16}' },
            [pscustomobject]@{ Input = $wrappedBase64Wide; Marker = '<redacted-line-wrapped-payload>'; ForbiddenPattern = 'B{16}' },
            [pscustomobject]@{ Input = $wrappedBase64Narrow; Marker = '<redacted-line-wrapped-payload>'; ForbiddenPattern = 'C{16}' },
            [pscustomobject]@{ Input = $wrappedBase64Whitespace; Marker = '<redacted-line-wrapped-payload>'; ForbiddenPattern = 'D{16}' },
            [pscustomobject]@{ Input = $wrappedBase64Url; Marker = '<redacted-line-wrapped-payload>'; ForbiddenPattern = 'E{16}' },
            [pscustomobject]@{ Input = $wrappedBase64UrlHyphen; Marker = '<redacted-line-wrapped-payload>'; ForbiddenPattern = 'F{16}' },
            [pscustomobject]@{ Input = $wrappedBase64CarriageReturn; Marker = '<redacted-line-wrapped-payload>'; ForbiddenPattern = 'G{16}' },
            [pscustomobject]@{ Input = $wrappedBase64InternalWhitespace; Marker = '<redacted-line-wrapped-payload>'; ForbiddenPattern = 'SElK' },
            [pscustomobject]@{ Input = $wrappedBase64BlankLines; Marker = '<redacted-line-wrapped-payload>'; ForbiddenPattern = 'I{16}' },
            [pscustomobject]@{ Input = $wrappedBase64WhitespaceOnlyLines; Marker = '<redacted-line-wrapped-payload>'; ForbiddenPattern = 'J{16}' },
            [pscustomobject]@{ Input = ('ab' * 300); Marker = '<redacted-hex-payload>'; ForbiddenPattern = '(?:ab){16}' },
            [pscustomobject]@{ Input = "safe$([char]1)$([char]2)text"; Marker = '<redacted-binary-control>'; ForbiddenPattern = '[\x01\x02]' }
        )) {
            $sanitizedPayload = ConvertTo-CMTraceSanitizedText -Text $encodedCase.Input
            $sanitizedPayload | Should -Match ([regex]::Escape($encodedCase.Marker))
            $sanitizedPayload | Should -Not -Match $encodedCase.ForbiddenPattern
            { Assert-CMTracePrivacySafeText -Text $sanitizedPayload -Label 'sanitized encoded payload' } |
                Should -Not -Throw
        }

        foreach ($separator in @(
            [char]0x00A0,
            [char]0x0085,
            [char]0x200B,
            [char]0x2028,
            [char]0x2029,
            [char]0x034F,
            [char]0x0301,
            [char]0xFE0F,
            [char]0x0001,
            [char]0x000B,
            [char]0x000C,
            [char]0x001F,
            [char]0x007F
        )) {
            $separatedPayload = ((@((('L' * 64) -join '')) * 5) -join [string]$separator)
            $sanitizedSeparatedPayload = ConvertTo-CMTraceSanitizedText -Text $separatedPayload
            $sanitizedSeparatedPayload | Should -BeExactly '<redacted-line-wrapped-payload>'
            $sanitizedSeparatedPayload | Should -Not -Match 'L{16}'
            { Assert-CMTracePrivacySafeText -Text $sanitizedSeparatedPayload -Label 'sanitized separated payload' } |
                Should -Not -Throw
        }

        foreach ($width in @(1, 5, 9)) {
            $encodedPayload = 'QUJD' * 80
            $wrappedParts = @(
                for ($offset = 0; $offset -lt $encodedPayload.Length; $offset += $width) {
                    $encodedPayload.Substring($offset, [Math]::Min($width, $encodedPayload.Length - $offset))
                }
            )
            $arbitrarilyWrappedPayload = $wrappedParts -join "`n"
            $sanitizedArbitrarilyWrappedPayload = ConvertTo-CMTraceSanitizedText -Text $arbitrarilyWrappedPayload
            $sanitizedArbitrarilyWrappedPayload | Should -BeExactly '<redacted-line-wrapped-payload>'
            { Assert-CMTracePrivacySafeText -Text $sanitizedArbitrarilyWrappedPayload -Label "width-$width encoded payload" } |
                Should -Not -Throw
        }

        foreach ($composedCase in @(
            [pscustomobject]@{ Input = (('M' * 128) + [char]1 + ('M' * 128)); Replacements = [ordered]@{}; Forbidden = 'M{16}' },
            [pscustomobject]@{ Input = ((('N' * 127) + '/') + 'user@example.com' + ('/' + ('N' * 127))); Replacements = [ordered]@{}; Forbidden = 'N{16}' },
            [pscustomobject]@{ Input = (('P' * 128) + 'C:\private\source' + ('P' * 128)); Replacements = [ordered]@{ 'C:\private\source' = '%REPOSITORY%' }; Forbidden = 'P{16}' }
        )) {
            $sanitizedComposedPayload = ConvertTo-CMTraceSanitizedText -Text $composedCase.Input -LiteralReplacements $composedCase.Replacements
            $sanitizedComposedPayload | Should -BeExactly '<redacted-line-wrapped-payload>'
            $sanitizedComposedPayload | Should -Not -Match $composedCase.Forbidden
            { Assert-CMTracePrivacySafeText -Text $sanitizedComposedPayload -Label 'sanitized composed payload' } |
                Should -Not -Throw
        }

        $apostrophe = [char]39
        foreach ($case in @(
            [pscustomobject]@{ Input = 'password="correct horse battery staple"'; Expected = 'password=<redacted>' },
            [pscustomobject]@{ Input = 'client_secret: "alpha beta gamma"'; Expected = 'client_secret:<redacted>' },
            [pscustomobject]@{ Input = ('secret=' + $apostrophe + 'single quoted value' + $apostrophe); Expected = 'secret=<redacted>' },
            [pscustomobject]@{ Input = 'password="alpha `"beta`" gamma"'; Expected = 'password=<redacted>' },
            [pscustomobject]@{ Input = 'password="""alpha beta"""'; Expected = 'password=<redacted>' }
        )) {
            $sanitizedAssignment = ConvertTo-CMTraceSanitizedText -Text $case.Input
            $sanitizedAssignment | Should -BeExactly $case.Expected
            { Assert-CMTracePrivacySafeText -Text $sanitizedAssignment -Label 'sanitized quoted assignment' } | Should -Not -Throw
        }
        foreach ($malformedAssignment in @(
            [pscustomobject]@{ Input = 'password="unclosed secret words'; Expected = 'password=<redacted>' },
            [pscustomobject]@{ Input = ('client_secret: ' + $apostrophe + 'unclosed secret words'); Expected = 'client_secret:<redacted>' }
        )) {
            $sanitizedMalformed = ConvertTo-CMTraceSanitizedText -Text $malformedAssignment.Input
            $sanitizedMalformed | Should -BeExactly $malformedAssignment.Expected
            { Assert-CMTracePrivacySafeText -Text $sanitizedMalformed -Label 'sanitized malformed quoted assignment' } | Should -Not -Throw
        }
        $blockScalar = "client_secret: |`n  alpha beta gamma"
        ConvertTo-CMTraceSanitizedText -Text $blockScalar | Should -BeExactly $blockScalar
        { Assert-CMTracePrivacySafeText -Text $blockScalar -Label 'YAML secret block scalar' } | Should -Throw

        foreach ($ordinarySplitAssignment in @(
            "password`nordinary=value",
            "password`n: ordinary value",
            "password`r`n=ordinary value"
        )) {
            ConvertTo-CMTraceSanitizedText -Text $ordinarySplitAssignment | Should -BeExactly $ordinarySplitAssignment
            { Assert-CMTracePrivacySafeText -Text $ordinarySplitAssignment -Label 'split non-assignment' } |
                Should -Not -Throw
        }
        { Assert-CMTracePrivacySafeText -Text 'C: / safe' -Label 'space-separated non-path' } |
            Should -Not -Throw
        $unicodeLineSeparator = [char]0x2028
        foreach ($reconstructableSplitAssignment in @(
            "password${unicodeLineSeparator}=ordinary value"
        )) {
            ConvertTo-CMTraceSanitizedText -Text $reconstructableSplitAssignment |
                Should -BeExactly $reconstructableSplitAssignment
            { Assert-CMTracePrivacySafeText -Text $reconstructableSplitAssignment -Label 'reconstructable split assignment' } |
                Should -Throw '*secret-like assignment*'
        }
        $tabbedAssignment = "password`t=`tordinary value"
        $sanitizedTabbedAssignment = ConvertTo-CMTraceSanitizedText -Text $tabbedAssignment
        $sanitizedTabbedAssignment | Should -BeExactly "password`t=<redacted>"
        { Assert-CMTracePrivacySafeText -Text $sanitizedTabbedAssignment -Label 'tabbed assignment' } | Should -Not -Throw

        $authorizationText = "Authorization: Custom-Scheme arbitrary-credential`nProxy-Authorization: Negotiate TlRMTVNTUAABAAA"
        $sanitizedAuthorization = ConvertTo-CMTraceSanitizedText -Text $authorizationText
        $sanitizedAuthorization | Should -Match '(?m)^Authorization: <redacted>$'
        $sanitizedAuthorization | Should -Match '(?m)^Proxy-Authorization: <redacted>$'
        { Assert-CMTracePrivacySafeText -Text $sanitizedAuthorization -Label 'sanitized authorization headers' } | Should -Not -Throw
        foreach ($unsafeHeader in @('Authorization: Custom-Scheme arbitrary-credential', 'Proxy-Authorization: Negotiate TlRMTVNTUAABAAA')) {
            { Assert-CMTracePrivacySafeText -Text $unsafeHeader -Label 'unsafe authorization header' } | Should -Throw
        }

        $wrappedBase64 = ((1..32 | ForEach-Object { 'QUJDRA==' }) -join "`n")
        { Assert-CMTracePrivacySafeText -Text $wrappedBase64 -Label 'wrapped base64' } | Should -Throw
        $shortWrappedBase64 = ((1..64 | ForEach-Object { 'QUJD' }) -join "`n")
        { Assert-CMTracePrivacySafeText -Text $shortWrappedBase64 -Label 'short wrapped base64' } | Should -Throw
        $prefixedWrappedBase64 = ((1..8 | ForEach-Object { "payload=$($_):$('QUJD' * 10)" }) -join "`n")
        $sanitizedPrefixedWrappedBase64 = ConvertTo-CMTraceSanitizedText -Text $prefixedWrappedBase64
        $sanitizedPrefixedWrappedBase64 | Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $prefixedWrappedBase64 -Label 'prefixed wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $narrowPrefixedWrappedBase64 = ((1..64 | ForEach-Object { "payload=$($_):QUJD" }) -join "`n")
        ConvertTo-CMTraceSanitizedText -Text $narrowPrefixedWrappedBase64 |
            Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $narrowPrefixedWrappedBase64 -Label 'narrow prefixed wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        foreach ($standaloneWrappedBase64 in @(
            ((1..64 | ForEach-Object { 'payload: QUJD' }) -join "`n"),
            ((1..64 | ForEach-Object { 'data=QUJD' }) -join "`n")
        )) {
            ConvertTo-CMTraceSanitizedText -Text $standaloneWrappedBase64 |
                Should -BeExactly '<redacted-line-wrapped-payload>'
            { Assert-CMTracePrivacySafeText -Text $standaloneWrappedBase64 -Label 'standalone-label wrapped base64' } |
                Should -Throw '*line-wrapped encoded payload*'
        }
        $singleCharacterWrappedBase64 = ((1..256 | ForEach-Object { "payload[$_]=Q" }) -join "`n")
        ConvertTo-CMTraceSanitizedText -Text $singleCharacterWrappedBase64 |
            Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $singleCharacterWrappedBase64 -Label 'single-character wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $bracketedWrappedBase64 = ((1..64 | ForEach-Object { "payload[$_]=QUJD" }) -join "`n")
        ConvertTo-CMTraceSanitizedText -Text $bracketedWrappedBase64 |
            Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $bracketedWrappedBase64 -Label 'bracketed wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $totalWrappedBase64 = ((1..64 | ForEach-Object { "payload=$_/64:QUJD" }) -join "`n")
        ConvertTo-CMTraceSanitizedText -Text $totalWrappedBase64 |
            Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $totalWrappedBase64 -Label 'N/total wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $punctuatedWrappedBase64 = ((1..64 | ForEach-Object { "payload[$_]=QUJD." }) -join "`n")
        ConvertTo-CMTraceSanitizedText -Text $punctuatedWrappedBase64 |
            Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $punctuatedWrappedBase64 -Label 'punctuated wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $metadataWrappedBase64 = ((1..64 | ForEach-Object { "payload[$_]=QUJD;crc=x" }) -join "`n")
        ConvertTo-CMTraceSanitizedText -Text $metadataWrappedBase64 |
            Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $metadataWrappedBase64 -Label 'metadata wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $quotedWrappedBase64 = ((1..64 | ForEach-Object { "payload[$_] = `"QUJD`"" }) -join "`n")
        ConvertTo-CMTraceSanitizedText -Text $quotedWrappedBase64 |
            Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $quotedWrappedBase64 -Label 'quoted wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $parenthesizedWrappedBase64 = ((1..64 | ForEach-Object { "payload[$_]=(QUJD)" }) -join "`n")
        ConvertTo-CMTraceSanitizedText -Text $parenthesizedWrappedBase64 |
            Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $parenthesizedWrappedBase64 -Label 'parenthesized wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $hashArrowWrappedBase64 = ((1..64 | ForEach-Object { "chunk #$_ -> QUJD" }) -join "`n")
        ConvertTo-CMTraceSanitizedText -Text $hashArrowWrappedBase64 |
            Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $hashArrowWrappedBase64 -Label 'hash-arrow wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $parenthesizedSequenceWrappedBase64 = ((1..64 | ForEach-Object { "payload ($_)`: QUJD" }) -join "`n")
        ConvertTo-CMTraceSanitizedText -Text $parenthesizedSequenceWrappedBase64 |
            Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $parenthesizedSequenceWrappedBase64 -Label 'parenthesized-sequence wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $nestedLabelWrappedBase64 = ((1..64 | ForEach-Object { "payload[$_]=data:QUJD # chunk" }) -join "`n")
        ConvertTo-CMTraceSanitizedText -Text $nestedLabelWrappedBase64 |
            Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $nestedLabelWrappedBase64 -Label 'nested-label wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $delimitedWrappedBase64 = ((1..64 | ForEach-Object { "$_,QUJD,ok" }) -join "`n")
        ConvertTo-CMTraceSanitizedText -Text $delimitedWrappedBase64 |
            Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $delimitedWrappedBase64 -Label 'delimited wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $bareBracketWrappedBase64 = ((1..64 | ForEach-Object { "[$_] QUJD" }) -join "`n")
        ConvertTo-CMTraceSanitizedText -Text $bareBracketWrappedBase64 |
            Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $bareBracketWrappedBase64 -Label 'bare-bracket wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $spacedLabelWrappedBase64 = ((1..64 | ForEach-Object { "part $_`: QUJD" }) -join "`n")
        ConvertTo-CMTraceSanitizedText -Text $spacedLabelWrappedBase64 |
            Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $spacedLabelWrappedBase64 -Label 'spaced-label wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $ordinalWrappedBase64 = ((1..64 | ForEach-Object { "$_`. QUJD" }) -join "`n")
        ConvertTo-CMTraceSanitizedText -Text $ordinalWrappedBase64 |
            Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $ordinalWrappedBase64 -Label 'ordinal wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $jsonWrappedBase64 = ((1..8 | ForEach-Object { '{"part":' + $_ + ',"data":"' + ('QUJD' * 10) + '"}' }) -join "`n")
        ConvertTo-CMTraceSanitizedText -Text $jsonWrappedBase64 |
            Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $jsonWrappedBase64 -Label 'JSON-wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $reversedJsonWrappedBase64 = ((1..64 | ForEach-Object { '{"data":"QUJD","seq":' + $_ + '}' }) -join "`n")
        ConvertTo-CMTraceSanitizedText -Text $reversedJsonWrappedBase64 |
            Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $reversedJsonWrappedBase64 -Label 'reversed JSON-wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $quotedSequenceJsonWrappedBase64 = ((1..64 | ForEach-Object { '{"seq":"' + $_ + '","data":"QUJD"}' }) -join "`n")
        ConvertTo-CMTraceSanitizedText -Text $quotedSequenceJsonWrappedBase64 |
            Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $quotedSequenceJsonWrappedBase64 -Label 'quoted-sequence JSON-wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $escapedSlashJsonWrappedBase64 = ((1..64 | ForEach-Object { '{"seq":' + $_ + ',"data":"\/\/\/\/"}' }) -join "`n")
        ConvertTo-CMTraceSanitizedText -Text $escapedSlashJsonWrappedBase64 |
            Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $escapedSlashJsonWrappedBase64 -Label 'escaped-slash JSON-wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $prettyJsonWrappedBase64 = ((1..64 | ForEach-Object {
                    "{`n  `"seq`": $_,`n  `"data`": `"QUJD`"`n}"
                }) -join "`n")
        $sanitizedPrettyJsonWrappedBase64 = ConvertTo-CMTraceSanitizedText -Text $prettyJsonWrappedBase64
        $sanitizedPrettyJsonWrappedBase64 | Should -Match '<redacted-line-wrapped-payload>\z'
        $sanitizedPrettyJsonWrappedBase64 | Should -Not -Match 'QUJD'
        { Assert-CMTracePrivacySafeText -Text $prettyJsonWrappedBase64 -Label 'pretty JSON-wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $prettyJsonMetadataWrappedBase64 = ((1..64 | ForEach-Object {
                    "{`n  `"seq`": $_,`n  `"data`": `"QUJD`",`n  `"status`": `"ok`"`n}"
                }) -join "`n")
        $sanitizedPrettyJsonMetadataWrappedBase64 = ConvertTo-CMTraceSanitizedText -Text $prettyJsonMetadataWrappedBase64
        $sanitizedPrettyJsonMetadataWrappedBase64 | Should -Match '<redacted-line-wrapped-payload>\z'
        $sanitizedPrettyJsonMetadataWrappedBase64 | Should -Not -Match 'QUJD'
        { Assert-CMTracePrivacySafeText -Text $prettyJsonMetadataWrappedBase64 -Label 'pretty JSON metadata-wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $prettyJsonArrayWrappedBase64 = "{`n  `"seq`": 1,`n  `"data`": [`n" +
            (((1..64 | ForEach-Object { '    "QUJD"' }) -join ",`n")) +
            "`n  ]`n}"
        $sanitizedPrettyJsonArrayWrappedBase64 = ConvertTo-CMTraceSanitizedText -Text $prettyJsonArrayWrappedBase64
        $sanitizedPrettyJsonArrayWrappedBase64 | Should -Match '<redacted-line-wrapped-payload>\z'
        $sanitizedPrettyJsonArrayWrappedBase64 | Should -Not -Match 'QUJD'
        { Assert-CMTracePrivacySafeText -Text $prettyJsonArrayWrappedBase64 -Label 'pretty JSON array-wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $longJsonMetadata = ((1..130 | ForEach-Object { '"ok"' }) -join ',')
        $longCompactJsonWrappedBase64 = ((1..64 | ForEach-Object {
                    '{"seq":' + $_ + ',"data":"QUJD","meta":[' + $longJsonMetadata + ']}'
                }) -join "`n")
        ($longCompactJsonWrappedBase64 -split "`n")[0].Length | Should -BeGreaterThan 512
        ConvertTo-CMTraceSanitizedText -Text $longCompactJsonWrappedBase64 |
            Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $longCompactJsonWrappedBase64 -Label 'long compact JSON-wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $unsequencedCompactJsonWrappedBase64 = ((1..64 | ForEach-Object { '{"data":"QUJD","status":"ok"}' }) -join "`n")
        ConvertTo-CMTraceSanitizedText -Text $unsequencedCompactJsonWrappedBase64 |
            Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $unsequencedCompactJsonWrappedBase64 -Label 'unsequenced compact JSON-wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $compactJsonArrayWrappedBase64 = '{"data":[' +
            (((1..64 | ForEach-Object { '"QUJD"' }) -join ',')) +
            ']}'
        ConvertTo-CMTraceSanitizedText -Text $compactJsonArrayWrappedBase64 |
            Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $compactJsonArrayWrappedBase64 -Label 'compact JSON array-wrapped base64' } |
            Should -Throw '*line-wrapped encoded payload*'
        $ordinaryStructuredJson = [ordered]@{}
        foreach ($index in 1..8) {
            $ordinaryStructuredJson["artifactSha$index"] = ('a' * 40)
        }
        $ordinaryStructuredJsonText = $ordinaryStructuredJson | ConvertTo-Json
        ConvertTo-CMTraceSanitizedText -Text $ordinaryStructuredJsonText |
            Should -BeExactly $ordinaryStructuredJsonText
        { Assert-CMTracePrivacySafeText -Text $ordinaryStructuredJsonText -Label 'ordinary structured JSON' } |
            Should -Not -Throw
        $shortEncodedRun = ((@((('K' * 64) -join '')) * 3) -join "`n")
        ConvertTo-CMTraceSanitizedText -Text $shortEncodedRun | Should -BeExactly $shortEncodedRun
        { Assert-CMTracePrivacySafeText -Text $shortEncodedRun -Label 'short encoded run' } | Should -Not -Throw

        $hyphenatedEncodedRun = ((1..32 | ForEach-Object { 'eventlog-filter-library-advanced-surface' }) -join "`n")
        $sanitizedHyphenatedRun = ConvertTo-CMTraceSanitizedText -Text $hyphenatedEncodedRun
        $sanitizedHyphenatedRun | Should -BeExactly '<redacted-line-wrapped-payload>'
        { Assert-CMTracePrivacySafeText -Text $sanitizedHyphenatedRun -Label 'sanitized ambiguous encoded run' } |
            Should -Not -Throw

        $oversizedText = 'safe.' * 52429
        $oversizedText.Length | Should -BeGreaterThan 262144
        $sanitizedOversizedText = ConvertTo-CMTraceSanitizedText -Text $oversizedText
        $sanitizedOversizedText | Should -BeExactly '<redacted-oversized-text>'
        { Assert-CMTracePrivacySafeText -Text $sanitizedOversizedText -Label 'sanitized oversized text' } |
            Should -Not -Throw

        $oversizedGateLog = ConvertTo-CMTraceSanitizedGateLog -GateId 'npm-ci' -GateStatus 'passed' `
            -Text "gate=npm-ci`nstatus=passed`nresult=$oversizedText"
        $oversizedGateLog | Should -BeExactly "gate=npm-ci`nstatus=passed`nresult=sanitized-log-body-withheld-after-size-limit`nThe complete raw log remains target-private."
        { Assert-CMTracePrivacySafeText -Text $oversizedGateLog -Label 'sanitized oversized gate log' } |
            Should -Not -Throw

        foreach ($collidingLiteral in @('a', 'npm', 'status')) {
            $collidingEnvelope = ConvertTo-CMTraceSanitizedGateLog -GateId 'npm-ci' -GateStatus 'passed' `
                -Text "gate=npm-ci`nstatus=passed`nresult=safe" `
                -LiteralReplacements ([ordered]@{ $collidingLiteral = '%USERNAME%' })
            $collidingEnvelope | Should -Match '\Agate=npm-ci\nstatus=passed(?:\n|\z)'
        }

        foreach ($separator in @([char]0x0001, [char]0x0301, [char]0x200B, [char]0x2028, [char]0x2060, [char]0xFE0F)) {
            $splitEmail = "user@exa$($separator)mple.com"
            $sanitizedSplitEmail = ConvertTo-CMTraceSanitizedText -Text $splitEmail
            { Assert-CMTracePrivacySafeText -Text $sanitizedSplitEmail -Label 'separator-split email' } |
                Should -Throw '*email address*'
        }
        foreach ($separator in @([char]0x034F, [char]0x200B, [char]0x2060, [char]0xFE0F)) {
            { Assert-CMTraceStringInSet -Value "pa$($separator)ssed" -Allowed @('passed', 'failed') -Label 'ordinal enum' } |
                Should -Throw '*not an allowed string value*'
        }
        foreach ($unknownPublicToken in @('<redacted-privateuser>', '%PRIVATEUSER%')) {
            { Assert-CMTracePrivacySafeText -Text "actor=$unknownPublicToken" -Label 'unknown sanitizer token' } |
                Should -Throw '*unrecognized sanitizer token*'
        }
        { Assert-CMTracePrivacySafeText -Text "actor=<redacted-pri$([char]0x200B)vateuser>" -Label 'split unknown sanitizer token' } |
            Should -Throw '*unrecognized sanitizer token*'

        $c1ControlText = "safe$([char]0x009B)31mVISIBLE"
        $sanitizedC1Control = ConvertTo-CMTraceSanitizedText -Text $c1ControlText
        $sanitizedC1Control | Should -BeExactly 'safe<redacted-binary-control>31mVISIBLE'
        { Assert-CMTracePrivacySafeText -Text $sanitizedC1Control -Label 'sanitized C1 control' } |
            Should -Not -Throw
        { Assert-CMTracePrivacySafeText -Text $c1ControlText -Label 'raw C1 control' } |
            Should -Throw '*binary control character*'

        $bidiControlText = "visible=$([char]0x202E)moc.elpmaxe@resu$([char]0x202C)"
        $sanitizedBidiControl = ConvertTo-CMTraceSanitizedText -Text $bidiControlText
        $sanitizedBidiControl | Should -Match ([regex]::Escape('<redacted-binary-control>'))
        { Assert-CMTracePrivacySafeText -Text $sanitizedBidiControl -Label 'sanitized bidi control' } |
            Should -Not -Throw
        { Assert-CMTracePrivacySafeText -Text $bidiControlText -Label 'raw bidi control' } |
            Should -Throw '*binary control character*'

        $strictControlPath = Join-Path $TestDrive 'c1-control.txt'
        Set-Content -LiteralPath $strictControlPath -Encoding utf8NoBOM -Value $c1ControlText
        { Read-CMTraceStrictUtf8Text -Path $strictControlPath } | Should -Throw '*disallowed control bytes*'

        $privateKeyMarkerTemplate = '-----{0} OPENSSH PRIVATE KEY-----'
        $privateKeyBeginMarker = $privateKeyMarkerTemplate -f 'BEGIN'
        $privateKeyEndMarker = $privateKeyMarkerTemplate -f 'END'
        $fullPrivateKey = "$privateKeyBeginMarker`nQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=`n$privateKeyEndMarker"
        $sanitizedPrivateKey = ConvertTo-CMTraceSanitizedText -Text $fullPrivateKey
        $sanitizedPrivateKey | Should -Be '<redacted-private-key-block>'
        { Assert-CMTracePrivacySafeText -Text $sanitizedPrivateKey -Label 'sanitized private key' } | Should -Not -Throw
        { Assert-CMTracePrivacySafeText -Text $fullPrivateKey -Label 'unsafe private key' } | Should -Throw

        $endOnlyPrivateKey = $privateKeyEndMarker
        $sanitizedEndMarker = ConvertTo-CMTraceSanitizedText -Text $endOnlyPrivateKey
        $sanitizedEndMarker | Should -Be '<redacted-private-key-marker>'
        { Assert-CMTracePrivacySafeText -Text $sanitizedEndMarker -Label 'sanitized private-key end marker' } | Should -Not -Throw
        { Assert-CMTracePrivacySafeText -Text $endOnlyPrivateKey -Label 'unsafe private-key end marker' } | Should -Throw
    }

    It 'keeps privacy matching culture invariant under Turkish case folding' {
        $originalCulture = [Threading.Thread]::CurrentThread.CurrentCulture
        $originalUiCulture = [Threading.Thread]::CurrentThread.CurrentUICulture
        try {
            $turkish = [Globalization.CultureInfo]::GetCultureInfo('tr-TR')
            [Threading.Thread]::CurrentThread.CurrentCulture = $turkish
            [Threading.Thread]::CurrentThread.CurrentUICulture = $turkish

            ConvertTo-CMTraceSanitizedText -Text 'owner=private@example.com' |
                Should -BeExactly 'owner=<redacted-email>'
            { Assert-CMTracePrivacySafeText -Text 'owner=private@example.com' -Label 'Turkish-culture email' } |
                Should -Throw '*email address*'
            ConvertTo-CMTraceSanitizedText -Text 'actor=i' -LiteralReplacements ([ordered]@{ 'I' = '%USERNAME%' }) |
                Should -BeExactly 'actor=%USERNAME%'

            $root = Join-Path $TestDrive 'turkish-private-literal'
            Write-EvidenceFixture -Root $root
            $privacyPath = Join-Path $root 'raw-logs/privacy-literals.json'
            $privacy = Get-Content -LiteralPath $privacyPath -Raw | ConvertFrom-Json
            $privacy.userName = 'I'
            Write-TestJson -Value $privacy -Path $privacyPath
            Set-Content -LiteralPath (Join-Path $root 'sanitized-logs/npm-ci.log') `
                -Value "gate=npm-ci`nstatus=passed`nactor=i" -Encoding utf8NoBOM
            Write-SummaryLogHash -Root $root -GateId 'npm-ci'
            $result = Invoke-ReturnContractValidation -EvidenceRoot $root
            $result.ExitCode | Should -Not -Be 0
            $result.Output | Should -Match 'target-private userName'
        }
        finally {
            [Threading.Thread]::CurrentThread.CurrentCulture = $originalCulture
            [Threading.Thread]::CurrentThread.CurrentUICulture = $originalUiCulture
        }
    }

    It 'validates the exact structured evidence and 33 hash-bound logs without creating a return archive' {
        $evidenceRoot = Join-Path $TestDrive 'evidence'
        Write-EvidenceFixture -Root $evidenceRoot
        $zipPath = Join-Path $TestDrive 'cmtraceopen-arm64-return.zip'
        $result = Invoke-ReturnContractValidation -EvidenceRoot $evidenceRoot
        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Output | Should -Match 'RETURN_CONTRACT_OK'
        $result.Output | Should -Not -Match 'RETURN_BUNDLE_OK'
        Test-Path -LiteralPath $zipPath | Should -BeFalse
        Test-Path -LiteralPath "$zipPath.sha256" | Should -BeFalse
    }

    It 'accepts a canonical size-withheld gate envelope through the return contract' {
        $evidenceRoot = Join-Path $TestDrive 'size-withheld-envelope'
        Write-EvidenceFixture -Root $evidenceRoot
        $logPath = Join-Path $evidenceRoot 'sanitized-logs/npm-ci.log'
        $safeBody = 'safe.' * 52429
        $sanitized = ConvertTo-CMTraceSanitizedGateLog -GateId 'npm-ci' -GateStatus 'passed' `
            -Text "gate=npm-ci`nstatus=passed`nresult=$safeBody"
        Set-Content -LiteralPath $logPath -Value $sanitized -Encoding utf8NoBOM
        Write-SummaryLogHash -Root $evidenceRoot -GateId 'npm-ci'
        $privacyPath = Join-Path $evidenceRoot 'raw-logs/privacy-literals.json'
        $privacy = Get-Content -LiteralPath $privacyPath -Raw | ConvertFrom-Json
        $privacy.userName = 'raw'
        $privacy.computerName = 'complete'
        $privacy.userDomain = 'log'
        Write-TestJson -Value $privacy -Path $privacyPath

        $result = Invoke-ReturnContractValidation -EvidenceRoot $evidenceRoot
        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Output | Should -Match 'RETURN_CONTRACT_OK'
    }

    It 'rejects case-variant sanitized gate envelopes' {
        $evidenceRoot = Join-Path $TestDrive 'case-variant-envelope'
        Write-EvidenceFixture -Root $evidenceRoot
        $logPath = Join-Path $evidenceRoot 'sanitized-logs/npm-ci.log'
        Set-Content -LiteralPath $logPath -Value "Gate=npm-ci`nStatus=passed`nresult=safe" -Encoding utf8NoBOM
        Write-SummaryLogHash -Root $evidenceRoot -GateId 'npm-ci'

        $result = Invoke-ReturnContractValidation -EvidenceRoot $evidenceRoot
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'Sanitized log envelope does not match'
    }

    It 'rejects a privacy-withheld fallback attached to a passed gate' {
        $evidenceRoot = Join-Path $TestDrive 'invalid-passed-privacy-fallback'
        Write-EvidenceFixture -Root $evidenceRoot
        $logPath = Join-Path $evidenceRoot 'sanitized-logs/npm-ci.log'
        Set-Content -LiteralPath $logPath -Encoding utf8NoBOM -Value @(
            'gate=npm-ci'
            'status=passed'
            'result=sanitized-log-withheld-after-privacy-validation-failure'
            'The complete raw log remains target-private.'
        )
        Write-SummaryLogHash -Root $evidenceRoot -GateId 'npm-ci'

        $result = Invoke-ReturnContractValidation -EvidenceRoot $evidenceRoot
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'privacy-withheld fallback is not canonical failed-gate'
    }

    It 'exempts only the validated public gate envelope from private-literal collisions' {
        $evidenceRoot = Join-Path $TestDrive 'public-envelope-collision'
        Write-EvidenceFixture -Root $evidenceRoot
        $privacyPath = Join-Path $evidenceRoot 'raw-logs/privacy-literals.json'
        $privacy = Get-Content -LiteralPath $privacyPath -Raw | ConvertFrom-Json
        $privacy.userName = 'npm'
        Write-TestJson -Value $privacy -Path $privacyPath

        $valid = Invoke-ReturnContractValidation -EvidenceRoot $evidenceRoot
        $valid.ExitCode | Should -Be 0 -Because $valid.Output
        $valid.Output | Should -Match 'RETURN_CONTRACT_OK'

        $logPath = Join-Path $evidenceRoot 'sanitized-logs/npm-ci.log'
        Set-Content -LiteralPath $logPath -Value "gate=npm-ci`nstatus=passed`nresult=npm" -Encoding utf8NoBOM
        Write-SummaryLogHash -Root $evidenceRoot -GateId 'npm-ci'
        $unsafe = Invoke-ReturnContractValidation -EvidenceRoot $evidenceRoot
        $unsafe.ExitCode | Should -Not -Be 0
        $unsafe.Output | Should -Match 'target-private userName'
    }

    It 'exempts recognized public sanitizer tokens from private-literal collision scans' {
        $cases = @(
            [pscustomobject]@{ Property = 'userName'; Literal = 'USERNAME'; Body = 'result=%USERNAME%' },
            [pscustomobject]@{ Property = 'repositoryPath'; Literal = 'REPOSITORY'; Body = 'result=%REPOSITORY%' },
            [pscustomobject]@{ Property = 'userName'; Literal = 'redacted'; Body = 'result=<redacted-email>' }
        )
        for ($index = 0; $index -lt $cases.Count; $index++) {
            $case = $cases[$index]
            $root = Join-Path $TestDrive "public-sanitizer-token-$index"
            Write-EvidenceFixture -Root $root
            $privacyPath = Join-Path $root 'raw-logs/privacy-literals.json'
            $privacy = Get-Content -LiteralPath $privacyPath -Raw | ConvertFrom-Json
            $privacy.($case.Property) = $case.Literal
            Write-TestJson -Value $privacy -Path $privacyPath
            $logPath = Join-Path $root 'sanitized-logs/npm-ci.log'
            Set-Content -LiteralPath $logPath -Value "gate=npm-ci`nstatus=passed`n$($case.Body)" -Encoding utf8NoBOM
            Write-SummaryLogHash -Root $root -GateId 'npm-ci'

            $result = Invoke-ReturnContractValidation -EvidenceRoot $root
            $result.ExitCode | Should -Be 0 -Because $result.Output
            $result.Output | Should -Match 'RETURN_CONTRACT_OK'
        }
    }

    It 'rejects private literals reconstructed by deleting suspicious Unicode join characters' {
        $joinCharacters = @([char]0x200B, [char]0x2028, [char]0x2060, [char]0xFE0F)
        for ($index = 0; $index -lt $joinCharacters.Count; $index++) {
            $root = Join-Path $TestDrive "split-private-literal-$index"
            Write-EvidenceFixture -Root $root
            $logPath = Join-Path $root 'sanitized-logs/npm-ci.log'
            $splitLiteral = "PrivateLab$($joinCharacters[$index])User"
            Set-Content -LiteralPath $logPath -Value "gate=npm-ci`nstatus=passed`nactor=$splitLiteral" -Encoding utf8NoBOM
            Write-SummaryLogHash -Root $root -GateId 'npm-ci'

            $result = Invoke-ReturnContractValidation -EvidenceRoot $root
            $result.ExitCode | Should -Not -Be 0
            $result.Output | Should -Match 'target-private userName|disallowed control bytes'
        }
    }

    It 'rejects canonically equivalent composed private identities' {
        $combiningAcute = [char]0x0301
        $combiningGraphemeJoiner = [char]0x034F
        $composedEAcute = [char]0x00E9
        $cases = @(
            [pscustomobject]@{ Property = 'userName'; Literal = "Jos$composedEAcute"; Body = "actor=Jose$combiningAcute" },
            [pscustomobject]@{ Property = 'userProfile'; Literal = "Jos$composedEAcute Profile"; Body = "profile=Jose${combiningAcute} Profile" },
            [pscustomobject]@{ Property = 'userName'; Literal = "Ada$combiningGraphemeJoiner"; Body = 'actor=Ada' }
        )
        for ($index = 0; $index -lt $cases.Count; $index++) {
            $case = $cases[$index]
            $root = Join-Path $TestDrive "normalized-private-literal-$index"
            Write-EvidenceFixture -Root $root
            $privacyPath = Join-Path $root 'raw-logs/privacy-literals.json'
            $privacy = Get-Content -LiteralPath $privacyPath -Raw | ConvertFrom-Json
            $privacy.($case.Property) = $case.Literal
            Write-TestJson -Value $privacy -Path $privacyPath
            $logPath = Join-Path $root 'sanitized-logs/npm-ci.log'
            Set-Content -LiteralPath $logPath -Value "gate=npm-ci`nstatus=passed`n$($case.Body)" -Encoding utf8NoBOM
            Write-SummaryLogHash -Root $root -GateId 'npm-ci'

            $result = Invoke-ReturnContractValidation -EvidenceRoot $root
            $result.ExitCode | Should -Not -Be 0
            $result.Output | Should -Match ([regex]::Escape("target-private $($case.Property)"))
        }
    }

    It 'requires machine schema 2 and string values for every normalized toolchain version' {
        $schemaRoot = Join-Path $TestDrive 'machine-schema-v1'
        Write-EvidenceFixture -Root $schemaRoot
        $schemaPath = Join-Path $schemaRoot 'machine.json'
        $schemaMachine = Get-Content -LiteralPath $schemaPath -Raw | ConvertFrom-Json
        $schemaMachine.schemaVersion = 1
        Write-TestJson -Value $schemaMachine -Path $schemaPath
        $schemaResult = Invoke-ReturnContractValidation -EvidenceRoot $schemaRoot
        $schemaResult.ExitCode | Should -Not -Be 0
        $schemaResult.Output | Should -Match 'machine.json'

        $fields = @(
            'powerShellVersion', 'gitVersion', 'npmVersion', 'pesterVersion',
            'cargoDenyVersion', 'cargoAuditVersion', 'clangVersion',
            'visualStudioVersion', 'windowsSdkVersion', 'webView2Version'
        )
        for ($index = 0; $index -lt $fields.Count; $index++) {
            $field = $fields[$index]
            $root = Join-Path $TestDrive ('machine-version-type-{0:D2}' -f $index)
            Write-EvidenceFixture -Root $root
            $path = Join-Path $root 'machine.json'
            $machine = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            $machine.$field = 1
            Write-TestJson -Value $machine -Path $path
            $result = Invoke-ReturnContractValidation -EvidenceRoot $root
            $result.ExitCode | Should -Not -Be 0 -Because "$field must be a JSON string"
            $result.Output | Should -Match ([regex]::Escape($field))
        }
    }

    It 'rejects a case-only JSON property rename' {
        $root = Join-Path $TestDrive 'case-only-machine-property'
        Write-EvidenceFixture -Root $root
        $path = Join-Path $root 'machine.json'
        $text = Get-Content -LiteralPath $path -Raw
        $renamed = [regex]::new('"schemaVersion"\s*:').Replace($text, '"SchemaVersion":', 1)
        $renamed | Should -Not -BeExactly $text
        Set-Content -LiteralPath $path -Value $renamed -Encoding utf8NoBOM -NoNewline

        $result = Invoke-ReturnContractValidation -EvidenceRoot $root
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'machine\.json.*missing or unexpected properties'
    }

    It 'rejects raw, ambiguous, path-bearing, null, array, zero, and malformed version evidence' {
        $cases = @(
            [pscustomobject]@{ Field = 'powerShellVersion'; Value = '7.6'; Label = 'two-part' },
            [pscustomobject]@{ Field = 'gitVersion'; Value = 'git version 2.51.0.windows.1'; Label = 'raw-banner' },
            [pscustomobject]@{ Field = 'nodeVersion'; Value = 'v22.18.0-beta.1'; Label = 'node-suffix' },
            [pscustomobject]@{ Field = 'nodeVersion'; Value = 'v22.000001.000001'; Label = 'node-leading-zero' },
            [pscustomobject]@{ Field = 'nodeVersion'; Value = 'v22.1000000.1'; Label = 'node-overlong' },
            [pscustomobject]@{ Field = 'npmVersion'; Value = "11.6.2`nsecond-line"; Label = 'newline' },
            [pscustomobject]@{ Field = 'rustVersion'; Value = 'rustc 1.89.0 (abc1234 2026-08-01)'; Label = 'rust-banner' },
            [pscustomobject]@{ Field = 'rustVersion'; Value = 'rustc 1.000088.0'; Label = 'rust-leading-zero' },
            [pscustomobject]@{ Field = 'rustVersion'; Value = 'rustc 1.1000000.0'; Label = 'rust-overlong' },
            [pscustomobject]@{ Field = 'pesterVersion'; Value = $null; Label = 'null' },
            [pscustomobject]@{ Field = 'cargoDenyVersion'; Value = [object[]]@('0.19.0'); Label = 'array' },
            [pscustomobject]@{ Field = 'cargoAuditVersion'; Value = '0.0.0'; Label = 'zero' },
            [pscustomobject]@{ Field = 'clangVersion'; Value = 'clang version 21.1.8'; Label = 'raw-clang-banner' },
            [pscustomobject]@{ Field = 'visualStudioVersion'; Value = '17.14.36310'; Label = 'three-part-vs' },
            [pscustomobject]@{ Field = 'windowsSdkVersion'; Value = 'C:\Program Files\Windows Kits\10'; Label = 'path' },
            [pscustomobject]@{ Field = 'webView2Version'; Value = '139.0.3405.86 beta'; Label = 'suffix' }
        )
        for ($index = 0; $index -lt $cases.Count; $index++) {
            $case = $cases[$index]
            $root = Join-Path $TestDrive ('machine-version-malformed-{0:D2}' -f $index)
            Write-EvidenceFixture -Root $root
            $path = Join-Path $root 'machine.json'
            $machine = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            $machine.($case.Field) = $case.Value
            Write-TestJson -Value $machine -Path $path
            $result = Invoke-ReturnContractValidation -EvidenceRoot $root
            $result.ExitCode | Should -Not -Be 0 -Because "$($case.Field) must reject $($case.Label) evidence"
            $result.Output | Should -Match ([regex]::Escape($case.Field))
        }
    }

    It 'enforces established toolchain floors while accepting future supported normalized versions' {
        $floorCases = @(
            [pscustomobject]@{ Field = 'powerShellVersion'; Value = '7.4.9' },
            [pscustomobject]@{ Field = 'pesterVersion'; Value = '4.10.1' },
            [pscustomobject]@{ Field = 'visualStudioVersion'; Value = '16.11.99999.1' },
            [pscustomobject]@{ Field = 'windowsSdkVersion'; Value = '10.0.22621.0' }
        )
        for ($index = 0; $index -lt $floorCases.Count; $index++) {
            $case = $floorCases[$index]
            $root = Join-Path $TestDrive ('machine-version-floor-{0:D2}' -f $index)
            Write-EvidenceFixture -Root $root
            $path = Join-Path $root 'machine.json'
            $machine = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            $machine.($case.Field) = $case.Value
            Write-TestJson -Value $machine -Path $path
            $result = Invoke-ReturnContractValidation -EvidenceRoot $root
            $result.ExitCode | Should -Not -Be 0
            $result.Output | Should -Match ([regex]::Escape($case.Field))
        }

        $futureRoot = Join-Path $TestDrive 'machine-version-future-supported'
        Write-EvidenceFixture -Root $futureRoot
        $futurePath = Join-Path $futureRoot 'machine.json'
        $future = Get-Content -LiteralPath $futurePath -Raw | ConvertFrom-Json
        $future.powerShellVersion = '8.1.0'
        $future.gitVersion = '3.1.0.windows.2'
        $future.npmVersion = '12.0.1'
        $future.pesterVersion = '6.1.0'
        $future.cargoDenyVersion = '1.0.0'
        $future.cargoAuditVersion = '1.1.0'
        $future.clangVersion = '22.0.0'
        $future.visualStudioVersion = '17.99.99999.1'
        $future.windowsSdkVersion = '10.0.30000.0'
        $future.webView2Version = '200.1.2.3'
        Write-TestJson -Value $future -Path $futurePath
        $futureResult = Invoke-ReturnContractValidation -EvidenceRoot $futureRoot
        $futureResult.ExitCode | Should -Be 0 -Because $futureResult.Output
        $futureResult.Output | Should -Match 'RETURN_CONTRACT_OK'

        $privateRoot = Join-Path $TestDrive 'machine-version-ip-private-value'
        Write-EvidenceFixture -Root $privateRoot
        $privatePath = Join-Path $privateRoot 'machine.json'
        $privateMachine = Get-Content -LiteralPath $privatePath -Raw | ConvertFrom-Json
        $privateMachine.cpuClass = '10.20.30.40'
        Write-TestJson -Value $privateMachine -Path $privatePath
        $privateResult = Invoke-ReturnContractValidation -EvidenceRoot $privateRoot
        $privateResult.ExitCode | Should -Not -Be 0
        $privateResult.Output | Should -Match 'IPv4(?:\s|\|)+address'

        $unknownCpuRoot = Join-Path $TestDrive 'machine-unknown-cpu'
        Write-EvidenceFixture -Root $unknownCpuRoot
        $unknownCpuPath = Join-Path $unknownCpuRoot 'machine.json'
        $unknownCpu = Get-Content -LiteralPath $unknownCpuPath -Raw | ConvertFrom-Json
        $unknownCpu.cpuClass = 'unknown'
        Write-TestJson -Value $unknownCpu -Path $unknownCpuPath
        $unknownCpuResult = Invoke-ReturnContractValidation -EvidenceRoot $unknownCpuRoot
        $unknownCpuResult.ExitCode | Should -Not -Be 0
        $unknownCpuResult.Output | Should -Match 'cpuClass'

        foreach ($cpuClass in @('UNKNOWN', ' Qualcomm ARM64 validation class ')) {
            $root = Join-Path $TestDrive ('machine-noncanonical-cpu-{0}' -f [guid]::NewGuid().ToString('N'))
            Write-EvidenceFixture -Root $root
            $path = Join-Path $root 'machine.json'
            $machine = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            $machine.cpuClass = $cpuClass
            Write-TestJson -Value $machine -Path $path
            $result = Invoke-ReturnContractValidation -EvidenceRoot $root
            $result.ExitCode | Should -Not -Be 0
            $result.Output | Should -Match 'cpuClass'
        }
    }

    It 'rejects machine values outside native producer domains and decoded privacy boundaries' {
        $processorRoot = Join-Path $TestDrive 'machine-processor-count-int64'
        Write-EvidenceFixture -Root $processorRoot
        $processorPath = Join-Path $processorRoot 'machine.json'
        $processorMachine = Get-Content -LiteralPath $processorPath -Raw | ConvertFrom-Json
        $processorMachine.logicalProcessorCount = [int64]::MaxValue
        Write-TestJson -Value $processorMachine -Path $processorPath
        $processorResult = Invoke-ReturnContractValidation -EvidenceRoot $processorRoot
        $processorResult.ExitCode | Should -Not -Be 0
        $processorResult.Output | Should -Match 'logicalProcessorCount.*Int32'

        foreach ($separator in @([char]0x0001, [char]0x2028)) {
            $root = Join-Path $TestDrive ('machine-cpu-private-control-{0}' -f [int]$separator)
            Write-EvidenceFixture -Root $root
            $path = Join-Path $root 'machine.json'
            $machine = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            $machine.cpuClass = "user@exa$($separator)mple.com"
            Write-TestJson -Value $machine -Path $path
            $result = Invoke-ReturnContractValidation -EvidenceRoot $root
            $result.ExitCode | Should -Not -Be 0
            $result.Output | Should -Match 'cpuClass|email address'
        }
    }

    It 'cannot create or claim a bundle in contract-only mode' {
        $evidenceRoot = Join-Path $TestDrive 'contract-only-output'
        Write-EvidenceFixture -Root $evidenceRoot
        $zipPath = Join-Path $TestDrive 'forbidden-contract-only.zip'
        $result = Invoke-HandoffScript -Path (Join-Path $script:ScriptsRoot 'New-CMTraceOpenArm64ValidationReturn.ps1') -Arguments @(
            '-EvidenceRoot', $evidenceRoot,
            '-ContractOnly',
            '-OutputPath', $zipPath
        )
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Not -Match 'RETURN_BUNDLE_OK|RETURN_CONTRACT_OK'
        Test-Path -LiteralPath $zipPath | Should -BeFalse
        Test-Path -LiteralPath "$zipPath.sha256" | Should -BeFalse
    }

    It 'cannot create a production return on an off-target host' -Skip:($IsWindows -and [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64' -and [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq 'Arm64' -and [Environment]::OSVersion.Version.Build -ge 22000) {
        $evidenceRoot = Join-Path $TestDrive 'off-target-production'
        Write-EvidenceFixture -Root $evidenceRoot
        $zipPath = Join-Path $TestDrive 'pr583-arm64-001.zip'
        $result = Invoke-HandoffScript -Path (Join-Path $script:ScriptsRoot 'New-CMTraceOpenArm64ValidationReturn.ps1') -Arguments @(
            '-EvidenceRoot', $evidenceRoot,
            '-OutputPath', $zipPath,
            '-RepositoryPath', $TestDrive
        )
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'Windows 11 ARM64'
        $result.Output | Should -Not -Match 'RETURN_BUNDLE_OK'
        Test-Path -LiteralPath $zipPath | Should -BeFalse
        Test-Path -LiteralPath "$zipPath.sha256" | Should -BeFalse
    }

    It 'rejects a hostname-bearing production basename before the platform gate' {
        $evidenceRoot = Join-Path $TestDrive 'private-output-basename'
        Write-EvidenceFixture -Root $evidenceRoot
        $zipPath = Join-Path $TestDrive 'PRIVATE-LAB-PC-pr583.zip'
        $result = Invoke-HandoffScript -Path (Join-Path $script:ScriptsRoot 'New-CMTraceOpenArm64ValidationReturn.ps1') -Arguments @(
            '-EvidenceRoot', $evidenceRoot,
            '-OutputPath', $zipPath,
            '-RepositoryPath', $TestDrive
        )
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'OutputPath basename must match pr583-arm64-NNN\.zip'
        $result.Output | Should -Not -Match 'Windows 11 ARM64'
        Test-Path -LiteralPath $zipPath | Should -BeFalse
        Test-Path -LiteralPath "$zipPath.sha256" | Should -BeFalse
    }

    It 'requires RepositoryPath for every production return invocation' {
        $evidenceRoot = Join-Path $TestDrive 'missing-production-repository'
        Write-EvidenceFixture -Root $evidenceRoot
        $zipPath = Join-Path $TestDrive 'missing-production-repository.zip'
        $result = Invoke-HandoffScript -Path (Join-Path $script:ScriptsRoot 'New-CMTraceOpenArm64ValidationReturn.ps1') -Arguments @(
            '-EvidenceRoot', $evidenceRoot,
            '-OutputPath', $zipPath
        )
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'RepositoryPath'
        $result.Output | Should -Not -Match 'RETURN_BUNDLE_OK'
        Test-Path -LiteralPath $zipPath | Should -BeFalse
        Test-Path -LiteralPath "$zipPath.sha256" | Should -BeFalse
    }

    It 'allows disposable lab and user literals in immutable contract wording but rejects them in mutable logs' {
        $root = Join-Path $TestDrive 'literal-collision'
        Write-EvidenceFixture -Root $root
        $privacyPath = Join-Path $root 'raw-logs/privacy-literals.json'
        $privacy = Get-Content -LiteralPath $privacyPath -Raw | ConvertFrom-Json
        $privacy.computerName = 'lab'
        $privacy.userName = 'user'
        Write-TestJson -Value $privacy -Path $privacyPath

        $logPath = Join-Path $root 'sanitized-logs/npm-ci.log'
        Set-Content -LiteralPath $logPath -Value "gate=npm-ci`nstatus=passed`nresult=available userland username" -Encoding utf8NoBOM
        Write-SummaryLogHash -Root $root -GateId 'npm-ci'
        $valid = Invoke-ReturnContractValidation -EvidenceRoot $root
        $valid.ExitCode | Should -Be 0 -Because $valid.Output
        $valid.Output | Should -Match 'RETURN_CONTRACT_OK'

        Set-Content -LiteralPath $logPath -Value "gate=npm-ci`nstatus=passed`nactor=user" -Encoding utf8NoBOM
        Write-SummaryLogHash -Root $root -GateId 'npm-ci'
        $unsafe = Invoke-ReturnContractValidation -EvidenceRoot $root
        $unsafe.ExitCode | Should -Not -Be 0
        $unsafe.Output | Should -Match 'target-private userName'
    }

    It 'rejects embedded target-private literals in logs and manual evidence IDs' {
        foreach ($case in @(
            [pscustomobject]@{ Name = 'computer'; Property = 'computerName'; Literal = 'PRIVATE-LAB-PC'; Text = 'prefix-PRIVATE-LAB-PC-suffix' },
            [pscustomobject]@{ Name = 'dns-domain'; Property = 'userDnsDomain'; Literal = 'contoso.example'; Text = 'xcontoso.exampley' }
        )) {
            $root = Join-Path $TestDrive "embedded-$($case.Name)"
            Write-EvidenceFixture -Root $root
            $privacyPath = Join-Path $root 'raw-logs/privacy-literals.json'
            $privacy = Get-Content -LiteralPath $privacyPath -Raw | ConvertFrom-Json
            $privacy.($case.Property) = $case.Literal
            Write-TestJson -Value $privacy -Path $privacyPath
            Set-Content -LiteralPath (Join-Path $root 'sanitized-logs/npm-ci.log') -Value "gate=npm-ci`nstatus=passed`nvalue=$($case.Text)" -Encoding utf8NoBOM
            Write-SummaryLogHash -Root $root -GateId 'npm-ci'
            $result = Invoke-ReturnContractValidation -EvidenceRoot $root
            $result.ExitCode | Should -Not -Be 0
            $result.Output | Should -Match ([regex]::Escape("target-private $($case.Property)"))
        }

        $evidenceIdRoot = Join-Path $TestDrive 'embedded-evidence-id'
        Write-EvidenceFixture -Root $evidenceIdRoot
        $privacyPath = Join-Path $evidenceIdRoot 'raw-logs/privacy-literals.json'
        $privacy = Get-Content -LiteralPath $privacyPath -Raw | ConvertFrom-Json
        $privacy.userName = 'lab'
        Write-TestJson -Value $privacy -Path $privacyPath
        $manualPath = Join-Path $evidenceIdRoot 'manual-results.json'
        $manual = Get-Content -LiteralPath $manualPath -Raw | ConvertFrom-Json
        $gate = @($manual.gates | Where-Object { $_.id -ceq 'clean-snapshot-version-isolation' })[0]
        $gate.status = 'BLOCKED'
        $gate.dispositionCode = 'ENVIRONMENT_UNAVAILABLE'
        $gate.executedAtUtc = '2026-08-23T16:10:00.0000000Z'
        $gate.evidenceId = 'prefix-lab-suffix'
        $gate.evidenceSha256 = Write-ManualEvidenceProof -Root $evidenceIdRoot -EvidenceId $gate.evidenceId
        Write-TestJson -Value $manual -Path $manualPath
        $evidenceIdResult = Invoke-ReturnContractValidation -EvidenceRoot $evidenceIdRoot
        $evidenceIdResult.ExitCode | Should -Not -Be 0
        $evidenceIdResult.Output | Should -Match 'target-private userName'
    }

    It 'uses drive-token boundaries without exempting short private literals' {
        $metricRoot = Join-Path $TestDrive 'home-drive-boundary-safe'
        Write-EvidenceFixture -Root $metricRoot
        Set-Content -LiteralPath (Join-Path $metricRoot 'sanitized-logs/npm-ci.log') -Value "gate=npm-ci`nstatus=passed`nresult=metric:" -Encoding utf8NoBOM
        Write-SummaryLogHash -Root $metricRoot -GateId 'npm-ci'
        $metricResult = Invoke-ReturnContractValidation -EvidenceRoot $metricRoot
        $metricResult.ExitCode | Should -Be 0 -Because $metricResult.Output

        $driveRoot = Join-Path $TestDrive 'home-drive-boundary-private'
        Write-EvidenceFixture -Root $driveRoot
        Set-Content -LiteralPath (Join-Path $driveRoot 'sanitized-logs/npm-ci.log') -Value "gate=npm-ci`nstatus=passed`ndrive=C:" -Encoding utf8NoBOM
        Write-SummaryLogHash -Root $driveRoot -GateId 'npm-ci'
        $driveResult = Invoke-ReturnContractValidation -EvidenceRoot $driveRoot
        $driveResult.ExitCode | Should -Not -Be 0
        $driveResult.Output | Should -Match 'target-private homeDrive'

        $shortRoot = Join-Path $TestDrive 'short-private-literal'
        Write-EvidenceFixture -Root $shortRoot
        $privacyPath = Join-Path $shortRoot 'raw-logs/privacy-literals.json'
        $privacy = Get-Content -LiteralPath $privacyPath -Raw | ConvertFrom-Json
        $privacy.userName = 'ab'
        Write-TestJson -Value $privacy -Path $privacyPath
        Set-Content -LiteralPath (Join-Path $shortRoot 'sanitized-logs/npm-ci.log') -Value "gate=npm-ci`nstatus=passed`nactor=ab" -Encoding utf8NoBOM
        Write-SummaryLogHash -Root $shortRoot -GateId 'npm-ci'
        $shortResult = Invoke-ReturnContractValidation -EvidenceRoot $shortRoot
        $shortResult.ExitCode | Should -Not -Be 0
        $shortResult.Output | Should -Match 'target-private userName'
    }

    It 'preserves null only when a failed gate has no trustworthy native exit code' {
        $root = Join-Path $TestDrive 'failed-null-exit-code'
        Write-EvidenceFixture -Root $root
        $summaryPath = Join-Path $root 'summary.json'
        $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
        $gate = @($summary.gates | Where-Object { $_.id -ceq 'source-clean-after' })[0]
        $gate.status = 'failed'
        $gate.exitCode = $null
        $summary.automaticStatus = 'FAILED'
        $rawPath = Join-Path $root 'raw-logs/source-clean-after.log'
        $sanitizedPath = Join-Path $root 'sanitized-logs/source-clean-after.log'
        Set-Content -LiteralPath $rawPath -Value "gate=source-clean-after`nstatus=failed`nprivateResult=runner-failure-without-native-code" -Encoding utf8NoBOM
        Set-Content -LiteralPath $sanitizedPath -Value "gate=source-clean-after`nstatus=failed`nresult=runner-failure-without-native-code" -Encoding utf8NoBOM
        $gate.rawLogSha256 = Get-CMTraceSha256 -Path $rawPath
        $gate.sanitizedLogSha256 = Get-CMTraceSha256 -Path $sanitizedPath
        Write-TestJson -Value $summary -Path $summaryPath
        Write-ManualBinding -Root $root

        $unknownResult = Invoke-ReturnContractValidation -EvidenceRoot $root
        $unknownResult.ExitCode | Should -Be 0 -Because $unknownResult.Output

        $gate.exitCode = 0
        Write-TestJson -Value $summary -Path $summaryPath
        Write-ManualBinding -Root $root
        $zeroResult = Invoke-ReturnContractValidation -EvidenceRoot $root
        $zeroResult.ExitCode | Should -Not -Be 0
        $zeroResult.Output | Should -Match 'cannot have exitCode 0'

        $gate.exitCode = 253
        Write-TestJson -Value $summary -Path $summaryPath
        Write-ManualBinding -Root $root
        $sentinelResult = Invoke-ReturnContractValidation -EvidenceRoot $root
        $sentinelResult.ExitCode | Should -Not -Be 0
        $sentinelResult.Output | Should -Match 'reserved wrapper infrastructure'
        $sentinelResult.Output | Should -Match 'exit code 253'
    }

    It 'accepts only native Int32 automatic process exit codes' {
        $root = Join-Path $TestDrive 'native-process-exit-range'
        Write-EvidenceFixture -Root $root
        $summaryPath = Join-Path $root 'summary.json'
        $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
        $gate = @($summary.gates | Where-Object { $_.id -ceq 'source-clean-after' })[0]
        $gate.status = 'failed'
        $summary.automaticStatus = 'FAILED'
        $rawPath = Join-Path $root 'raw-logs/source-clean-after.log'
        $sanitizedPath = Join-Path $root 'sanitized-logs/source-clean-after.log'
        Set-Content -LiteralPath $rawPath -Value "gate=source-clean-after`nstatus=failed`nprivateResult=native-exit" -Encoding utf8NoBOM
        Set-Content -LiteralPath $sanitizedPath -Value "gate=source-clean-after`nstatus=failed`nresult=native-exit" -Encoding utf8NoBOM
        $gate.rawLogSha256 = Get-CMTraceSha256 -Path $rawPath
        $gate.sanitizedLogSha256 = Get-CMTraceSha256 -Path $sanitizedPath

        foreach ($exitCode in @([int64][int]::MinValue, [int64][int]::MaxValue)) {
            $gate.exitCode = $exitCode
            Write-TestJson -Value $summary -Path $summaryPath
            Write-ManualBinding -Root $root
            $valid = Invoke-ReturnContractValidation -EvidenceRoot $root
            $valid.ExitCode | Should -Be 0 -Because $valid.Output
        }
        foreach ($exitCode in @(([int64][int]::MinValue - 1L), ([int64][int]::MaxValue + 1L), [int64]::MaxValue)) {
            $gate.exitCode = $exitCode
            Write-TestJson -Value $summary -Path $summaryPath
            Write-ManualBinding -Root $root
            $invalid = Invoke-ReturnContractValidation -EvidenceRoot $root
            $invalid.ExitCode | Should -Not -Be 0
            $invalid.Output | Should -Match 'native Int32(?:\s|\|)+process-exit range'
        }
    }

    It 'rejects incomplete, inconsistent, and wrong-architecture JSON evidence' {
        $manualRoot = Join-Path $TestDrive 'missing-manual-gate'
        Write-EvidenceFixture -Root $manualRoot
        $manualPath = Join-Path $manualRoot 'manual-results.json'
        $manual = Get-Content -LiteralPath $manualPath -Raw | ConvertFrom-Json
        $manual.gates = @($manual.gates | Select-Object -Skip 1)
        Write-TestJson -Value $manual -Path $manualPath
        $manualResult = Invoke-ReturnContractValidation -EvidenceRoot $manualRoot
        $manualResult.ExitCode | Should -Not -Be 0
        $manualResult.Output | Should -Match 'gate count'

        $summaryRoot = Join-Path $TestDrive 'inconsistent-summary'
        Write-EvidenceFixture -Root $summaryRoot
        $summaryPath = Join-Path $summaryRoot 'summary.json'
        $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
        $summary.automaticStatus = 'FAILED'
        Write-TestJson -Value $summary -Path $summaryPath
        Write-ManualBinding -Root $summaryRoot
        $summaryResult = Invoke-ReturnContractValidation -EvidenceRoot $summaryRoot
        $summaryResult.ExitCode | Should -Not -Be 0
        $summaryResult.Output | Should -Match 'automaticStatus'

        $machineRoot = Join-Path $TestDrive 'x64-machine'
        Write-EvidenceFixture -Root $machineRoot
        $machinePath = Join-Path $machineRoot 'machine.json'
        $machine = Get-Content -LiteralPath $machinePath -Raw | ConvertFrom-Json
        $machine.osArchitecture = 'X64'
        Write-TestJson -Value $machine -Path $machinePath
        $machineResult = Invoke-ReturnContractValidation -EvidenceRoot $machineRoot
        $machineResult.ExitCode | Should -Not -Be 0
        $machineResult.Output | Should -Match 'machine osArchitecture'
    }

    It 'rejects one-element arrays where fixed strings and statuses are required' {
        $coordinateRoot = Join-Path $TestDrive 'array-coordinate'
        Write-EvidenceFixture -Root $coordinateRoot
        $coordinateSummaryPath = Join-Path $coordinateRoot 'summary.json'
        $coordinateSummary = Get-Content -LiteralPath $coordinateSummaryPath -Raw | ConvertFrom-Json
        $coordinateSummary.handoffId = [object[]]@($script:CMTraceHandoffId)
        Write-TestJson -Value $coordinateSummary -Path $coordinateSummaryPath
        Write-ManualBinding -Root $coordinateRoot
        $coordinateResult = Invoke-ReturnContractValidation -EvidenceRoot $coordinateRoot
        $coordinateResult.ExitCode | Should -Not -Be 0
        $coordinateResult.Output | Should -Match 'string|coordinate'

        $statusRoot = Join-Path $TestDrive 'array-status'
        Write-EvidenceFixture -Root $statusRoot
        $statusSummaryPath = Join-Path $statusRoot 'summary.json'
        $statusSummary = Get-Content -LiteralPath $statusSummaryPath -Raw | ConvertFrom-Json
        $statusSummary.gates[0].status = [object[]]@('passed')
        Write-TestJson -Value $statusSummary -Path $statusSummaryPath
        Write-ManualBinding -Root $statusRoot
        $statusResult = Invoke-ReturnContractValidation -EvidenceRoot $statusRoot
        $statusResult.ExitCode | Should -Not -Be 0
        $statusResult.Output | Should -Match 'string|status'
    }

    It 'rejects noncanonical uppercase SHA-256 evidence' {
        $root = Join-Path $TestDrive 'uppercase-sha'
        Write-EvidenceFixture -Root $root
        $summaryPath = Join-Path $root 'summary.json'
        $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
        $summary.gates[0].rawLogSha256 = $summary.gates[0].rawLogSha256.ToUpperInvariant()
        Write-TestJson -Value $summary -Path $summaryPath
        Write-ManualBinding -Root $root
        $result = Invoke-ReturnContractValidation -EvidenceRoot $root
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'lowercase SHA-256'
    }

    It 'rejects an executed gate whose dependency did not pass' {
        $root = Join-Path $TestDrive 'invalid-dependency-execution'
        Write-EvidenceFixture -Root $root
        $summaryPath = Join-Path $root 'summary.json'
        $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
        $npmGate = @($summary.gates | Where-Object id -eq 'npm-ci')[0]
        $npmGate.status = 'failed'
        $npmGate.exitCode = 1
        $rawPath = Join-Path $root 'raw-logs/npm-ci.log'
        $sanitizedPath = Join-Path $root 'sanitized-logs/npm-ci.log'
        Set-Content -LiteralPath $rawPath -Value "gate=npm-ci`nstatus=failed`nresult=bounded-test-evidence" -Encoding utf8NoBOM
        Set-Content -LiteralPath $sanitizedPath -Value "gate=npm-ci`nstatus=failed`nresult=bounded-test-evidence" -Encoding utf8NoBOM
        $npmGate.rawLogSha256 = Get-CMTraceSha256 -Path $rawPath
        $npmGate.sanitizedLogSha256 = Get-CMTraceSha256 -Path $sanitizedPath
        $summary.automaticStatus = 'FAILED'
        Write-TestJson -Value $summary -Path $summaryPath
        Write-ManualBinding -Root $root
        $result = Invoke-ReturnContractValidation -EvidenceRoot $root
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'failed or blocked dependency'
    }

    It 'rejects scalar blockedBy even when exactly one dependency blocked the gate' {
        $root = Join-Path $TestDrive 'scalar-one-dependency-blocked-by'
        Write-EvidenceFixture -Root $root
        $summaryPath = Join-Path $root 'summary.json'
        $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
        $failedGate = @($summary.gates | Where-Object id -eq 'windows-build-provenance')[0]
        $failedGate.status = 'failed'
        $failedGate.exitCode = 1
        $blockedGate = @($summary.gates | Where-Object id -eq 'arm64-pe-verification')[0]
        $blockedGate.status = 'blocked'
        $blockedGate.exitCode = $null
        $blockedGate.startedAtUtc = $null
        $blockedGate.durationMilliseconds = 0
        $blockedGate.command = $null
        $blockedGate.blockedBy = 'windows-build-provenance'

        foreach ($gate in @($failedGate, $blockedGate)) {
            $rawPath = Join-Path $root "raw-logs/$($gate.id).log"
            $sanitizedPath = Join-Path $root "sanitized-logs/$($gate.id).log"
            Set-Content -LiteralPath $rawPath -Value "gate=$($gate.id)`nstatus=$($gate.status)`nprivateResult=bounded-test-evidence" -Encoding utf8NoBOM
            Set-Content -LiteralPath $sanitizedPath -Value "gate=$($gate.id)`nstatus=$($gate.status)`nresult=bounded-test-evidence" -Encoding utf8NoBOM
            $gate.rawLogSha256 = Get-CMTraceSha256 -Path $rawPath
            $gate.sanitizedLogSha256 = Get-CMTraceSha256 -Path $sanitizedPath
        }
        $summary.automaticStatus = 'FAILED'
        Write-TestJson -Value $summary -Path $summaryPath

        $artifactsPath = Join-Path $root 'artifacts.json'
        $artifacts = Get-Content -LiteralPath $artifactsPath -Raw | ConvertFrom-Json
        $artifacts.items = @()
        Write-TestJson -Value $artifacts -Path $artifactsPath
        Write-ManualBinding -Root $root

        $result = Invoke-ReturnContractValidation -EvidenceRoot $root
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'blockedBy must be a JSON array'
    }

    It 'accepts a correctly artifact-bound partial PASS and rejects an impossible exact-head surface PASS' {
        $passRoot = Join-Path $TestDrive 'partial-pass'
        Write-EvidenceFixture -Root $passRoot
        $manualPath = Join-Path $passRoot 'manual-results.json'
        $manual = Get-Content -LiteralPath $manualPath -Raw | ConvertFrom-Json
        $gate = @($manual.gates | Where-Object id -eq 'full-portable-launch')[0]
        $gate.status = 'PASS'
        $gate.dispositionCode = 'CONFIRMED'
        $gate.executedAtUtc = '2026-08-23T17:00:00.0000000Z'
        $gate.evidenceId = 'full-portable-launch-001'
        $gate.evidenceSha256 = Write-ManualEvidenceProof -Root $passRoot -EvidenceId $gate.evidenceId
        $gate.nativeArm64Observed = $true
        $gate.independentReadback = $true
        $gate.artifactSha256 = Get-CMTraceSha256 -Path (Join-Path $passRoot 'raw-artifacts/full/cmtrace-open.exe')
        Write-TestJson -Value $manual -Path $manualPath
        $passResult = Invoke-ReturnContractValidation -EvidenceRoot $passRoot
        $passResult.ExitCode | Should -Be 0 -Because $passResult.Output

        $gapRoot = Join-Path $TestDrive 'impossible-surface-pass'
        Write-EvidenceFixture -Root $gapRoot
        $gapManualPath = Join-Path $gapRoot 'manual-results.json'
        $gapManual = Get-Content -LiteralPath $gapManualPath -Raw | ConvertFrom-Json
        $gap = @($gapManual.gates | Where-Object id -eq 'eventlog-grouping-drag-pivot-surface')[0]
        $gap.status = 'PASS'
        $gap.dispositionCode = 'CONFIRMED'
        $gap.executedAtUtc = '2026-08-23T17:01:00.0000000Z'
        $gap.evidenceId = 'drag-pivot-surface-001'
        $gap.evidenceSha256 = Write-ManualEvidenceProof -Root $gapRoot -EvidenceId $gap.evidenceId
        $gap.nativeArm64Observed = $true
        $gap.independentReadback = $true
        Write-TestJson -Value $gapManual -Path $gapManualPath
        $gapResult = Invoke-ReturnContractValidation -EvidenceRoot $gapRoot
        $gapResult.ExitCode | Should -Not -Be 0
        $gapResult.Output | Should -Match 'cannot be marked PASS'
    }

    It 'requires three positive cold-window and first-row values with exact medians' {
        $coldRoot = Join-Path $TestDrive 'cold-window-three-runs'
        Write-EvidenceFixture -Root $coldRoot
        $coldManualPath = Join-Path $coldRoot 'manual-results.json'
        $coldManual = Get-Content -LiteralPath $coldManualPath -Raw | ConvertFrom-Json
        $coldGate = @($coldManual.gates | Where-Object id -eq 'performance-cold-window-launch')[0]
        $coldGate.status = 'PASS'
        $coldGate.dispositionCode = 'CONFIRMED'
        $coldGate.executedAtUtc = '2026-08-23T18:00:00.0000000Z'
        $coldGate.evidenceId = 'performance-cold-window-launch-001'
        $coldGate.evidenceSha256 = Write-ManualEvidenceProof -Root $coldRoot -EvidenceId $coldGate.evidenceId
        $coldGate.nativeArm64Observed = $true
        $coldGate.independentReadback = $true
        $coldGate.artifactSha256 = Get-CMTraceSha256 -Path (Join-Path $coldRoot 'raw-artifacts/full/cmtrace-open.exe')
        $coldManual.measurements.coldLaunchRun1Milliseconds = 310
        $coldManual.measurements.coldLaunchRun2Milliseconds = 190
        $coldManual.measurements.coldLaunchRun3Milliseconds = 250
        $coldManual.measurements.coldLaunchMilliseconds = 250
        $coldManual.measurements.coldLaunchRun1PeakWorkingSetBytes = 3100
        $coldManual.measurements.coldLaunchRun2PeakWorkingSetBytes = 1900
        $coldManual.measurements.coldLaunchRun3PeakWorkingSetBytes = 2500
        $coldManual.measurements.coldLaunchPeakWorkingSetBytes = 2500
        Write-TestJson -Value $coldManual -Path $coldManualPath
        $coldResult = Invoke-ReturnContractValidation -EvidenceRoot $coldRoot
        $coldResult.ExitCode | Should -Be 0 -Because $coldResult.Output

        $wrongMedianRoot = Join-Path $TestDrive 'cold-window-wrong-median'
        Write-EvidenceFixture -Root $wrongMedianRoot
        $wrongPath = Join-Path $wrongMedianRoot 'manual-results.json'
        $wrong = Get-Content -LiteralPath $wrongPath -Raw | ConvertFrom-Json
        $wrongGate = @($wrong.gates | Where-Object id -eq 'performance-cold-window-launch')[0]
        $wrongGate.status = 'PASS'
        $wrongGate.dispositionCode = 'CONFIRMED'
        $wrongGate.executedAtUtc = '2026-08-23T18:01:00.0000000Z'
        $wrongGate.evidenceId = 'performance-cold-window-launch-002'
        $wrongGate.evidenceSha256 = Write-ManualEvidenceProof -Root $wrongMedianRoot -EvidenceId $wrongGate.evidenceId
        $wrongGate.nativeArm64Observed = $true
        $wrongGate.independentReadback = $true
        $wrongGate.artifactSha256 = Get-CMTraceSha256 -Path (Join-Path $wrongMedianRoot 'raw-artifacts/full/cmtrace-open.exe')
        foreach ($name in @('coldLaunchRun1Milliseconds', 'coldLaunchRun2Milliseconds', 'coldLaunchRun3Milliseconds', 'coldLaunchRun1PeakWorkingSetBytes', 'coldLaunchRun2PeakWorkingSetBytes', 'coldLaunchRun3PeakWorkingSetBytes')) {
            $wrong.measurements.$name = 100
        }
        $wrong.measurements.coldLaunchMilliseconds = 101
        $wrong.measurements.coldLaunchPeakWorkingSetBytes = 100
        Write-TestJson -Value $wrong -Path $wrongPath
        $wrongResult = Invoke-ReturnContractValidation -EvidenceRoot $wrongMedianRoot
        $wrongResult.ExitCode | Should -Not -Be 0
        $wrongResult.Output | Should -Match 'exact medians'

        $firstRowRoot = Join-Path $TestDrive 'first-row-three-runs'
        Write-EvidenceFixture -Root $firstRowRoot
        $firstRowPath = Join-Path $firstRowRoot 'manual-results.json'
        $firstRow = Get-Content -LiteralPath $firstRowPath -Raw | ConvertFrom-Json
        $firstRowGate = @($firstRow.gates | Where-Object id -eq 'performance-cold-first-visible-row')[0]
        $firstRowGate.status = 'PASS'
        $firstRowGate.dispositionCode = 'CONFIRMED'
        $firstRowGate.executedAtUtc = '2026-08-23T18:02:00.0000000Z'
        $firstRowGate.evidenceId = 'performance-first-row-001'
        $firstRowGate.evidenceSha256 = Write-ManualEvidenceProof -Root $firstRowRoot -EvidenceId $firstRowGate.evidenceId
        $firstRowGate.nativeArm64Observed = $true
        $firstRowGate.independentReadback = $true
        $firstRowGate.artifactSha256 = Get-CMTraceSha256 -Path (Join-Path $firstRowRoot 'raw-artifacts/full/cmtrace-open.exe')
        $firstRow.measurements.firstRowRun1Milliseconds = 500
        $firstRow.measurements.firstRowRun2Milliseconds = 300
        $firstRow.measurements.firstRowRun3Milliseconds = 400
        $firstRow.measurements.firstRowMilliseconds = 400
        Write-TestJson -Value $firstRow -Path $firstRowPath
        $firstRowResult = Invoke-ReturnContractValidation -EvidenceRoot $firstRowRoot
        $firstRowResult.ExitCode | Should -Be 0 -Because $firstRowResult.Output
    }

    It 'rejects stale unowned measurements and impossible MDMDiag counts' {
        $staleRoot = Join-Path $TestDrive 'stale-unowned-measurement'
        Write-EvidenceFixture -Root $staleRoot
        $stalePath = Join-Path $staleRoot 'manual-results.json'
        $stale = Get-Content -LiteralPath $stalePath -Raw | ConvertFrom-Json
        $stale.measurements.localWideRecordCount = 10
        Write-TestJson -Value $stale -Path $stalePath
        $staleResult = Invoke-ReturnContractValidation -EvidenceRoot $staleRoot
        $staleResult.ExitCode | Should -Not -Be 0
        $staleResult.Output | Should -Match 'must be null until an owning(?:\s|\|)+gate is exercised'

        foreach ($case in @(
            [pscustomobject]@{ Name = 'too-many-members'; Archive = 513; Parsed = 1 },
            [pscustomobject]@{ Name = 'parsed-exceeds-members'; Archive = 2; Parsed = 3 }
        )) {
            $root = Join-Path $TestDrive "mdmdiag-$($case.Name)"
            Write-EvidenceFixture -Root $root
            $path = Join-Path $root 'manual-results.json'
            $manual = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            $gate = @($manual.gates | Where-Object id -eq 'mdmdiag-real-nonvacuous')[0]
            $gate.status = 'PASS'
            $gate.dispositionCode = 'CONFIRMED'
            $gate.executedAtUtc = '2026-08-23T18:03:00.0000000Z'
            $gate.evidenceId = "mdmdiag-$($case.Name)-001"
            $gate.evidenceSha256 = Write-ManualEvidenceProof -Root $root -EvidenceId $gate.evidenceId
            $gate.nativeArm64Observed = $true
            $gate.independentReadback = $true
            $gate.artifactSha256 = Get-CMTraceSha256 -Path (Join-Path $root 'raw-artifacts/full/cmtrace-open.exe')
            $manual.measurements.mdmArchiveMemberCount = $case.Archive
            $manual.measurements.mdmParsedEvtxMemberCount = $case.Parsed
            $manual.measurements.mdmRecordCount = 1
            Write-TestJson -Value $manual -Path $path
            $result = Invoke-ReturnContractValidation -EvidenceRoot $root
            $result.ExitCode | Should -Not -Be 0
            $result.Output | Should -Match '1\.\.512 archive members'
        }
    }

    It 'rejects impossible MDMDiag counts supplied through a sibling owning gate' {
        foreach ($case in @(
            [pscustomobject]@{ Name = 'sibling-too-many-members'; Archive = 513; Parsed = 1 },
            [pscustomobject]@{ Name = 'sibling-parsed-exceeds-members'; Archive = 2; Parsed = 3 }
        )) {
            $root = Join-Path $TestDrive "mdmdiag-$($case.Name)"
            Write-EvidenceFixture -Root $root
            $path = Join-Path $root 'manual-results.json'
            $manual = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            $gate = @($manual.gates | Where-Object id -eq 'mdmdiag-member-accounting')[0]
            $gate.status = 'PASS'
            $gate.dispositionCode = 'CONFIRMED'
            $gate.executedAtUtc = '2026-08-23T18:04:00.0000000Z'
            $gate.evidenceId = "mdmdiag-$($case.Name)-001"
            $gate.evidenceSha256 = Write-ManualEvidenceProof -Root $root -EvidenceId $gate.evidenceId
            $gate.nativeArm64Observed = $true
            $gate.independentReadback = $true
            $gate.artifactSha256 = Get-CMTraceSha256 -Path (Join-Path $root 'raw-artifacts/full/cmtrace-open.exe')
            $manual.measurements.mdmArchiveMemberCount = $case.Archive
            $manual.measurements.mdmParsedEvtxMemberCount = $case.Parsed
            Write-TestJson -Value $manual -Path $path

            $result = Invoke-ReturnContractValidation -EvidenceRoot $root
            $result.ExitCode | Should -Not -Be 0
            $result.Output | Should -Match '1\.\.512 archive members'
        }
    }

    It 'rejects PASS MDMDiag gates with null owning measurements' {
        foreach ($gateId in @('mdmdiag-real-nonvacuous', 'mdmdiag-member-accounting', 'mdmdiag-record-provenance')) {
            $root = Join-Path $TestDrive "mdmdiag-null-measurements-$gateId"
            Write-EvidenceFixture -Root $root
            $path = Join-Path $root 'manual-results.json'
            $manual = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            $gate = @($manual.gates | Where-Object id -eq $gateId)[0]
            $gate.status = 'PASS'
            $gate.dispositionCode = 'CONFIRMED'
            $gate.executedAtUtc = '2026-08-23T18:05:00.0000000Z'
            $gate.evidenceId = "mdmdiag-null-$gateId-001"
            $gate.evidenceSha256 = Write-ManualEvidenceProof -Root $root -EvidenceId $gate.evidenceId
            $gate.nativeArm64Observed = $true
            $gate.independentReadback = $true
            $gate.artifactSha256 = Get-CMTraceSha256 -Path (Join-Path $root 'raw-artifacts/full/cmtrace-open.exe')
            if ($gateId -in @('mdmdiag-real-nonvacuous', 'mdmdiag-record-provenance')) {
                $manual.measurements.mdmRecordCount = 1
            }
            Write-TestJson -Value $manual -Path $path

            $result = Invoke-ReturnContractValidation -EvidenceRoot $root
            $result.ExitCode | Should -Not -Be 0
            $result.Output | Should -Match 'mdmArchiveMemberCount.*integer'
        }
    }

    It 'rejects disguised binary logs even when the attacker updates the claimed hash' {
        $root = Join-Path $TestDrive 'binary-log'
        Write-EvidenceFixture -Root $root
        $path = Join-Path $root 'sanitized-logs/npm-ci.log'
        [IO.File]::WriteAllBytes($path, [byte[]]@(0x4D, 0x5A, 0x00, 0xFF, 0x00, 0x01))
        Write-SummaryLogHash -Root $root -GateId 'npm-ci'
        $result = Invoke-ReturnContractValidation -EvidenceRoot $root
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'strict UTF-8|binary|control'
    }

    It 'rejects long encoded payloads even when they are valid UTF-8 text' {
        $root = Join-Path $TestDrive 'encoded-log'
        Write-EvidenceFixture -Root $root
        $encoded = [Convert]::ToBase64String([byte[]]::new(65536))
        Set-Content -LiteralPath (Join-Path $root 'sanitized-logs/npm-ci.log') -Value "gate=npm-ci`nstatus=passed`npayload=$encoded" -Encoding utf8NoBOM
        Write-SummaryLogHash -Root $root -GateId 'npm-ci'
        $result = Invoke-ReturnContractValidation -EvidenceRoot $root
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'Base64 payload'

        $prefixedRoot = Join-Path $TestDrive 'narrow-prefixed-encoded-log'
        Write-EvidenceFixture -Root $prefixedRoot
        $prefixedPayload = ((1..64 | ForEach-Object { "payload=$($_):QUJD" }) -join "`n")
        Set-Content -LiteralPath (Join-Path $prefixedRoot 'sanitized-logs/npm-ci.log') `
            -Value "gate=npm-ci`nstatus=passed`n$prefixedPayload" -Encoding utf8NoBOM
        Write-SummaryLogHash -Root $prefixedRoot -GateId 'npm-ci'
        $prefixedResult = Invoke-ReturnContractValidation -EvidenceRoot $prefixedRoot
        $prefixedResult.ExitCode | Should -Not -Be 0
        $prefixedResult.Output | Should -Match 'line-wrapped encoded payload'
    }

    It 'rejects sanitized logs that exceed the 16 MiB aggregate return limit' {
        $root = Join-Path $TestDrive 'aggregate-sanitized-log-limit'
        Write-EvidenceFixture -Root $root
        $summaryPath = Join-Path $root 'summary.json'
        $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
        $targetLogBytes = 1048500
        foreach ($gate in @($summary.gates | Select-Object -First 17)) {
            $logPath = Join-Path $root "sanitized-logs/$($gate.id).log"
            $prefix = "gate=$($gate.id)`nstatus=$($gate.status)`nresult=`n"
            $remainingBytes = $targetLogBytes - [Text.Encoding]::UTF8.GetByteCount($prefix)
            $payload = $prefix + ('s.' * [Math]::Floor($remainingBytes / 2)) + $(if (($remainingBytes % 2) -eq 1) { 's' } else { '' })
            [Text.Encoding]::UTF8.GetByteCount($payload) | Should -Be $targetLogBytes
            [IO.File]::WriteAllText($logPath, $payload, [Text.UTF8Encoding]::new($false))
            $gate.sanitizedLogSha256 = Get-CMTraceSha256 -Path $logPath
        }
        Write-TestJson -Value $summary -Path $summaryPath
        Write-ManualBinding -Root $root

        $result = Invoke-ReturnContractValidation -EvidenceRoot $root
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match '16 MiB aggregate return limit'
    }

    It 'rejects remote identities and secrets even when their log hash is internally consistent' {
        $root = Join-Path $TestDrive 'unsafe-log'
        Write-EvidenceFixture -Root $root
        Set-Content -LiteralPath (Join-Path $root 'sanitized-logs/npm-ci.log') -Value "gate=npm-ci`nstatus=passed`nremote=HOST01.corp.local`nip=10.20.30.40`n{`"token`":`"supersecret`"}" -Encoding utf8NoBOM
        Write-SummaryLogHash -Root $root -GateId 'npm-ci'
        $result = Invoke-ReturnContractValidation -EvidenceRoot $root
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'privacy scan'
    }

    It 'rejects scalar provenance installers instead of array-wrapping them' {
        $root = Join-Path $TestDrive 'scalar-provenance-installers'
        Write-EvidenceFixture -Root $root
        $artifactsPath = Join-Path $root 'artifacts.json'
        $artifacts = Get-Content -LiteralPath $artifactsPath -Raw | ConvertFrom-Json
        $artifacts.items[3].installers = $artifacts.items[3].installers[0]
        Write-TestJson -Value $artifacts -Path $artifactsPath
        $roundTrippedArtifacts = Get-Content -LiteralPath $artifactsPath -Raw | ConvertFrom-Json
        ($roundTrippedArtifacts.items[3].installers -is [System.Array]) | Should -BeFalse
        Write-ManualBinding -Root $root

        $result = Invoke-ReturnContractValidation -EvidenceRoot $root
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'exactly one NSIS installer'
    }

    It 'rejects split standalone provenance and a non-distinct installed derivation' {
        $baselineRoot = Join-Path $TestDrive 'valid-distinct-provenance'
        Write-EvidenceFixture -Root $baselineRoot
        $baselineArtifacts = Get-Content -LiteralPath (Join-Path $baselineRoot 'artifacts.json') -Raw | ConvertFrom-Json
        $baselineArtifacts.items[0].sha256 | Should -BeExactly $baselineArtifacts.items[3].releaseExecutable.sha256
        $baselineArtifacts.items[3].installers[0].expectedInstalledExecutable.sha256 | Should -Not -BeExactly $baselineArtifacts.items[3].releaseExecutable.sha256
        $baselineResult = Invoke-ReturnContractValidation -EvidenceRoot $baselineRoot
        $baselineResult.ExitCode | Should -Be 0 -Because $baselineResult.Output

        $splitRoot = Join-Path $TestDrive 'split-standalone-provenance'
        Write-EvidenceFixture -Root $splitRoot
        $splitPrivatePath = Join-Path $splitRoot 'raw-artifacts/provenance/windows-build-provenance.json'
        $splitPrivate = Get-Content -LiteralPath $splitPrivatePath -Raw | ConvertFrom-Json
        $splitPrivate.releaseExecutable.sha256 = '6' * 64
        Write-TestJson -Value $splitPrivate -Path $splitPrivatePath
        $splitArtifactsPath = Join-Path $splitRoot 'artifacts.json'
        $splitArtifacts = Get-Content -LiteralPath $splitArtifactsPath -Raw | ConvertFrom-Json
        $splitArtifacts.items[3].releaseExecutable.sha256 = $splitPrivate.releaseExecutable.sha256
        $splitArtifacts.items[3].manifestSha256 = Get-CMTraceSha256 -Path $splitPrivatePath
        Write-TestJson -Value $splitArtifacts -Path $splitArtifactsPath
        Write-ManualBinding -Root $splitRoot
        $splitResult = Invoke-ReturnContractValidation -EvidenceRoot $splitRoot
        $splitResult.ExitCode | Should -Not -Be 0
        $splitResult.Output | Should -Match 'Full portable artifact does not match standalone'

        $equalRoot = Join-Path $TestDrive 'equal-installed-provenance'
        Write-EvidenceFixture -Root $equalRoot
        $equalPrivatePath = Join-Path $equalRoot 'raw-artifacts/provenance/windows-build-provenance.json'
        $equalPrivate = Get-Content -LiteralPath $equalPrivatePath -Raw | ConvertFrom-Json
        $equalPrivate.installers[0].expectedInstalledExecutable.sha256 = $equalPrivate.releaseExecutable.sha256
        Write-TestJson -Value $equalPrivate -Path $equalPrivatePath
        $equalArtifactsPath = Join-Path $equalRoot 'artifacts.json'
        $equalArtifacts = Get-Content -LiteralPath $equalArtifactsPath -Raw | ConvertFrom-Json
        $equalArtifacts.items[3].installers[0].expectedInstalledExecutable.sha256 = $equalArtifacts.items[3].releaseExecutable.sha256
        $equalArtifacts.items[3].manifestSha256 = Get-CMTraceSha256 -Path $equalPrivatePath
        Write-TestJson -Value $equalArtifacts -Path $equalArtifactsPath
        Write-ManualBinding -Root $equalRoot
        $equalResult = Invoke-ReturnContractValidation -EvidenceRoot $equalRoot
        $equalResult.ExitCode | Should -Not -Be 0
        $equalResult.Output | Should -Match 'Expected installed executable evidence must be the same-length'
    }

    It 'rejects provenance mismatch' {
        $artifactRoot = Join-Path $TestDrive 'artifact-mismatch'
        Write-EvidenceFixture -Root $artifactRoot
        $artifactsPath = Join-Path $artifactRoot 'artifacts.json'
        $artifacts = Get-Content -LiteralPath $artifactsPath -Raw | ConvertFrom-Json
        $artifacts.items[3].installers[0].sha256 = '7' * 64
        Write-TestJson -Value $artifacts -Path $artifactsPath
        Write-ManualBinding -Root $artifactRoot
        $artifactResult = Invoke-ReturnContractValidation -EvidenceRoot $artifactRoot
        $artifactResult.ExitCode | Should -Not -Be 0
        $artifactResult.Output | Should -Match 'does not match its provenance'

        $privateProvenanceRoot = Join-Path $TestDrive 'private-provenance-mismatch'
        Write-EvidenceFixture -Root $privateProvenanceRoot
        $privateProvenancePath = Join-Path $privateProvenanceRoot 'raw-artifacts/provenance/windows-build-provenance.json'
        $privateProvenance = Get-Content -LiteralPath $privateProvenancePath -Raw | ConvertFrom-Json
        $privateProvenance.target = 'x86_64-pc-windows-msvc'
        Write-TestJson -Value $privateProvenance -Path $privateProvenancePath
        $privateArtifactsPath = Join-Path $privateProvenanceRoot 'artifacts.json'
        $privateArtifacts = Get-Content -LiteralPath $privateArtifactsPath -Raw | ConvertFrom-Json
        $privateArtifacts.items[3].manifestSha256 = Get-CMTraceSha256 -Path $privateProvenancePath
        Write-TestJson -Value $privateArtifacts -Path $privateArtifactsPath
        Write-ManualBinding -Root $privateProvenanceRoot
        $privateProvenanceResult = Invoke-ReturnContractValidation -EvidenceRoot $privateProvenanceRoot
        $privateProvenanceResult.ExitCode | Should -Not -Be 0
        $privateProvenanceResult.Output | Should -Match 'private provenance target'
    }

    It 'rejects a target-private literal embedded in an otherwise self-consistent installer path' {
        $root = Join-Path $TestDrive 'private-installer-path'
        Write-EvidenceFixture -Root $root

        $privacyPath = Join-Path $root 'raw-logs/privacy-literals.json'
        $privacy = Get-Content -LiteralPath $privacyPath -Raw | ConvertFrom-Json
        $privacy.userName = 'PrivateLabUser'
        Write-TestJson -Value $privacy -Path $privacyPath

        $privateProvenancePath = Join-Path $root 'raw-artifacts/provenance/windows-build-provenance.json'
        $privateProvenance = Get-Content -LiteralPath $privateProvenancePath -Raw | ConvertFrom-Json
        $privateProvenance.installers[0].path = 'nsis/PrivateLabUser-setup.exe'
        Write-TestJson -Value $privateProvenance -Path $privateProvenancePath

        $artifactsPath = Join-Path $root 'artifacts.json'
        $artifacts = Get-Content -LiteralPath $artifactsPath -Raw | ConvertFrom-Json
        $artifacts.items[3].installers[0].path = 'nsis/PrivateLabUser-setup.exe'
        $artifacts.items[3].manifestSha256 = Get-CMTraceSha256 -Path $privateProvenancePath
        Write-TestJson -Value $artifacts -Path $artifactsPath
        Write-ManualBinding -Root $root

        $result = Invoke-ReturnContractValidation -EvidenceRoot $root
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'provenance NSIS installer path'
    }

    It 'rejects reparse root evidence' -Skip:(-not $script:CMTraceSymbolicLinkSupported) {
        $linkRoot = Join-Path $TestDrive 'linked-json'
        Write-EvidenceFixture -Root $linkRoot
        $external = Join-Path $TestDrive 'external-summary.json'
        Copy-Item -LiteralPath (Join-Path $linkRoot 'summary.json') -Destination $external
        Remove-Item -LiteralPath (Join-Path $linkRoot 'summary.json')
        New-Item -ItemType SymbolicLink -Path (Join-Path $linkRoot 'summary.json') -Target $external | Out-Null
        $linkResult = Invoke-ReturnContractValidation -EvidenceRoot $linkRoot
        $linkResult.ExitCode | Should -Not -Be 0
        $linkResult.Output | Should -Match 'reparse'

        $directoryLinkRoot = Join-Path $TestDrive 'linked-raw-directory'
        Write-EvidenceFixture -Root $directoryLinkRoot
        $externalRaw = Join-Path $TestDrive 'external-raw-logs'
        Move-Item -LiteralPath (Join-Path $directoryLinkRoot 'raw-logs') -Destination $externalRaw
        New-Item -ItemType SymbolicLink -Path (Join-Path $directoryLinkRoot 'raw-logs') -Target $externalRaw | Out-Null
        $directoryLinkResult = Invoke-ReturnContractValidation -EvidenceRoot $directoryLinkRoot
        $directoryLinkResult.ExitCode | Should -Not -Be 0
        $directoryLinkResult.Output | Should -Match 'reparse'
    }
}
