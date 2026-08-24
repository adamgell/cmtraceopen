[CmdletBinding()]
param(
    [switch]$PlanOnly,

    [string]$PlanOutputPath,

    [string]$RepositoryPath,

    [string]$EvidenceRoot,

    [ValidateRange(1, 720)]
    [int]$GateTimeoutMinutes = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'CMTraceOpenArm64Handoff.Common.ps1')

$script:CMTraceGateTimeoutMinutes = $GateTimeoutMinutes

$plan = @(
    [ordered]@{ id = 'source-integrity'; class = 'source'; description = 'Verify exact commit, tree, lockfiles, remote, submodules, and clean status.'; dependsOn = @() },
    [ordered]@{ id = 'npm-ci'; class = 'automated'; description = 'Install the frozen npm dependency graph with npm ci.'; dependsOn = @('source-integrity') },
    [ordered]@{ id = 'typescript'; class = 'automated'; description = 'Run the TypeScript no-emit compiler gate.'; dependsOn = @('npm-ci') },
    [ordered]@{ id = 'frontend-build'; class = 'automated'; description = 'Build the production frontend.'; dependsOn = @('npm-ci') },
    [ordered]@{ id = 'frontend-tests'; class = 'automated'; description = 'Run the complete Vitest suite.'; dependsOn = @('npm-ci') },
    [ordered]@{ id = 'release-contract-tests'; class = 'automated'; description = 'Run bundle, provenance, updater, and nightly Node contract tests.'; dependsOn = @('npm-ci') },
    [ordered]@{ id = 'npm-audit'; class = 'security'; description = 'Fail on high-severity npm advisories.'; dependsOn = @('npm-ci') },
    [ordered]@{ id = 'playwright-browser'; class = 'automated'; description = 'Install the matching Playwright Chromium browser in the lab account cache.'; dependsOn = @('npm-ci') },
    [ordered]@{ id = 'playwright-e2e'; class = 'automated'; description = 'Run the complete Playwright UI contract suite.'; dependsOn = @('playwright-browser') },
    [ordered]@{ id = 'installer-pester'; class = 'automated'; description = 'Run Windows installer cleanup Pester tests.'; dependsOn = @('source-integrity') },
    [ordered]@{ id = 'collector-pester'; class = 'automated'; description = 'Run diagnostic collector Pester tests without collecting host evidence.'; dependsOn = @('source-integrity') },
    [ordered]@{ id = 'cargo-fmt'; class = 'automated'; description = 'Check Rust workspace formatting.'; dependsOn = @('source-integrity') },
    [ordered]@{ id = 'parser-tests'; class = 'automated'; description = 'Run the locked parser crate test suite natively on ARM64.'; dependsOn = @('source-integrity') },
    [ordered]@{ id = 'parser-clippy'; class = 'automated'; description = 'Run strict parser Clippy across all targets.'; dependsOn = @('source-integrity') },
    [ordered]@{ id = 'parser-wasm-check'; class = 'automated'; description = 'Check the pure parser for wasm32-unknown-unknown.'; dependsOn = @('source-integrity') },
    [ordered]@{ id = 'esp-native'; class = 'automated'; description = 'Run native Windows ESP source integration tests.'; dependsOn = @('source-integrity') },
    [ordered]@{ id = 'esp-graph'; class = 'automated'; description = 'Run Graph ESP integration tests without tenant access.'; dependsOn = @('source-integrity') },
    [ordered]@{ id = 'windows-full-build'; class = 'automated'; description = 'Compile every full-edition Windows test target without running it.'; dependsOn = @('source-integrity') },
    [ordered]@{ id = 'windows-full-tests'; class = 'automated'; description = 'Run the complete full-edition Windows all-feature suite.'; dependsOn = @('windows-full-build') },
    [ordered]@{ id = 'windows-full-clippy'; class = 'automated'; description = 'Run strict full-edition Windows Clippy.'; dependsOn = @('windows-full-build') },
    [ordered]@{ id = 'windows-lite-tests'; class = 'automated'; description = 'Run the Lite Windows test suite.'; dependsOn = @('source-integrity') },
    [ordered]@{ id = 'windows-lite-clippy'; class = 'automated'; description = 'Run strict Lite Windows Clippy.'; dependsOn = @('source-integrity') },
    [ordered]@{ id = 'msrv'; class = 'automated'; description = 'Check the locked workspace with Rust 1.88.'; dependsOn = @('source-integrity') },
    [ordered]@{ id = 'cargo-deny'; class = 'security'; description = 'Run license and dependency-ban policy.'; dependsOn = @('source-integrity') },
    [ordered]@{ id = 'cargo-audit'; class = 'security'; description = 'Run the Rust vulnerability audit.'; dependsOn = @('source-integrity') },
    [ordered]@{ id = 'arm64-full-build'; class = 'artifact'; description = 'Build an unsigned native ARM64 Full portable executable.'; dependsOn = @('npm-ci', 'windows-full-build') },
    [ordered]@{ id = 'arm64-lite-build'; class = 'artifact'; description = 'Build an unsigned native ARM64 Lite portable executable.'; dependsOn = @('npm-ci', 'windows-lite-tests') },
    [ordered]@{ id = 'bundle-output-clean'; class = 'artifact'; description = 'Remove only generated target-specific bundle output before packaging.'; dependsOn = @('arm64-lite-build') },
    [ordered]@{ id = 'arm64-nsis-build'; class = 'artifact'; description = 'Build an unsigned exact-head ARM64 NSIS installer with updater signing disabled.'; dependsOn = @('bundle-output-clean') },
    [ordered]@{ id = 'bundle-output-verification'; class = 'artifact'; description = 'Verify current-version target-specific bundle outputs.'; dependsOn = @('arm64-nsis-build') },
    [ordered]@{ id = 'windows-build-provenance'; class = 'artifact'; description = 'Generate exact-source local Windows artifact provenance.'; dependsOn = @('bundle-output-verification') },
    [ordered]@{ id = 'arm64-pe-verification'; class = 'artifact'; description = 'Verify Full and Lite PE machine headers and record bounded artifact hashes.'; dependsOn = @('windows-build-provenance', 'arm64-full-build', 'arm64-lite-build') },
    [ordered]@{ id = 'source-clean-after'; class = 'source'; description = 'Reverify exact source coordinates and clean status after all generated work.'; dependsOn = @() }
)

$planDocument = [ordered]@{
    schemaVersion = 1
    handoffId = $script:CMTraceHandoffId
    sourceCommit = $script:CMTraceExpectedSourceCommit
    sourceTree = $script:CMTraceExpectedSourceTree
    target = $script:CMTraceRustTarget
    gates = $plan
}

if (Compare-Object -SyncWindow 0 -ReferenceObject $script:CMTraceAutomaticGateIds -DifferenceObject @($plan.id)) {
    throw 'The automatic plan does not match the sealed automatic gate contract.'
}
foreach ($gate in $plan) {
    $contract = $script:CMTraceAutomaticGateContracts[$gate.id]
    if ($gate.class -ne $contract.class -or (Compare-Object -SyncWindow 0 -ReferenceObject @($contract.dependsOn) -DifferenceObject @($gate.dependsOn))) {
        throw "Automatic gate contract mismatch: $($gate.id)."
    }
}

[void](Assert-CMTraceHandoffIntegrity)

if ($PlanOnly) {
    if (-not [string]::IsNullOrWhiteSpace($PlanOutputPath)) {
        $fullPlanOutput = [IO.Path]::GetFullPath($PlanOutputPath)
        if (Test-Path -LiteralPath $fullPlanOutput -PathType Any) {
            throw "Plan output already exists and will not be overwritten: $fullPlanOutput"
        }
        $planParent = Split-Path -Parent $fullPlanOutput
        if (-not (Test-Path -LiteralPath $planParent -PathType Container)) {
            throw "Plan output parent must already exist: $planParent"
        }
        $handoffRoot = [IO.Path]::GetFullPath((Get-CMTraceHandoffRoot)).TrimEnd([char]'\', [char]'/')
        if ($fullPlanOutput.StartsWith(($handoffRoot + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Plan output cannot be written inside the sealed handoff package.'
        }
        if (-not [string]::IsNullOrWhiteSpace($RepositoryPath)) {
            $fullPlanRepository = [IO.Path]::GetFullPath($RepositoryPath).TrimEnd([char]'\', [char]'/')
            $repositoryPrefix = $fullPlanRepository + [IO.Path]::DirectorySeparatorChar
            if ($fullPlanOutput.Equals($fullPlanRepository, [StringComparison]::OrdinalIgnoreCase) -or
                $fullPlanOutput.StartsWith($repositoryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Plan output cannot be written inside the supplied repository.'
            }
        }
        Write-CMTraceNewJson -Value $planDocument -Path $fullPlanOutput
        Write-Output "PLAN_WRITTEN $fullPlanOutput"
    }
    else {
        $planDocument | ConvertTo-Json -Depth 10
    }
    return
}

if ($null -eq ('CMTraceOpen.Validation.BoundedWriteStream' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace CMTraceOpen.Validation
{
    public sealed class BoundedWriteStream : Stream
    {
        private readonly Stream inner;
        private readonly long maximumBytes;
        private long writtenBytes;

        public BoundedWriteStream(Stream inner, long maximumBytes)
        {
            this.inner = inner ?? throw new ArgumentNullException(nameof(inner));
            if (maximumBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maximumBytes));
            this.maximumBytes = maximumBytes;
        }

        private int AllowedCount(int requested)
        {
            long remaining = maximumBytes - writtenBytes;
            return remaining <= 0 ? 0 : (int)Math.Min(remaining, requested);
        }

        private void RejectOverflow(int requested, int allowed)
        {
            if (allowed != requested) throw new IOException("Process output exceeded its bounded capture stream.");
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            int allowed = AllowedCount(count);
            if (allowed > 0) { inner.Write(buffer, offset, allowed); writtenBytes += allowed; }
            RejectOverflow(count, allowed);
        }

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            int allowed = AllowedCount(count);
            if (allowed > 0)
            {
                await inner.WriteAsync(buffer, offset, allowed, cancellationToken).ConfigureAwait(false);
                writtenBytes += allowed;
            }
            RejectOverflow(count, allowed);
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int allowed = AllowedCount(buffer.Length);
            if (allowed > 0)
            {
                await inner.WriteAsync(buffer.Slice(0, allowed), cancellationToken).ConfigureAwait(false);
                writtenBytes += allowed;
            }
            RejectOverflow(buffer.Length, allowed);
        }

        public override void Flush() => inner.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);
        protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => inner.Length;
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
'@
}

Initialize-CMTraceOwnedProcessType

Assert-CMTraceWindows11Arm64
Assert-CMTraceNoSensitiveEnvironment

if ([string]::IsNullOrWhiteSpace($RepositoryPath) -or [string]::IsNullOrWhiteSpace($EvidenceRoot)) {
    throw 'RepositoryPath and EvidenceRoot are required unless -PlanOnly is used.'
}

$resolvedRepository = (Resolve-Path -LiteralPath $RepositoryPath).Path
$fullEvidenceRoot = Assert-CMTraceFixedLocalNtfsPath -Path $EvidenceRoot -Label 'EvidenceRoot' -ForbiddenRoots @($resolvedRepository, (Get-CMTraceHandoffRoot)) -MustNotExist
$inputRoot = Join-Path ([IO.Path]::GetPathRoot($resolvedRepository)) 'cmtraceopen-input'
[void](Assert-CMTraceSafeTemporaryRoot -ForbiddenRoots @(
    $resolvedRepository,
    $fullEvidenceRoot,
    $inputRoot,
    (Get-CMTraceHandoffRoot)
))

New-Item -ItemType Directory -Path $fullEvidenceRoot | Out-Null
$rawLogRoot = Join-Path $fullEvidenceRoot 'raw-logs'
$sanitizedLogRoot = Join-Path $fullEvidenceRoot 'sanitized-logs'
$rawArtifactRoot = Join-Path $fullEvidenceRoot 'raw-artifacts'
New-Item -ItemType Directory -Path $rawLogRoot, $sanitizedLogRoot, $rawArtifactRoot | Out-Null
$emptyNpmConfig = Join-Path $rawLogRoot 'empty.npmrc'
Set-Content -LiteralPath $emptyNpmConfig -Value '' -Encoding ascii

# This private file never leaves the target. The return exporter uses it to
# reject literal host identities that generic secret patterns cannot detect.
$privacyLiterals = [ordered]@{
    computerName = $env:COMPUTERNAME
    userName = $env:USERNAME
    userDomain = $env:USERDOMAIN
    userDnsDomain = $env:USERDNSDOMAIN
    logonServer = $env:LOGONSERVER
    userProfile = $env:USERPROFILE
    homePath = $env:HOMEPATH
    homeDrive = $env:HOMEDRIVE
    oneDrive = $env:OneDrive
    oneDriveCommercial = $env:OneDriveCommercial
    oneDriveConsumer = $env:OneDriveConsumer
    repositoryPath = $resolvedRepository
    evidencePath = $fullEvidenceRoot
    handoffPath = Get-CMTraceHandoffRoot
}
Write-CMTraceJson -Value $privacyLiterals -Path (Join-Path $rawLogRoot 'privacy-literals.json')

$preflightPath = Join-Path $rawLogRoot 'preflight.json'
& (Join-Path $PSScriptRoot 'Test-CMTraceOpenArm64Preflight.ps1') -RepositoryPath $resolvedRepository -OutputPath $preflightPath | Out-Null

$privateLiterals = [ordered]@{}
foreach ($entry in @(
    [pscustomobject]@{ Value = $resolvedRepository; Replacement = '%REPOSITORY%' },
    [pscustomobject]@{ Value = $fullEvidenceRoot; Replacement = '%EVIDENCE_ROOT%' },
    [pscustomobject]@{ Value = (Get-CMTraceHandoffRoot); Replacement = '%HANDOFF%' },
    [pscustomobject]@{ Value = $env:USERPROFILE; Replacement = '%USERPROFILE%' },
    [pscustomobject]@{ Value = $env:USERNAME; Replacement = '%USERNAME%' },
    [pscustomobject]@{ Value = $env:COMPUTERNAME; Replacement = '%COMPUTERNAME%' },
    [pscustomobject]@{ Value = $env:USERDOMAIN; Replacement = '%USERDOMAIN%' },
    [pscustomobject]@{ Value = $env:USERDNSDOMAIN; Replacement = '%USERDNSDOMAIN%' },
    [pscustomobject]@{ Value = $env:LOGONSERVER; Replacement = '%LOGONSERVER%' },
    [pscustomobject]@{ Value = $env:OneDrive; Replacement = '%ONEDRIVE%' },
    [pscustomobject]@{ Value = $env:OneDriveCommercial; Replacement = '%ONEDRIVE%' },
    [pscustomobject]@{ Value = $env:OneDriveConsumer; Replacement = '%ONEDRIVE%' }
)) {
    if (-not [string]::IsNullOrWhiteSpace([string]$entry.Value)) {
        $privateLiterals[[string]$entry.Value] = $entry.Replacement
    }
}

function Enter-CMTraceArm64DeveloperEnvironment {
    $llvmPath = Join-Path $env:ProgramFiles 'LLVM\bin'
    if (-not (Test-Path -LiteralPath (Join-Path $llvmPath 'clang.exe') -PathType Leaf)) {
        throw 'The exact Program Files LLVM toolchain disappeared after preflight.'
    }
    $env:Path = "$llvmPath;$env:Path"
    $cargoPath = Join-Path $env:USERPROFILE '.cargo\bin'
    if (Test-Path -LiteralPath $cargoPath) {
        $env:Path = "$cargoPath;$env:Path"
    }

    $vswhereCandidates = @(@(
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'),
        (Join-Path $env:ProgramFiles 'Microsoft Visual Studio\Installer\vswhere.exe')
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) })
    if (@($vswhereCandidates).Count -eq 0) {
        throw 'vswhere.exe was not found after preflight.'
    }
    $vsArguments = @('-latest', '-products', '*', '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', 'Microsoft.VisualStudio.Component.VC.Tools.ARM64', 'Microsoft.VisualStudio.Component.Windows11SDK.26100')
    $pathCapture = Invoke-CMTraceOwnedProcessCapture -FilePath $vswhereCandidates[0] -Arguments @($vsArguments + @('-property', 'installationPath')) -WorkingDirectory $resolvedRepository
    $vsInstallPath = $pathCapture.StdOut.Trim()
    if ($pathCapture.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($pathCapture.StdErr) -or
        [string]::IsNullOrWhiteSpace($vsInstallPath) -or $vsInstallPath -match '[\r\n]') {
        throw 'Visual Studio ARM64 developer environment could not be resolved.'
    }
    $versionCapture = Invoke-CMTraceOwnedProcessCapture -FilePath $vswhereCandidates[0] -Arguments @($vsArguments + @('-property', 'installationVersion')) -WorkingDirectory $resolvedRepository
    if ($versionCapture.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($versionCapture.StdErr)) {
        throw 'Visual Studio installation version could not be read.'
    }
    $script:CMTraceVisualStudioVersion = ConvertTo-CMTraceNormalizedToolVersion -Tool VisualStudio -Text $versionCapture.StdOut
    $modulePath = Join-Path $vsInstallPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll'
    Import-Module $modulePath -Force
    # The repository's supported ARM64 path uses the amd64-hosted compiler tools
    # under Windows-on-ARM emulation while targeting native ARM64 output.
    Enter-VsDevShell -VsInstallPath $vsInstallPath -SkipAutomaticLocation -Arch arm64 -HostArch amd64 | Out-Null
}

$script:CMTracePrivacyWithheldGates = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)

function Write-CMTraceGateLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GateId,

        [Parameter(Mandatory = $true)]
        [string]$RawText,

        [Parameter(Mandatory = $true)]
        [ValidateSet('passed', 'failed', 'blocked')]
        [string]$GateStatus
    )

    $rawPath = Join-Path $rawLogRoot "$GateId.log"
    $sanitizedPath = Join-Path $sanitizedLogRoot "$GateId.log"
    Set-Content -LiteralPath $rawPath -Value $RawText -Encoding utf8NoBOM
    $sanitized = ConvertTo-CMTraceSanitizedGateLog -GateId $GateId -GateStatus $GateStatus `
        -Text $RawText -LiteralReplacements $privateLiterals
    $privacyWithheld = $false
    try {
        Assert-CMTracePrivacySafeText -Text $sanitized -Label "$GateId sanitized log"
    }
    catch {
        $privacyWithheld = $true
        [void]$script:CMTracePrivacyWithheldGates.Add($GateId)
        $sanitized = "gate=$GateId`nstatus=failed`nresult=sanitized-log-withheld-after-privacy-validation-failure`nThe complete raw log remains target-private."
    }
    Set-Content -LiteralPath $sanitizedPath -Value $sanitized -Encoding utf8NoBOM
    return [pscustomobject]@{
        rawHash = Get-CMTraceSha256 -Path $rawPath
        sanitizedFile = "sanitized-logs/$GateId.log"
        sanitizedHash = Get-CMTraceSha256 -Path $sanitizedPath
        privacyWithheld = $privacyWithheld
    }
}

$results = [System.Collections.Generic.List[object]]::new()

function Get-CMTraceGateResult {
    param([string]$Id)
    return $results | Where-Object { $_.id -eq $Id } | Select-Object -First 1
}

function Test-CMTraceDependenciesPassed {
    param([string[]]$Dependencies)
    foreach ($dependency in $Dependencies) {
        $result = Get-CMTraceGateResult -Id $dependency
        if (-not $result -or $result.status -ne 'passed') {
            return $false
        }
    }
    return $true
}

function Add-CMTraceBlockedGate {
    param([object]$Gate)
    $blockedBy = @($Gate.dependsOn | Where-Object { (Get-CMTraceGateResult -Id $_).status -ne 'passed' })
    $text = "gate=$($Gate.id)`nstatus=blocked`nblockedBy=$($blockedBy -join ',')`nGate was blocked by required gate(s)."
    $log = Write-CMTraceGateLog -GateId $Gate.id -GateStatus 'blocked' -RawText $text
    $record = [pscustomobject][ordered]@{
        id = $Gate.id
        class = $Gate.class
        status = 'blocked'
        exitCode = $null
        startedAtUtc = $null
        durationMilliseconds = 0
        command = $null
        rawLogSha256 = $log.rawHash
        sanitizedLog = $log.sanitizedFile
        sanitizedLogSha256 = $log.sanitizedHash
        blockedBy = $blockedBy
    }
    $results.Add($record)
    return $record
}

function Invoke-CMTraceInternalGate {
    param(
        [object]$Gate,
        [scriptblock]$Action
    )

    if (-not (Test-CMTraceDependenciesPassed -Dependencies $Gate.dependsOn)) {
        return Add-CMTraceBlockedGate -Gate $Gate
    }
    $started = (Get-Date).ToUniversalTime()
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $status = 'passed'
    try {
        $detail = (& $Action | Out-String).Trim()
        $rawText = "gate=$($Gate.id)`nstartedAtUtc=$($started.ToString('o'))`nstatus=passed`n$detail"
    }
    catch {
        $status = 'failed'
        $rawText = "gate=$($Gate.id)`nstartedAtUtc=$($started.ToString('o'))`nstatus=failed`n$($_.Exception.ToString())"
    }
    finally {
        $timer.Stop()
    }
    $log = Write-CMTraceGateLog -GateId $Gate.id -GateStatus $status -RawText $rawText
    if ($log.privacyWithheld) {
        $status = 'failed'
    }
    $record = [pscustomobject][ordered]@{
        id = $Gate.id
        class = $Gate.class
        status = $status
        exitCode = if ($status -eq 'passed') { 0 } else { 1 }
        startedAtUtc = $started.ToString('o')
        durationMilliseconds = $timer.ElapsedMilliseconds
        command = '<internal handoff gate>'
        rawLogSha256 = $log.rawHash
        sanitizedLog = $log.sanitizedFile
        sanitizedLogSha256 = $log.sanitizedHash
        blockedBy = @()
    }
    $results.Add($record)
    return $record
}

function Read-CMTraceProcessCaptureExcerpt {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [ValidateRange(1024, 8388608)]
        [int]$MaximumBytes = 4194304
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return ''
    }
    $entry = Get-Item -LiteralPath $Path -Force
    $encoding = [Text.UTF8Encoding]::new($false, $false)
    if ($entry.Length -le $MaximumBytes) {
        return $encoding.GetString([IO.File]::ReadAllBytes($entry.FullName))
    }

    $half = [int]($MaximumBytes / 2)
    $head = [byte[]]::new($half)
    $tail = [byte[]]::new($half)
    $stream = [IO.File]::OpenRead($entry.FullName)
    try {
        $stream.ReadExactly($head, 0, $head.Length)
        $stream.Position = [Math]::Max(0, $stream.Length - $tail.Length)
        $stream.ReadExactly($tail, 0, $tail.Length)
    }
    finally {
        $stream.Dispose()
    }
    return $encoding.GetString($head) +
        "`n<process-output-excerpted; complete stream retained target-private>`n" +
        $encoding.GetString($tail)
}

function Join-CMTraceFailureMessage {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Current,

        [Parameter(Mandatory = $true)]
        [string]$Next
    )

    if ([string]::IsNullOrWhiteSpace($Current)) {
        return $Next
    }
    return "$Current`n$Next"
}

function Invoke-CMTraceProcessGate {
    param(
        [object]$Gate,
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [string[]]$Arguments = @(),
        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,
        [System.Collections.IDictionary]$Environment = @{},
        [AllowEmptyCollection()][object[]]$ContentBindings = @(),
        [string]$SafeDisplayCommand
    )

    if (-not (Test-CMTraceDependenciesPassed -Dependencies $Gate.dependsOn)) {
        return Add-CMTraceBlockedGate -Gate $Gate
    }

    $started = (Get-Date).ToUniversalTime()
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $status = 'failed'
    $exitCode = $null
    $displayCommand = if ([string]::IsNullOrWhiteSpace($SafeDisplayCommand)) { "gate:$($Gate.id)" } else { $SafeDisplayCommand }
    $stdoutCapturePath = Join-Path $rawLogRoot "$($Gate.id).stdout.private.log"
    $stderrCapturePath = Join-Path $rawLogRoot "$($Gate.id).stderr.private.log"
    $captureLimitBytes = 33554432L
    $perStreamCaptureLimitBytes = 16777216L
    $failureMessage = $null
    $process = $null
    $ownedJob = $null
    $ownedLaunch = $null
    $processStarted = $false
    $jobAssigned = $false
    $stdoutStream = $null
    $stderrStream = $null
    $stdoutTask = $null
    $stderrTask = $null
    $wrapperInfrastructureFailure = $false
    $targetGuard = $null
    $contentGuards = [Collections.Generic.List[IO.FileStream]]::new()
    Write-Information "GATE_START $($Gate.id) timeoutMinutes=$script:CMTraceGateTimeoutMinutes rawLog=$rawLogRoot" -InformationAction Continue

    try {
        # Every process gate gets a fresh source/control readback. This prevents
        # a prior npm/Cargo lifecycle from hiding changed inputs behind Git
        # index flags, ignored environment files, or ancestor Cargo config.
        [void](Assert-CMTraceSourceIntegrity -RepositoryPath $resolvedRepository)
        [void](Assert-CMTraceCargoConfigurationBoundary -WorkingDirectory $WorkingDirectory `
            -AllowedConfigurationPaths @((Join-Path $resolvedRepository '.cargo\config.toml')))
        [void](Assert-CMTraceActiveRustToolchain -WorkingDirectory $WorkingDirectory)
        $resolvedCommand = (Get-Command $FilePath -ErrorAction Stop).Source
        $targetGuard = Open-CMTraceGuardedReadFile -Path $resolvedCommand -Label "Automatic gate target $($Gate.id)"
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $targetGuard.Path
        $startInfo.WorkingDirectory = $WorkingDirectory
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        foreach ($argument in $Arguments) {
            [void]$startInfo.ArgumentList.Add($argument)
        }
        $childEnvironment = [ordered]@{
            GIT_CONFIG_NOSYSTEM = '1'
            GIT_CONFIG_GLOBAL = 'NUL'
            GIT_TERMINAL_PROMPT = '0'
            GCM_INTERACTIVE = 'Never'
            GIT_ASKPASS = ''
            SSH_ASKPASS = ''
            GIT_NO_REPLACE_OBJECTS = '1'
            NPM_CONFIG_USERCONFIG = $emptyNpmConfig
            NPM_CONFIG_GLOBALCONFIG = $emptyNpmConfig
            NPM_CONFIG_UPDATE_NOTIFIER = 'false'
            NPM_CONFIG_FUND = 'false'
        }
        foreach ($entry in $Environment.GetEnumerator()) {
            $childEnvironment[[string]$entry.Key] = [string]$entry.Value
        }
        Initialize-CMTraceChildEnvironment -StartInfo $startInfo -Environment $childEnvironment

        foreach ($binding in @($ContentBindings)) {
            if ($null -eq $binding -or
                @($binding.PSObject.Properties.Name | Where-Object { $_ -cin @('Path', 'Sha256', 'Bytes', 'Label') }).Count -ne 4 -or
                @($binding.PSObject.Properties.Name).Count -ne 4) {
                throw 'Each automatic-gate content binding must contain exactly Path, Sha256, Bytes, and Label.'
            }
            $contentGuard = Open-CMTraceGuardedReadFile -Path ([string]$binding.Path) -Label ([string]$binding.Label) `
                -ExpectedSha256 ([string]$binding.Sha256) -ExpectedBytes ([int64]$binding.Bytes)
            $contentGuards.Add($contentGuard.Stream)
        }

        $ownedLaunch = Get-CMTraceOwnedProcessLaunch -TargetStartInfo $startInfo
        $ownedJob = [CMTraceOpen.Validation.OwnedProcessJob]::new()
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $ownedLaunch.StartInfo
        if (-not $process.Start()) {
            throw "Could not start $FilePath."
        }
        $processStarted = $true
        $ownedJob.Assign($process)
        $jobAssigned = $true
        $captureBudget = [CMTraceOpen.Validation.AggregateCaptureBudget]::new($captureLimitBytes)
        $stdoutAggregateStream = [CMTraceOpen.Validation.AggregateBoundedWriteStream]::new([IO.File]::Create($stdoutCapturePath), $captureBudget)
        $stdoutStream = [CMTraceOpen.Validation.BoundedWriteStream]::new($stdoutAggregateStream, $perStreamCaptureLimitBytes)
        $stderrAggregateStream = [CMTraceOpen.Validation.AggregateBoundedWriteStream]::new([IO.File]::Create($stderrCapturePath), $captureBudget)
        $stderrStream = [CMTraceOpen.Validation.BoundedWriteStream]::new($stderrAggregateStream, $perStreamCaptureLimitBytes)
        $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdoutStream)
        $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderrStream)
        [void]$ownedLaunch.ReadyEvent.Set()
        Wait-CMTraceOwnedTargetStarted -OwnedLaunch $ownedLaunch -WrapperProcess $process
        $targetGuard.Stream.Dispose()
        $targetGuard = $null
        $deadline = [DateTimeOffset]::UtcNow.AddMinutes($script:CMTraceGateTimeoutMinutes)
        $terminationRequested = $false
        $terminationDrainDeadline = [DateTimeOffset]::MaxValue
        while ($ownedJob.ActiveProcessCount -gt 0 -or -not $process.HasExited -or
            -not $stdoutTask.IsCompleted -or -not $stderrTask.IsCompleted) {
            $now = [DateTimeOffset]::UtcNow
            if (-not $terminationRequested -and ($stdoutTask.IsFaulted -or $stderrTask.IsFaulted)) {
                $failureMessage = "Gate output exceeded its $perStreamCaptureLimitBytes-byte per-stream or $captureLimitBytes-byte aggregate target-private capture limit."
                $terminationRequested = $true
                $terminationDrainDeadline = $now.AddSeconds(5)
                $ownedJob.Terminate(1)
            }
            elseif (-not $terminationRequested -and $now -ge $deadline) {
                $failureMessage = "Gate timed out after $script:CMTraceGateTimeoutMinutes minutes."
                $terminationRequested = $true
                $terminationDrainDeadline = $now.AddSeconds(5)
                $ownedJob.Terminate(1)
            }
            if ($terminationRequested -and $now -ge $terminationDrainDeadline -and
                ($ownedJob.ActiveProcessCount -gt 0 -or -not $process.HasExited -or
                    -not $stdoutTask.IsCompleted -or -not $stderrTask.IsCompleted)) {
                $failureMessage = Join-CMTraceFailureMessage -Current $failureMessage -Next 'Owned process Job or output streams did not empty within the bounded five-second termination drain.'
                break
            }
            Start-Sleep -Milliseconds 50
        }
        if ($null -eq $failureMessage) {
            if ($ownedJob.ActiveProcessCount -ne 0 -or -not $process.HasExited -or
                -not $stdoutTask.IsCompleted -or -not $stderrTask.IsCompleted) {
                throw 'Owned gate process completed before its Job and redirected streams were empty.'
            }
            $exitCode = $process.ExitCode
            $status = if ($exitCode -eq 0) { 'passed' } else { 'failed' }
        }
        elseif ($process.HasExited) {
            $exitCode = $process.ExitCode
        }
    }
    catch {
        $failureMessage = $_.Exception.ToString()
        $status = 'failed'
    }
    finally {
        if ($processStarted -and -not $jobAssigned -and -not $process.HasExited) {
            try { $process.Kill($true) } catch { $failureMessage = Join-CMTraceFailureMessage -Current $failureMessage -Next $_.Exception.ToString() }
        }
        if ($null -ne $ownedJob) {
            $jobStillActive = $true
            try { $jobStillActive = $ownedJob.ActiveProcessCount -gt 0 } catch { $failureMessage = Join-CMTraceFailureMessage -Current $failureMessage -Next $_.Exception.ToString() }
            if ($processStarted -and ($jobStillActive -or -not $process.HasExited -or
                    ($null -ne $stdoutTask -and -not $stdoutTask.IsCompleted) -or
                    ($null -ne $stderrTask -and -not $stderrTask.IsCompleted))) {
                try { $ownedJob.Terminate(1) } catch { $failureMessage = Join-CMTraceFailureMessage -Current $failureMessage -Next $_.Exception.ToString() }
            }
            $ownedJob.Dispose()
        }
        if ($null -ne $ownedLaunch) {
            $ownedLaunch.TargetStartedEvent.Dispose()
            $ownedLaunch.ReadyEvent.Dispose()
        }
        if ($processStarted -and -not $process.HasExited) {
            [void]$process.WaitForExit(5000)
        }
        $pendingCopyTasks = @(@($stdoutTask, $stderrTask) | Where-Object { $null -ne $_ -and -not $_.IsCompleted })
        if ($pendingCopyTasks.Count -gt 0 -and $null -ne $process) {
            try { $process.StandardOutput.BaseStream.Dispose() } catch { $failureMessage = Join-CMTraceFailureMessage -Current $failureMessage -Next $_.Exception.ToString() }
            try { $process.StandardError.BaseStream.Dispose() } catch { $failureMessage = Join-CMTraceFailureMessage -Current $failureMessage -Next $_.Exception.ToString() }
            try {
                if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$pendingCopyTasks, 5000)) {
                    $failureMessage = Join-CMTraceFailureMessage -Current $failureMessage -Next 'Owned process output copy tasks exceeded the bounded five-second shutdown wait.'
                }
            }
            catch {
                $failureMessage = Join-CMTraceFailureMessage -Current $failureMessage -Next $_.Exception.ToString()
            }
        }
        foreach ($copyTask in @($stdoutTask, $stderrTask)) {
            if ($null -ne $copyTask -and $copyTask.IsCompleted) {
                try { [void]($copyTask.GetAwaiter().GetResult()) } catch { $failureMessage = Join-CMTraceFailureMessage -Current $failureMessage -Next $_.Exception.ToString() }
            }
        }
        foreach ($captureStream in @($stdoutStream, $stderrStream)) {
            if ($null -ne $captureStream) { $captureStream.Dispose() }
        }
        if ($null -ne $process) { $process.Dispose() }
        if ($null -ne $targetGuard) { $targetGuard.Stream.Dispose() }
        foreach ($contentGuard in $contentGuards) { $contentGuard.Dispose() }
        $timer.Stop()
    }

    $stdout = Read-CMTraceProcessCaptureExcerpt -Path $stdoutCapturePath
    $stderr = Read-CMTraceProcessCaptureExcerpt -Path $stderrCapturePath
    $capturePaths = @($stdoutCapturePath, $stderrCapturePath)
    $capturedBytes = ($capturePaths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | ForEach-Object {
        (Get-Item -LiteralPath $_ -Force).Length
    } | Measure-Object -Sum).Sum
    if ($capturedBytes -gt $captureLimitBytes) {
        $captureFailure = "Gate output exceeded the $captureLimitBytes-byte target-private capture limit."
        $failureMessage = Join-CMTraceFailureMessage -Current $failureMessage -Next $captureFailure
    }
    if (Test-CMTraceOwnedProcessWrapperFailureExitCode -ExitCode $exitCode) {
        $wrapperInfrastructureFailure = $true
        $wrapperFailure = "Owned-process wrapper returned reserved infrastructure exit code $script:CMTraceOwnedProcessWrapperFailureExitCode before a trustworthy native child result; this is not a native gate exit."
        $failureMessage = Join-CMTraceFailureMessage -Current $failureMessage -Next $wrapperFailure
        $exitCode = $null
        $status = 'failed'
    }
    if (-not [string]::IsNullOrWhiteSpace($failureMessage)) {
        $stderr = Join-CMTraceFailureMessage -Current $stderr -Next $failureMessage
        $status = 'failed'
        # Null is intentional when no trustworthy native exit code exists; only replace a contradictory zero.
        if ($null -ne $exitCode -and $exitCode -eq 0) { $exitCode = 1 }
    }

    $rawText = @"
gate=$($Gate.id)
startedAtUtc=$($started.ToString('o'))
workingDirectory=$WorkingDirectory
command=$displayCommand
exitCode=$exitCode
status=$status
--- stdout ---
$stdout
--- stderr ---
$stderr
"@
    $log = Write-CMTraceGateLog -GateId $Gate.id -GateStatus $status -RawText $rawText
    if ($log.privacyWithheld) {
        $status = 'failed'
        if (-not $wrapperInfrastructureFailure -and ($null -eq $exitCode -or $exitCode -eq 0)) { $exitCode = 1 }
    }
    $record = [pscustomobject][ordered]@{
        id = $Gate.id
        class = $Gate.class
        status = $status
        exitCode = $exitCode
        startedAtUtc = $started.ToString('o')
        durationMilliseconds = $timer.ElapsedMilliseconds
        command = $displayCommand
        rawLogSha256 = $log.rawHash
        sanitizedLog = $log.sanitizedFile
        sanitizedLogSha256 = $log.sanitizedHash
        blockedBy = @()
    }
    $results.Add($record)
    Write-Information "GATE_END $($Gate.id) status=$status elapsedMilliseconds=$($timer.ElapsedMilliseconds)" -InformationAction Continue
    return $record
}

function Write-CMTraceGatePostFailure {
    param(
        [object]$Result,
        [string]$Message
    )

    $Result.status = 'failed'
    $Result.exitCode = 1
    $rawPath = Join-Path $rawLogRoot "$($Result.id).log"
    $rawText = Get-Content -LiteralPath $rawPath -Raw
    $rawText = [regex]::Replace($rawText, '(?m)^status=passed\r?$', 'status=failed')
    $rawText = "$rawText`npostConditionFailure=$Message"
    $log = Write-CMTraceGateLog -GateId $Result.id -GateStatus 'failed' -RawText $rawText
    $Result.rawLogSha256 = $log.rawHash
    $Result.sanitizedLogSha256 = $log.sanitizedHash
}

function ConvertTo-CMTracePesterEncodedCommand {
    param([string]$TestPath)
    $resolvedTestPath = (Resolve-Path -LiteralPath $TestPath).Path
    [void](Assert-CMTraceNoReparseAncestor -Path $resolvedTestPath -Label 'Pester test input')
    $testEntry = Get-Item -LiteralPath $resolvedTestPath -Force
    if ($testEntry.PSIsContainer -or ($testEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Pester test input must be a regular, non-reparse file.'
    }
    $testBinding = [pscustomobject][ordered]@{
        Path = $testEntry.FullName
        Sha256 = Get-CMTraceSha256 -Path $testEntry.FullName
        Bytes = [int64]$testEntry.Length
        Label = 'Pester test input'
    }
    $escaped = $resolvedTestPath.Replace("'", "''")
    $trustedPester = Get-CMTraceTrustedPesterModule
    $escapedManifest = $trustedPester.Path.Replace("'", "''")
    $command = "Import-Module -Name '$escapedManifest' -RequiredVersion '$($trustedPester.Version)' -Force -ErrorAction Stop; `$result = Invoke-Pester -Path '$escaped' -Output Detailed -PassThru; if (`$result.Result -ne 'Passed') { throw `"Pester result: `$(`$result.Result)`" }"
    return [pscustomobject]@{
        Token = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        ContentBindings = [object[]](@($trustedPester.ContentBindings) + @($testBinding))
    }
}

function Get-PlanGate {
    param([string]$Id)
    return $plan | Where-Object { $_.id -eq $Id } | Select-Object -First 1
}

function Invoke-CMTraceToolVersionOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [string[]]$Arguments = @(),

        [System.Collections.IDictionary]$Environment = @{},

        [AllowEmptyCollection()]
        [object[]]$ContentBindings = @(),

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $capture = Invoke-CMTraceOwnedProcessCapture -FilePath $FilePath -Arguments $Arguments -WorkingDirectory $resolvedRepository -Environment $Environment -ContentBindings $ContentBindings
    if ($capture.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($capture.StdErr)) {
        throw "$Label version command failed inside the bounded owned process."
    }
    return $capture.StdOut.Trim()
}

Enter-CMTraceArm64DeveloperEnvironment

$cargo = (Get-Command cargo.exe -ErrorAction Stop).Source
$rustc = (Get-Command rustc.exe -ErrorAction Stop).Source
$git = (Get-Command git.exe -ErrorAction Stop).Source
$node = (Get-Command node.exe -ErrorAction Stop).Source
$nodeRoot = Split-Path -Parent $node
$npmCli = Join-Path $nodeRoot 'node_modules\npm\bin\npm-cli.js'
$npxCli = Join-Path $nodeRoot 'node_modules\npm\bin\npx-cli.js'
foreach ($cli in @($npmCli, $npxCli)) {
    if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) {
        throw "Node's bundled npm CLI is missing after preflight: $cli"
    }
}
$pwsh = (Get-Command pwsh.exe -ErrorAction Stop).Source
$cargoDeny = (Get-Command cargo-deny.exe -ErrorAction Stop).Source
$cargoAudit = (Get-Command cargo-audit.exe -ErrorAction Stop).Source
$clang = Join-Path $env:ProgramFiles 'LLVM\bin\clang.exe'
$bundleRootRelative = "src-tauri/target/$script:CMTraceRustTarget/release/bundle"
$releaseRootRelative = "src-tauri/target/$script:CMTraceRustTarget/release"
$releaseRoot = Join-Path $resolvedRepository $releaseRootRelative
$unsignedConfig = Join-Path (Get-CMTraceHandoffRoot) 'tauri.unsigned-validation.conf.json'
$unsignedConfigBinding = Get-CMTraceContentBinding -Path $unsignedConfig -Label 'Sealed unsigned Tauri validation configuration'

[void](Invoke-CMTraceInternalGate -Gate (Get-PlanGate 'source-integrity') -Action {
    [void](Assert-CMTraceSourceIntegrity -RepositoryPath $resolvedRepository -RequireNoIgnoredFiles)
    [void](Assert-CMTraceLivePullRequest)
    "sourceCommit=$script:CMTraceExpectedSourceCommit`nsourceTree=$script:CMTraceExpectedSourceTree"
})

[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'npm-ci') -FilePath $node -Arguments @($npmCli, 'ci') -WorkingDirectory $resolvedRepository)
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'typescript') -FilePath $node -Arguments @($npxCli, 'tsc', '--noEmit') -WorkingDirectory $resolvedRepository)
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'frontend-build') -FilePath $node -Arguments @($npmCli, 'run', 'frontend:build') -WorkingDirectory $resolvedRepository)
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'frontend-tests') -FilePath $node -Arguments @($npmCli, 'run', 'test') -WorkingDirectory $resolvedRepository)
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'release-contract-tests') -FilePath $node -Arguments @('--test', 'scripts/ci-bundle-outputs.test.mjs', 'scripts/ci-windows-provenance.test.mjs', '.github/scripts/updater-manifest.test.mjs', '.github/scripts/nightly-channel.test.mjs') -WorkingDirectory $resolvedRepository)
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'npm-audit') -FilePath $node -Arguments @($npmCli, 'audit', '--audit-level=high') -WorkingDirectory $resolvedRepository)
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'playwright-browser') -FilePath $node -Arguments @($npxCli, 'playwright', 'install', 'chromium') -WorkingDirectory $resolvedRepository)
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'playwright-e2e') -FilePath $node -Arguments @($npmCli, 'run', 'test:e2e') -WorkingDirectory $resolvedRepository)

$installerPester = ConvertTo-CMTracePesterEncodedCommand -TestPath (Join-Path $resolvedRepository 'src-tauri/installer/remove-file-associations.Tests.ps1')
$collectorPester = ConvertTo-CMTracePesterEncodedCommand -TestPath (Join-Path $resolvedRepository 'scripts/collection/tests/Invoke-CmtraceEvidenceCollection.Tests.ps1')
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'installer-pester') -FilePath $pwsh -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $installerPester.Token) -WorkingDirectory $resolvedRepository -ContentBindings $installerPester.ContentBindings -SafeDisplayCommand 'pwsh -EncodedCommand <redacted>')
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'collector-pester') -FilePath $pwsh -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $collectorPester.Token) -WorkingDirectory $resolvedRepository -ContentBindings $collectorPester.ContentBindings -SafeDisplayCommand 'pwsh -EncodedCommand <redacted>')

[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'cargo-fmt') -FilePath $cargo -Arguments @('fmt', '--all', '--', '--check') -WorkingDirectory $resolvedRepository)
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'parser-tests') -FilePath $cargo -Arguments @('test', '--locked', '-p', 'cmtraceopen-parser', '--target', $script:CMTraceRustTarget) -WorkingDirectory $resolvedRepository)
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'parser-clippy') -FilePath $cargo -Arguments @('clippy', '--locked', '-p', 'cmtraceopen-parser', '--all-targets', '--target', $script:CMTraceRustTarget, '--', '-D', 'warnings') -WorkingDirectory $resolvedRepository)
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'parser-wasm-check') -FilePath $cargo -Arguments @('check', '--locked', '-p', 'cmtraceopen-parser', '--target', 'wasm32-unknown-unknown') -WorkingDirectory $resolvedRepository)
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'esp-native') -FilePath $cargo -Arguments @('test', '--locked', '-p', 'cmtrace-open', '--all-features', '--target', $script:CMTraceRustTarget, '--test', 'esp_diagnostics_sources') -WorkingDirectory $resolvedRepository)
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'esp-graph') -FilePath $cargo -Arguments @('test', '--locked', '-p', 'cmtrace-open', '--all-features', '--target', $script:CMTraceRustTarget, '--test', 'graph_esp_diagnostics') -WorkingDirectory $resolvedRepository)
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'windows-full-build') -FilePath $cargo -Arguments @('test', '--locked', '-p', 'cmtrace-open', '--all-features', '--target', $script:CMTraceRustTarget, '--no-run') -WorkingDirectory $resolvedRepository)
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'windows-full-tests') -FilePath $cargo -Arguments @('test', '--locked', '-p', 'cmtrace-open', '--all-features', '--target', $script:CMTraceRustTarget) -WorkingDirectory $resolvedRepository)
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'windows-full-clippy') -FilePath $cargo -Arguments @('clippy', '--locked', '-p', 'cmtrace-open', '--all-targets', '--all-features', '--target', $script:CMTraceRustTarget, '--', '-D', 'warnings') -WorkingDirectory $resolvedRepository)
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'windows-lite-tests') -FilePath $cargo -Arguments @('test', '--locked', '-p', 'cmtrace-open', '--no-default-features', '--target', $script:CMTraceRustTarget) -WorkingDirectory $resolvedRepository)
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'windows-lite-clippy') -FilePath $cargo -Arguments @('clippy', '--locked', '-p', 'cmtrace-open', '--no-default-features', '--all-targets', '--target', $script:CMTraceRustTarget, '--', '-D', 'warnings') -WorkingDirectory $resolvedRepository)
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'msrv') -FilePath $cargo -Arguments @('+1.88', 'check', '--workspace', '--all-features', '--locked', '--target', $script:CMTraceRustTarget) -WorkingDirectory $resolvedRepository)
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'cargo-deny') -FilePath $cargoDeny -Arguments @('check') -WorkingDirectory (Join-Path $resolvedRepository 'src-tauri'))
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'cargo-audit') -FilePath $cargoAudit -Arguments @() -WorkingDirectory $resolvedRepository)

$fullBuild = Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'arm64-full-build') -FilePath $node -Arguments @($npxCli, 'tauri', 'build', '--target', $script:CMTraceRustTarget, '--no-bundle') -WorkingDirectory $resolvedRepository
$fullArtifact = Join-Path $rawArtifactRoot 'full/cmtrace-open.exe'
if ($fullBuild.status -eq 'passed') {
    try {
        New-Item -ItemType Directory -Path (Split-Path -Parent $fullArtifact) | Out-Null
        Copy-Item -LiteralPath (Join-Path $releaseRoot 'cmtrace-open.exe') -Destination $fullArtifact
    }
    catch {
        Write-CMTraceGatePostFailure -Result $fullBuild -Message $_.Exception.Message
    }
}

$liteBuild = Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'arm64-lite-build') -FilePath $node -Arguments @($npxCli, 'tauri', 'build', '--target', $script:CMTraceRustTarget, '--no-bundle', '--config', 'src-tauri/tauri.lite.conf.json', '--', '--no-default-features') -WorkingDirectory $resolvedRepository
$liteArtifact = Join-Path $rawArtifactRoot 'lite/cmtrace-open.exe'
if ($liteBuild.status -eq 'passed') {
    try {
        New-Item -ItemType Directory -Path (Split-Path -Parent $liteArtifact) | Out-Null
        Copy-Item -LiteralPath (Join-Path $releaseRoot 'cmtrace-open.exe') -Destination $liteArtifact
    }
    catch {
        Write-CMTraceGatePostFailure -Result $liteBuild -Message $_.Exception.Message
    }
}

$bundleEnvironment = @{ BUNDLE_ROOT = $bundleRootRelative }
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'bundle-output-clean') -FilePath $node -Arguments @('scripts/ci-bundle-outputs.mjs', 'clean') -WorkingDirectory $resolvedRepository -Environment $bundleEnvironment)
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'arm64-nsis-build') -FilePath $node -Arguments @($npxCli, 'tauri', 'build', '--target', $script:CMTraceRustTarget, '--bundles', 'nsis', '--config', $unsignedConfig) -WorkingDirectory $resolvedRepository -ContentBindings @($unsignedConfigBinding))
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'bundle-output-verification') -FilePath $node -Arguments @('scripts/ci-bundle-outputs.mjs', 'verify') -WorkingDirectory $resolvedRepository -Environment $bundleEnvironment)
$provenanceEnvironment = @{
    RELEASE_ROOT = $releaseRootRelative
    TARGET_TRIPLE = $script:CMTraceRustTarget
    SOURCE_COMMIT = $script:CMTraceExpectedSourceCommit
    GITHUB_SHA = $script:CMTraceExpectedSourceCommit
}
[void](Invoke-CMTraceProcessGate -Gate (Get-PlanGate 'windows-build-provenance') -FilePath $node -Arguments @('scripts/ci-windows-provenance.mjs') -WorkingDirectory $resolvedRepository -Environment $provenanceEnvironment)

$artifactEvidence = [System.Collections.Generic.List[object]]::new()
[void](Invoke-CMTraceInternalGate -Gate (Get-PlanGate 'arm64-pe-verification') -Action {
    $verifiedArtifactEvidence = [System.Collections.Generic.List[object]]::new()
    foreach ($artifact in @(
        [pscustomobject]@{ Edition = 'full-portable'; Path = $fullArtifact; RequireArm64 = $true },
        [pscustomobject]@{ Edition = 'lite-portable'; Path = $liteArtifact; RequireArm64 = $true }
    )) {
        if (-not (Test-Path -LiteralPath $artifact.Path -PathType Leaf)) {
            throw "Missing $($artifact.Edition) artifact."
        }
        $machine = Get-CMTracePEMachine -Path $artifact.Path
        if ($artifact.RequireArm64 -and $machine -ne 0xAA64) {
            throw "$($artifact.Edition) PE machine was 0x$($machine.ToString('X4')), expected ARM64 0xAA64."
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $artifact.Path
        if ([string]$signature.Status -ne 'NotSigned') {
            throw "$($artifact.Edition) unexpectedly carried an Authenticode signature: $($signature.Status)."
        }
        $verifiedArtifactEvidence.Add([ordered]@{
            kind = $artifact.Edition
            bytes = (Get-Item -LiteralPath $artifact.Path).Length
            sha256 = Get-CMTraceSha256 -Path $artifact.Path
            peMachine = ('0x{0:X4}' -f $machine)
            architecture = 'arm64'
            authenticodeStatus = [string]$signature.Status
        })
    }

    $nsisCandidates = @(Get-ChildItem -LiteralPath (Join-Path $releaseRoot 'bundle/nsis') -Filter '*-setup.exe' -File -Recurse)
    if ($nsisCandidates.Count -ne 1) {
        throw "Expected one NSIS installer, found $($nsisCandidates.Count)."
    }
    $nsisArtifact = Join-Path $rawArtifactRoot 'nsis/cmtrace-open-setup.exe'
    New-Item -ItemType Directory -Path (Split-Path -Parent $nsisArtifact) | Out-Null
    Copy-Item -LiteralPath $nsisCandidates[0].FullName -Destination $nsisArtifact
    $nsisMachine = Get-CMTracePEMachine -Path $nsisArtifact
    $nsisSignature = Get-AuthenticodeSignature -LiteralPath $nsisArtifact
    if ($nsisMachine -ne 0x014C) {
        throw "NSIS bootstrapper PE machine was 0x$($nsisMachine.ToString('X4')), expected x86 0x014C."
    }
    if ([string]$nsisSignature.Status -ne 'NotSigned') {
        throw "NSIS bootstrapper unexpectedly carried an Authenticode signature: $($nsisSignature.Status)."
    }
    $verifiedArtifactEvidence.Add([ordered]@{
        kind = 'nsis-installer'
        bytes = (Get-Item -LiteralPath $nsisArtifact).Length
        sha256 = Get-CMTraceSha256 -Path $nsisArtifact
        peMachine = ('0x{0:X4}' -f $nsisMachine)
        architecture = 'x86-bootstrapper'
        authenticodeStatus = [string]$nsisSignature.Status
    })

    $provenancePath = Join-Path $releaseRoot 'bundle/provenance/windows-build-provenance.json'
    $provenance = Get-Content -LiteralPath $provenancePath -Raw | ConvertFrom-Json
    if ($provenance.schemaVersion -isnot [int64] -or $provenance.schemaVersion -ne 2) {
        throw 'Generated Windows provenance does not bind to the exact source and ARM64 target.'
    }
    foreach ($coordinate in @(
        [pscustomobject]@{ Value = $provenance.sourceCommit; Expected = $script:CMTraceExpectedSourceCommit; Label = 'generated provenance sourceCommit' },
        [pscustomobject]@{ Value = $provenance.buildCommit; Expected = $script:CMTraceExpectedSourceCommit; Label = 'generated provenance buildCommit' },
        [pscustomobject]@{ Value = $provenance.target; Expected = $script:CMTraceRustTarget; Label = 'generated provenance target' },
        [pscustomobject]@{ Value = $provenance.packageVersion; Expected = '1.5.1'; Label = 'generated provenance packageVersion' }
    )) {
        Assert-CMTraceExactStringValue -Value $coordinate.Value -Expected $coordinate.Expected -Label $coordinate.Label
    }
    $provenanceInstallers = @($provenance.installers)
    if ($provenanceInstallers.Count -ne 1) {
        throw 'Generated Windows provenance must contain exactly one NSIS installer entry.'
    }
    $provenanceInstaller = $provenanceInstallers[0]
    Assert-CMTraceExactStringValue -Value $provenanceInstaller.path -Expected 'nsis/CMTrace Open_1.5.1_arm64-setup.exe' -Label 'generated provenance installer path'
    Assert-CMTraceExactStringValue -Value $provenanceInstaller.bundleType -Expected 'nsis' -Label 'generated provenance bundleType'
    if ($provenanceInstaller.sha256 -isnot [string] -or
        $provenanceInstaller.sha256 -cne (Get-CMTraceSha256 -Path $nsisArtifact) -or
        $provenanceInstaller.bytes -isnot [int64] -or
        $provenanceInstaller.bytes -ne (Get-Item -LiteralPath $nsisArtifact).Length) {
        throw 'Copied NSIS artifact does not match its generated provenance entry.'
    }
    if ($provenanceInstaller.expectedInstalledExecutable.derivation -isnot [string] -or
        $provenanceInstaller.expectedInstalledExecutable.derivation -cne 'tauriBundleTypeMarkerV1' -or
        $provenanceInstaller.expectedInstalledExecutable.path -isnot [string] -or
        $provenanceInstaller.expectedInstalledExecutable.path -cne 'cmtrace-open.exe' -or
        $provenanceInstaller.expectedInstalledExecutable.sha256 -isnot [string] -or
        $provenanceInstaller.expectedInstalledExecutable.sha256 -notmatch '^[0-9a-f]{64}$' -or
        $provenanceInstaller.expectedInstalledExecutable.bytes -isnot [int64] -or
        $provenanceInstaller.expectedInstalledExecutable.bytes -le 0) {
        throw 'Generated NSIS installed-executable evidence is missing or malformed.'
    }
    if ($provenance.releaseExecutable.path -isnot [string] -or $provenance.releaseExecutable.path -cne 'cmtrace-open.exe' -or
        $provenance.releaseExecutable.sha256 -isnot [string] -or
        $provenance.releaseExecutable.sha256 -notmatch '^[0-9a-f]{64}$' -or
        $provenance.releaseExecutable.bytes -isnot [int64] -or
        $provenance.releaseExecutable.bytes -le 0) {
        throw 'Generated standalone release-executable evidence is missing or malformed.'
    }
    $fullPortableEvidence = @($verifiedArtifactEvidence | Where-Object { $_.kind -ceq 'full-portable' })
    if ($fullPortableEvidence.Count -ne 1 -or
        $fullPortableEvidence[0].bytes -ne $provenance.releaseExecutable.bytes -or
        $fullPortableEvidence[0].sha256 -cne $provenance.releaseExecutable.sha256) {
        throw 'Recorded Full portable artifact does not match generated standalone release-executable provenance.'
    }
    # The Tauri NSIS marker changes the installed image hash without changing its byte length.
    if ($provenanceInstaller.expectedInstalledExecutable.bytes -ne $provenance.releaseExecutable.bytes) {
        throw 'Generated installed-executable provenance must be the same-length, distinct Tauri NSIS derivation of the standalone release executable; byte length differs.'
    }
    if ($provenanceInstaller.expectedInstalledExecutable.sha256 -ceq $provenance.releaseExecutable.sha256) {
        throw 'Generated installed-executable provenance must be the same-length, distinct Tauri NSIS derivation of the standalone release executable; SHA-256 is not distinct.'
    }
    $privateProvenancePath = Join-Path $rawArtifactRoot 'provenance/windows-build-provenance.json'
    New-Item -ItemType Directory -Path (Split-Path -Parent $privateProvenancePath) | Out-Null
    Copy-Item -LiteralPath $provenancePath -Destination $privateProvenancePath
    $verifiedArtifactEvidence.Add([ordered]@{
        kind = 'windows-build-provenance'
        schemaVersion = 2
        sourceCommit = $provenance.sourceCommit
        buildCommit = $provenance.buildCommit
        target = $provenance.target
        packageVersion = $provenance.packageVersion
        releaseExecutable = [ordered]@{
            path = $provenance.releaseExecutable.path
            bytes = [int64]$provenance.releaseExecutable.bytes
            sha256 = $provenance.releaseExecutable.sha256
        }
        installers = @([ordered]@{
            path = $provenanceInstaller.path
            bytes = [int64]$provenanceInstaller.bytes
            sha256 = $provenanceInstaller.sha256
            bundleType = $provenanceInstaller.bundleType
            expectedInstalledExecutable = [ordered]@{
                path = $provenanceInstaller.expectedInstalledExecutable.path
                bytes = [int64]$provenanceInstaller.expectedInstalledExecutable.bytes
                sha256 = $provenanceInstaller.expectedInstalledExecutable.sha256
                derivation = $provenanceInstaller.expectedInstalledExecutable.derivation
            }
        })
        manifestSha256 = Get-CMTraceSha256 -Path $privateProvenancePath
    })
    foreach ($verifiedArtifact in $verifiedArtifactEvidence) {
        $artifactEvidence.Add($verifiedArtifact)
    }
    'ARM64 Full/Lite PE headers and exact-source provenance verified; NSIS bootstrapper architecture recorded separately.'
})

[void](Invoke-CMTraceInternalGate -Gate (Get-PlanGate 'source-clean-after') -Action {
    [void](Assert-CMTraceSourceIntegrity -RepositoryPath $resolvedRepository)
    [void](Assert-CMTraceLivePullRequest)
    'Exact source and clean status preserved after generated validation work.'
})

$failedOrBlocked = @($results | Where-Object { $_.status -ne 'passed' })
$failedGates = @($results | Where-Object { $_.status -eq 'failed' })
$blockedGates = @($results | Where-Object { $_.status -eq 'blocked' })
$summary = [ordered]@{
    schemaVersion = 1
    handoffId = $script:CMTraceHandoffId
    sourceCommit = $script:CMTraceExpectedSourceCommit
    sourceTree = $script:CMTraceExpectedSourceTree
    target = $script:CMTraceRustTarget
    startedAtUtc = @($results | Where-Object { $_.startedAtUtc } | Select-Object -First 1).startedAtUtc
    completedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    automaticStatus = if ($failedGates.Count -gt 0) { 'FAILED' } elseif ($blockedGates.Count -gt 0) { 'BLOCKED' } else { 'PASSED' }
    gates = @($results)
    rawEvidenceReturned = $false
}
$summaryPath = Join-Path $fullEvidenceRoot 'summary.json'
Write-CMTraceJson -Value $summary -Path $summaryPath

$osVersion = [Environment]::OSVersion.Version
$powerShellVersion = ConvertTo-CMTraceNormalizedToolVersion -Tool PowerShell -Text $PSVersionTable.PSVersion.ToString()
$gitVersion = ConvertTo-CMTraceNormalizedToolVersion -Tool Git -Text (Invoke-CMTraceToolVersionOutput -FilePath $git -Arguments @('--version') -Label 'Git')
$nodeVersion = ConvertTo-CMTraceNormalizedToolVersion -Tool Node -Text (Invoke-CMTraceToolVersionOutput -FilePath $node -Arguments @('--version') -Label 'Node.js')
$nodeArchitecture = Invoke-CMTraceToolVersionOutput -FilePath $node -Arguments @('-p', 'process.arch') -Label 'Node.js architecture'
if ($nodeArchitecture -cne 'arm64') {
    throw 'Node.js version capture did not run in a native ARM64 process.'
}
$npmEnvironment = @{
    NPM_CONFIG_USERCONFIG = $emptyNpmConfig
    NPM_CONFIG_GLOBALCONFIG = $emptyNpmConfig
    NPM_CONFIG_UPDATE_NOTIFIER = 'false'
    NPM_CONFIG_FUND = 'false'
}
$npmVersion = ConvertTo-CMTraceNormalizedToolVersion -Tool Npm -Text (Invoke-CMTraceToolVersionOutput -FilePath $node -Arguments @($npmCli, '--version') -Environment $npmEnvironment -Label 'npm')
$rustVerbose = Invoke-CMTraceToolVersionOutput -FilePath $rustc -Arguments @('-Vv') -Label 'Rust'
$rustVersion = ConvertTo-CMTraceNormalizedToolVersion -Tool Rust -Text $rustVerbose
$rustHostMatches = [regex]::Matches($rustVerbose, '(?m)^host:\s*(?<host>\S+)\s*$', [Text.RegularExpressions.RegexOptions]::CultureInvariant)
if ($rustHostMatches.Count -ne 1 -or $rustHostMatches[0].Groups['host'].Value -cne $script:CMTraceRustTarget) {
    throw 'Rust version capture did not prove the native ARM64 MSVC host.'
}
$rustHost = $rustHostMatches[0].Groups['host'].Value
$trustedPester = Get-CMTraceTrustedPesterModule
$escapedPesterManifest = $trustedPester.Path.Replace("'", "''")
$pesterCommand = "Import-Module -Name '$escapedPesterManifest' -RequiredVersion '$($trustedPester.Version)' -Force -ErrorAction Stop; [Console]::Out.Write((Get-Module Pester).Version.ToString())"
$pesterVersion = ConvertTo-CMTraceNormalizedToolVersion -Tool Pester -Text (Invoke-CMTraceToolVersionOutput -FilePath $pwsh -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', $pesterCommand) -ContentBindings $trustedPester.ContentBindings -Label 'Pester')
if ($pesterVersion -cne $trustedPester.Version) {
    throw 'Machine evidence Pester version differs from its pinned PSGallery binding.'
}
$cargoDenyVersion = ConvertTo-CMTraceNormalizedToolVersion -Tool CargoDeny -Text (Invoke-CMTraceToolVersionOutput -FilePath $cargoDeny -Arguments @('--version') -Label 'cargo-deny')
$cargoAuditVersion = ConvertTo-CMTraceNormalizedToolVersion -Tool CargoAudit -Text (Invoke-CMTraceToolVersionOutput -FilePath $cargoAudit -Arguments @('--version') -Label 'cargo-audit')
$clangVersion = ConvertTo-CMTraceNormalizedToolVersion -Tool Clang -Text (Invoke-CMTraceToolVersionOutput -FilePath $clang -Arguments @('--version') -Label 'LLVM Clang')
if ([string]::IsNullOrWhiteSpace($script:CMTraceVisualStudioVersion)) {
    throw 'Visual Studio version was not retained from the bounded developer-environment resolution.'
}
$visualStudioVersion = ConvertTo-CMTraceNormalizedToolVersion -Tool VisualStudio -Text $script:CMTraceVisualStudioVersion
if ([string]::IsNullOrWhiteSpace($env:WindowsSDKVersion) -or [string]::IsNullOrWhiteSpace($env:WindowsSdkDir)) {
    throw 'The ARM64 developer environment did not expose its active Windows SDK coordinate.'
}
$windowsSdkVersion = ConvertTo-CMTraceNormalizedToolVersion -Tool WindowsSdk -Text $env:WindowsSDKVersion.Trim().TrimEnd([char]'\', [char]'/')
$expectedWindowsSdkRoot = [IO.Path]::GetFullPath((Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10')).TrimEnd([char]'\', [char]'/')
$activeWindowsSdkRoot = [IO.Path]::GetFullPath($env:WindowsSdkDir).TrimEnd([char]'\', [char]'/')
if (-not $activeWindowsSdkRoot.Equals($expectedWindowsSdkRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The active Windows SDK directory is not the standard Windows Kits 10 installation.'
}
$expectedMtPath = [IO.Path]::GetFullPath((Join-Path $activeWindowsSdkRoot "bin\$windowsSdkVersion\x64\mt.exe"))
$activeMtCommand = Get-Command mt.exe -CommandType Application -ErrorAction Stop
if (-not (Test-Path -LiteralPath $expectedMtPath -PathType Leaf) -or
    -not [IO.Path]::GetFullPath($activeMtCommand.Source).Equals($expectedMtPath, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The active mt.exe does not exactly read back from the normalized Windows SDK version.'
}
$webView2Version = Get-CMTraceWebView2Version
$physicalMemory = [int64](Get-CimInstance -ClassName Win32_ComputerSystem -OperationTimeoutSec 5 -ErrorAction Stop).TotalPhysicalMemory
$processors = @(Get-CimInstance -ClassName Win32_Processor -OperationTimeoutSec 5 -ErrorAction Stop)
$cpuClasses = @($processors | ForEach-Object { ([string]$_.Name).Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
if ($cpuClasses.Count -ne 1) {
    throw 'Machine provenance requires exactly one nonempty processor hardware class.'
}
$cpuClass = $cpuClasses[0]
$sourceVolume = Get-Volume -DriveLetter ([IO.Path]::GetPathRoot($resolvedRepository).Substring(0, 1)) -ErrorAction Stop
$machine = [ordered]@{
    schemaVersion = 2
    handoffId = $script:CMTraceHandoffId
    sourceCommit = $script:CMTraceExpectedSourceCommit
    sourceTree = $script:CMTraceExpectedSourceTree
    target = $script:CMTraceRustTarget
    os = 'Windows 11'
    osVersion = $osVersion.ToString()
    osBuild = $osVersion.Build
    osArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    processArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
    processorArchitecture = $env:PROCESSOR_ARCHITECTURE
    logicalProcessorCount = [Environment]::ProcessorCount
    cpuClass = $cpuClass
    physicalMemoryBytes = $physicalMemory
    powerShellVersion = $powerShellVersion
    gitVersion = $gitVersion
    nodeVersion = $nodeVersion
    nodeArchitecture = $nodeArchitecture
    npmVersion = $npmVersion
    rustVersion = $rustVersion
    rustHost = $rustHost
    pesterVersion = $pesterVersion
    cargoDenyVersion = $cargoDenyVersion
    cargoAuditVersion = $cargoAuditVersion
    clangVersion = $clangVersion
    visualStudioVersion = $visualStudioVersion
    windowsSdkVersion = $windowsSdkVersion
    webView2Version = $webView2Version
    sourceVolumeFileSystem = [string]$sourceVolume.FileSystem
    sourceVolumeDriveType = [string]$sourceVolume.DriveType
    sourceOutsideKnownSyncRoots = $true
    identityFieldsIntentionallyOmitted = @('computerName', 'userName', 'domain', 'deviceId', 'tenantId', 'ipAddress')
}
Write-CMTraceJson -Value $machine -Path (Join-Path $fullEvidenceRoot 'machine.json')
$artifactsPath = Join-Path $fullEvidenceRoot 'artifacts.json'
Write-CMTraceJson -Value ([ordered]@{
    schemaVersion = 1
    handoffId = $script:CMTraceHandoffId
    sourceCommit = $script:CMTraceExpectedSourceCommit
    sourceTree = $script:CMTraceExpectedSourceTree
    target = $script:CMTraceRustTarget
    items = @($artifactEvidence)
}) -Path $artifactsPath
$manualResults = Get-Content -LiteralPath (Join-Path (Get-CMTraceHandoffRoot) 'manual-results.template.json') -Raw | ConvertFrom-Json
$manualResults.automaticSummarySha256 = Get-CMTraceSha256 -Path $summaryPath
$manualResults.artifactsSha256 = Get-CMTraceSha256 -Path $artifactsPath
Write-CMTraceJson -Value $manualResults -Path (Join-Path $fullEvidenceRoot 'manual-results.json')

if ($failedOrBlocked.Count -gt 0) {
    $ids = ($failedOrBlocked.id -join ', ')
    $privacyDetail = if ($script:CMTracePrivacyWithheldGates.Count -gt 0) {
        " Sanitized logs were withheld after privacy validation failed for: $(@($script:CMTracePrivacyWithheldGates | Sort-Object) -join ',')."
    }
    else { '' }
    throw "ARM64 automatic validation did not pass every required gate: $ids.$privacyDetail Raw evidence was retained locally; return only the sanitized bundle."
}

Write-Output 'AUTOMATIC_VALIDATION_PASSED_MANUAL_PENDING'
