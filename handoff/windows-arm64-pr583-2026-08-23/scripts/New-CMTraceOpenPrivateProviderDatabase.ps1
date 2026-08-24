[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RepositoryPath,

    [Parameter(Mandatory = $true)]
    [string]$EvidenceRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'CMTraceOpenArm64Handoff.Common.ps1')

[void](Assert-CMTraceHandoffIntegrity)
Assert-CMTraceWindows11Arm64
Assert-CMTraceNoSensitiveEnvironment
$resolvedRepository = Assert-CMTraceSourceIntegrity -RepositoryPath $RepositoryPath
& (Join-Path $PSScriptRoot 'Test-CMTraceOpenArm64Preflight.ps1') -RepositoryPath $resolvedRepository -AllowIgnoredGeneratedFiles | Out-Null
$resolvedEvidence = Assert-CMTraceFixedLocalNtfsPath -Path $EvidenceRoot -Label 'EvidenceRoot' -ForbiddenRoots @($resolvedRepository, (Get-CMTraceHandoffRoot))

$rawArtifactRoot = Join-Path $resolvedEvidence 'raw-artifacts'
if (-not (Test-Path -LiteralPath $rawArtifactRoot -PathType Container)) {
    throw 'EvidenceRoot must already contain raw-artifacts from the automatic runner.'
}
[void](Assert-CMTraceFixedLocalNtfsPath -Path $rawArtifactRoot -Label 'Raw artifact root' -ForbiddenRoots @($resolvedRepository, (Get-CMTraceHandoffRoot)))
$providerRoot = Join-Path $rawArtifactRoot 'private-provider'
[void](Assert-CMTraceFixedLocalNtfsPath -Path $providerRoot -Label 'Private provider workspace' -ForbiddenRoots @($resolvedRepository, (Get-CMTraceHandoffRoot)) -MustNotExist)
New-Item -ItemType Directory -Path $providerRoot | Out-Null
$archivePath = Join-Path $providerRoot 'exact-source.zip'
$archiveSource = Join-Path $providerRoot 'source'
$databaseRoot = Join-Path $providerRoot 'database'
$providerDb = Join-Path $databaseRoot 'machine-wide.db'
$sourceCargoConfiguration = Join-Path $resolvedRepository '.cargo\config.toml'
$archiveCargoConfiguration = Join-Path $archiveSource '.cargo\config.toml'

$git = (Get-Command git.exe -ErrorAction Stop).Source
$cargo = (Get-Command cargo.exe -ErrorAction Stop).Source
$gitEnvironment = [ordered]@{
    GIT_CONFIG_NOSYSTEM = '1'
    GIT_CONFIG_GLOBAL = 'NUL'
    GIT_TERMINAL_PROMPT = '0'
    GCM_INTERACTIVE = 'Never'
    GIT_ASKPASS = ''
    SSH_ASKPASS = ''
    GIT_NO_REPLACE_OBJECTS = '1'
}

$privateCargoTimeout = [TimeSpan]::FromMinutes(180)
$privateCargoOutputLimitBytes = 33554432L
$privateCargoBufferBytes = 8192
Initialize-CMTraceOwnedProcessType

function Invoke-CMTracePrivateCargoProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[a-z0-9][a-z0-9-]{0,63}$')]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList,

        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,

        [System.Collections.IDictionary]$Environment = @{},

        [AllowEmptyCollection()]
        [object[]]$ContentBindings = @()
    )

    $resolvedWorkingDirectory = (Resolve-Path -LiteralPath $WorkingDirectory).Path
    $repositoryPrefix = $resolvedRepository.TrimEnd([char]'\', [char]'/') + [IO.Path]::DirectorySeparatorChar
    $archivePrefix = $archiveSource.TrimEnd([char]'\', [char]'/') + [IO.Path]::DirectorySeparatorChar
    $allowedCargoConfiguration = if ($resolvedWorkingDirectory.Equals($resolvedRepository, [StringComparison]::OrdinalIgnoreCase) -or
        $resolvedWorkingDirectory.StartsWith($repositoryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        $sourceCargoConfiguration
    }
    elseif ($resolvedWorkingDirectory.Equals($archiveSource, [StringComparison]::OrdinalIgnoreCase) -or
        $resolvedWorkingDirectory.StartsWith($archivePrefix, [StringComparison]::OrdinalIgnoreCase)) {
        $archiveCargoConfiguration
    }
    else {
        throw "Private Cargo working directory escapes both authenticated source roots: $resolvedWorkingDirectory"
    }
    [void](Assert-CMTraceSourceIntegrity -RepositoryPath $resolvedRepository)
    [void](Assert-CMTraceCargoConfigurationBoundary -WorkingDirectory $resolvedWorkingDirectory `
        -AllowedConfigurationPaths @($allowedCargoConfiguration))
    [void](Assert-CMTraceActiveRustToolchain -WorkingDirectory $resolvedWorkingDirectory)

    $stdoutPath = Join-Path $providerRoot "$Id.stdout.private.log"
    $stderrPath = Join-Path $providerRoot "$Id.stderr.private.log"
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $cargo
    $startInfo.WorkingDirectory = $resolvedWorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $ArgumentList) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    Initialize-CMTraceChildEnvironment -StartInfo $startInfo -Environment $Environment

    $ownedLaunch = $null
    $ownedJob = $null
    $process = $null
    $processStarted = $false
    $jobAssigned = $false
    $stdoutFile = $null
    $stderrFile = $null
    $stdoutReadTask = $null
    $stderrReadTask = $null
    $stdoutComplete = $false
    $stderrComplete = $false
    $timedOut = $false
    $outputLimitExceeded = $false
    $terminationDrainFailures = [Collections.Generic.List[string]]::new()
    $capturedBytes = 0L
    $exitCode = $null
    $targetGuard = $null
    $targetStartFailure = $null
    $terminationRequested = $false
    $terminationDrainDeadline = [DateTimeOffset]::MaxValue
    $contentGuards = [Collections.Generic.List[IO.FileStream]]::new()

    try {
        $targetGuard = Open-CMTraceGuardedReadFile -Path $cargo -Label "Private Cargo target $Id"
        $startInfo.FileName = $targetGuard.Path
        foreach ($binding in @($ContentBindings)) {
            if ($null -eq $binding -or
                @($binding.PSObject.Properties.Name | Where-Object { $_ -cin @('Path', 'Sha256', 'Bytes', 'Label') }).Count -ne 4 -or
                @($binding.PSObject.Properties.Name).Count -ne 4) {
                throw 'Each private Cargo content binding must contain exactly Path, Sha256, Bytes, and Label.'
            }
            $contentGuard = Open-CMTraceGuardedReadFile -Path ([string]$binding.Path) -Label ([string]$binding.Label) `
                -ExpectedSha256 ([string]$binding.Sha256) -ExpectedBytes ([int64]$binding.Bytes)
            $contentGuards.Add($contentGuard.Stream)
        }
        $ownedLaunch = Get-CMTraceOwnedProcessLaunch -TargetStartInfo $startInfo
        $ownedJob = [CMTraceOpen.Validation.OwnedProcessJob]::new()
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $ownedLaunch.StartInfo
        $stdoutFile = [IO.File]::Open($stdoutPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $stderrFile = [IO.File]::Open($stderrPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        if (-not $process.Start()) {
            throw "Could not start private cargo process '$Id'."
        }
        $processStarted = $true
        $ownedJob.Assign($process)
        $jobAssigned = $true
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $stdoutBuffer = [byte[]]::new($privateCargoBufferBytes)
        $stderrBuffer = [byte[]]::new($privateCargoBufferBytes)
        $stdoutReadTask = $process.StandardOutput.BaseStream.ReadAsync($stdoutBuffer, 0, $stdoutBuffer.Length)
        $stderrReadTask = $process.StandardError.BaseStream.ReadAsync($stderrBuffer, 0, $stderrBuffer.Length)
        [void]$ownedLaunch.ReadyEvent.Set()
        try {
            Wait-CMTraceOwnedTargetStarted -OwnedLaunch $ownedLaunch -WrapperProcess $process
            $targetGuard.Stream.Dispose()
            $targetGuard = $null
        }
        catch {
            $targetStartFailure = $_.Exception.Message
            $terminationRequested = $true
            $terminationDrainDeadline = [DateTimeOffset]::UtcNow.AddSeconds(5)
            try { $ownedJob.Terminate(1) }
            catch { $terminationDrainFailures.Add("Target-start Job termination failed: $($_.Exception.Message)") }
        }

        while ($ownedJob.ActiveProcessCount -gt 0 -or -not $process.HasExited -or -not $stdoutComplete -or -not $stderrComplete) {
            $now = [DateTimeOffset]::UtcNow
            if (-not $terminationRequested -and $timer.Elapsed -ge $privateCargoTimeout) {
                $timedOut = $true
                $terminationRequested = $true
                $terminationDrainDeadline = $now.AddSeconds(5)
                $ownedJob.Terminate(1)
            }
            if ($terminationRequested -and $now -ge $terminationDrainDeadline -and
                ($ownedJob.ActiveProcessCount -gt 0 -or -not $process.HasExited -or
                 -not $stdoutComplete -or -not $stderrComplete)) {
                $terminationDrainFailures.Add('Owned process Job or redirected streams exceeded the bounded in-loop termination drain.')
                break
            }

            $pendingTasks = @()
            $pendingStreams = @()
            if (-not $stdoutComplete) {
                $pendingTasks += $stdoutReadTask
                $pendingStreams += 'stdout'
            }
            if (-not $stderrComplete) {
                $pendingTasks += $stderrReadTask
                $pendingStreams += 'stderr'
            }
            if ($pendingTasks.Count -eq 0) {
                if ($process.HasExited) {
                    Start-Sleep -Milliseconds 50
                }
                else {
                    [void]$process.WaitForExit(250)
                }
                continue
            }

            $completedIndex = [Threading.Tasks.Task]::WaitAny([Threading.Tasks.Task[]]$pendingTasks, 250)
            if ($completedIndex -lt 0) {
                continue
            }

            $streamName = $pendingStreams[$completedIndex]
            if ($streamName -eq 'stdout') {
                $readBytes = $stdoutReadTask.GetAwaiter().GetResult()
                if ($readBytes -eq 0) {
                    $stdoutComplete = $true
                }
                else {
                    $remainingBytes = [Math]::Max(0L, $privateCargoOutputLimitBytes - $capturedBytes)
                    $writeBytes = [int][Math]::Min([long]$readBytes, $remainingBytes)
                    if ($writeBytes -gt 0) {
                        $stdoutFile.Write($stdoutBuffer, 0, $writeBytes)
                        $capturedBytes += $writeBytes
                    }
                    if ($writeBytes -lt $readBytes) {
                        $outputLimitExceeded = $true
                        if (-not $terminationRequested) {
                            $terminationRequested = $true
                            $terminationDrainDeadline = [DateTimeOffset]::UtcNow.AddSeconds(5)
                            $ownedJob.Terminate(1)
                        }
                    }
                    $stdoutReadTask = $process.StandardOutput.BaseStream.ReadAsync($stdoutBuffer, 0, $stdoutBuffer.Length)
                }
            }
            else {
                $readBytes = $stderrReadTask.GetAwaiter().GetResult()
                if ($readBytes -eq 0) {
                    $stderrComplete = $true
                }
                else {
                    $remainingBytes = [Math]::Max(0L, $privateCargoOutputLimitBytes - $capturedBytes)
                    $writeBytes = [int][Math]::Min([long]$readBytes, $remainingBytes)
                    if ($writeBytes -gt 0) {
                        $stderrFile.Write($stderrBuffer, 0, $writeBytes)
                        $capturedBytes += $writeBytes
                    }
                    if ($writeBytes -lt $readBytes) {
                        $outputLimitExceeded = $true
                        if (-not $terminationRequested) {
                            $terminationRequested = $true
                            $terminationDrainDeadline = [DateTimeOffset]::UtcNow.AddSeconds(5)
                            $ownedJob.Terminate(1)
                        }
                    }
                    $stderrReadTask = $process.StandardError.BaseStream.ReadAsync($stderrBuffer, 0, $stderrBuffer.Length)
                }
            }
        }

        $timer.Stop()
        $stdoutFile.Flush($true)
        $stderrFile.Flush($true)
        if ($process.HasExited) {
            $exitCode = $process.ExitCode
        }
    }
    finally {
        $processStillActive = $processStarted
        if ($processStarted) {
            try { $processStillActive = -not $process.HasExited }
            catch { $terminationDrainFailures.Add("Process activity query failed: $($_.Exception.Message)") }
        }
        if ($processStarted -and -not $jobAssigned -and $processStillActive) {
            try { $process.Kill($true) } catch { $terminationDrainFailures.Add("Fallback process-tree Kill failed: $($_.Exception.Message)") }
        }
        $jobStillActive = $false
        if ($null -ne $ownedJob) {
            try { $jobStillActive = $ownedJob.ActiveProcessCount -gt 0 }
            catch {
                $jobStillActive = $true
                $terminationDrainFailures.Add("Job activity query failed: $($_.Exception.Message)")
            }
        }
        if ($null -ne $ownedJob -and $processStarted -and
            ($jobStillActive -or $processStillActive -or
             ($null -ne $stdoutReadTask -and -not $stdoutReadTask.IsCompleted) -or
             ($null -ne $stderrReadTask -and -not $stderrReadTask.IsCompleted))) {
            try { $ownedJob.Terminate(1) }
            catch { $terminationDrainFailures.Add("Job termination failed: $($_.Exception.Message)") }
        }
        if ($null -ne $ownedJob) {
            try { $ownedJob.Dispose() }
            catch { $terminationDrainFailures.Add("Job disposal failed: $($_.Exception.Message)") }
        }
        if ($null -ne $ownedLaunch) {
            try { $ownedLaunch.TargetStartedEvent.Dispose() }
            catch { $terminationDrainFailures.Add("Target-start-event disposal failed: $($_.Exception.Message)") }
            try { $ownedLaunch.ReadyEvent.Dispose() }
            catch { $terminationDrainFailures.Add("Launch-event disposal failed: $($_.Exception.Message)") }
        }
        if ($processStarted -and $processStillActive) {
            try {
                if (-not $process.WaitForExit(5000)) {
                    $terminationDrainFailures.Add('Owned process did not exit within the bounded five-second termination drain.')
                }
            }
            catch { $terminationDrainFailures.Add("Process exit wait failed: $($_.Exception.Message)") }
        }
        $pendingReadTasks = @(@($stdoutReadTask, $stderrReadTask) | Where-Object { $null -ne $_ -and -not $_.IsCompleted })
        if ($pendingReadTasks.Count -gt 0 -and $null -ne $process) {
            try { $process.StandardOutput.BaseStream.Dispose() }
            catch { $terminationDrainFailures.Add("Standard-output stream disposal failed: $($_.Exception.Message)") }
            try { $process.StandardError.BaseStream.Dispose() }
            catch { $terminationDrainFailures.Add("Standard-error stream disposal failed: $($_.Exception.Message)") }
            try {
                if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$pendingReadTasks, 5000)) {
                    $terminationDrainFailures.Add('Redirected stream reads did not finish within the bounded five-second termination drain.')
                }
            }
            catch { $terminationDrainFailures.Add("Redirected stream drain failed: $($_.Exception.Message)") }
        }
        if ($null -ne $stdoutFile) {
            try { $stdoutFile.Dispose() }
            catch { $terminationDrainFailures.Add("Standard-output file disposal failed: $($_.Exception.Message)") }
        }
        if ($null -ne $stderrFile) {
            try { $stderrFile.Dispose() }
            catch { $terminationDrainFailures.Add("Standard-error file disposal failed: $($_.Exception.Message)") }
        }
        if ($null -ne $process) {
            try { $process.Dispose() }
            catch { $terminationDrainFailures.Add("Process disposal failed: $($_.Exception.Message)") }
        }
        if ($null -ne $targetGuard) {
            try { $targetGuard.Stream.Dispose() }
            catch { $terminationDrainFailures.Add("Target guard disposal failed: $($_.Exception.Message)") }
        }
        foreach ($contentGuard in $contentGuards) {
            try { $contentGuard.Dispose() }
            catch { $terminationDrainFailures.Add("Content guard disposal failed: $($_.Exception.Message)") }
        }
    }

    $terminationDrainDetail = if ($terminationDrainFailures.Count -eq 0) { '' } else {
        " Termination drain details: $($terminationDrainFailures -join ' | ')"
    }
    if (-not [string]::IsNullOrWhiteSpace($targetStartFailure) -or
        (Test-CMTraceOwnedProcessWrapperFailureExitCode -ExitCode $exitCode)) {
        throw "Private cargo owned-process wrapper failed before a trustworthy native child result for '$Id'.$terminationDrainDetail"
    }
    if ($timedOut) {
        throw "Private cargo process '$Id' timed out after 180 minutes.$terminationDrainDetail"
    }
    if ($outputLimitExceeded) {
        throw "Private cargo process '$Id' exceeded the $privateCargoOutputLimitBytes-byte aggregate output limit.$terminationDrainDetail"
    }
    if ($terminationDrainFailures.Count -gt 0) {
        throw "Private cargo process '$Id' did not close its owned process and redirected streams within the bounded five-second termination drain: $($terminationDrainFailures -join ' | ')"
    }
    [pscustomobject]@{
        ExitCode = $exitCode
        StandardOutputPath = $stdoutPath
        StandardErrorPath = $stderrPath
        CapturedBytes = $capturedBytes
    }
}

$smokeResult = Invoke-CMTracePrivateCargoProcess -Id 'provider-smoke-test' -WorkingDirectory $resolvedRepository -ArgumentList @(
    'test', '--locked', '-p', 'cmtrace-open', '--all-features', '--target', $script:CMTraceRustTarget,
    '--lib', 'event_log::capture::tests::windows_provider_walk_writes_named_rows_with_composite_keys',
    '--', '--exact', '--ignored', '--nocapture', '--test-threads=1'
)
if ($smokeResult.ExitCode -ne 0) {
    throw 'The exact native provider-capture smoke test failed.'
}

$archiveResult = Invoke-CMTraceOwnedProcessCapture -FilePath $git -WorkingDirectory $resolvedRepository `
    -Environment $gitEnvironment -TimeoutSeconds 120 -Arguments @(
        '-c', 'credential.helper=', '-c', 'core.hooksPath=NUL', '-C', $resolvedRepository,
        'archive', '--format=zip', "--output=$archivePath", $script:CMTraceExpectedSourceCommit
    )
if ($archiveResult.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
    throw 'Could not create the target-private exact-source archive.'
}
Expand-Archive -LiteralPath $archivePath -DestinationPath $archiveSource
if ((Get-CMTraceSha256 -Path (Join-Path $archiveSource 'Cargo.lock')) -ne (Get-CMTraceSha256 -Path (Join-Path $resolvedRepository 'Cargo.lock'))) {
    throw 'The archived Cargo.lock does not match the immutable source checkout.'
}
if ((Get-CMTraceSha256 -Path $archiveCargoConfiguration) -ne (Get-CMTraceSha256 -Path $sourceCargoConfiguration)) {
    throw 'The archived Cargo configuration does not match the immutable source checkout.'
}

$exampleDirectory = Join-Path $archiveSource 'src-tauri\examples'
if (-not (Test-Path -LiteralPath $exampleDirectory -PathType Container)) {
    New-Item -ItemType Directory -Path $exampleDirectory | Out-Null
}
$providerCaptureSource = Join-Path (Get-CMTraceHandoffRoot) 'assets\provider_capture.rs'
$providerCaptureCopy = Join-Path $exampleDirectory 'provider_capture.rs'
Copy-Item -LiteralPath $providerCaptureSource -Destination $providerCaptureCopy
if ((Get-CMTraceSha256 -Path $providerCaptureCopy) -cne (Get-CMTraceSha256 -Path $providerCaptureSource)) {
    throw 'The private provider helper copy differs from the sealed handoff asset.'
}
New-Item -ItemType Directory -Path $databaseRoot | Out-Null

$publicationBindings = @(
    Get-CMTraceContentBinding -Path $archiveCargoConfiguration -Label 'Private archive Cargo configuration'
    Get-CMTraceContentBinding -Path $providerCaptureCopy -Label 'Private copied provider capture helper'
)
$publicationTestResult = Invoke-CMTracePrivateCargoProcess -Id 'provider-publication-test' -WorkingDirectory $archiveSource `
    -ContentBindings $publicationBindings -ArgumentList @(
    'test', '--locked', '-p', 'cmtrace-open', '--no-default-features', '--features', 'event-log',
    '--target', $script:CMTraceRustTarget, '--example', 'provider_capture',
    'tests::publish_no_replace_preserves_existing_destination', '--', '--exact', '--nocapture', '--test-threads=1'
)
if ($publicationTestResult.ExitCode -ne 0) {
    throw 'The target-native provider publication no-overwrite regression failed.'
}

$captureBindings = @(
    Get-CMTraceContentBinding -Path $archiveCargoConfiguration -Label 'Private archive Cargo configuration'
    Get-CMTraceContentBinding -Path $providerCaptureCopy -Label 'Private copied provider capture helper'
)
$captureResult = Invoke-CMTracePrivateCargoProcess -Id 'provider-capture' -WorkingDirectory $archiveSource `
    -ContentBindings $captureBindings -ArgumentList @(
    'run', '--locked', '-p', 'cmtrace-open', '--no-default-features', '--features', 'event-log',
    '--target', $script:CMTraceRustTarget, '--example', 'provider_capture', '--', $providerDb
)
if ($captureResult.ExitCode -ne 0) {
    throw 'The exact native provider capture failed; no partial database is acceptable.'
}
$captureSuccess = @(Select-String -LiteralPath $captureResult.StandardOutputPath -CaseSensitive -Pattern '^PROVIDER_CAPTURE_OK providerCount=([0-9]+)$')
if ($captureSuccess.Count -ne 1) {
    throw 'The provider capture did not report exactly one verified provider-row count.'
}
$providerCountMatch = [regex]::Match($captureSuccess[0].Line, '^PROVIDER_CAPTURE_OK providerCount=([0-9]+)$')
if (-not $providerCountMatch.Success) {
    throw 'The provider capture success line is not the exact canonical marker.'
}
$providerCount = [long]$providerCountMatch.Groups[1].Value
if ($providerCount -le 100) {
    throw 'The retained provider database contains too few provider rows for acceptance.'
}
if (-not (Test-Path -LiteralPath $providerDb -PathType Leaf)) {
    throw 'The provider capture reported success without publishing its database.'
}
$databaseFiles = @(Get-ChildItem -LiteralPath $databaseRoot -Filter '*.db' -File -Force)
if ($databaseFiles.Count -ne 1 -or $databaseFiles[0].FullName -ne $providerDb) {
    throw 'The retained provider database must be isolated in a directory containing exactly one .db file.'
}

$tests = @(
    'event_log::provider_db::real_database_tests::opens_a_real_database_and_reports_its_size',
    'event_log::provider_db::real_database_tests::renders_a_real_mdm_description_end_to_end',
    'event_log::provider_db::real_database_tests::every_payload_in_a_sample_of_providers_inflates',
    'event_log::parser::description_tests::an_unknown_event_id_falls_back_rather_than_inventing_a_description',
    'event_log::parser::description_tests::a_loaded_database_renders_a_real_provider_description',
    'event_log::parser::description_tests::an_event_the_database_does_not_cover_still_falls_back'
)
for ($testIndex = 0; $testIndex -lt $tests.Count; $testIndex++) {
    $test = $tests[$testIndex]
    $providerDbBinding = Get-CMTraceContentBinding -Path $providerDb -Label 'Retained private provider database'
    $testResult = Invoke-CMTracePrivateCargoProcess -Id ('retained-provider-test-{0:D2}' -f ($testIndex + 1)) -WorkingDirectory $resolvedRepository -Environment @{
        CMTRACEOPEN_PROVIDER_DB = $providerDb
    } -ContentBindings @($providerDbBinding) -ArgumentList @(
        'test', '--locked', '-p', 'cmtrace-open', '--all-features', '--target', $script:CMTraceRustTarget,
        '--lib', $test, '--', '--exact', '--ignored', '--nocapture', '--test-threads=1'
    )
    if ($testResult.ExitCode -ne 0) {
        throw "Retained provider database test failed: $test"
    }
}

$privateEvidence = [ordered]@{
    schemaVersion = 1
    sourceCommit = $script:CMTraceExpectedSourceCommit
    target = $script:CMTraceRustTarget
    databaseBytes = (Get-Item -LiteralPath $providerDb).Length
    databaseSha256 = Get-CMTraceSha256 -Path $providerDb
    providerCount = $providerCount
    captureSmokePassed = $true
    retainedDatabaseTestsPassed = $tests.Count
}
Write-CMTraceJson -Value $privateEvidence -Path (Join-Path $providerRoot 'provider-validation.json')
[void](Assert-CMTraceSourceIntegrity -RepositoryPath $resolvedRepository)

Write-Output 'PRIVATE_PROVIDER_VALIDATION_PASSED'
