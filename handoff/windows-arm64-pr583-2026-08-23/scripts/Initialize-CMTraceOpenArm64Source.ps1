[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DestinationPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'CMTraceOpenArm64Handoff.Common.ps1')

[void](Assert-CMTraceHandoffIntegrity)

$fullDestination = [IO.Path]::GetFullPath($DestinationPath)
if (Test-Path -LiteralPath $fullDestination) {
    throw "Destination already exists and will not be changed: $fullDestination"
}

Assert-CMTraceWindows11Arm64
[void](Assert-CMTraceFixedLocalNtfsPath -Path $fullDestination -Label 'Destination' -ForbiddenRoots @((Get-CMTraceHandoffRoot)) -MustNotExist)
$inputRoot = Join-Path ([IO.Path]::GetPathRoot($fullDestination)) 'cmtraceopen-input'
[void](Assert-CMTraceSafeTemporaryRoot -ForbiddenRoots @($fullDestination, $inputRoot, (Get-CMTraceHandoffRoot)))
Assert-CMTraceNoSensitiveEnvironment
[void](Assert-CMTraceLivePullRequest)

$git = Get-Command git.exe -ErrorAction SilentlyContinue
if (-not $git) {
    throw 'git.exe is required. Run the prerequisite procedure in README.md first.'
}

$gitIsolation = Get-CMTraceGitIsolationContext -ForbiddenRoots @(
    $fullDestination, $inputRoot, (Get-CMTraceHandoffRoot)
)
$gitEnvironment = $gitIsolation.Environment

function Invoke-CMTraceInitializerGit {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,

        [Parameter(Mandatory = $true)]
        [string]$Operation,

        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 60
    )

    $gitConfigGuard = $null
    try {
        $gitConfigGuard = Open-CMTraceGitIsolationGuard -Context $gitIsolation `
            -ForbiddenRoots @($fullDestination, $inputRoot, (Get-CMTraceHandoffRoot))
        try {
            return Invoke-CMTraceOwnedProcessCapture -FilePath $git.Source -Arguments $Arguments `
                -WorkingDirectory $WorkingDirectory -Environment $gitEnvironment -TimeoutSeconds $TimeoutSeconds
        }
        catch {
            throw "$Operation did not complete safely: $($_.Exception.Message)"
        }
    }
    finally {
        if ($null -ne $gitConfigGuard) { $gitConfigGuard.Dispose() }
    }
}

$destinationParent = Split-Path -Parent $fullDestination
New-Item -ItemType Directory -Path $fullDestination -ErrorAction Stop | Out-Null
$clone = Invoke-CMTraceInitializerGit -Operation 'Git clone' -WorkingDirectory $destinationParent -TimeoutSeconds 300 -Arguments @(
    '-c', 'core.autocrlf=false', '-c', 'core.longpaths=true',
    'clone', '--quiet', '--depth', '1', '--single-branch', '--branch', $script:CMTraceExpectedSourceBranch,
    '--no-checkout', $script:CMTraceExpectedRemote, $fullDestination
)
if ($clone.ExitCode -ne 0) {
    throw "Git clone failed. The partial destination was preserved for inspection: $fullDestination"
}

# Configure line-ending and long-path behavior before the first checkout so a
# machine-level core.autocrlf setting cannot dirty the sealed source tree.
$configurationCommands = @(
    [pscustomobject]@{ Operation = 'Git core.autocrlf configuration'; Arguments = @('-C', $fullDestination, 'config', 'core.autocrlf', 'false'); Failure = 'Could not set core.autocrlf=false.' },
    [pscustomobject]@{ Operation = 'Git core.longpaths configuration'; Arguments = @('-C', $fullDestination, 'config', 'core.longpaths', 'true'); Failure = 'Could not set core.longpaths=true.' },
    [pscustomobject]@{ Operation = 'Git push URL disablement'; Arguments = @('-C', $fullDestination, 'remote', 'set-url', '--push', 'origin', 'DISABLED'); Failure = 'Could not disable the origin push URL.' }
)
foreach ($command in $configurationCommands) {
    $result = Invoke-CMTraceInitializerGit -Operation $command.Operation -WorkingDirectory $fullDestination -Arguments $command.Arguments
    if ($result.ExitCode -ne 0) {
        throw "$($command.Failure) The checkout was preserved for inspection: $fullDestination"
    }
}

$advertisedResult = Invoke-CMTraceInitializerGit -Operation 'Git branch-head readback' -WorkingDirectory $fullDestination -Arguments @(
    '-C', $fullDestination, 'ls-remote', '--exit-code', 'origin', "refs/heads/$script:CMTraceExpectedSourceBranch"
)
$advertisedPattern = '^([0-9a-f]{40})\s+refs/heads/' + [regex]::Escape($script:CMTraceExpectedSourceBranch) + '$'
$advertised = $advertisedResult.StdOut.Trim()
$advertisedMatch = [regex]::Match($advertised, $advertisedPattern)
if ($advertisedResult.ExitCode -ne 0 -or -not $advertisedMatch.Success) {
    throw "Could not resolve the advertised PR branch head. The checkout was preserved for inspection: $fullDestination"
}
$advertisedCommit = $advertisedMatch.Groups[1].Value
if ($advertisedCommit -cne $script:CMTraceExpectedSourceCommit) {
    throw "The PR branch moved to $advertisedCommit; this exact-SHA handoff is stale. The checkout was preserved for inspection."
}

try {
    $checkout = Invoke-CMTraceInitializerGit -Operation 'Exact-SHA checkout' -WorkingDirectory $fullDestination -TimeoutSeconds 300 -Arguments @(
        '-c', 'core.autocrlf=false', '-C', $fullDestination,
        'checkout', '--quiet', '--detach', $script:CMTraceExpectedSourceCommit
    )
}
catch {
    throw "Exact-SHA checkout did not complete safely. The complete shallow clone was preserved for inspection: $fullDestination. Details: $($_.Exception.Message)"
}
if ($checkout.ExitCode -ne 0) {
    throw "Exact-SHA checkout failed. The checkout was preserved for inspection: $fullDestination"
}

$allowedSigners = Join-Path (Get-CMTraceHandoffRoot) 'PUBLIC_ALLOWED_SIGNERS'
$signature = Invoke-CMTraceInitializerGit -Operation 'Exact source signature verification' -WorkingDirectory $fullDestination -Arguments @(
    '-C', $fullDestination, '-c', "gpg.ssh.allowedSignersFile=$allowedSigners",
    'verify-commit', $script:CMTraceExpectedSourceCommit
)
if ($signature.ExitCode -ne 0) {
    throw 'The exact source commit signature did not verify against PUBLIC_ALLOWED_SIGNERS.'
}

[void](Assert-CMTraceSourceIntegrity -RepositoryPath $fullDestination -RequireNoIgnoredFiles)
Write-Output "SOURCE_READY $script:CMTraceExpectedSourceCommit"
