[CmdletBinding()]
param(
    [string]$StatePath = (Join-Path $env:ProgramData 'CmtraceOpen\State\collection-bootstrap.json'),
    [string]$TaskName = 'CmtraceOpen-EvidenceCollection-Once',
    [int]$ThrottleHours = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-DetectionResult {
    param(
        [Parameter(Mandatory = $true)]
        [int]$ExitCode,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Output $Message
    exit $ExitCode
}

function Get-ForwardedArgumentList {
    $argumentList = New-Object System.Collections.Generic.List[string]

    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        $argumentList.Add('-{0}' -f $entry.Key)
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

    $sysNativePowerShell = Join-Path $env:WINDIR 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $sysNativePowerShell -PathType Leaf)) {
        return
    }

    # Re-enter through 64-bit PowerShell so Task Scheduler and ProgramData access stay in the expected view.
    & $sysNativePowerShell -NoLogo -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @(Get-ForwardedArgumentList)
    exit $LASTEXITCODE
}

function Remove-ThrottleStateFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return
    }

    try {
        Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
    }
    catch {
    }
}

function ConvertFrom-JsonCompat {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content,
        [Parameter()]
        [int]$Depth = 10
    )

    $command = Get-Command -Name ConvertFrom-Json -ErrorAction Stop
    if ($command.Parameters.ContainsKey('Depth')) {
        return ($Content | ConvertFrom-Json -Depth $Depth -ErrorAction Stop)
    }

    return ($Content | ConvertFrom-Json -ErrorAction Stop)
}

function Read-ThrottleState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $content = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($content)) {
            return $null
        }

        return (ConvertFrom-JsonCompat -Content $content -Depth 10)
    }
    catch {
        return $null
    }
}

function Get-RegisteredUtc {
    param(
        [Parameter(Mandatory = $true)]
        [object]$State
    )

    $registeredText = [string]$State.registeredUtc
    if ([string]::IsNullOrWhiteSpace($registeredText)) {
        return $null
    }

    $registeredUtc = [datetime]::MinValue
    $dateStyles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [datetime]::TryParse($registeredText, [System.Globalization.CultureInfo]::InvariantCulture, $dateStyles, [ref]$registeredUtc)) {
        return $null
    }

    return $registeredUtc.ToUniversalTime()
}

function Resolve-TaskName {
    param(
        [Parameter(Mandatory = $true)]
        [object]$State,
        [Parameter(Mandatory = $true)]
        [string]$DefaultTaskName
    )

    $stateTaskName = [string]$State.taskName
    if ([string]::IsNullOrWhiteSpace($stateTaskName)) {
        return $DefaultTaskName
    }

    return $stateTaskName
}

function Get-Task {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
}

Invoke-In64BitPowerShell

if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
    Write-DetectionResult -ExitCode 1 -Message 'no-state'
}

$state = Read-ThrottleState -Path $StatePath
if ($null -eq $state) {
    Remove-ThrottleStateFile -Path $StatePath
    Write-DetectionResult -ExitCode 1 -Message 'invalid-state'
}

$registeredUtc = Get-RegisteredUtc -State $state
if ($null -eq $registeredUtc) {
    Remove-ThrottleStateFile -Path $StatePath
    Write-DetectionResult -ExitCode 1 -Message 'invalid-state'
}

$expiresUtc = $registeredUtc.AddHours($ThrottleHours)
if ($expiresUtc -le (Get-Date).ToUniversalTime()) {
    Remove-ThrottleStateFile -Path $StatePath
    Write-DetectionResult -ExitCode 1 -Message 'expired-state'
}

$resolvedTaskName = Resolve-TaskName -State $state -DefaultTaskName $TaskName
if (-not (Get-Task -Name $resolvedTaskName)) {
    Remove-ThrottleStateFile -Path $StatePath
    Write-DetectionResult -ExitCode 1 -Message 'missing-task'
}

Write-DetectionResult -ExitCode 0 -Message 'throttled'