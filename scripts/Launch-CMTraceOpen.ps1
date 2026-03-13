[CmdletBinding()]
param(
    [ValidateSet('Dev', 'Build', 'BuildAndRun')]
    [string]$Mode = 'Dev',
    [switch]$InstallDependencies
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Resolve-VsWherePath {
    $candidates = @((
            (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'),
            (Join-Path $env:ProgramFiles 'Microsoft Visual Studio\Installer\vswhere.exe')
        ) | Where-Object { $_ -and (Test-Path $_) })

    if ($candidates.Count -gt 0) {
        return $candidates[0]
    }

    $vsWhereCommand = Get-Command vswhere.exe -ErrorAction SilentlyContinue
    if ($vsWhereCommand) {
        return $vsWhereCommand.Source
    }

    throw 'Could not find vswhere.exe. Install Visual Studio Installer or add vswhere.exe to PATH.'
}

function Enable-VsDeveloperPowerShell {
    $vsWherePath = Resolve-VsWherePath
    $vsInstallPath = & $vsWherePath -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath

    if (-not $vsInstallPath) {
        throw 'Could not find a Visual Studio installation with the C++ build tools workload.'
    }

    $devShellModule = Join-Path $vsInstallPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll'
    if (-not (Test-Path $devShellModule)) {
        throw "Could not find Microsoft.VisualStudio.DevShell.dll at '$devShellModule'."
    }

    Import-Module $devShellModule
    Enter-VsDevShell -VsInstallPath $vsInstallPath -SkipAutomaticLocation | Out-Null

    return $vsInstallPath
}

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,
        [string[]]$Arguments = @()
    )

    $displayArguments = if ($Arguments.Count -gt 0) { " $($Arguments -join ' ')" } else { '' }
    Write-Step "$Command$displayArguments"

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw ("Command failed with exit code {0}: {1}{2}" -f $LASTEXITCODE, $Command, $displayArguments)
    }
}

function Get-ModeConfiguration {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Dev', 'Build', 'BuildAndRun')]
        [string]$Mode
    )

    switch ($Mode) {
        'Dev' {
            return @{
                NpmScript             = 'app:dev'
                RequiresBuiltArtifact = $false
            }
        }
        'Build' {
            return @{
                NpmScript             = 'app:build:release'
                RequiresBuiltArtifact = $false
            }
        }
        'BuildAndRun' {
            return @{
                NpmScript             = 'app:build:release'
                RequiresBuiltArtifact = $true
            }
        }
    }
}

function Resolve-BuiltArtifactPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppRoot
    )

    $releaseDirectory = Join-Path $AppRoot 'src-tauri\target\release'
    if (-not (Test-Path $releaseDirectory)) {
        throw "Release directory was not found at '$releaseDirectory'."
    }

    $candidate = Get-ChildItem -Path $releaseDirectory -Filter '*.exe' -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

    if (-not $candidate) {
        throw "No built executable was found in '$releaseDirectory'."
    }

    return $candidate.FullName
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$appRoot = Split-Path -Parent $scriptRoot
$nodeModulesPath = Join-Path $appRoot 'node_modules'

Write-Step 'Entering Visual Studio Developer PowerShell'
$vsInstallPath = Enable-VsDeveloperPowerShell
Write-Host "Using Visual Studio at $vsInstallPath" -ForegroundColor DarkGray

Set-Location $appRoot

if ($InstallDependencies -or -not (Test-Path $nodeModulesPath)) {
    Invoke-CheckedCommand -Command 'npm.cmd' -Arguments @('install')
}
else {
    Write-Step 'Skipping npm install because node_modules already exists. Use -InstallDependencies to force reinstall.'
}

$modeConfiguration = Get-ModeConfiguration -Mode $Mode
Invoke-CheckedCommand -Command 'npm.cmd' -Arguments @('run', $modeConfiguration.NpmScript)

if ($modeConfiguration.RequiresBuiltArtifact) {
    $builtExecutable = Resolve-BuiltArtifactPath -AppRoot $appRoot
    Write-Step "Launching built app from '$builtExecutable'"
    Start-Process -FilePath $builtExecutable
}
