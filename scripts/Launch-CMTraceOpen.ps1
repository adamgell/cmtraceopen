[CmdletBinding()]
param(
    [ValidateSet('Dev', 'Build', 'BuildExeOnly', 'BuildAndRun', 'FullRebuildDev')]
    [string]$Mode = 'Dev',
    [switch]$InstallDependencies,
    [switch]$EnablePatternAnalysis,
    [string]$OpenPath
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

function Add-PathEntryIfExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathEntry
    )

    if (-not (Test-Path $PathEntry)) {
        return
    }

    $pathSegments = @($env:Path -split ';') | Where-Object { $_ }
    if ($pathSegments -contains $PathEntry) {
        return
    }

    $env:Path = "$PathEntry;$env:Path"
}

function Add-RustToolchainToPath {
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    Add-PathEntryIfExists -PathEntry $cargoBin
}

function Assert-CommandAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandName,

        [Parameter(Mandatory = $true)]
        [string]$ErrorMessage
    )

    if (-not (Get-Command $CommandName -ErrorAction SilentlyContinue)) {
        throw $ErrorMessage
    }
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
        [ValidateSet('Dev', 'Build', 'BuildExeOnly', 'BuildAndRun', 'FullRebuildDev')]
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
        'BuildExeOnly' {
            return @{
                NpmScript             = 'app:build:exe-only'
                RequiresBuiltArtifact = $false
            }
        }
        'BuildAndRun' {
            return @{
                NpmScript             = 'app:build:release'
                RequiresBuiltArtifact = $false
                FullClean             = $false
            }
        }
        'FullRebuildDev' {
            return @{
                NpmScript             = 'app:dev'
                RequiresBuiltArtifact = $false
                FullClean             = $true
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

Write-Step 'Ensuring Rust toolchain is available on PATH'
Add-RustToolchainToPath

Write-Step 'Entering Visual Studio Developer PowerShell'
$vsInstallPath = Enable-VsDeveloperPowerShell
Write-Host "Using Visual Studio at $vsInstallPath" -ForegroundColor DarkGray

Add-RustToolchainToPath
Assert-CommandAvailable -CommandName 'cargo.exe' -ErrorMessage 'Could not find cargo.exe on PATH. Install Rust via rustup or run scripts/Install-CMTraceOpenBuildPrereqs.ps1, then open a new terminal and retry.'

Set-Location $appRoot

if ($InstallDependencies -or -not (Test-Path $nodeModulesPath)) {
    Invoke-CheckedCommand -Command 'npm.cmd' -Arguments @('install')
}
else {
    Write-Step 'Skipping npm install because node_modules already exists. Use -InstallDependencies to force reinstall.'
}

$modeConfiguration = Get-ModeConfiguration -Mode $Mode

if ($modeConfiguration.ContainsKey('FullClean') -and $modeConfiguration.FullClean) {
    Write-Step 'Cleaning Rust build artifacts (cargo clean)'
    Invoke-CheckedCommand -Command 'cargo.exe' -Arguments @('clean', '--manifest-path', (Join-Path $appRoot 'src-tauri\Cargo.toml'))

    $frontendDist = Join-Path $appRoot 'dist'
    if (Test-Path $frontendDist) {
        Write-Step 'Removing frontend dist folder'
        Remove-Item -Recurse -Force $frontendDist
    }

    Write-Step 'Reinstalling npm dependencies'
    Invoke-CheckedCommand -Command 'npm.cmd' -Arguments @('ci')
}

if ($EnablePatternAnalysis) {
    Write-Step 'Enabling Pattern Analysis workspace (clustering feature)'
    $tauriArgs = @()

    switch ($modeConfiguration.NpmScript) {
        'app:dev'           { $tauriArgs += 'dev' }
        'app:build:release' { $tauriArgs += @('build', '--release') }
        'app:build:exe-only'{ $tauriArgs += @('build', '--no-bundle') }
    }

    $tauriArgs += @('-f', 'clustering')

    if ($OpenPath) {
        $tauriArgs += @('--', $OpenPath)
    }

    Invoke-CheckedCommand -Command 'npx.cmd' -Arguments (@('tauri') + $tauriArgs)
}
else {
    $npmArguments = @('run', $modeConfiguration.NpmScript)
    if ($OpenPath) {
        $npmArguments += @('--', '--', $OpenPath)
    }

    Invoke-CheckedCommand -Command 'npm.cmd' -Arguments $npmArguments
}

if ($modeConfiguration.RequiresBuiltArtifact) {
    $builtExecutable = Resolve-BuiltArtifactPath -AppRoot $appRoot
    Write-Step "Launching built app from '$builtExecutable'"
    if ($OpenPath) {
        Start-Process -FilePath $builtExecutable -ArgumentList @($OpenPath)
    }
    else {
        Start-Process -FilePath $builtExecutable
    }
}
