[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('BuildTools', 'Community')]
    [string]$VisualStudioSku = 'BuildTools',

    [switch]$EnableVbScript,
    [switch]$InstallRepoDependencies,
    [switch]$SkipValidation,

    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot)
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

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isElevated) {
        throw 'Run this script from an elevated PowerShell session. The documented setup uses admin installs through winget and DISM.'
    }
}

function Refresh-SessionPath {
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $segments = @($machinePath, $userPath) | Where-Object { $_ }
    $env:Path = ($segments -join ';')

    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    if ((Test-Path $cargoBin) -and ($env:Path -notlike "*$cargoBin*")) {
        $env:Path = "$cargoBin;$env:Path"
    }
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

function Invoke-CheckedProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [string[]]$ArgumentList = @()
    )

    $displayArguments = if ($ArgumentList.Count -gt 0) { " $($ArgumentList -join ' ')" } else { '' }
    Write-Step "$FilePath$displayArguments"

    $escapedArguments = $ArgumentList | ForEach-Object {
        if ($_ -match '[\s"]') {
            '"{0}"' -f ($_.Replace('"', '\"'))
        }
        else {
            $_
        }
    }

    $process = Start-Process -FilePath $FilePath -ArgumentList ($escapedArguments -join ' ') -Wait -PassThru -NoNewWindow
    if ($process.ExitCode -ne 0) {
        throw ("Process failed with exit code {0}: {1}{2}" -f $process.ExitCode, $FilePath, $displayArguments)
    }
}

function Resolve-WingetPath {
    $command = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $command) {
        throw 'Could not find winget.exe. Install App Installer from Microsoft Store or repair the winget installation first.'
    }

    return $command.Source
}

function Invoke-NativeCommandCapture {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [string[]]$Arguments = @()
    )

    $displayArguments = if ($Arguments.Count -gt 0) { " $($Arguments -join ' ')" } else { '' }
    Write-Step "$Command$displayArguments"

    $output = & $Command @Arguments 2>&1
    $exitCode = $LASTEXITCODE

    return [pscustomobject]@{
        ExitCode = $exitCode
        Output   = @($output)
    }
}

# Cache of installed winget package IDs, populated once on first use.
$script:InstalledWingetPackages = $null

function Get-InstalledWingetPackages {
    if ($null -ne $script:InstalledWingetPackages) {
        return $script:InstalledWingetPackages
    }

    $wingetPath = Resolve-WingetPath
    Write-Step "$wingetPath list --source winget"

    $output = & $wingetPath list --source winget 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to enumerate installed winget packages (exit code $LASTEXITCODE)."
    }

    # Parse the tabular output: each installed package has its ID in the second column.
    # Lines that look like package rows contain at least two whitespace-separated tokens
    # where the second token contains a dot (e.g., "Git.Git").
    $ids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($line in $output) {
        $text = $line.ToString().Trim()
        if ($text -match '\S+\s+(\S+\.\S+)') {
            [void]$ids.Add($Matches[1])
        }
    }

    $script:InstalledWingetPackages = $ids
    return $ids
}

function Test-WingetPackageInstalled {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackageId
    )

    $installed = Get-InstalledWingetPackages
    return $installed.Contains($PackageId)
}

function Install-WingetPackage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackageId,

        [string[]]$AdditionalArguments = @()
    )

    $wingetPath = Resolve-WingetPath
    $arguments = @(
        'install',
        '--id', $PackageId,
        '--exact',
        '--source', 'winget',
        '--accept-source-agreements',
        '--accept-package-agreements'
    ) + $AdditionalArguments

    if (Test-WingetPackageInstalled -PackageId $PackageId) {
        Write-Step "Skipping $PackageId because it is already installed."
        Refresh-SessionPath
        return
    }

    if ($PSCmdlet.ShouldProcess($PackageId, 'Install package with winget')) {
        $displayArguments = $arguments -join ' '
        Write-Step "$wingetPath $displayArguments"

        & $wingetPath @arguments
        $ec = $LASTEXITCODE

        # 0                  = success
        # -1978335189 (0x8A150017) = APPINSTALLER_CLI_ERROR_NO_APPLICABLE_UPGRADE
        #   winget found the package already installed with no newer version available.
        # -1978335135 (0x8A150081) = APPINSTALLER_CLI_ERROR_PACKAGE_ALREADY_INSTALLED
        if ($ec -ne 0 -and $ec -ne -1978335189 -and $ec -ne -1978335135) {
            throw ("Command failed with exit code {0}: {1} {2}" -f $ec, $wingetPath, $displayArguments)
        }

        if ($ec -eq -1978335189 -or $ec -eq -1978335135) {
            Write-Step "Skipping $PackageId — already installed (detected by winget installer)."
        }

        # Invalidate the cache so subsequent checks see the newly installed package.
        $script:InstalledWingetPackages = $null
        Refresh-SessionPath
    }
}

function Resolve-VisualStudioInstallerPath {
    [string[]]$candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\setup.exe'),
        (Join-Path $env:ProgramFiles 'Microsoft Visual Studio\Installer\setup.exe')
    ) | Where-Object { $_ -and (Test-Path $_) }

    if ($null -ne $candidates -and $candidates.Count -gt 0) {
        return $candidates[0]
    }

    throw 'Could not find the Visual Studio Installer setup.exe.'
}

function Get-VisualStudioInstallationPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProductRequirement,

        [string[]]$Requires = @()
    )

    try {
        $vsWherePath = Resolve-VsWherePath
    }
    catch {
        # vswhere.exe not found means Visual Studio is not installed at all.
        return $null
    }
    $arguments = @('-latest', '-products', $ProductRequirement)

    foreach ($requirement in $Requires) {
        $arguments += @('-requires', $requirement)
    }

    $arguments += @('-property', 'installationPath')

    $installationPath = & $vsWherePath @arguments | Select-Object -First 1
    if ($null -ne $installationPath) {
        $trimmedInstallationPath = $installationPath.ToString().Trim()
        if ($trimmedInstallationPath) {
            return $trimmedInstallationPath
        }
    }

    return $null
}

function Get-VisualStudioInstallationsSummary {
    $vsWherePath = Resolve-VsWherePath
    $json = & $vsWherePath -products * -format json
    if (-not $json) {
        return @()
    }

    $instances = $json | ConvertFrom-Json
    return @($instances | ForEach-Object {
            '{0} [{1}] at {2}' -f $_.displayName, $_.installationVersion, $_.installationPath
        })
}

function Install-VisualStudioTools {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('BuildTools', 'Community')]
        [string]$Sku
    )

    $packageId = if ($Sku -eq 'Community') {
        'Microsoft.VisualStudio.2022.Community'
    }
    else {
        'Microsoft.VisualStudio.2022.BuildTools'
    }

    $productRequirement = if ($Sku -eq 'Community') {
        'Microsoft.VisualStudio.Product.Community'
    }
    else {
        'Microsoft.VisualStudio.Product.BuildTools'
    }

    $workload = 'Microsoft.VisualStudio.Workload.VCTools'
    $vcComponent = 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64'
    $sdk = 'Microsoft.VisualStudio.Component.Windows11SDK.26100'
    $override = "--passive --add $workload --add $vcComponent --add $sdk --includeRecommended"

    $compliantInstallPath = Get-VisualStudioInstallationPath -ProductRequirement $productRequirement -Requires @($vcComponent)
    if ($compliantInstallPath) {
        Write-Step "Skipping $packageId because the required C++ build tools are already installed at '$compliantInstallPath'."
        return
    }

    $existingInstallPath = Get-VisualStudioInstallationPath -ProductRequirement $productRequirement
    if ($existingInstallPath) {
        $installerPath = Resolve-VisualStudioInstallerPath
        Write-Step "Updating Visual Studio at '$existingInstallPath' to add the C++ workload and Windows SDK."
        Invoke-CheckedProcess -FilePath $installerPath -ArgumentList @(
            'modify',
            '--installPath', $existingInstallPath,
            '--add', $workload,
            '--add', $vcComponent,
            '--add', $sdk,
            '--includeRecommended',
            '--passive',
            '--norestart'
        )
        return
    }

    Install-WingetPackage -PackageId $packageId -AdditionalArguments @('--override', $override)

    # After winget install, the package may already have been registered without the
    # C++ workload (winget skips if the package ID is present). Re-check and modify
    # the installation to add the required components if they are still missing.
    $postInstallPath = Get-VisualStudioInstallationPath -ProductRequirement $productRequirement
    if ($postInstallPath) {
        $postCompliantPath = Get-VisualStudioInstallationPath -ProductRequirement $productRequirement -Requires @($vcComponent)
        if (-not $postCompliantPath) {
            $installerPath = Resolve-VisualStudioInstallerPath
            Write-Step "Adding the C++ workload and Windows SDK to the installation at '$postInstallPath'."
            Invoke-CheckedProcess -FilePath $installerPath -ArgumentList @(
                'modify',
                '--installPath', $postInstallPath,
                '--add', $workload,
                '--add', $vcComponent,
                '--add', $sdk,
                '--includeRecommended',
                '--passive',
                '--norestart'
            )
        }
    }
}

function Enable-VbScriptFeature {
    if ($PSCmdlet.ShouldProcess('Windows optional feature VBSCRIPT', 'Enable feature')) {
        Invoke-CheckedCommand -Command 'dism.exe' -Arguments @('/online', '/enable-feature', '/featurename:VBSCRIPT', '/all', '/norestart')
    }
}

function Resolve-VsWherePath {
    [string[]]$candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'),
        (Join-Path $env:ProgramFiles 'Microsoft Visual Studio\Installer\vswhere.exe')
    ) | Where-Object { $_ -and (Test-Path $_) }

    if ($null -ne $candidates -and $candidates.Count -gt 0) {
        return $candidates[0]
    }

    $command = Get-Command vswhere.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    throw 'Could not find vswhere.exe after Visual Studio installation.'
}

function Enable-VsDeveloperPowerShell {
    $vsWherePath = Resolve-VsWherePath
    $vsInstallPath = & $vsWherePath -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath

    if (-not $vsInstallPath) {
        $summary = Get-VisualStudioInstallationsSummary
        $details = if (@($summary).Count -gt 0) {
            [Environment]::NewLine + 'Detected Visual Studio instances:' + [Environment]::NewLine + (($summary | ForEach-Object { "- $_" }) -join [Environment]::NewLine)
        }
        else {
            ''
        }

        throw ('Could not find a Visual Studio installation with the C++ build tools workload.' + $details)
    }

    $devShellModule = Join-Path $vsInstallPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll'
    if (-not (Test-Path $devShellModule)) {
        throw "Could not find Microsoft.VisualStudio.DevShell.dll at '$devShellModule'."
    }

    Import-Module $devShellModule -Force
    Enter-VsDevShell -VsInstallPath $vsInstallPath -SkipAutomaticLocation | Out-Null

    return $vsInstallPath
}

function Assert-CommandAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandName,

        [string]$ErrorMessage = "Required command '$CommandName' was not found on PATH."
    )

    if (-not (Get-Command $CommandName -ErrorAction SilentlyContinue)) {
        throw $ErrorMessage
    }
}

function Invoke-ToolchainValidation {
    Write-Step 'Refreshing PATH and validating installed toolchain'
    Refresh-SessionPath

    Assert-CommandAvailable -CommandName 'git.exe'
    Assert-CommandAvailable -CommandName 'node.exe'
    Assert-CommandAvailable -CommandName 'npm.cmd'
    Assert-CommandAvailable -CommandName 'rustc.exe'
    Assert-CommandAvailable -CommandName 'cargo.exe'
    Assert-CommandAvailable -CommandName 'rustup.exe'

    Invoke-CheckedCommand -Command 'git.exe' -Arguments @('--version')
    Invoke-CheckedCommand -Command 'node.exe' -Arguments @('-v')
    Invoke-CheckedCommand -Command 'npm.cmd' -Arguments @('-v')
    Invoke-CheckedCommand -Command 'rustc.exe' -Arguments @('-V')
    Invoke-CheckedCommand -Command 'cargo.exe' -Arguments @('-V')
    Invoke-CheckedCommand -Command 'rustup.exe' -Arguments @('show', 'active-toolchain')

    $vsInstallPath = Enable-VsDeveloperPowerShell
    Write-Host "Using Visual Studio at $vsInstallPath" -ForegroundColor DarkGray

    Invoke-CheckedCommand -Command 'where.exe' -Arguments @('cl')
    Invoke-CheckedCommand -Command 'where.exe' -Arguments @('link')
}

function Install-RepoPackages {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    if (-not (Test-Path (Join-Path $Root 'package.json'))) {
        throw "Could not find package.json under '$Root'."
    }

    if (-not (Test-Path (Join-Path $Root 'package-lock.json'))) {
        throw "Could not find package-lock.json under '$Root'. This repo expects npm ci."
    }

    Push-Location $Root
    try {
        Invoke-CheckedCommand -Command 'npm.cmd' -Arguments @('ci')
    }
    finally {
        Pop-Location
    }
}

Assert-Elevated

Write-Step 'Installing Windows development prerequisites for CMTrace Open'

Install-WingetPackage -PackageId 'Git.Git'
Install-WingetPackage -PackageId 'OpenJS.NodeJS.LTS'
Install-VisualStudioTools -Sku $VisualStudioSku
Install-WingetPackage -PackageId 'Microsoft.EdgeWebView2Runtime'
Install-WingetPackage -PackageId 'Rustlang.Rustup'

if ($EnableVbScript) {
    Enable-VbScriptFeature
}

if (-not $SkipValidation) {
    Invoke-ToolchainValidation
}

if ($InstallRepoDependencies) {
    Install-RepoPackages -Root $RepoRoot
}

Write-Step 'Setup complete'
Write-Host 'Next steps:' -ForegroundColor Green
Write-Host '  1. Open a new terminal so any environment updates are picked up globally.' -ForegroundColor Green
Write-Host '  2. From the repo root, run npm run tauri dev for local development.' -ForegroundColor Green
Write-Host '  3. Use npm run app:build:release for a release build.' -ForegroundColor Green