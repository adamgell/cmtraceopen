[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RepositoryPath,

    [string]$OutputPath,

    [switch]$AllowIgnoredGeneratedFiles
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'CMTraceOpenArm64Handoff.Common.ps1')

[void](Assert-CMTraceHandoffIntegrity)
Assert-CMTraceWindows11Arm64
Assert-CMTraceNoSensitiveEnvironment

$resolvedRepository = (Resolve-Path -LiteralPath $RepositoryPath).Path
$allowIgnoredGeneratedFilesRequested = [bool]$AllowIgnoredGeneratedFiles
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    [void](Assert-CMTraceFixedLocalNtfsPath -Path $OutputPath -Label 'Preflight OutputPath' -ForbiddenRoots @($resolvedRepository, (Get-CMTraceHandoffRoot)) -MustNotExist)
}
$inputRoot = Join-Path ([IO.Path]::GetPathRoot($resolvedRepository)) 'cmtraceopen-input'
$preflightTemporaryForbiddenRoots = @($resolvedRepository, $inputRoot, (Get-CMTraceHandoffRoot))
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $preflightTemporaryForbiddenRoots += [IO.Path]::GetFullPath($OutputPath)
}
$checks = [System.Collections.Generic.List[object]]::new()
$literalReplacements = [ordered]@{}
foreach ($entry in @(
    [pscustomobject]@{ Value = $resolvedRepository; Replacement = '%REPOSITORY%' }
    [pscustomobject]@{ Value = $env:USERPROFILE; Replacement = '%USERPROFILE%' }
    [pscustomobject]@{ Value = $env:USERNAME; Replacement = '%USERNAME%' }
    [pscustomobject]@{ Value = $env:COMPUTERNAME; Replacement = '%COMPUTERNAME%' }
)) {
    if (-not [string]::IsNullOrWhiteSpace([string]$entry.Value)) {
        $literalReplacements[[string]$entry.Value] = $entry.Replacement
    }
}

function Add-PreflightCheck {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Check
    )

    try {
        $detail = & $Check
        $checks.Add([ordered]@{
            id = $Id
            status = 'passed'
            detail = ConvertTo-CMTraceSanitizedText -Text ([string]$detail) -LiteralReplacements $literalReplacements
        })
    }
    catch {
        $checks.Add([ordered]@{
            id = $Id
            status = 'failed'
            detail = ConvertTo-CMTraceSanitizedText -Text $_.Exception.Message -LiteralReplacements $literalReplacements
        })
    }
}

function Invoke-PreflightNative {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [string[]]$Arguments = @(),

        [AllowEmptyCollection()]
        [object[]]$ContentBindings = @()
    )

    $capture = Invoke-CMTraceOwnedProcessCapture -FilePath $Command -Arguments $Arguments `
        -WorkingDirectory $resolvedRepository -ContentBindings $ContentBindings
    if ($capture.ExitCode -ne 0) {
        throw "$Command failed with exit code $($capture.ExitCode)."
    }
    if (-not [string]::IsNullOrWhiteSpace($capture.StdErr)) {
        throw "$Command wrote to stderr despite exit code 0."
    }
    return ConvertTo-CMTraceNormalizedNativeOutput -Text $capture.StdOut
}

Add-PreflightCheck -Id 'windows-arm64' -Check {
    $osArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    $processArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
    $version = [Environment]::OSVersion.Version
    if ($osArchitecture -ne 'Arm64' -or $processArchitecture -ne 'Arm64' -or $version.Build -lt 22000) {
        throw "Expected Windows 11 Arm64/Arm64, found $osArchitecture/$processArchitecture build $($version.Build)."
    }
    return "Windows build $($version.Build); OS=$osArchitecture; process=$processArchitecture"
}

Add-PreflightCheck -Id 'powershell-version' -Check {
    $version = ConvertTo-CMTraceNormalizedToolVersion -Tool PowerShell -Text $PSVersionTable.PSVersion.ToString()
    return "PowerShell $version"
}

Add-PreflightCheck -Id 'native-lab-process' -Check {
    if ($env:PROCESSOR_ARCHITECTURE -ne 'ARM64') {
        throw "PROCESSOR_ARCHITECTURE must be ARM64, found '$env:PROCESSOR_ARCHITECTURE'."
    }
    if (-not [string]::IsNullOrWhiteSpace($env:WSL_INTEROP) -or -not [string]::IsNullOrWhiteSpace($env:WINEPREFIX)) {
        throw 'Validation must run directly on Windows, not WSL or Wine.'
    }
    return 'native Windows ARM64 lab process'
}

Add-PreflightCheck -Id 'temporary-root-boundary' -Check {
    $temporaryRoot = Assert-CMTraceSafeTemporaryRoot -ForbiddenRoots $preflightTemporaryForbiddenRoots
    return "fixed local disjoint temporary root: $temporaryRoot"
}

Add-PreflightCheck -Id 'no-signing-or-auth-material' -Check {
    # Assert-CMTraceNoSensitiveEnvironment rejects every NPM_CONFIG_* variable,
    # including a custom NPM_CONFIG_USERCONFIG path, before default files are read.
    Assert-CMTraceNoSensitiveEnvironment

    $nodePath = (Get-Command node.exe -CommandType Application -ErrorAction Stop).Source
    $nodeRoot = Split-Path -Parent $nodePath
    $npmCli = Join-Path $nodeRoot 'node_modules\npm\bin\npm-cli.js'
    if (-not (Test-Path -LiteralPath $npmCli -PathType Leaf)) {
        throw 'The native Node installation does not contain its bundled npm CLI.'
    }

    $preflightTemporaryRoot = Assert-CMTraceSafeTemporaryRoot -ForbiddenRoots $preflightTemporaryForbiddenRoots
    $emptyNpmUserConfig = Join-Path $preflightTemporaryRoot '.cmtraceopen-absent-user.npmrc'
    $emptyNpmGlobalConfig = Join-Path $preflightTemporaryRoot '.cmtraceopen-absent-global.npmrc'
    foreach ($emptyConfig in @($emptyNpmUserConfig, $emptyNpmGlobalConfig)) {
        if (Test-Path -LiteralPath $emptyConfig -PathType Any) {
            throw 'The reserved absent npm config probe path unexpectedly exists.'
        }
    }
    $prefixCapture = Invoke-CMTraceOwnedProcessCapture -FilePath $nodePath -WorkingDirectory $resolvedRepository -Arguments @(
        $npmCli,
        "--userconfig=$emptyNpmUserConfig",
        "--globalconfig=$emptyNpmGlobalConfig",
        '--location=global',
        '--update-notifier=false',
        'config', 'get', 'prefix'
    )
    $npmPrefix = $prefixCapture.StdOut.Trim()
    if ($prefixCapture.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($prefixCapture.StdErr) -or
        [string]::IsNullOrWhiteSpace($npmPrefix) -or $npmPrefix -match '[\r\n]' -or
        -not [IO.Path]::IsPathFullyQualified($npmPrefix)) {
        throw 'Could not resolve the isolated native npm global prefix safely.'
    }
    foreach ($emptyConfig in @($emptyNpmUserConfig, $emptyNpmGlobalConfig)) {
        if (Test-Path -LiteralPath $emptyConfig -PathType Any) {
            throw 'The npm prefix probe unexpectedly created a config file.'
        }
    }

    $npmConfigFiles = @(
        (Join-Path $resolvedRepository '.npmrc'),
        (Join-Path $env:USERPROFILE '.npmrc'),
        (Join-Path $env:APPDATA 'npm\etc\npmrc'),
        (Join-Path $env:ProgramData 'npm\etc\npmrc'),
        (Join-Path $nodeRoot 'etc\npmrc'),
        (Join-Path $npmPrefix 'etc\npmrc')
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
    if (@($npmConfigFiles).Count -gt 0) {
        throw 'Remove repository, user, and global npmrc files before validation.'
    }

    $cargoCredentialFiles = @(
        (Join-Path $env:USERPROFILE '.cargo\credentials'),
        (Join-Path $env:USERPROFILE '.cargo\credentials.toml')
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
    if (@($cargoCredentialFiles).Count -gt 0) {
        throw 'Remove Cargo credential files from the disposable lab account before validation.'
    }

    $cargoControlFiles = @(
        (Join-Path $env:USERPROFILE '.cargo\config'),
        (Join-Path $env:USERPROFILE '.cargo\config.toml')
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
    if (@($cargoControlFiles).Count -gt 0) {
        throw 'Remove user-level Cargo configuration from the disposable lab account before validation.'
    }

    $gitPath = (Get-Command git.exe -CommandType Application -ErrorAction Stop).Source
    $gitConfigCapture = Invoke-CMTraceOwnedProcessCapture -FilePath $gitPath -Arguments @('config', '--global', '--list', '--show-origin') -WorkingDirectory $resolvedRepository
    $missingGlobalGitConfig = Test-CMTraceMissingGlobalGitConfigResult -ExitCode $gitConfigCapture.ExitCode `
        -StdOut $gitConfigCapture.StdOut -StdErr $gitConfigCapture.StdErr
    $cleanGitConfigResult =
        ($gitConfigCapture.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($gitConfigCapture.StdErr)) -or
        $missingGlobalGitConfig
    if (-not $cleanGitConfigResult) {
        throw 'Could not inspect the global Git configuration.'
    }
    $gitConfigText = if ($missingGlobalGitConfig) { '' } else { $gitConfigCapture.StdOut }
    if ($gitConfigText -match '(?i)(credential\.|http\..*extraheader|url\..*insteadof|core\.sshcommand|gpg\.|user\.signingkey)') {
        throw 'Use a disposable lab account without global Git credential, URL-rewrite, SSH-command, or signing configuration.'
    }
    return 'no configured signing, proxy, SSH-agent, Git credential controls, repository/user/global npmrc, or user Cargo credential/configuration state detected'
}

Add-PreflightCheck -Id 'live-pr-coordinate' -Check {
    [void](Assert-CMTraceLivePullRequest)
    return 'PR 583 is open at the sealed head and base coordinate'
}

Add-PreflightCheck -Id 'local-ntfs-source' -Check {
    [void](Assert-CMTraceFixedLocalNtfsPath -Path $resolvedRepository -Label 'Source' -ForbiddenRoots @((Get-CMTraceHandoffRoot)))
    return 'fixed NTFS source volume'
}

Add-PreflightCheck -Id 'exact-source' -Check {
    if ($allowIgnoredGeneratedFilesRequested) {
        [void](Assert-CMTraceSourceIntegrity -RepositoryPath $resolvedRepository)
    }
    else {
        [void](Assert-CMTraceSourceIntegrity -RepositoryPath $resolvedRepository -RequireNoIgnoredFiles)
    }
    return $script:CMTraceExpectedSourceCommit
}

Add-PreflightCheck -Id 'git' -Check {
    $output = Invoke-PreflightNative -Command 'git.exe' -Arguments @('--version')
    return ConvertTo-CMTraceNormalizedToolVersion -Tool Git -Text $output
}

Add-PreflightCheck -Id 'node-arm64' -Check {
    $version = ConvertTo-CMTraceNormalizedToolVersion -Tool Node -Text (Invoke-PreflightNative -Command 'node.exe' -Arguments @('--version'))
    $architecture = Invoke-PreflightNative -Command 'node.exe' -Arguments @('-p', 'process.arch')
    if ($version -notmatch '^v22\.' -or $architecture -ne 'arm64') {
        throw "Node.js 22 ARM64 is required; found version=$version architecture=$architecture."
    }
    return "$version $architecture"
}

Add-PreflightCheck -Id 'npm' -Check {
    $nodePath = (Get-Command node.exe -ErrorAction Stop).Source
    $nodeRoot = Split-Path -Parent $nodePath
    $npmCli = Join-Path $nodeRoot 'node_modules\npm\bin\npm-cli.js'
    $npxCli = Join-Path $nodeRoot 'node_modules\npm\bin\npx-cli.js'
    foreach ($cli in @($npmCli, $npxCli)) {
        if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) {
            throw "Node's bundled npm CLI is missing: $cli"
        }
    }
    $output = Invoke-PreflightNative -Command $nodePath -Arguments @($npmCli, '--version')
    return ConvertTo-CMTraceNormalizedToolVersion -Tool Npm -Text $output
}

Add-PreflightCheck -Id 'rust-host' -Check {
    $output = Invoke-PreflightNative -Command 'rustc.exe' -Arguments @('-Vv')
    $version = ConvertTo-CMTraceNormalizedToolVersion -Tool Rust -Text $output
    $hostMatches = [regex]::Matches($output, '(?m)^host:\s*(?<host>\S+)\s*$', [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if ($hostMatches.Count -ne 1 -or $hostMatches[0].Groups['host'].Value -cne $script:CMTraceRustTarget) {
        throw 'Native ARM64 Rust host is required.'
    }
    return "$version; host=$script:CMTraceRustTarget"
}

Add-PreflightCheck -Id 'rust-targets' -Check {
    $targets = Invoke-PreflightNative -Command 'rustup.exe' -Arguments @('target', 'list', '--installed')
    foreach ($required in @($script:CMTraceRustTarget, 'wasm32-unknown-unknown')) {
        if (@($targets -split "`n") -notcontains $required) {
            throw "Missing Rust target $required."
        }
    }
    return "$script:CMTraceRustTarget, wasm32-unknown-unknown"
}

Add-PreflightCheck -Id 'rust-components' -Check {
    $rustupCapture = Invoke-CMTraceOwnedProcessCapture -FilePath 'rustup.exe' -Arguments @('--version') -WorkingDirectory $resolvedRepository
    $rustupVersion = ConvertTo-CMTraceNormalizedRustupVersionEvidence -ExitCode $rustupCapture.ExitCode `
        -StdOut $rustupCapture.StdOut -StdErr $rustupCapture.StdErr
    $components = Invoke-PreflightNative -Command 'rustup.exe' -Arguments @('component', 'list', '--installed')
    if ($components -notmatch '(?m)^clippy-' -or $components -notmatch '(?m)^rustfmt-') {
        throw 'The clippy and rustfmt Rust components are required.'
    }
    $toolchains = Invoke-PreflightNative -Command 'rustup.exe' -Arguments @('toolchain', 'list')
    if ($toolchains -notmatch '(?m)^1\.88(?:\.\d+)?-') {
        throw 'Rust 1.88 is required for the MSRV gate.'
    }
    $active = Invoke-PreflightNative -Command 'rustup.exe' -Arguments @('show', 'active-toolchain')
    if ($active -notmatch '^stable-aarch64-pc-windows-msvc\s+\(default\)$') {
        throw "The active default Rust toolchain must be stable-aarch64-pc-windows-msvc; found '$active'."
    }
    $msrv = Invoke-PreflightNative -Command 'rustup.exe' -Arguments @('run', '1.88', 'rustc', '-Vv')
    if ($msrv -notmatch '(?m)^host: aarch64-pc-windows-msvc$') {
        throw 'Rust 1.88 must be installed with the native ARM64 MSVC host.'
    }
    $msrvTargets = Invoke-PreflightNative -Command 'rustup.exe' -Arguments @('target', 'list', '--installed', '--toolchain', '1.88')
    if (@($msrvTargets -split "`n") -notcontains $script:CMTraceRustTarget) {
        throw 'Rust 1.88 is missing the aarch64-pc-windows-msvc target standard library.'
    }
    return "rustup $rustupVersion; stable native ARM64 default; clippy, rustfmt; Rust 1.88 native ARM64 target"
}

Add-PreflightCheck -Id 'cargo-security-tools' -Check {
    $deny = ConvertTo-CMTraceNormalizedToolVersion -Tool CargoDeny -Text (Invoke-PreflightNative -Command 'cargo-deny.exe' -Arguments @('--version'))
    $audit = ConvertTo-CMTraceNormalizedToolVersion -Tool CargoAudit -Text (Invoke-PreflightNative -Command 'cargo-audit.exe' -Arguments @('--version'))
    return "$deny; $audit"
}

Add-PreflightCheck -Id 'llvm' -Check {
    $llvmPath = Join-Path $env:ProgramFiles 'LLVM\bin'
    $clangPath = Join-Path $llvmPath 'clang.exe'
    if (-not (Test-Path -LiteralPath $clangPath -PathType Leaf)) {
        throw "The required LLVM clang.exe is missing from $llvmPath."
    }
    $output = Invoke-PreflightNative -Command $clangPath -Arguments @('--version')
    return ConvertTo-CMTraceNormalizedToolVersion -Tool Clang -Text $output
}

Add-PreflightCheck -Id 'visual-studio-arm64' -Check {
    $vswhereCandidates = @(@(
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'),
        (Join-Path $env:ProgramFiles 'Microsoft Visual Studio\Installer\vswhere.exe')
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) })
    if (@($vswhereCandidates).Count -eq 0) {
        throw 'vswhere.exe was not found.'
    }
    $arguments = @('-latest', '-products', '*', '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', 'Microsoft.VisualStudio.Component.VC.Tools.ARM64', 'Microsoft.VisualStudio.Component.Windows11SDK.26100')
    $installation = Invoke-PreflightNative -Command $vswhereCandidates[0] -Arguments @($arguments + @('-property', 'installationPath'))
    if ([string]::IsNullOrWhiteSpace($installation) -or $installation.Trim() -match '[\r\n]') {
        throw 'Visual Studio C++ x64/ARM64 tools and Windows 11 SDK 26100 are required.'
    }
    $versionOutput = Invoke-PreflightNative -Command $vswhereCandidates[0] -Arguments @($arguments + @('-property', 'installationVersion'))
    $version = ConvertTo-CMTraceNormalizedToolVersion -Tool VisualStudio -Text $versionOutput
    return "Visual Studio $version C++ ARM64 toolchain"
}

Add-PreflightCheck -Id 'windows-sdk-mt' -Check {
    $exactSourceCheck = @($checks | Where-Object { $_.id -ceq 'exact-source' })
    if ($exactSourceCheck.Count -ne 1 -or $exactSourceCheck[0].status -cne 'passed') {
        throw 'The exact-source check did not pass; the repository SDK resolver will not be executed.'
    }
    $resolver = Join-Path $resolvedRepository 'scripts/resolve-windows-sdk-mt.ps1'
    $mtPath = Invoke-PreflightNative -Command (Join-Path $PSHOME 'pwsh.exe') -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-File', $resolver)
    if (-not (Test-Path -LiteralPath $mtPath -PathType Leaf)) {
        throw 'Windows SDK mt.exe resolver did not return a file.'
    }
    $normalizedPath = ([IO.Path]::GetFullPath($mtPath)).Replace('/', '\')
    $pathMatch = [regex]::Match($normalizedPath, '(?i)\\Windows Kits\\10\\bin\\(?<version>[^\\]+)\\x64\\mt\.exe\z')
    if (-not $pathMatch.Success) {
        throw 'Windows SDK mt.exe was not resolved from the standard versioned x64 SDK directory.'
    }
    $version = ConvertTo-CMTraceNormalizedToolVersion -Tool WindowsSdk -Text $pathMatch.Groups['version'].Value
    return "Windows SDK $version manifest tool"
}

Add-PreflightCheck -Id 'webview2-runtime' -Check {
    $version = Get-CMTraceWebView2Version
    return "WebView2 $version"
}

Add-PreflightCheck -Id 'pester' -Check {
    $trustedPester = Get-CMTraceTrustedPesterModule
    $escapedManifest = $trustedPester.Path.Replace("'", "''")
    $command = "Import-Module -Name '$escapedManifest' -RequiredVersion '$($trustedPester.Version)' -Force -ErrorAction Stop; [Console]::Out.Write((Get-Module Pester).Version.ToString())"
    $output = Invoke-PreflightNative -Command (Join-Path $PSHOME 'pwsh.exe') `
        -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', $command) `
        -ContentBindings $trustedPester.ContentBindings
    $version = ConvertTo-CMTraceNormalizedToolVersion -Tool Pester -Text $output
    if ($version -cne $trustedPester.Version) { throw 'Imported Pester version differs from its pinned PSGallery binding.' }
    return "Pester $version from canonical PSGallery"
}

Add-PreflightCheck -Id 'owned-process-regression' -Check {
    $testPath = Join-Path (Get-CMTraceHandoffRoot) 'tests\Handoff.Tests.ps1'
    $escapedTestPath = $testPath.Replace("'", "''")
    $trustedPester = Get-CMTraceTrustedPesterModule
    $testEntry = Get-Item -LiteralPath $testPath -Force
    $testBinding = [pscustomobject][ordered]@{
        Path = $testEntry.FullName
        Sha256 = Get-CMTraceSha256 -Path $testEntry.FullName
        Bytes = [int64]$testEntry.Length
        Label = 'Sealed owned-process regression tests'
    }
    $pesterContentBindings = [object[]](@($trustedPester.ContentBindings) + @($testBinding))
    $escapedPesterManifest = $trustedPester.Path.Replace("'", "''")
    $command = @"
`$ErrorActionPreference = 'Stop'
Import-Module -Name '$escapedPesterManifest' -RequiredVersion '$($trustedPester.Version)' -Force -ErrorAction Stop
`$configuration = New-PesterConfiguration
`$configuration.Run.Path = '$escapedTestPath'
`$configuration.Run.PassThru = `$true
`$configuration.Filter.FullName = @(
    '*returns the reserved wrapper failure exit for a target-start failure*',
    '*captures native child stdout*',
    '*captures native child stderr*',
    '*drains simultaneous native child stdout and stderr without deadlock*',
    '*propagates a nonzero native child exit after draining both streams*',
    '*enforces the aggregate capture limit across forwarded child streams*',
    '*terminates a timed-out native child and its descendant*',
    '*runs native ARM64 Git with the controlled isolated configuration*',
    '*drains and classifies documented private-helper target-start failure*',
    '*drains and classifies private provider Cargo target-start failure*',
    '*terminates an inherited-stdio descendant after its root process exits*',
    '*delivers bounded standard input to an owned native child*',
    '*holds a guarded launch file against replacement until target-start release*',
    '*holds verified content bindings until the consuming child exits*'
)
`$configuration.Output.Verbosity = 'None'
`$result = Invoke-Pester -Configuration `$configuration
`$summary = [ordered]@{
    selected = [int](`$result.PassedCount + `$result.FailedCount + `$result.SkippedCount)
    passed = [int]`$result.PassedCount
    failed = [int]`$result.FailedCount
    skipped = [int]`$result.SkippedCount
}
[Console]::Out.Write((`$summary | ConvertTo-Json -Compress))
if (`$summary.selected -ne 14 -or `$summary.passed -ne 14 -or `$summary.failed -ne 0 -or `$summary.skipped -ne 0) { exit 1 }
"@
    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $capture = Invoke-CMTraceOwnedProcessCapture -FilePath (Join-Path $PSHOME 'pwsh.exe') `
        -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedCommand) `
        -WorkingDirectory $resolvedRepository -ContentBindings $pesterContentBindings -TimeoutSeconds 120
    if ($capture.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($capture.StdErr)) {
        throw 'The focused owned-process lifecycle regression did not pass.'
    }
    try {
        $result = $capture.StdOut.Trim() | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw 'The focused owned-process lifecycle regression returned malformed bounded output.'
    }
    $propertyNames = @($result.PSObject.Properties.Name | Sort-Object)
    if (Compare-Object -SyncWindow 0 -ReferenceObject @('failed', 'passed', 'selected', 'skipped') -DifferenceObject $propertyNames) {
        throw 'The focused owned-process lifecycle regression returned an unexpected result contract.'
    }
    foreach ($name in @('failed', 'passed', 'selected', 'skipped')) {
        if ($result.$name -isnot [int32] -and $result.$name -isnot [int64]) {
            throw 'The focused owned-process lifecycle regression returned a non-integer count.'
        }
    }
    if ($result.selected -ne 14 -or $result.passed -ne 14 -or $result.failed -ne 0 -or $result.skipped -ne 0) {
        throw 'The focused owned-process lifecycle regression must report exactly fourteen passed tests and no failures or skips.'
    }
    return 'owned process lifecycle regression: 14 passed, 0 failed, 0 skipped'
}

$failed = @($checks | Where-Object { $_.status -eq 'failed' })
$report = [ordered]@{
    schemaVersion = 1
    handoffId = $script:CMTraceHandoffId
    sourceCommit = $script:CMTraceExpectedSourceCommit
    target = $script:CMTraceRustTarget
    checkedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    status = if ($failed.Count -eq 0) { 'passed' } else { 'failed' }
    checks = @($checks)
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    Write-CMTraceNewJson -Value $report -Path $OutputPath
}

if ($failed.Count -gt 0) {
    $ids = ($failed.id -join ', ')
    throw "ARM64 preflight failed: $ids. See README.md prerequisite instructions and the preflight JSON for bounded details."
}

Write-Output 'PREFLIGHT_OK'
