Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CMTraceExpectedSourceCommit = '39ee0b4f6f2e42e5845c6d86f5f9b03fa06e0c84'
$script:CMTraceExpectedSourceTree = '251c7ccaea9e4195cde986b45971dd56d9e861d6'
$script:CMTraceExpectedCargoLockBlob = '9a7e7c287e695a975658a253eac9576cc491e033'
$script:CMTraceExpectedPackageLockBlob = '42eed8fc692efb0fdf3ebf2e2ed0d240d6c96f31'
$script:CMTraceExpectedSourceBranch = 'orchestration/event-viewer-epic'
$script:CMTraceExpectedBaseCommit = '59679c06b5dd1f5d59849a14d527f4b262b30a1c'
$script:CMTraceExpectedRemote = 'https://github.com/adamgell/cmtraceopen.git'
$script:CMTraceRustTarget = 'aarch64-pc-windows-msvc'
$script:CMTraceHandoffId = 'cmtraceopen-pr583-windows11-arm64-2026-08-23'
$script:CMTraceExpectedTemporaryRoot = 'C:\cmtraceopen-validation\temp'
$script:CMTraceOwnedProcessWrapperFailureExitCode = 253
$script:CMTraceExpectedPesterVersion = [version]'5.7.1'
$script:CMTraceExpectedPowerShellGallery = 'https://www.powershellgallery.com/api/v2'
$script:CMTraceExpectedPesterPackagePath = 'C:\cmtraceopen-validation\tools\Pester.5.7.1.nupkg'
$script:CMTraceExpectedPesterPackageBytes = 325233L
$script:CMTraceExpectedPesterPackageSha256 = '4a27904c6814a5fbe4758f8e49861f6a1994aee77b71165a5c43c0371ba6c580'
$script:CMTraceExpectedPesterModuleRoot = 'C:\cmtraceopen-validation\tools\PowerShell\Modules\Pester\5.7.1'
$script:CMTraceExpectedSignerLine = 'me@adamgell.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFD1r+PkL8s2wE9zQUf535TkDFVbMKnf+ItnZljMTu6Z'
$script:CMTraceAutomaticGateIds = @(
    'source-integrity',
    'npm-ci',
    'typescript',
    'frontend-build',
    'frontend-tests',
    'release-contract-tests',
    'npm-audit',
    'playwright-browser',
    'playwright-e2e',
    'installer-pester',
    'collector-pester',
    'cargo-fmt',
    'parser-tests',
    'parser-clippy',
    'parser-wasm-check',
    'esp-native',
    'esp-graph',
    'windows-full-build',
    'windows-full-tests',
    'windows-full-clippy',
    'windows-lite-tests',
    'windows-lite-clippy',
    'msrv',
    'cargo-deny',
    'cargo-audit',
    'arm64-full-build',
    'arm64-lite-build',
    'bundle-output-clean',
    'arm64-nsis-build',
    'bundle-output-verification',
    'windows-build-provenance',
    'arm64-pe-verification',
    'source-clean-after'
)
$script:CMTraceAutomaticGateContracts = [ordered]@{
    'source-integrity' = [ordered]@{ class = 'source'; dependsOn = @() }
    'npm-ci' = [ordered]@{ class = 'automated'; dependsOn = @('source-integrity') }
    'typescript' = [ordered]@{ class = 'automated'; dependsOn = @('npm-ci') }
    'frontend-build' = [ordered]@{ class = 'automated'; dependsOn = @('npm-ci') }
    'frontend-tests' = [ordered]@{ class = 'automated'; dependsOn = @('npm-ci') }
    'release-contract-tests' = [ordered]@{ class = 'automated'; dependsOn = @('npm-ci') }
    'npm-audit' = [ordered]@{ class = 'security'; dependsOn = @('npm-ci') }
    'playwright-browser' = [ordered]@{ class = 'automated'; dependsOn = @('npm-ci') }
    'playwright-e2e' = [ordered]@{ class = 'automated'; dependsOn = @('playwright-browser') }
    'installer-pester' = [ordered]@{ class = 'automated'; dependsOn = @('source-integrity') }
    'collector-pester' = [ordered]@{ class = 'automated'; dependsOn = @('source-integrity') }
    'cargo-fmt' = [ordered]@{ class = 'automated'; dependsOn = @('source-integrity') }
    'parser-tests' = [ordered]@{ class = 'automated'; dependsOn = @('source-integrity') }
    'parser-clippy' = [ordered]@{ class = 'automated'; dependsOn = @('source-integrity') }
    'parser-wasm-check' = [ordered]@{ class = 'automated'; dependsOn = @('source-integrity') }
    'esp-native' = [ordered]@{ class = 'automated'; dependsOn = @('source-integrity') }
    'esp-graph' = [ordered]@{ class = 'automated'; dependsOn = @('source-integrity') }
    'windows-full-build' = [ordered]@{ class = 'automated'; dependsOn = @('source-integrity') }
    'windows-full-tests' = [ordered]@{ class = 'automated'; dependsOn = @('windows-full-build') }
    'windows-full-clippy' = [ordered]@{ class = 'automated'; dependsOn = @('windows-full-build') }
    'windows-lite-tests' = [ordered]@{ class = 'automated'; dependsOn = @('source-integrity') }
    'windows-lite-clippy' = [ordered]@{ class = 'automated'; dependsOn = @('source-integrity') }
    'msrv' = [ordered]@{ class = 'automated'; dependsOn = @('source-integrity') }
    'cargo-deny' = [ordered]@{ class = 'security'; dependsOn = @('source-integrity') }
    'cargo-audit' = [ordered]@{ class = 'security'; dependsOn = @('source-integrity') }
    'arm64-full-build' = [ordered]@{ class = 'artifact'; dependsOn = @('npm-ci', 'windows-full-build') }
    'arm64-lite-build' = [ordered]@{ class = 'artifact'; dependsOn = @('npm-ci', 'windows-lite-tests') }
    'bundle-output-clean' = [ordered]@{ class = 'artifact'; dependsOn = @('arm64-lite-build') }
    'arm64-nsis-build' = [ordered]@{ class = 'artifact'; dependsOn = @('bundle-output-clean') }
    'bundle-output-verification' = [ordered]@{ class = 'artifact'; dependsOn = @('arm64-nsis-build') }
    'windows-build-provenance' = [ordered]@{ class = 'artifact'; dependsOn = @('bundle-output-verification') }
    'arm64-pe-verification' = [ordered]@{ class = 'artifact'; dependsOn = @('windows-build-provenance', 'arm64-full-build', 'arm64-lite-build') }
    'source-clean-after' = [ordered]@{ class = 'source'; dependsOn = @() }
}

function Get-CMTraceHandoffRoot {
    return Split-Path -Parent $PSScriptRoot
}

function Test-CMTraceOwnedProcessWrapperFailureExitCode {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$ExitCode
    )

    return $null -ne $ExitCode -and [int64]$ExitCode -eq $script:CMTraceOwnedProcessWrapperFailureExitCode
}

function ConvertTo-CMTraceNormalizedNativeOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    return $Text.Trim().Replace("`r`n", "`n")
}

function ConvertTo-CMTraceNormalizedRustupVersionEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [int]$ExitCode,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$StdOut,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$StdErr
    )

    if ($ExitCode -ne 0) {
        throw 'rustup --version failed.'
    }
    $version = ConvertTo-CMTraceNormalizedToolVersion -Tool Rustup -Text (
        ConvertTo-CMTraceNormalizedNativeOutput -Text $StdOut
    )
    $normalizedError = ConvertTo-CMTraceNormalizedNativeOutput -Text $StdErr
    $supportedError = '\Ainfo: This is the version for the rustup toolchain manager, not the rustc compiler\.\ninfo: [Tt]he currently active `rustc` version is `(?:rustc (?:0|[1-9]\d{0,5})(?:\.(?:0|[1-9]\d{0,5})){2}(?:-(?:nightly|beta)(?:\.\d+)?)? \([0-9a-f]{7,40} \d{4}-\d{2}-\d{2}\)|\((?:timeout|error) reading rustc version\)|\(rustc does not exist\))`\z'
    if ($normalizedError -cnotmatch $supportedError) {
        throw 'rustup --version did not return its exact supported informational stderr contract.'
    }
    return $version
}

function Assert-CMTracePathWithinRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd([char]'\', [char]'/')
    $rootPrefix = $fullRoot + [IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must be a child of the exact reserved root: $fullRoot"
    }
    return $fullPath
}

function Get-CMTraceHandoffManifest {
    $manifestPath = Join-Path (Get-CMTraceHandoffRoot) 'MANIFEST.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Handoff manifest is missing: $manifestPath"
    }

    return Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
}

function Get-CMTraceRelativePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return [IO.Path]::GetRelativePath($Root, $Path).Replace('\', '/')
}

function Get-CMTraceSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Read-CMTraceStrictUtf8Text {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [ValidateRange(1, 16777216)]
        [int]$MaximumBytes = 1048576
    )

    $entry = Get-Item -LiteralPath $Path -Force
    if (-not $entry.PSIsContainer -and ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
        if ($entry.Length -gt $MaximumBytes) {
            throw "Return text exceeds the $MaximumBytes-byte limit: $Path"
        }
    }
    else {
        throw "Return text must be a regular non-reparse file: $Path"
    }

    $bytes = [IO.File]::ReadAllBytes($entry.FullName)
    try {
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    }
    catch {
        throw "Return text is not strict UTF-8: $Path"
    }
    if ($text.IndexOf([char]0) -ge 0 -or $text -match '[\x01-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F\p{Cf}]') {
        throw "Return text contains binary or disallowed control bytes: $Path"
    }
    return $text
}

function Assert-CMTraceExactPropertySet {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string[]]$Names,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $actual = @($Value.PSObject.Properties.Name)
    $expected = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in $Names) {
        if (-not $expected.Add($name)) {
            throw "$Label contract contains a duplicate expected property."
        }
    }
    if ($actual.Count -ne $expected.Count -or @($actual | Where-Object { -not $expected.Contains($_) }).Count -ne 0) {
        throw "$Label has missing or unexpected properties."
    }
}

function Assert-CMTraceExactStringValue {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Expected,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if ($Value -isnot [string] -or -not [string]::Equals($Value, $Expected, [StringComparison]::Ordinal)) {
        throw "$Label does not match the sealed string value."
    }
}

function Assert-CMTraceStringInSet {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string[]]$Allowed,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $allowedSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($allowedValue in $Allowed) {
        [void]$allowedSet.Add($allowedValue)
    }
    if ($Value -isnot [string] -or -not $allowedSet.Contains([string]$Value)) {
        throw "$Label is not an allowed string value."
    }
}

function Test-CMTraceSensitiveEnvironmentName {
    param([Parameter(Mandatory = $true)][string]$Name)

    $exact = @(
        'ALL_PROXY', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY',
        'GIT_ASKPASS', 'SSH_ASKPASS', 'SSH_AUTH_SOCK', 'SSH_AGENT_PID',
        'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG_NOSYSTEM',
        'GIT_CONFIG_COUNT', 'GIT_CONFIG_PARAMETERS',
        'HOME', 'PREFIX',
        'NODE_OPTIONS', 'NODE_PATH', 'NODE_ENV', 'NODE_EXTRA_CA_CERTS',
        'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTFLAGS', 'RUSTDOCFLAGS',
        'RUSTUP_TOOLCHAIN', 'RUSTUP_DIST_SERVER', 'RUSTUP_UPDATE_ROOT',
        'RUSTC', 'RUSTDOC', 'RUSTUP_HOME', 'RUSTC_BOOTSTRAP',
        'CC', 'CXX', 'AR', 'RANLIB', 'LD', 'LINK', '_LINK_', 'LINKER', 'CL', '_CL_',
        'CFLAGS', 'CXXFLAGS', 'ARFLAGS', 'LDFLAGS', 'MAKEFLAGS', 'CMAKE', 'LIBCLANG_PATH',
        'CI', 'GITHUB_ACTIONS', 'TF_BUILD', 'PWDEBUG',
        'GITHUB_TOKEN', 'GH_TOKEN', 'NPM_TOKEN', 'NODE_AUTH_TOKEN',
        'TAURI_SIGNING_PRIVATE_KEY', 'TAURI_SIGNING_PRIVATE_KEY_PASSWORD',
        'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_TENANT_ID',
        'AZURE_STORAGE_CONNECTION_STRING', 'AZURE_CONFIG_DIR',
        'ARM_CLIENT_ID', 'ARM_CLIENT_SECRET', 'ARM_TENANT_ID',
        'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
        'AWS_SHARED_CREDENTIALS_FILE', 'AWS_CONFIG_FILE', 'AWS_PROFILE', 'AWS_DEFAULT_PROFILE', 'AWS_WEB_IDENTITY_TOKEN_FILE',
        'GOOGLE_APPLICATION_CREDENTIALS', 'CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE', 'CLOUDSDK_CONFIG',
        'DATABASE_URL', 'DOCKER_AUTH_CONFIG', 'DOCKER_CONFIG', 'KUBECONFIG',
        'PGPASSWORD', 'PGPASSFILE', 'MYSQL_PWD', 'POSTGRES_URL', 'REDIS_URL', 'MONGODB_URI',
        'PIP_INDEX_URL', 'PIP_EXTRA_INDEX_URL',
        'KRB5_CLIENT_KTNAME', 'KRB5CCNAME', 'OCI_CLI_KEY_FILE',
        'IDENTITY_ENDPOINT', 'IDENTITY_HEADER', 'MSI_ENDPOINT', 'MSI_SECRET',
        'SIGNING_ENDPOINT',
        'SIGNING_ACCOUNT_NAME', 'SIGNING_PROFILE_NAME'
    )
    if ($Name -in $exact) {
        return $true
    }
    return $Name -match '(?i)(?:_TOKEN|_SECRET|_PASSWORD|_PASSWD|_PRIVATE_KEY|_CREDENTIALS|_API_KEY|_PAT|_ACCESS_KEY|_ACCESS_TOKEN|_ACCESSTOKEN|_AUTH|_AUTHTOKEN|_AUTH_TOKEN)$' -or
        $Name -match '(?i)^(?:AWS|AZURE|ARM|GOOGLE|CLOUDSDK|DOCKER|VAULT|TF|TFE|DATABASE)(?:_|$)' -or
        $Name -match '(?i)^KUBE' -or
        $Name -match '(?i)^(?:SQL|SQLAZURE|MYSQL|POSTGRESQL|CUSTOM)CONNSTR_' -or
        $Name -match '(?i)(?:^|_)(?:CONNECTION_STRING|CONNECTIONSTRINGS?|CONNSTR|DSN)(?:_|$)' -or
        $Name -match '(?i)^CARGO_REGISTRIES_.+_TOKEN$' -or
        $Name -match '(?i)^GIT_' -or
        $Name -match '(?i)^NPM_CONFIG_' -or
        $Name -match '(?i)^CARGO_' -or
        $Name -match '(?i)^TAURI_' -or
        $Name -match '(?i)^PLAYWRIGHT_' -or
        $Name -match '(?i)^VITE_' -or
        $Name -match '(?i)^CMTRACE' -or
        $Name -match '(?i)^JAMF_' -or
        $Name -match '(?i)^BINDGEN_EXTRA_CLANG_ARGS(?:_|$)' -or
        $Name -match '(?i)^CMAKE_' -or
        $Name -match '(?i)^(?:(?:HOST|TARGET)_)?(?:CC|CXX|AR|RANLIB|CFLAGS|CXXFLAGS|ARFLAGS)(?:_.+)?$' -or
        $Name -match '(?i)^.+_(?:CC|CXX|AR|RANLIB|CFLAGS|CXXFLAGS|ARFLAGS)$' -or
        $Name -match '(?i)(?:^|_)(?:PROXY|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY)$'
}

function Test-CMTraceAllowedInheritedEnvironmentName {
    param([Parameter(Mandatory = $true)][string]$Name)

    $allowed = @(
        'ALLUSERSPROFILE', 'APPDATA', 'COMPUTERNAME', 'ComSpec', 'DriverData',
        'HOMEDRIVE', 'HOMEPATH', 'LOCALAPPDATA',
        'NUMBER_OF_PROCESSORS', 'OS', 'Path', 'PATHEXT',
        'PROCESSOR_ARCHITECTURE', 'PROCESSOR_IDENTIFIER', 'PROCESSOR_LEVEL', 'PROCESSOR_REVISION',
        'ProgramData', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramFiles(Arm)', 'ProgramW6432',
        'CommonProgramFiles', 'CommonProgramFiles(x86)', 'CommonProgramFiles(Arm)', 'CommonProgramW6432',
        'PSModulePath', 'PUBLIC', 'SystemDrive', 'SystemRoot', 'TEMP', 'TMP',
        'USERPROFILE', 'USERNAME', 'windir',
        'CommandPromptType', 'DevEnvDir', 'ExtensionSdkDir',
        'FrameworkDir', 'FrameworkDir32', 'FrameworkVersion', 'FrameworkVersion32',
        'INCLUDE', 'LIB', 'LIBPATH', 'NETFXSDKDir', 'UCRTVersion', 'UniversalCRTSdkDir',
        'VCINSTALLDIR', 'VCToolsInstallDir', 'VCToolsRedistDir', 'VCToolsVersion',
        'VisualStudioVersion', 'VSINSTALLDIR',
        'WindowsLibPath', 'WindowsSdkBinPath', 'WindowsSdkDir', 'WindowsSDKLibVersion', 'WindowsSDKVersion',
        '__VSCMD_PREINIT_PATH'
    )
    return $Name -iin $allowed
}

function Test-CMTraceAllowedSessionEnvironmentName {
    param([Parameter(Mandatory = $true)][string]$Name)

    return (Test-CMTraceAllowedInheritedEnvironmentName -Name $Name) -or $Name -iin @(
        'COMPUTERNAME', 'LOGONSERVER', 'SESSIONNAME',
        'USERDOMAIN', 'USERDNSDOMAIN', 'USERDOMAIN_ROAMINGPROFILE',
        'OneDrive', 'OneDriveCommercial', 'OneDriveConsumer',
        'WT_SESSION', 'WT_PROFILE_ID', 'TERM', 'COLORTERM', 'TERM_PROGRAM', 'TERM_PROGRAM_VERSION',
        'PROMPT', 'POWERSHELL_DISTRIBUTION_CHANNEL', 'PSExecutionPolicyPreference', '__PSLockDownPolicy'
    )
}

function Test-CMTraceAllowedChildEnvironmentOverrideName {
    param([Parameter(Mandatory = $true)][string]$Name)

    return $Name -iin @(
        'BUNDLE_ROOT', 'RELEASE_ROOT', 'TARGET_TRIPLE', 'SOURCE_COMMIT', 'GITHUB_SHA',
        'CMTRACEOPEN_PROVIDER_DB', 'CMTRACEOPEN_DISABLE_UPDATE_CHECKS', 'CMTRACE_EVTX_FIXTURE',
        'GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_GLOBAL', 'GIT_TERMINAL_PROMPT', 'GCM_INTERACTIVE',
        'GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0',
        'GIT_CONFIG_KEY_1', 'GIT_CONFIG_VALUE_1', 'GIT_CONFIG_KEY_2', 'GIT_CONFIG_VALUE_2',
        'GIT_ASKPASS', 'SSH_ASKPASS', 'GIT_NO_REPLACE_OBJECTS',
        'NPM_CONFIG_USERCONFIG', 'NPM_CONFIG_GLOBALCONFIG',
        'NPM_CONFIG_UPDATE_NOTIFIER', 'NPM_CONFIG_FUND'
    )
}

function Initialize-CMTraceChildEnvironment {
    param(
        [Parameter(Mandatory = $true)]
        [Diagnostics.ProcessStartInfo]$StartInfo,

        [System.Collections.IDictionary]$Environment = @{}
    )

    $inherited = [ordered]@{}
    foreach ($environmentName in @($StartInfo.Environment.Keys)) {
        $name = [string]$environmentName
        if (Test-CMTraceAllowedInheritedEnvironmentName -Name $name) {
            $inherited[$name] = [string]$StartInfo.Environment[$environmentName]
        }
    }

    $StartInfo.Environment.Clear()
    foreach ($entry in $inherited.GetEnumerator()) {
        $StartInfo.Environment[[string]$entry.Key] = [string]$entry.Value
    }
    foreach ($entry in $Environment.GetEnumerator()) {
        $name = [string]$entry.Key
        if (-not (Test-CMTraceAllowedChildEnvironmentOverrideName -Name $name)) {
            throw "Child environment override is not in the sealed allowlist: $name"
        }
        $StartInfo.Environment[$name] = [string]$entry.Value
    }
}

function Assert-CMTraceNoSensitiveEnvironment {
    $present = @([Environment]::GetEnvironmentVariables().Keys | ForEach-Object { [string]$_ } | Where-Object {
        -not (Test-CMTraceAllowedSessionEnvironmentName -Name $_)
    } | Sort-Object -Unique)
    if ($present.Count -gt 0) {
        throw "Remove every non-ordinary environment variable from the disposable lab session; rejected names: $($present -join ', ')."
    }
}

function Test-CMTraceMissingGlobalGitConfigResult {
    param(
        [Parameter(Mandatory = $true)]
        [int]$ExitCode,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$StdOut,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$StdErr
    )

    return $ExitCode -eq 128 -and [string]::IsNullOrWhiteSpace($StdOut) -and
        $StdErr -match "(?s)\Afatal: unable to read config file '[^\r\n]+': No such file or directory\r?\n?\z"
}

function Initialize-CMTraceOwnedProcessType {
    if ($null -ne ('CMTraceOpen.Validation.OwnedProcessJob' -as [type])) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace CMTraceOpen.Validation
{
    public sealed class OwnedProcessJob : IDisposable
    {
        private const uint JobObjectLimitKillOnJobClose = 0x00002000;
        private const int JobObjectExtendedLimitInformationClass = 9;
        private IntPtr handle;

        public OwnedProcessJob()
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException("Owned process jobs require Windows.");
            }

            handle = CreateJobObject(IntPtr.Zero, null);
            if (handle == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not create the validation process Job Object.");
            }

            var limits = new JobObjectExtendedLimitInformation();
            limits.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
            if (!SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformationClass,
                ref limits,
                (uint)Marshal.SizeOf<JobObjectExtendedLimitInformation>()))
            {
                int error = Marshal.GetLastWin32Error();
                CloseHandle(handle);
                handle = IntPtr.Zero;
                throw new Win32Exception(error, "Could not configure the validation process Job Object.");
            }
        }

        public void Assign(Process process)
        {
            if (process == null) throw new ArgumentNullException(nameof(process));
            IntPtr current = handle;
            if (current == IntPtr.Zero) throw new ObjectDisposedException(nameof(OwnedProcessJob));
            if (!AssignProcessToJobObject(current, process.Handle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not assign the validation process to its Job Object.");
            }
        }

        public void Terminate(int exitCode)
        {
            IntPtr current = handle;
            if (current == IntPtr.Zero) return;
            if (!TerminateJobObject(current, unchecked((uint)exitCode)))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not terminate the validation process Job Object.");
            }
        }

        public uint ActiveProcessCount
        {
            get
            {
                IntPtr current = handle;
                if (current == IntPtr.Zero) throw new ObjectDisposedException(nameof(OwnedProcessJob));
                JobObjectBasicAccountingInformation accounting;
                if (!QueryInformationJobObject(
                    current,
                    JobObjectBasicAccountingInformationClass,
                    out accounting,
                    (uint)Marshal.SizeOf<JobObjectBasicAccountingInformation>(),
                    IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not query the validation process Job Object.");
                }
                return accounting.ActiveProcesses;
            }
        }

        public int[] ActiveProcessIds
        {
            get
            {
                IntPtr current = handle;
                if (current == IntPtr.Zero) throw new ObjectDisposedException(nameof(OwnedProcessJob));
                int maximumCapacity = (int.MaxValue - 8) / IntPtr.Size;
                int capacity = 16;
                for (int attempt = 0; attempt < 8; attempt++)
                {
                    int bufferLength = checked(8 + (IntPtr.Size * capacity));
                    IntPtr buffer = Marshal.AllocHGlobal(bufferLength);
                    try
                    {
                        bool succeeded = QueryInformationJobObject(
                            current,
                            JobObjectBasicProcessIdListClass,
                            buffer,
                            (uint)bufferLength,
                            out _);
                        if (!succeeded)
                        {
                            int error = Marshal.GetLastWin32Error();
                            if (error != ErrorMoreData)
                            {
                                throw new Win32Exception(error, "Could not query validation Job process identifiers.");
                            }
                        }

                        // JOBOBJECT_BASIC_PROCESS_ID_LIST begins with two fixed DWORD
                        // counts, followed by pointer-sized ULONG_PTR IDs at byte 8.
                        uint assignedValue = unchecked((uint)Marshal.ReadInt32(buffer, 0));
                        uint listedValue = unchecked((uint)Marshal.ReadInt32(buffer, 4));
                        if (assignedValue > maximumCapacity || listedValue > maximumCapacity)
                        {
                            throw new InvalidOperationException("The validation Job returned more process identifiers than can be represented safely.");
                        }
                        int assigned = checked((int)assignedValue);
                        int listed = checked((int)listedValue);
                        if (listed > capacity || listed > assigned)
                        {
                            throw new InvalidOperationException("The validation Job returned an invalid process identifier list.");
                        }

                        if (succeeded && listed == assigned)
                        {
                            var processIds = new int[listed];
                            for (int index = 0; index < listed; index++)
                            {
                                int offset = checked(8 + (index * IntPtr.Size));
                                ulong value = IntPtr.Size == 8
                                    ? unchecked((ulong)Marshal.ReadInt64(buffer, offset))
                                    : unchecked((uint)Marshal.ReadInt32(buffer, offset));
                                if (value > int.MaxValue)
                                {
                                    throw new InvalidOperationException("The validation Job returned an unsupported process identifier.");
                                }
                                processIds[index] = (int)value;
                            }
                            return processIds;
                        }

                        int doubledCapacity = capacity <= maximumCapacity / 2
                            ? capacity * 2
                            : maximumCapacity;
                        int nextCapacity = Math.Max(doubledCapacity, assigned);
                        if (nextCapacity <= capacity || nextCapacity > maximumCapacity)
                        {
                            throw new InvalidOperationException("The complete validation Job process list is too large to capture safely.");
                        }
                        capacity = nextCapacity;
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(buffer);
                    }
                }
                throw new InvalidOperationException("Validation Job process membership changed too quickly to capture safely.");
            }
        }

        public void Dispose()
        {
            IntPtr current = Interlocked.Exchange(ref handle, IntPtr.Zero);
            if (current != IntPtr.Zero)
            {
                CloseHandle(current);
            }
            GC.SuppressFinalize(this);
        }

        ~OwnedProcessJob()
        {
            Dispose();
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IoCounters
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JobObjectBasicLimitInformation
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JobObjectBasicAccountingInformation
        {
            public long TotalUserTime;
            public long TotalKernelTime;
            public long ThisPeriodTotalUserTime;
            public long ThisPeriodTotalKernelTime;
            public uint TotalPageFaultCount;
            public uint TotalProcesses;
            public uint ActiveProcesses;
            public uint TotalTerminatedProcesses;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JobObjectExtendedLimitInformation
        {
            public JobObjectBasicLimitInformation BasicLimitInformation;
            public IoCounters IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr jobAttributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(
            IntPtr job,
            int informationClass,
            ref JobObjectExtendedLimitInformation information,
            uint informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

        private const int JobObjectBasicAccountingInformationClass = 1;
        private const int JobObjectBasicProcessIdListClass = 3;
        private const int ErrorMoreData = 234;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryInformationJobObject(
            IntPtr job,
            int informationClass,
            out JobObjectBasicAccountingInformation information,
            uint informationLength,
            IntPtr returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryInformationJobObject(
            IntPtr job,
            int informationClass,
            IntPtr information,
            uint informationLength,
            out uint returnLength);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);
    }

    public sealed class AggregateCaptureBudget
    {
        private readonly object sync = new object();
        private long remainingBytes;

        public AggregateCaptureBudget(long maximumBytes)
        {
            if (maximumBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maximumBytes));
            remainingBytes = maximumBytes;
        }

        public int Claim(int requested)
        {
            if (requested < 0) throw new ArgumentOutOfRangeException(nameof(requested));
            lock (sync)
            {
                int allowed = (int)Math.Min(remainingBytes, requested);
                remainingBytes -= allowed;
                return allowed;
            }
        }
    }

    public sealed class AggregateBoundedWriteStream : Stream
    {
        private readonly Stream inner;
        private readonly AggregateCaptureBudget budget;

        public AggregateBoundedWriteStream(Stream inner, AggregateCaptureBudget budget)
        {
            this.inner = inner ?? throw new ArgumentNullException(nameof(inner));
            this.budget = budget ?? throw new ArgumentNullException(nameof(budget));
        }

        private void RejectOverflow(int requested, int allowed)
        {
            if (allowed != requested) throw new IOException("Process output exceeded its aggregate capture limit.");
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            int allowed = budget.Claim(count);
            if (allowed > 0) inner.Write(buffer, offset, allowed);
            RejectOverflow(count, allowed);
        }

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            int allowed = budget.Claim(count);
            if (allowed > 0)
            {
                await inner.WriteAsync(buffer, offset, allowed, cancellationToken).ConfigureAwait(false);
            }
            RejectOverflow(count, allowed);
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int allowed = budget.Claim(buffer.Length);
            if (allowed > 0)
            {
                await inner.WriteAsync(buffer.Slice(0, allowed), cancellationToken).ConfigureAwait(false);
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

function Get-CMTraceOwnedProcessLaunch {
    param(
        [Parameter(Mandatory = $true)]
        [Diagnostics.ProcessStartInfo]$TargetStartInfo
    )

    Initialize-CMTraceOwnedProcessType
    $eventName = "Local\cmtraceopen-validation-ready-{0}" -f [guid]::NewGuid().ToString('N')
    $targetStartedEventName = "Local\cmtraceopen-validation-target-started-{0}" -f [guid]::NewGuid().ToString('N')
    $readyEvent = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::ManualReset, $eventName)
    $targetStartedEvent = $null
    try {
        $targetStartedEvent = [Threading.EventWaitHandle]::new(
            $false,
            [Threading.EventResetMode]::ManualReset,
            $targetStartedEventName
        )
        $configuration = [ordered]@{
            fileName = $TargetStartInfo.FileName
            workingDirectory = $TargetStartInfo.WorkingDirectory
            arguments = @($TargetStartInfo.ArgumentList)
            redirectStandardOutput = $TargetStartInfo.RedirectStandardOutput
            redirectStandardError = $TargetStartInfo.RedirectStandardError
            redirectStandardInput = $TargetStartInfo.RedirectStandardInput
        }
        $configurationBytes = [Text.Encoding]::UTF8.GetBytes(($configuration | ConvertTo-Json -Depth 4 -Compress))
        $configurationToken = [Convert]::ToBase64String($configurationBytes)
        # A real child exit 253 is conservatively reserved as untrustworthy infrastructure evidence.
        $wrapperFailureExitCode = $script:CMTraceOwnedProcessWrapperFailureExitCode
        $wrapperScript = @"
`$ErrorActionPreference = 'Stop'
`$readyEvent = `$null
`$targetStartedEvent = `$null
`$child = `$null
`$stdoutTask = `$null
`$stderrTask = `$null
`$stdinTask = `$null
try {
    `$readyEvent = [Threading.EventWaitHandle]::OpenExisting('$eventName')
    `$targetStartedEvent = [Threading.EventWaitHandle]::OpenExisting('$targetStartedEventName')
    if (-not `$readyEvent.WaitOne(30000)) {
        throw 'The validation process ownership handshake timed out.'
    }
    `$configurationJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$configurationToken'))
    `$configuration = `$configurationJson | ConvertFrom-Json
    `$startInfo = [Diagnostics.ProcessStartInfo]::new()
    `$startInfo.FileName = [string]`$configuration.fileName
    `$startInfo.WorkingDirectory = [string]`$configuration.workingDirectory
    `$startInfo.UseShellExecute = `$false
    `$startInfo.CreateNoWindow = `$true
    `$startInfo.RedirectStandardOutput = [bool]`$configuration.redirectStandardOutput
    `$startInfo.RedirectStandardError = [bool]`$configuration.redirectStandardError
    `$startInfo.RedirectStandardInput = [bool]`$configuration.redirectStandardInput
    foreach (`$argument in @(`$configuration.arguments)) {
        [void]`$startInfo.ArgumentList.Add([string]`$argument)
    }
    `$child = [Diagnostics.Process]::new()
    `$child.StartInfo = `$startInfo
    if (-not `$child.Start()) {
        throw 'The owned validation command could not start.'
    }
    if (`$startInfo.RedirectStandardOutput) {
        `$stdoutTask = `$child.StandardOutput.BaseStream.CopyToAsync([Console]::OpenStandardOutput())
    }
    if (`$startInfo.RedirectStandardError) {
        `$stderrTask = `$child.StandardError.BaseStream.CopyToAsync([Console]::OpenStandardError())
    }
    if (`$startInfo.RedirectStandardInput) {
        `$stdinTask = [Console]::OpenStandardInput().CopyToAsync(`$child.StandardInput.BaseStream)
    }
    [void]`$targetStartedEvent.Set()
    if (`$null -ne `$stdinTask) {
        try {
            [void]`$stdinTask.GetAwaiter().GetResult()
        }
        finally {
            `$child.StandardInput.Close()
        }
    }
    `$child.WaitForExit()
    foreach (`$outputTask in @(`$stdoutTask, `$stderrTask)) {
        if (`$null -ne `$outputTask) {
            [void]`$outputTask.GetAwaiter().GetResult()
        }
    }
    exit `$child.ExitCode
}
catch {
    [Console]::Error.WriteLine(`$_.Exception.ToString())
    exit $wrapperFailureExitCode
}
finally {
    if (`$null -ne `$child) { `$child.Dispose() }
    if (`$null -ne `$targetStartedEvent) { `$targetStartedEvent.Dispose() }
    if (`$null -ne `$readyEvent) { `$readyEvent.Dispose() }
}
"@
        $wrapperToken = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($wrapperScript))
        $pwsh = Join-Path $PSHOME 'pwsh.exe'
        if (-not (Test-Path -LiteralPath $pwsh -PathType Leaf)) {
            throw 'The current native PowerShell executable could not be resolved for the owned-process wrapper.'
        }
        $wrapperStartInfo = [Diagnostics.ProcessStartInfo]::new()
        $wrapperStartInfo.FileName = $pwsh
        $wrapperStartInfo.WorkingDirectory = $TargetStartInfo.WorkingDirectory
        $wrapperStartInfo.UseShellExecute = $false
        $wrapperStartInfo.CreateNoWindow = $true
        $wrapperStartInfo.RedirectStandardOutput = $true
        $wrapperStartInfo.RedirectStandardError = $true
        $wrapperStartInfo.RedirectStandardInput = $TargetStartInfo.RedirectStandardInput
        [void]$wrapperStartInfo.ArgumentList.Add('-NoLogo')
        [void]$wrapperStartInfo.ArgumentList.Add('-NoProfile')
        [void]$wrapperStartInfo.ArgumentList.Add('-NonInteractive')
        [void]$wrapperStartInfo.ArgumentList.Add('-EncodedCommand')
        [void]$wrapperStartInfo.ArgumentList.Add($wrapperToken)
        $wrapperStartInfo.Environment.Clear()
        foreach ($environmentName in $TargetStartInfo.Environment.Keys) {
            $wrapperStartInfo.Environment[[string]$environmentName] = [string]$TargetStartInfo.Environment[$environmentName]
        }
        return [pscustomobject]@{
            StartInfo = $wrapperStartInfo
            ReadyEvent = $readyEvent
            TargetStartedEvent = $targetStartedEvent
        }
    }
    catch {
        if ($null -ne $targetStartedEvent) {
            $targetStartedEvent.Dispose()
        }
        $readyEvent.Dispose()
        throw
    }
}

function Wait-CMTraceOwnedTargetStarted {
    param(
        [Parameter(Mandatory = $true)]
        [object]$OwnedLaunch,

        [Parameter(Mandatory = $true)]
        [Diagnostics.Process]$WrapperProcess,

        [ValidateRange(1, 30)]
        [int]$TimeoutSeconds = 30
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ($OwnedLaunch.TargetStartedEvent.WaitOne(25)) {
            return
        }
        if ($WrapperProcess.HasExited) {
            throw 'The owned-process wrapper exited before it confirmed that the requested target started.'
        }
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw "The owned-process wrapper did not confirm target start within $TimeoutSeconds seconds."
}

function Invoke-CMTraceOwnedProcessCapture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [string[]]$Arguments = @(),

        [string]$WorkingDirectory = (Get-Location).Path,

        [System.Collections.IDictionary]$Environment = @{},

        [AllowEmptyCollection()]
        [object[]]$ContentBindings = @(),

        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 30,

        [ValidateRange(1, 1048576)]
        [int]$MaximumCaptureBytes = 65536,

        [ValidateLength(1, 1048576)]
        [string]$StandardInputText
    )

    Initialize-CMTraceOwnedProcessType
    $resolvedCommand = if (Test-Path -LiteralPath $FilePath -PathType Leaf) {
        (Resolve-Path -LiteralPath $FilePath).Path
    }
    else {
        (Get-Command $FilePath -CommandType Application -ErrorAction Stop).Source
    }
    $resolvedWorkingDirectory = (Resolve-Path -LiteralPath $WorkingDirectory).Path
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $resolvedCommand
    $startInfo.WorkingDirectory = $resolvedWorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardInput = $PSBoundParameters.ContainsKey('StandardInputText')
    foreach ($argument in $Arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    Initialize-CMTraceChildEnvironment -StartInfo $startInfo -Environment $Environment

    $maximumCaptureBytes = [long]$MaximumCaptureBytes
    $process = $null
    $ownedJob = $null
    $ownedLaunch = $null
    $processStarted = $false
    $jobAssigned = $false
    $stdoutMemory = $null
    $stderrMemory = $null
    $stdoutStream = $null
    $stderrStream = $null
    $stdoutTask = $null
    $stderrTask = $null
    $stdoutBytes = [byte[]]::new(0)
    $stderrBytes = [byte[]]::new(0)
    $exitCode = $null
    $failureMessage = $null
    $targetStartFailure = $null
    $targetGuard = $null
    $contentGuards = [Collections.Generic.List[IO.FileStream]]::new()

    try {
        $targetGuard = Open-CMTraceGuardedReadFile -Path $resolvedCommand -Label 'Owned process target'
        $startInfo.FileName = $targetGuard.Path
        foreach ($binding in @($ContentBindings)) {
            if ($null -eq $binding -or
                @($binding.PSObject.Properties.Name | Where-Object { $_ -cin @('Path', 'Sha256', 'Bytes', 'Label') }).Count -ne 4 -or
                @($binding.PSObject.Properties.Name).Count -ne 4) {
                throw 'Each owned-process content binding must contain exactly Path, Sha256, Bytes, and Label.'
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
            throw 'The bounded owned process could not start.'
        }
        $processStarted = $true
        $ownedJob.Assign($process)
        $jobAssigned = $true

        $captureBudget = [CMTraceOpen.Validation.AggregateCaptureBudget]::new($maximumCaptureBytes)
        $stdoutMemory = [IO.MemoryStream]::new()
        $stderrMemory = [IO.MemoryStream]::new()
        $stdoutStream = [CMTraceOpen.Validation.AggregateBoundedWriteStream]::new($stdoutMemory, $captureBudget)
        $stderrStream = [CMTraceOpen.Validation.AggregateBoundedWriteStream]::new($stderrMemory, $captureBudget)
        $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdoutStream)
        $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderrStream)
        [void]$ownedLaunch.ReadyEvent.Set()
        try {
            Wait-CMTraceOwnedTargetStarted -OwnedLaunch $ownedLaunch -WrapperProcess $process
            $targetGuard.Stream.Dispose()
            $targetGuard = $null
        }
        catch {
            $targetStartFailure = $_.Exception.Message
        }
        if ([string]::IsNullOrWhiteSpace($targetStartFailure) -and $startInfo.RedirectStandardInput) {
            $inputTask = $process.StandardInput.WriteAsync($StandardInputText)
            if (-not $inputTask.Wait(5000)) {
                throw 'Owned process standard-input delivery exceeded five seconds.'
            }
            [void]$inputTask.GetAwaiter().GetResult()
            $process.StandardInput.Close()
        }

        $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
        $terminationRequested = $false
        $terminationDrainDeadline = [DateTimeOffset]::MaxValue
        if (-not [string]::IsNullOrWhiteSpace($targetStartFailure)) {
            $failureMessage = "Owned-process wrapper failed before a trustworthy native child result: $targetStartFailure"
            $terminationRequested = $true
            $terminationDrainDeadline = [DateTimeOffset]::UtcNow.AddSeconds(5)
            if ($ownedJob.ActiveProcessCount -gt 0 -or -not $process.HasExited) {
                $ownedJob.Terminate(1)
            }
        }
        while ($ownedJob.ActiveProcessCount -gt 0 -or -not $process.HasExited -or
            -not $stdoutTask.IsCompleted -or -not $stderrTask.IsCompleted) {
            $now = [DateTimeOffset]::UtcNow
            if (-not $terminationRequested -and ($stdoutTask.IsFaulted -or $stderrTask.IsFaulted)) {
                $failureMessage = "Owned process output exceeded the strict $maximumCaptureBytes-byte aggregate capture limit."
                $terminationRequested = $true
                $terminationDrainDeadline = $now.AddSeconds(5)
                $ownedJob.Terminate(1)
            }
            elseif (-not $terminationRequested -and $now -ge $deadline) {
                $failureMessage = "Owned process timed out after $TimeoutSeconds seconds."
                $terminationRequested = $true
                $terminationDrainDeadline = $now.AddSeconds(5)
                $ownedJob.Terminate(1)
            }
            if ($terminationRequested -and $now -ge $terminationDrainDeadline -and
                ($ownedJob.ActiveProcessCount -gt 0 -or -not $process.HasExited -or
                    -not $stdoutTask.IsCompleted -or -not $stderrTask.IsCompleted)) {
                $failureMessage = "$failureMessage Owned process termination or stream drain exceeded five seconds."
                break
            }
            Start-Sleep -Milliseconds 25
        }

        if ([string]::IsNullOrWhiteSpace($failureMessage)) {
            if ($ownedJob.ActiveProcessCount -ne 0 -or -not $process.HasExited -or
                -not $stdoutTask.IsCompleted -or -not $stderrTask.IsCompleted) {
                throw 'Owned process completion was observed before its Job and streams were empty.'
            }
            $exitCode = $process.ExitCode
        }
    }
    catch {
        if ([string]::IsNullOrWhiteSpace($failureMessage)) {
            $failureMessage = $_.Exception.Message
        }
    }
    finally {
        if ($processStarted -and -not $jobAssigned -and -not $process.HasExited) {
            try { $process.Kill($true) } catch { $failureMessage = "$failureMessage $($_.Exception.Message)" }
        }
        if ($null -ne $ownedJob) {
            $jobStillActive = $true
            try { $jobStillActive = $ownedJob.ActiveProcessCount -gt 0 } catch { $failureMessage = "$failureMessage $($_.Exception.Message)" }
            if ($processStarted -and ($jobStillActive -or -not $process.HasExited -or
                    ($null -ne $stdoutTask -and -not $stdoutTask.IsCompleted) -or
                    ($null -ne $stderrTask -and -not $stderrTask.IsCompleted))) {
                try { $ownedJob.Terminate(1) } catch { $failureMessage = "$failureMessage $($_.Exception.Message)" }
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
            try { $process.StandardOutput.BaseStream.Dispose() } catch { $failureMessage = "$failureMessage $($_.Exception.Message)" }
            try { $process.StandardError.BaseStream.Dispose() } catch { $failureMessage = "$failureMessage $($_.Exception.Message)" }
            try {
                if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$pendingCopyTasks, 5000)) {
                    $failureMessage = "$failureMessage Owned process stream shutdown exceeded five seconds."
                }
            }
            catch {
                $failureMessage = "$failureMessage $($_.Exception.Message)"
            }
        }
        foreach ($copyTask in @($stdoutTask, $stderrTask)) {
            if ($null -ne $copyTask -and $copyTask.IsCompleted) {
                try { [void]$copyTask.GetAwaiter().GetResult() } catch {
                    if ([string]::IsNullOrWhiteSpace($failureMessage)) {
                        $failureMessage = "Owned process output exceeded the strict $maximumCaptureBytes-byte aggregate capture limit."
                    }
                }
            }
        }
        if ($null -ne $stdoutMemory) { $stdoutBytes = $stdoutMemory.ToArray() }
        if ($null -ne $stderrMemory) { $stderrBytes = $stderrMemory.ToArray() }
        foreach ($captureStream in @($stdoutStream, $stderrStream)) {
            if ($null -ne $captureStream) { $captureStream.Dispose() }
        }
        if ($null -ne $process) { $process.Dispose() }
        if ($null -ne $targetGuard) { $targetGuard.Stream.Dispose() }
        foreach ($contentGuard in $contentGuards) { $contentGuard.Dispose() }
    }

    if (($stdoutBytes.Length + $stderrBytes.Length) -gt $maximumCaptureBytes) {
        $failureMessage = "Owned process output exceeded the strict $maximumCaptureBytes-byte aggregate capture limit."
    }
    if (Test-CMTraceOwnedProcessWrapperFailureExitCode -ExitCode $exitCode) {
        $wrapperFailure = "Owned-process wrapper returned reserved infrastructure exit code $script:CMTraceOwnedProcessWrapperFailureExitCode before a trustworthy native child result."
        $failureMessage = if ([string]::IsNullOrWhiteSpace($failureMessage)) { $wrapperFailure } else { "$failureMessage $wrapperFailure" }
        $exitCode = $null
    }
    if (-not [string]::IsNullOrWhiteSpace($failureMessage)) {
        throw $failureMessage.Trim()
    }
    $encoding = [Text.UTF8Encoding]::new($false, $false)
    return [pscustomobject][ordered]@{
        ExitCode = [int]$exitCode
        StdOut = $encoding.GetString($stdoutBytes)
        StdErr = $encoding.GetString($stderrBytes)
    }
}

function ConvertTo-CMTraceNormalizedToolVersion {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('PowerShell', 'Git', 'Node', 'Npm', 'Rust', 'Rustup', 'Pester', 'CargoDeny', 'CargoAudit', 'Clang', 'VisualStudio', 'WindowsSdk', 'WebView2')]
        [string]$Tool,

        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    $threePart = '(?:0|[1-9]\d{0,5})(?:\.(?:0|[1-9]\d{0,5})){2}'
    $fourPart = '(?:0|[1-9]\d{0,5})(?:\.(?:0|[1-9]\d{0,5})){3}'
    $trimmed = $Text.Trim()
    $pattern = switch ($Tool) {
        'PowerShell' { "\A(?<version>$threePart)\z" }
        'Git' { "\Agit version (?<version>(?<core>$threePart)\.windows\.(?:0|[1-9]\d{0,5}))\z" }
        'Node' { "\Av(?<version>$threePart)\z" }
        'Npm' { "\A(?<version>$threePart)\z" }
        'Rust' { "\Arustc (?<version>$threePart)(?: \([0-9a-f]{7,40} \d{4}-\d{2}-\d{2}\))?(?:\r?\n|\z)" }
        'Rustup' { "\Arustup (?<version>$threePart)(?: :: $threePart\+(?:0|[1-9]\d{0,5}))? \([0-9a-f]{7,40} \d{4}-\d{2}-\d{2}\)\z" }
        'Pester' { "\A(?<version>$threePart)\z" }
        'CargoDeny' { "\Acargo-deny (?<version>$threePart)\z" }
        'CargoAudit' { "\Acargo-audit (?<version>$threePart)\z" }
        'Clang' { "\Aclang version (?<version>$threePart)[^\r\n]*(?:\r?\n|\z)" }
        'VisualStudio' { "\A(?<version>$fourPart)\z" }
        'WindowsSdk' { "\A(?<version>$fourPart)\z" }
        'WebView2' { "\A(?<version>$fourPart)\z" }
    }
    $match = [regex]::Match($trimmed, $pattern, [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $match.Success) {
        throw "$Tool did not return one normalized supported version."
    }
    $version = $match.Groups['version'].Value
    $parsedVersion = if ($Tool -eq 'Git') { [version]$match.Groups['core'].Value } else { [version]$version }
    if ($parsedVersion.Major -eq 0 -and $parsedVersion.Minor -eq 0 -and
        $parsedVersion.Build -eq 0 -and $parsedVersion.Revision -le 0) {
        throw "$Tool returned an empty version token."
    }
    switch ($Tool) {
        'PowerShell' {
            if ($parsedVersion -lt [version]'7.5.0') { throw 'PowerShell 7.5 or later is required.' }
        }
        'Node' {
            if ($parsedVersion.Major -ne 22) { throw 'Node.js 22 is required.' }
        }
        'Rust' {
            if ($parsedVersion -lt [version]'1.88.0') { throw 'Rust 1.88 or later is required.' }
        }
        'Rustup' {
            if ($parsedVersion -lt [version]'1.28.1') { throw 'rustup 1.28.1 or later is required.' }
        }
        'Pester' {
            if ($parsedVersion -lt [version]'5.0.0') { throw 'Pester 5 or later is required.' }
        }
        'VisualStudio' {
            if ($parsedVersion.Major -ne 17) { throw 'Visual Studio 2022 is required.' }
        }
        'WindowsSdk' {
            if ($parsedVersion.Major -ne 10 -or $parsedVersion.Minor -ne 0 -or $parsedVersion.Build -lt 26100) {
                throw 'Windows SDK 10.0.26100 or later is required.'
            }
        }
    }
    if ($Tool -eq 'Git') { return $version }
    if ($Tool -eq 'Node') { return "v$version" }
    if ($Tool -eq 'Rust') { return "rustc $version" }
    return $version
}

function Get-CMTraceWebView2Version {
    $clientId = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    $keys = @(
        "HKCU:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$clientId",
        "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$clientId",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$clientId"
    )
    $versions = @($keys | Where-Object { Test-Path -LiteralPath $_ -PathType Container } | ForEach-Object {
        $value = Get-ItemPropertyValue -LiteralPath $_ -Name 'pv' -ErrorAction Stop
        ConvertTo-CMTraceNormalizedToolVersion -Tool WebView2 -Text ([string]$value)
    } | Sort-Object -Unique)
    if ($versions.Count -ne 1) {
        throw 'Microsoft Edge WebView2 Runtime must have one unambiguous installed version.'
    }
    return $versions[0]
}

function Assert-CMTraceLivePullRequest {
    $pullRequest = $null
    $lastReadError = $null
    foreach ($attempt in 1..3) {
        try {
            $pullRequest = Invoke-RestMethod -Method Get -Uri 'https://api.github.com/repos/adamgell/cmtraceopen/pulls/583' -TimeoutSec 30 -Headers @{
                Accept = 'application/vnd.github+json'
                'User-Agent' = 'cmtraceopen-arm64-validation-handoff'
                'X-GitHub-Api-Version' = '2022-11-28'
            }
            break
        }
        catch {
            $lastReadError = $_.Exception.Message
            if ($attempt -lt 3) {
                Start-Sleep -Seconds (2 * $attempt)
            }
        }
    }
    if ($null -eq $pullRequest) {
        throw "Could not read the public PR 583 coordinate from GitHub after three bounded attempts: $lastReadError"
    }

    if (($pullRequest.number -isnot [int32] -and $pullRequest.number -isnot [int64]) -or
        $pullRequest.number -ne 583 -or
        $pullRequest.merged -isnot [bool] -or $pullRequest.merged -ne $false) {
        throw 'PR 583 is no longer the sealed open head/base coordinate; prepare a new handoff.'
    }
    foreach ($coordinate in @(
        [pscustomobject]@{ Value = $pullRequest.state; Expected = 'open'; Label = 'PR state' },
        [pscustomobject]@{ Value = $pullRequest.head.ref; Expected = $script:CMTraceExpectedSourceBranch; Label = 'PR head branch' },
        [pscustomobject]@{ Value = $pullRequest.head.sha; Expected = $script:CMTraceExpectedSourceCommit; Label = 'PR head commit' },
        [pscustomobject]@{ Value = $pullRequest.base.ref; Expected = 'main'; Label = 'PR base branch' },
        [pscustomobject]@{ Value = $pullRequest.base.sha; Expected = $script:CMTraceExpectedBaseCommit; Label = 'PR base commit' }
    )) {
        Assert-CMTraceExactStringValue -Value $coordinate.Value -Expected $coordinate.Expected -Label $coordinate.Label
    }
    return $true
}

function Assert-CMTraceFixedLocalNtfsPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Label,

        [string[]]$ForbiddenRoots = @(),

        [switch]$MustNotExist
    )

    Assert-CMTraceWindows11Arm64
    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($MustNotExist -and (Test-Path -LiteralPath $fullPath -PathType Any)) {
        throw "$Label already exists and will not be overwritten: $fullPath"
    }
    if (-not (Test-Path -LiteralPath $fullPath -PathType Any)) {
        $directParent = Split-Path -Parent $fullPath
        if (-not (Test-Path -LiteralPath $directParent -PathType Container)) {
            throw "$Label parent must already exist: $directParent"
        }
    }
    if ($fullPath.StartsWith('\\') -or
        $fullPath -match '(?i)[\\/](?:OneDrive|Dropbox|Google Drive|My Drive|iCloudDrive|Box|Creative Cloud Files|Nextcloud|Syncthing)(?:[\\/]|$)') {
        throw "$Label must be on a local, non-synchronized path."
    }
    foreach ($oneDriveName in @('OneDrive', 'OneDriveCommercial', 'OneDriveConsumer')) {
        $oneDriveRoot = [Environment]::GetEnvironmentVariable($oneDriveName)
        if (-not [string]::IsNullOrWhiteSpace($oneDriveRoot)) {
            $resolvedOneDrive = [IO.Path]::GetFullPath($oneDriveRoot).TrimEnd([char]'\', [char]'/')
            if ($fullPath.Equals($resolvedOneDrive, [StringComparison]::OrdinalIgnoreCase) -or
                $fullPath.StartsWith(($resolvedOneDrive + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) {
                throw "$Label must not be inside a synchronized OneDrive root."
            }
        }
    }

    $root = [IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($root) -or $root -eq $fullPath -or $root -notmatch '^[A-Za-z]:\\$') {
        throw "$Label must be a non-root path on a local drive."
    }
    $volume = Get-Volume -DriveLetter $root.Substring(0, 1) -ErrorAction Stop
    if ($volume.DriveType -ne 'Fixed' -or $volume.FileSystem -ne 'NTFS') {
        throw "$Label volume must be fixed NTFS; found $($volume.DriveType)/$($volume.FileSystem)."
    }

    $relativeToVolume = [IO.Path]::GetRelativePath($root, $fullPath).Replace('/', '\')
    $topLevel = @($relativeToVolume.Split('\', [StringSplitOptions]::RemoveEmptyEntries))[0]
    $approvedTopLevels = @('CMTraceOpen-Handoff', 'CMTraceOpen-Return', 'cmtraceopen-input', 'cmtraceopen-validation', 'src')
    if ($topLevel -notin $approvedTopLevels) {
        throw "$Label must be under a reserved local validation root: $($approvedTopLevels -join ', ')."
    }

    $existing = $fullPath
    while (-not (Test-Path -LiteralPath $existing -PathType Any)) {
        $parent = Split-Path -Parent $existing
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $existing) {
            throw "$Label must have an existing local parent."
        }
        $existing = $parent
    }
    $cursor = $existing
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        $entry = Get-Item -LiteralPath $cursor -Force
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label cannot traverse a symlink, junction, or reparse point: $cursor"
        }
        if ($cursor -eq $root.TrimEnd([char]'\')) {
            break
        }
        $parent = Split-Path -Parent $cursor
        if ($parent -eq $cursor) {
            break
        }
        $cursor = $parent
    }

    foreach ($forbidden in $ForbiddenRoots) {
        if ([string]::IsNullOrWhiteSpace($forbidden)) {
            continue
        }
        $fullForbidden = [IO.Path]::GetFullPath($forbidden).TrimEnd([char]'\', [char]'/')
        if ($fullPath.Equals($fullForbidden, [StringComparison]::OrdinalIgnoreCase) -or
            $fullPath.StartsWith(($fullForbidden + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase) -or
            $fullForbidden.StartsWith(($fullPath.TrimEnd([char]'\', [char]'/') + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) {
            throw "$Label must be disjoint from protected path $fullForbidden."
        }
    }
    return $fullPath
}

function Assert-CMTraceNoReparseAncestor {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $existing = $fullPath
    while (-not (Test-Path -LiteralPath $existing -PathType Any)) {
        $parent = Split-Path -Parent $existing
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $existing) {
            throw "$Label must have an existing non-reparse ancestor."
        }
        $existing = $parent
    }

    $cursor = $existing
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        $entry = Get-Item -LiteralPath $cursor -Force
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label cannot traverse a symlink, junction, or reparse point: $cursor"
        }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) {
            break
        }
        $cursor = $parent
    }
    return $fullPath
}

function Open-CMTraceGuardedReadFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Label,

        [AllowEmptyString()]
        [string]$ExpectedSha256 = '',

        [int64]$ExpectedBytes = -1
    )

    $hasExpectedBinding = -not [string]::IsNullOrWhiteSpace($ExpectedSha256)
    if ($hasExpectedBinding -ne ($ExpectedBytes -ge 0)) {
        throw "$Label expected SHA-256 and byte length must be supplied together."
    }
    if ($hasExpectedBinding -and ($ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$' -or $ExpectedBytes -le 0)) {
        throw "$Label expected byte binding is malformed."
    }

    $fullPath = [IO.Path]::GetFullPath($Path)
    [void](Assert-CMTraceNoReparseAncestor -Path $fullPath -Label $Label)
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "$Label is missing or is not a regular file."
    }
    $entry = Get-Item -LiteralPath $fullPath -Force
    if ($entry.PSIsContainer -or
        ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $entry.Length -le 0) {
        throw "$Label must be a nonempty regular, non-reparse file."
    }

    $stream = $null
    try {
        # FileShare.Read denies new write/delete handles. On Windows this keeps the
        # verified pathname bound until the caller explicitly releases the guard.
        $stream = [IO.File]::Open(
            $entry.FullName,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        [void](Assert-CMTraceNoReparseAncestor -Path $entry.FullName -Label $Label)
        $readback = Get-Item -LiteralPath $entry.FullName -Force
        if ($readback.PSIsContainer -or
            ($readback.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $readback.Length -ne $stream.Length) {
            throw "$Label path identity changed while its read guard was acquired."
        }

        $actualSha256 = (Get-FileHash -InputStream $stream -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hasExpectedBinding -and
            ($stream.Length -ne $ExpectedBytes -or $actualSha256 -cne $ExpectedSha256)) {
            throw "$Label does not match its expected byte and SHA-256 binding."
        }
        $stream.Position = 0
        $result = [pscustomobject]@{
            Path = $readback.FullName
            Bytes = [int64]$stream.Length
            Sha256 = $actualSha256
            Stream = $stream
        }
        $stream = $null
        return $result
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Get-CMTraceContentBinding {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $resolvedPath = (Resolve-Path -LiteralPath $Path).Path
    [void](Assert-CMTraceNoReparseAncestor -Path $resolvedPath -Label $Label)
    $entry = Get-Item -LiteralPath $resolvedPath -Force
    if ($entry.PSIsContainer -or
        ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $entry.Length -le 0) {
        throw "$Label must be a nonempty regular, non-reparse file."
    }
    return [pscustomobject][ordered]@{
        Path = $entry.FullName
        Sha256 = Get-CMTraceSha256 -Path $entry.FullName
        Bytes = [int64]$entry.Length
        Label = $Label
    }
}

function Get-CMTraceTrustedPesterModule {
    $repositories = @(Get-PSRepository -ErrorAction Stop)
    if ($repositories.Count -ne 1 -or $repositories[0].Name -cne 'PSGallery') {
        throw 'The disposable validation account must have exactly one registered PowerShell repository named PSGallery.'
    }
    $repositorySource = ([string]$repositories[0].SourceLocation).TrimEnd([char]'/')
    if (-not $repositorySource.Equals(
            $script:CMTraceExpectedPowerShellGallery,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'PSGallery is not registered at the canonical PowerShell Gallery v2 endpoint.'
    }

    $packagePath = Assert-CMTraceFixedLocalNtfsPath -Path $script:CMTraceExpectedPesterPackagePath `
        -Label 'Pinned PSGallery Pester package' -ForbiddenRoots @((Get-CMTraceHandoffRoot))
    $moduleRoot = Assert-CMTraceFixedLocalNtfsPath -Path $script:CMTraceExpectedPesterModuleRoot `
        -Label 'Isolated Pester module root' -ForbiddenRoots @((Get-CMTraceHandoffRoot))
    [void](Assert-CMTraceNoReparseAncestor -Path $moduleRoot -Label 'Isolated Pester module root')
    $moduleRootEntry = Get-Item -LiteralPath $moduleRoot -Force
    if (-not $moduleRootEntry.PSIsContainer -or
        ($moduleRootEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Isolated Pester module root must be a regular, non-reparse directory.'
    }

    $packageGuard = Open-CMTraceGuardedReadFile -Path $packagePath -Label 'Pinned PSGallery Pester package' `
        -ExpectedSha256 $script:CMTraceExpectedPesterPackageSha256 `
        -ExpectedBytes $script:CMTraceExpectedPesterPackageBytes
    try {
        $expectedFiles = [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        $packageGuard.Stream.Position = 0
        $archive = [IO.Compression.ZipArchive]::new(
            $packageGuard.Stream,
            [IO.Compression.ZipArchiveMode]::Read,
            $true
        )
        try {
            foreach ($entry in $archive.Entries) {
                if ([string]::IsNullOrEmpty($entry.Name)) { continue }
                $relativePath = $entry.FullName.Replace('\', '/')
                $segments = @($relativePath.Split('/'))
                if ([IO.Path]::IsPathRooted($relativePath) -or
                    $entry.FullName.Contains('\') -or
                    $relativePath.Contains(':') -or
                    @($segments | Where-Object { [string]::IsNullOrEmpty($_) -or $_ -in @('.', '..') }).Count -ne 0 -or
                    $expectedFiles.ContainsKey($relativePath)) {
                    throw "Pinned Pester package contains an unsafe or duplicate entry: $relativePath"
                }
                $entryStream = $entry.Open()
                try {
                    $entrySha256 = (Get-FileHash -InputStream $entryStream -Algorithm SHA256).Hash.ToLowerInvariant()
                }
                finally {
                    $entryStream.Dispose()
                }
                $expectedFiles.Add($relativePath, [pscustomobject]@{
                        Bytes = [int64]$entry.Length
                        Sha256 = $entrySha256
                    })
            }
        }
        finally {
            $archive.Dispose()
        }

        $allEntries = @(Get-ChildItem -LiteralPath $moduleRoot -Recurse -Force)
        if (@($allEntries | Where-Object {
                    ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
                }).Count -ne 0) {
            throw 'Isolated Pester module root contains a reparse entry.'
        }
        $actualFiles = @($allEntries | Where-Object { -not $_.PSIsContainer })
        if ($actualFiles.Count -ne $expectedFiles.Count) {
            throw 'Isolated Pester module file inventory differs from the pinned package.'
        }
        $contentBindings = [Collections.Generic.List[object]]::new()
        foreach ($file in $actualFiles) {
            $relativePath = [IO.Path]::GetRelativePath($moduleRoot, $file.FullName).Replace('\', '/')
            if (-not $expectedFiles.ContainsKey($relativePath)) {
                throw "Isolated Pester module contains an unexpected file: $relativePath"
            }
            $expected = $expectedFiles[$relativePath]
            $fileGuard = Open-CMTraceGuardedReadFile -Path $file.FullName `
                -Label "Isolated Pester file $relativePath" `
                -ExpectedSha256 $expected.Sha256 -ExpectedBytes $expected.Bytes
            $fileGuard.Stream.Dispose()
            $contentBindings.Add([pscustomobject][ordered]@{
                    Path = $file.FullName
                    Sha256 = [string]$expected.Sha256
                    Bytes = [int64]$expected.Bytes
                    Label = "Isolated Pester file $relativePath"
                })
        }
    }
    finally {
        $packageGuard.Stream.Dispose()
    }

    $manifestPath = Join-Path $moduleRoot 'Pester.psd1'
    $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
    if ($manifest.Version -ne $script:CMTraceExpectedPesterVersion -or
        $manifest.Guid -ne [guid]'a699dea5-2c73-4616-a270-1f7abb777e71' -or
        [string]$manifest.Author -cne 'Pester Team') {
        throw 'Isolated Pester manifest identity differs from the pinned package contract.'
    }
    return [pscustomobject]@{
        Path = [IO.Path]::GetFullPath($manifestPath)
        Version = $script:CMTraceExpectedPesterVersion.ToString()
        Repository = 'PSGallery'
        RepositorySourceLocation = $script:CMTraceExpectedPowerShellGallery
        ContentBindings = [object[]]$contentBindings.ToArray()
    }
}

function Get-CMTracePEMachine {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -lt 64) {
            throw 'PE file is too short to contain a DOS header.'
        }
        $reader = [IO.BinaryReader]::new($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) {
            throw 'Missing DOS MZ header.'
        }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 64 -or $peOffset -gt ($stream.Length - 6)) {
            throw 'PE header offset is outside the file.'
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw 'Missing PE signature.'
        }
        return $reader.ReadUInt16()
    }
    finally {
        $stream.Dispose()
    }
}

function Get-CMTraceVerifiedArm64Executable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Root,

        [AllowEmptyString()]
        [string]$ExpectedSha256 = '',

        [int64]$ExpectedBytes = -1
    )

    $hasExpectedBinding = -not [string]::IsNullOrWhiteSpace($ExpectedSha256)
    if ($hasExpectedBinding -ne ($ExpectedBytes -ge 0)) {
        throw 'Expected ARM64 executable SHA-256 and byte length must be supplied together.'
    }
    if ($hasExpectedBinding -and ($ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$' -or $ExpectedBytes -le 0)) {
        throw 'Expected ARM64 executable binding is malformed.'
    }

    $fullPath = Assert-CMTracePathWithinRoot -Path $Path -Root $Root -Label 'Private ARM64 executable'
    [void](Assert-CMTraceNoReparseAncestor -Path $fullPath -Label 'Private ARM64 executable')
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw 'Private ARM64 executable is missing or is not a regular file.'
    }
    $entry = Get-Item -LiteralPath $fullPath -Force
    if ($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $entry.Length -le 0) {
        throw 'Private ARM64 executable must be a nonempty regular, non-reparse file.'
    }
    $machine = Get-CMTracePEMachine -Path $entry.FullName
    if ($machine -ne 0xAA64) {
        throw "Private executable PE machine was 0x$($machine.ToString('X4')), expected native ARM64 0xAA64."
    }
    [void](Assert-CMTraceNoReparseAncestor -Path $entry.FullName -Label 'Private ARM64 executable')
    $readback = Get-Item -LiteralPath $entry.FullName -Force
    if ($readback.Length -ne $entry.Length -or ($readback.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Private ARM64 executable identity changed during verification.'
    }
    $actualSha256 = Get-CMTraceSha256 -Path $readback.FullName
    if ($hasExpectedBinding -and ($readback.Length -ne $ExpectedBytes -or $actualSha256 -cne $ExpectedSha256)) {
        throw 'Private ARM64 executable no longer matches its post-build byte and SHA-256 binding.'
    }
    return [pscustomobject]@{
        Path = $readback.FullName
        Bytes = [int64]$readback.Length
        Sha256 = $actualSha256
        PeMachine = '0xAA64'
    }
}

function Assert-CMTraceSafeTemporaryRoot {
    param(
        [string[]]$ForbiddenRoots = @()
    )

    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([char]'\', [char]'/')
    $expectedTemporaryRoot = [IO.Path]::GetFullPath($script:CMTraceExpectedTemporaryRoot).TrimEnd([char]'\', [char]'/')
    if (-not $temporaryRoot.Equals($expectedTemporaryRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "TEMP and TMP must use the reserved validation temporary root $script:CMTraceExpectedTemporaryRoot."
    }
    foreach ($environmentName in @('TEMP', 'TMP')) {
        $environmentValue = [Environment]::GetEnvironmentVariable($environmentName, 'Process')
        if ([string]::IsNullOrWhiteSpace($environmentValue)) {
            throw "$environmentName must be set to the explicit validation temporary root."
        }
        $environmentPath = [IO.Path]::GetFullPath($environmentValue).TrimEnd([char]'\', [char]'/')
        if (-not $environmentPath.Equals($temporaryRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw "TEMP, TMP, and GetTempPath() must resolve to the same validation temporary root."
        }
    }

    $temporaryVolumeRoot = [IO.Path]::GetPathRoot($temporaryRoot).TrimEnd([char]'\', [char]'/')
    if ($temporaryRoot.Equals($temporaryVolumeRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The validation temporary root cannot be a volume root.'
    }
    foreach ($forbiddenRoot in $ForbiddenRoots) {
        if ([string]::IsNullOrWhiteSpace($forbiddenRoot)) {
            continue
        }
        $fullForbidden = [IO.Path]::GetFullPath($forbiddenRoot).TrimEnd([char]'\', [char]'/')
        if ($temporaryRoot.Equals($fullForbidden, [StringComparison]::OrdinalIgnoreCase) -or
            $temporaryRoot.StartsWith(($fullForbidden + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase) -or
            $fullForbidden.StartsWith(($temporaryRoot + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) {
            throw "The validation temporary root must be disjoint from protected path $fullForbidden."
        }
    }

    $probePath = Join-Path $temporaryRoot ('cmtraceopen-temp-boundary-{0}' -f [guid]::NewGuid().ToString('N'))
    [void](Assert-CMTraceFixedLocalNtfsPath -Path $probePath -Label 'Temporary root' -ForbiddenRoots $ForbiddenRoots -MustNotExist)
    return $temporaryRoot
}

function Assert-CMTraceGitIsolationContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [string]$TemporaryRoot,

        [string[]]$ForbiddenRoots = @()
    )

    $expectedProperties = @('Root', 'TemporaryRoot', 'GlobalConfigPath', 'HooksPath', 'Environment')
    $actualProperties = @($Context.PSObject.Properties.Name)
    if ($actualProperties.Count -ne $expectedProperties.Count -or
        @($expectedProperties | Where-Object { $_ -cnotin $actualProperties }).Count -ne 0) {
        throw 'Git isolation context has an unexpected shape.'
    }

    $fullTemporaryRoot = [IO.Path]::GetFullPath($TemporaryRoot).TrimEnd([char]'\', [char]'/')
    if (-not (Test-Path -LiteralPath $fullTemporaryRoot -PathType Container)) {
        throw 'Git isolation temporary root is missing or is not a directory.'
    }
    [void](Assert-CMTraceNoReparseAncestor -Path $fullTemporaryRoot -Label 'Git isolation temporary root')
    $temporaryEntry = Get-Item -LiteralPath $fullTemporaryRoot -Force
    if (-not $temporaryEntry.PSIsContainer -or
        ($temporaryEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Git isolation temporary root must be a regular, non-reparse directory.'
    }

    $contextTemporaryRoot = [IO.Path]::GetFullPath([string]$Context.TemporaryRoot).TrimEnd([char]'\', [char]'/')
    if (-not $contextTemporaryRoot.Equals($fullTemporaryRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Git isolation context belongs to a different temporary root.'
    }
    $root = Assert-CMTracePathWithinRoot -Path ([string]$Context.Root) -Root $fullTemporaryRoot -Label 'Git isolation root'
    $globalConfigPath = Assert-CMTracePathWithinRoot -Path ([string]$Context.GlobalConfigPath) -Root $root -Label 'Git isolation global config'
    $hooksPath = Assert-CMTracePathWithinRoot -Path ([string]$Context.HooksPath) -Root $root -Label 'Git isolation hooks path'
    if (-not $globalConfigPath.Equals((Join-Path $root 'empty.gitconfig'), [StringComparison]::OrdinalIgnoreCase) -or
        -not $hooksPath.Equals((Join-Path $globalConfigPath 'hooks'), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Git isolation context paths differ from the sealed layout.'
    }
    foreach ($path in @($root, $globalConfigPath, $hooksPath)) {
        [void](Assert-CMTraceNoReparseAncestor -Path $path -Label 'Git isolation path')
    }

    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw 'Git isolation root is missing or is not a directory.'
    }
    $rootEntry = Get-Item -LiteralPath $root -Force
    if (-not $rootEntry.PSIsContainer -or
        ($rootEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Git isolation root must be a regular, non-reparse directory.'
    }
    if (-not (Test-Path -LiteralPath $globalConfigPath -PathType Leaf)) {
        throw 'Git isolation global config is missing or is not a regular file.'
    }
    $globalConfigEntry = Get-Item -LiteralPath $globalConfigPath -Force
    if ($globalConfigEntry.PSIsContainer -or
        ($globalConfigEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $globalConfigEntry.Length -ne 0) {
        throw 'Git isolation global config must remain an empty regular, non-reparse file.'
    }
    $rootEntries = @(Get-ChildItem -LiteralPath $root -Force)
    if ($rootEntries.Count -ne 1 -or
        -not $rootEntries[0].FullName.Equals($globalConfigPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Git isolation root must contain only its guarded empty global config.'
    }
    if (Test-Path -LiteralPath $hooksPath -PathType Any) {
        throw 'Git isolation hooks path must remain impossible beneath the guarded global config file.'
    }

    foreach ($forbiddenRoot in $ForbiddenRoots) {
        if ([string]::IsNullOrWhiteSpace($forbiddenRoot)) { continue }
        $fullForbidden = [IO.Path]::GetFullPath($forbiddenRoot).TrimEnd([char]'\', [char]'/')
        if ($root.Equals($fullForbidden, [StringComparison]::OrdinalIgnoreCase) -or
            $root.StartsWith(($fullForbidden + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase) -or
            $fullForbidden.StartsWith(($root.TrimEnd([char]'\', [char]'/') + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) {
            throw "Git isolation root must be disjoint from protected path $fullForbidden."
        }
    }

    if ($Context.Environment -isnot [System.Collections.IDictionary]) {
        throw 'Git isolation environment must be a dictionary.'
    }
    $expectedEnvironment = [ordered]@{
        GIT_CONFIG_NOSYSTEM = '1'
        GIT_CONFIG_GLOBAL = $globalConfigPath
        GIT_CONFIG_COUNT = '3'
        GIT_CONFIG_KEY_0 = 'credential.helper'
        GIT_CONFIG_VALUE_0 = ''
        GIT_CONFIG_KEY_1 = 'core.hooksPath'
        GIT_CONFIG_VALUE_1 = $hooksPath
        GIT_CONFIG_KEY_2 = 'init.templateDir'
        GIT_CONFIG_VALUE_2 = ''
        GIT_TERMINAL_PROMPT = '0'
        GCM_INTERACTIVE = 'Never'
        GIT_ASKPASS = ''
        SSH_ASKPASS = ''
        GIT_NO_REPLACE_OBJECTS = '1'
    }
    if ($Context.Environment.Count -ne $expectedEnvironment.Count) {
        throw 'Git isolation environment has an unexpected entry count.'
    }
    foreach ($entry in $expectedEnvironment.GetEnumerator()) {
        if (-not $Context.Environment.Contains([string]$entry.Key) -or
            -not [string]::Equals([string]$Context.Environment[[string]$entry.Key], [string]$entry.Value, [StringComparison]::Ordinal)) {
            throw "Git isolation environment entry is missing or changed: $($entry.Key)"
        }
    }
    return $true
}

function New-CMTraceGitIsolationContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TemporaryRoot,

        [string[]]$ForbiddenRoots = @()
    )

    $fullTemporaryRoot = [IO.Path]::GetFullPath($TemporaryRoot).TrimEnd([char]'\', [char]'/')
    if (-not (Test-Path -LiteralPath $fullTemporaryRoot -PathType Container)) {
        throw 'Git isolation temporary root must already exist.'
    }
    [void](Assert-CMTraceNoReparseAncestor -Path $fullTemporaryRoot -Label 'Git isolation temporary root')
    $root = Join-Path $fullTemporaryRoot ('cmtraceopen-git-isolation-{0}' -f [guid]::NewGuid().ToString('N'))
    foreach ($forbiddenRoot in $ForbiddenRoots) {
        if ([string]::IsNullOrWhiteSpace($forbiddenRoot)) { continue }
        $fullForbidden = [IO.Path]::GetFullPath($forbiddenRoot).TrimEnd([char]'\', [char]'/')
        if ($root.Equals($fullForbidden, [StringComparison]::OrdinalIgnoreCase) -or
            $root.StartsWith(($fullForbidden + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase) -or
            $fullForbidden.StartsWith(($root + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) {
            throw "Git isolation root must be disjoint from protected path $fullForbidden."
        }
    }
    New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
    $globalConfigPath = Join-Path $root 'empty.gitconfig'
    $configStream = [IO.File]::Open(
        $globalConfigPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    $configStream.Dispose()
    $hooksPath = Join-Path $globalConfigPath 'hooks'

    $environment = [ordered]@{
        GIT_CONFIG_NOSYSTEM = '1'
        GIT_CONFIG_GLOBAL = $globalConfigPath
        GIT_CONFIG_COUNT = '3'
        GIT_CONFIG_KEY_0 = 'credential.helper'
        GIT_CONFIG_VALUE_0 = ''
        GIT_CONFIG_KEY_1 = 'core.hooksPath'
        GIT_CONFIG_VALUE_1 = $hooksPath
        GIT_CONFIG_KEY_2 = 'init.templateDir'
        GIT_CONFIG_VALUE_2 = ''
        GIT_TERMINAL_PROMPT = '0'
        GCM_INTERACTIVE = 'Never'
        GIT_ASKPASS = ''
        SSH_ASKPASS = ''
        GIT_NO_REPLACE_OBJECTS = '1'
    }
    $context = [pscustomobject][ordered]@{
        Root = $root
        TemporaryRoot = $fullTemporaryRoot
        GlobalConfigPath = $globalConfigPath
        HooksPath = $hooksPath
        Environment = $environment
    }
    [void](Assert-CMTraceGitIsolationContext -Context $context -TemporaryRoot $fullTemporaryRoot -ForbiddenRoots $ForbiddenRoots)
    return $context
}

function Get-CMTraceGitIsolationContext {
    [CmdletBinding()]
    param(
        [string[]]$ForbiddenRoots = @()
    )

    $temporaryRoot = Assert-CMTraceSafeTemporaryRoot -ForbiddenRoots $ForbiddenRoots
    $cachedVariable = Get-Variable -Name CMTraceGitIsolationContext -Scope Script -ErrorAction SilentlyContinue
    if ($null -eq $cachedVariable -or $null -eq $cachedVariable.Value) {
        $script:CMTraceGitIsolationContext = New-CMTraceGitIsolationContext `
            -TemporaryRoot $temporaryRoot -ForbiddenRoots $ForbiddenRoots
    }
    [void](Assert-CMTraceGitIsolationContext -Context $script:CMTraceGitIsolationContext `
        -TemporaryRoot $temporaryRoot -ForbiddenRoots $ForbiddenRoots)
    return $script:CMTraceGitIsolationContext
}

function Open-CMTraceGitIsolationGuard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [string[]]$ForbiddenRoots = @()
    )

    [void](Assert-CMTraceGitIsolationContext -Context $Context `
        -TemporaryRoot ([string]$Context.TemporaryRoot) -ForbiddenRoots $ForbiddenRoots)
    $stream = $null
    try {
        $stream = [IO.File]::Open(
            [string]$Context.GlobalConfigPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        if ($stream.Length -ne 0) {
            throw 'Git isolation global config changed while its read guard was acquired.'
        }
        [void](Assert-CMTraceGitIsolationContext -Context $Context `
            -TemporaryRoot ([string]$Context.TemporaryRoot) -ForbiddenRoots $ForbiddenRoots)
        $result = $stream
        $stream = $null
        return $result
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Get-CMTraceOrdinalSortedString {
    param(
        [AllowEmptyCollection()]
        [string[]]$Value = @()
    )

    $sorted = [string[]]@($Value)
    [Array]::Sort($sorted, [StringComparer]::Ordinal)
    return $sorted
}

function Write-CMTraceJson {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $Value | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $Path -Encoding utf8NoBOM
}

function Write-CMTraceNewText {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [ValidateSet('utf8NoBOM', 'ascii')]
        [string]$Encoding = 'utf8NoBOM'
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $parent = Split-Path -Parent $fullPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "New text file parent must already exist: $parent"
    }

    $temporaryPath = Join-Path $parent ('.cmtraceopen-text-{0}.tmp' -f [guid]::NewGuid().ToString('N'))
    $stream = $null
    $writer = $null
    $temporaryCreated = $false
    try {
        $stream = [IO.File]::Open($temporaryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $temporaryCreated = $true
        $textEncoding = if ($Encoding -ceq 'ascii') {
            [Text.Encoding]::ASCII
        }
        else {
            [Text.UTF8Encoding]::new($false)
        }
        $writer = [IO.StreamWriter]::new($stream, $textEncoding)
        $stream = $null
        $writer.Write($Text)
        $writer.Flush()
        $writer.Dispose()
        $writer = $null
        [IO.File]::Move($temporaryPath, $fullPath, $false)
        $temporaryCreated = $false
    }
    catch {
        $primaryFailure = $_
        $cleanupExceptions = [System.Collections.Generic.List[Exception]]::new()
        if ($null -ne $writer) {
            try {
                $writer.Dispose()
            }
            catch {
                $cleanupExceptions.Add($_.Exception)
            }
            finally {
                $writer = $null
            }
        }
        if ($null -ne $stream) {
            try {
                $stream.Dispose()
            }
            catch {
                $cleanupExceptions.Add($_.Exception)
            }
            finally {
                $stream = $null
            }
        }
        if ($temporaryCreated) {
            try {
                if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
                    Remove-Item -LiteralPath $temporaryPath -Force
                }
            }
            catch {
                $cleanupExceptions.Add($_.Exception)
            }
        }
        if ($cleanupExceptions.Count -gt 0) {
            $cleanupText = @($cleanupExceptions | ForEach-Object Message) -join '; '
            $innerExceptions = @($primaryFailure.Exception) + @($cleanupExceptions)
            $aggregateMessage = "Primary new-text publication failed: $($primaryFailure.Exception.Message) Cleanup also failed: $cleanupText"
            throw [AggregateException]::new($aggregateMessage, [Exception[]]$innerExceptions)
        }
        throw $primaryFailure
    }
    finally {
        if ($null -ne $writer) {
            $writer.Dispose()
        }
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Write-CMTraceNewJson {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $json = $Value | ConvertTo-Json -Depth 20
    Write-CMTraceNewText -Text ($json + [Environment]::NewLine) -Path $Path -Encoding utf8NoBOM
}

function New-CMTraceDeterministicZip {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This internal fail-no-overwrite helper creates only the exact archive path already approved by its caller.'
    )]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceRoot,

        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    $resolvedRoot = (Resolve-Path -LiteralPath $SourceRoot).Path
    $rootEntry = Get-Item -LiteralPath $resolvedRoot -Force
    if (-not $rootEntry.PSIsContainer -or ($rootEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Deterministic ZIP source must be a regular non-reparse directory.'
    }
    $fullDestination = [IO.Path]::GetFullPath($DestinationPath)
    if (Test-Path -LiteralPath $fullDestination -PathType Any) {
        throw "Deterministic ZIP destination already exists: $fullDestination"
    }
    $destinationParent = Split-Path -Parent $fullDestination
    if (-not (Test-Path -LiteralPath $destinationParent -PathType Container)) {
        throw "Deterministic ZIP destination parent must already exist: $destinationParent"
    }
    $rootPrefix = $resolvedRoot.TrimEnd([char]'\', [char]'/') + [IO.Path]::DirectorySeparatorChar
    if ($fullDestination.Equals($resolvedRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $fullDestination.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Deterministic ZIP destination must be outside its source root.'
    }

    $allEntries = @(Get-ChildItem -LiteralPath $resolvedRoot -Recurse -Force)
    if (@($allEntries | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }).Count -gt 0) {
        throw 'Deterministic ZIP source cannot contain a symlink, junction, or reparse point.'
    }
    $filesByRelativePath = @{}
    $seenPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in @($allEntries | Where-Object { -not $_.PSIsContainer })) {
        $relativePath = Get-CMTraceRelativePath -Root $resolvedRoot -Path $file.FullName
        if ($relativePath.StartsWith('/') -or $relativePath.StartsWith('../') -or $relativePath.Contains('/../') -or
            $relativePath.Contains('\') -or [IO.Path]::IsPathRooted($relativePath) -or -not $seenPaths.Add($relativePath)) {
            throw "Deterministic ZIP source contains an unsafe or case-colliding path: $relativePath"
        }
        $filesByRelativePath[$relativePath] = $file.FullName
    }
    foreach ($directory in @($allEntries | Where-Object { $_.PSIsContainer })) {
        $directoryPrefix = $directory.FullName.TrimEnd([char]'\', [char]'/') + [IO.Path]::DirectorySeparatorChar
        if (@($filesByRelativePath.Values | Where-Object { $_.StartsWith($directoryPrefix, [StringComparison]::OrdinalIgnoreCase) }).Count -eq 0) {
            throw 'Deterministic ZIP source cannot contain an empty directory.'
        }
    }

    $relativePaths = @(Get-CMTraceOrdinalSortedString -Value @($filesByRelativePath.Keys))
    $fixedTimestamp = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
    $temporaryPath = Join-Path $destinationParent ('.cmtraceopen-zip-{0}.tmp' -f [guid]::NewGuid().ToString('N'))
    $temporaryCreated = $false
    try {
        $fileStream = [IO.File]::Open($temporaryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $temporaryCreated = $true
        try {
            $archive = [IO.Compression.ZipArchive]::new($fileStream, [IO.Compression.ZipArchiveMode]::Create, $false, [Text.Encoding]::UTF8)
            try {
                foreach ($relativePath in $relativePaths) {
                    $entry = $archive.CreateEntry($relativePath, [IO.Compression.CompressionLevel]::Optimal)
                    $entry.LastWriteTime = $fixedTimestamp
                    $entry.ExternalAttributes = 0
                    $sourceStream = [IO.File]::Open($filesByRelativePath[$relativePath], [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
                    try {
                        $entryStream = $entry.Open()
                        try {
                            $sourceStream.CopyTo($entryStream)
                        }
                        finally {
                            $entryStream.Dispose()
                        }
                    }
                    finally {
                        $sourceStream.Dispose()
                    }
                }
            }
            finally {
                $archive.Dispose()
            }
        }
        finally {
            $fileStream.Dispose()
        }
        [IO.File]::Move($temporaryPath, $fullDestination, $false)
        $temporaryCreated = $false
    }
    catch {
        $primaryFailure = $_
        $cleanupException = $null
        if ($temporaryCreated) {
            try {
                if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
                    Remove-Item -LiteralPath $temporaryPath -Force
                }
            }
            catch {
                $cleanupException = $_.Exception
            }
        }
        if ($null -ne $cleanupException) {
            $aggregateMessage = "Primary deterministic-ZIP publication failed: $($primaryFailure.Exception.Message) Cleanup also failed: $($cleanupException.Message)"
            throw [AggregateException]::new($aggregateMessage, [Exception[]]@($primaryFailure.Exception, $cleanupException))
        }
        throw $primaryFailure
    }
    return $fixedTimestamp
}

function Assert-CMTraceChecksumInventory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $resolvedRoot = (Resolve-Path -LiteralPath $Root).Path
    $rootEntry = Get-Item -LiteralPath $resolvedRoot -Force
    if (-not $rootEntry.PSIsContainer -or ($rootEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Context root must be a regular non-reparse directory."
    }
    $checksumPath = Join-Path $resolvedRoot 'SHA256SUMS.txt'
    if (-not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) {
        throw "$Context checksum manifest is missing: $checksumPath"
    }
    $checksumEntry = Get-Item -LiteralPath $checksumPath -Force
    if ($checksumEntry.PSIsContainer -or ($checksumEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Context checksum manifest must be a regular non-reparse file."
    }

    $expected = [ordered]@{}
    $seenPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($line in Get-Content -LiteralPath $checksumPath) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            throw "$Context checksum manifest contains a blank line."
        }
        if ($line -cnotmatch '^([0-9a-f]{64})  (.+)$') {
            throw "$Context checksum manifest contains an invalid line."
        }

        $relativePath = $Matches[2]
        if ($relativePath.Contains('\') -or $relativePath -eq 'SHA256SUMS.txt' -or
            $relativePath.StartsWith('/') -or $relativePath.StartsWith('../') -or
            $relativePath.Contains('/../') -or [IO.Path]::IsPathRooted($relativePath) -or
            $relativePath -match '^[A-Za-z]:[\\/]') {
            throw "Unsafe checksum path: $relativePath"
        }
        $fullCandidate = [IO.Path]::GetFullPath((Join-Path $resolvedRoot $relativePath))
        $rootPrefix = $resolvedRoot.TrimEnd([char]'\', [char]'/') + [IO.Path]::DirectorySeparatorChar
        if (-not $fullCandidate.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Unsafe checksum path: $relativePath"
        }
        if (-not $seenPaths.Add($relativePath)) {
            throw "Duplicate checksum path: $relativePath"
        }
        $expected[$relativePath] = $Matches[1]
    }

    $allEntries = @(Get-ChildItem -LiteralPath $resolvedRoot -Recurse -Force)
    $reparseEntries = @($allEntries | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 })
    if ($reparseEntries.Count -gt 0) {
        throw "$Context payload cannot contain a symlink, junction, or reparse point."
    }

    $actualPaths = @(Get-CMTraceOrdinalSortedString -Value @($allEntries | Where-Object { -not $_.PSIsContainer } |
        ForEach-Object { Get-CMTraceRelativePath -Root $resolvedRoot -Path $_.FullName } |
        Where-Object { $_ -ne 'SHA256SUMS.txt' }))
    $expectedPaths = @(Get-CMTraceOrdinalSortedString -Value @($expected.Keys))
    if (Compare-Object -ReferenceObject $expectedPaths -DifferenceObject $actualPaths) {
        throw "$Context file inventory does not match SHA256SUMS.txt."
    }

    $expectedDirectories = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($relativePath in $expected.Keys) {
        $segments = @($relativePath.Split('/'))
        for ($index = 1; $index -lt $segments.Count; $index++) {
            [void]$expectedDirectories.Add(($segments[0..($index - 1)] -join '/'))
        }
    }
    $actualDirectories = @(Get-CMTraceOrdinalSortedString -Value @($allEntries | Where-Object { $_.PSIsContainer } |
        ForEach-Object { Get-CMTraceRelativePath -Root $resolvedRoot -Path $_.FullName }))
    $expectedDirectoryPaths = @(Get-CMTraceOrdinalSortedString -Value @($expectedDirectories))
    if (Compare-Object -ReferenceObject $expectedDirectoryPaths -DifferenceObject $actualDirectories) {
        throw "$Context directory inventory contains an unexpected or empty directory."
    }

    foreach ($relativePath in $expected.Keys) {
        $actualHash = Get-CMTraceSha256 -Path (Join-Path $resolvedRoot $relativePath)
        if ($actualHash -cne $expected[$relativePath]) {
            throw "$Context checksum mismatch: $relativePath"
        }
    }
    return $true
}

function Assert-CMTraceHandoffIntegrity {
    param(
        [string]$HandoffRoot = (Get-CMTraceHandoffRoot)
    )

    [void](Assert-CMTraceNoReparseAncestor -Path $HandoffRoot -Label 'Handoff root')
    $resolvedRoot = (Resolve-Path -LiteralPath $HandoffRoot).Path
    [void](Assert-CMTraceChecksumInventory -Root $resolvedRoot -Context 'Handoff')
    Assert-CMTraceHandoffManifest -HandoffRoot $resolvedRoot
    return $true
}

function Assert-CMTraceHandoffManifest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HandoffRoot
    )

    $manifestPath = Join-Path $HandoffRoot 'MANIFEST.json'
    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    }
    catch {
        throw "MANIFEST.json is malformed: $($_.Exception.Message)"
    }

    if (($manifest.schemaVersion -isnot [int32] -and $manifest.schemaVersion -isnot [int64]) -or
        $manifest.schemaVersion -ne 1) {
        throw 'MANIFEST.json schemaVersion must be 1.'
    }
    $expectedCoordinates = [ordered]@{
        repository = $script:CMTraceExpectedRemote
        pullRequest = 583
        pullRequestUrl = 'https://github.com/adamgell/cmtraceopen/pull/583'
        branch = $script:CMTraceExpectedSourceBranch
        sourceCommit = $script:CMTraceExpectedSourceCommit
        sourceTree = $script:CMTraceExpectedSourceTree
        baseCommit = $script:CMTraceExpectedBaseCommit
        cargoLockBlob = $script:CMTraceExpectedCargoLockBlob
        packageLockBlob = $script:CMTraceExpectedPackageLockBlob
        commitSignerPrincipal = 'me@adamgell.com'
        commitSignerFingerprint = 'SHA256:87j5tuVscw4mFc0vo/OWOaRusQl1joEop5olrbM11GQ'
        rustTarget = $script:CMTraceRustTarget
        applicationVersionAtSource = '1.5.1'
    }
    foreach ($entry in $expectedCoordinates.GetEnumerator()) {
        $actual = $manifest.validationTarget.($entry.Key)
        if ($entry.Key -eq 'pullRequest') {
            if (($actual -isnot [int32] -and $actual -isnot [int64]) -or $actual -ne 583) {
                throw 'MANIFEST.json validationTarget.pullRequest must be the integer 583.'
            }
            continue
        }
        Assert-CMTraceExactStringValue -Value $actual -Expected ([string]$entry.Value) -Label "MANIFEST.json validationTarget.$($entry.Key)"
    }
    if ($manifest.classification.validationHelperSourceIncluded -isnot [bool] -or $manifest.classification.validationHelperSourceIncluded -ne $true) {
        throw 'MANIFEST.json classification.validationHelperSourceIncluded must be true.'
    }
    if ($manifest.classification.publicCommitVerificationKeyIncluded -isnot [bool] -or $manifest.classification.publicCommitVerificationKeyIncluded -ne $true) {
        throw 'MANIFEST.json classification.publicCommitVerificationKeyIncluded must be true.'
    }
    foreach ($field in @('applicationSourceCodeIncluded', 'gitHistoryIncluded', 'applicationArtifactsIncluded', 'customerDataIncluded', 'credentialsIncluded', 'privateSigningMaterialIncluded')) {
        if ($manifest.classification.$field -isnot [bool] -or $manifest.classification.$field -ne $false) {
            throw "MANIFEST.json classification.$field must be false."
        }
    }

    $allowedSignersPath = Join-Path $HandoffRoot 'PUBLIC_ALLOWED_SIGNERS'
    $allowedSigners = @((Get-Content -LiteralPath $allowedSignersPath) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($allowedSigners.Count -ne 1 -or -not $allowedSigners[0].Equals($script:CMTraceExpectedSignerLine, [StringComparison]::Ordinal)) {
        throw 'PUBLIC_ALLOWED_SIGNERS must contain only the sealed public SSH verification key.'
    }
}

function ConvertTo-CMTraceSanitizerTokenFreeText {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )

    $publicTokenPattern = '(?:' +
        '<redacted>|' +
        '<redacted-(?:aws-key|base64-payload|binary-control|email|github-token|guid|hex-payload|ipv4|ipv6|jwt|line-wrapped-payload|mac|oversized-text|path|private-domain|private-key-block|private-key-marker|query|sid|unc-path)>|' +
        '%(?:COMPUTERNAME|EVIDENCE_ROOT|HANDOFF|LOGONSERVER|ONEDRIVE|REPOSITORY|USERDNSDOMAIN|USERDOMAIN|USERNAME|USERPROFILE)%' +
        ')'
    $options = [Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    return [regex]::Replace($Text, $publicTokenPattern, '', $options)
}

function ConvertTo-CMTracePrivacyReconstructionText {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )

    # Form D exposes combining marks before they are removed. Normalizing to
    # Form C first would let an inserted mark compose with an adjacent letter
    # and conceal a reconstructed credential or identifier.
    $canonical = $Text.Normalize([Text.NormalizationForm]::FormD)
    return [regex]::Replace(
        $canonical,
        '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F\p{Cf}\p{M}\p{Zl}\p{Zp}\u00A0\u1680\u2000-\u200A\u202F\u205F\u3000]',
        ''
    )
}

function ConvertTo-CMTracePrivacyCanonicalScanText {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )

    # Preserve ordinary spaces, TAB, CR, and LF so benign token boundaries do
    # not become credentials. Remove only redaction-join controls and Unicode
    # separators/marks whose deletion reconstructs a hidden value.
    return ConvertTo-CMTracePrivacyReconstructionText -Text (
        ConvertTo-CMTraceSanitizerTokenFreeText -Text $Text
    )
}

function ConvertTo-CMTraceSanitizedText {
    param(
        [AllowEmptyString()]
        [string]$Text,

        [System.Collections.IDictionary]$LiteralReplacements = [ordered]@{}
    )

    $maximumSanitizedCharacters = 262144
    if ($Text.Length -gt $maximumSanitizedCharacters) {
        return '<redacted-oversized-text>'
    }

    $result = $Text.Normalize([Text.NormalizationForm]::FormC)
    $replacements = @($LiteralReplacements.GetEnumerator() | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.Key)
    } | Sort-Object { ([string]$_.Key).Normalize([Text.NormalizationForm]::FormC).Length } -Descending)

    foreach ($entry in $replacements) {
        $pattern = [regex]::Escape(([string]$entry.Key).Normalize([Text.NormalizationForm]::FormC))
        $replacementValue = [string]$entry.Value
        $result = [regex]::Replace(
            $result,
            $pattern,
            [System.Text.RegularExpressions.MatchEvaluator]{
                param($match)
                $null = $match.Value
                return $replacementValue
            },
            ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
                [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
        )
    }

    $cultureInvariant = [Text.RegularExpressions.RegexOptions]::CultureInvariant
    $result = [regex]::Replace($result, '\x1B(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1B\\))', '', $cultureInvariant)
    $result = [regex]::Replace($result, '(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b', '<redacted-email>', $cultureInvariant)
    $result = [regex]::Replace($result, '(?i)\bS-1-(?:\d{1,15}|0x[0-9a-f]{12})(?:-\d{1,10}){1,15}\b', '<redacted-sid>', $cultureInvariant)
    $result = [regex]::Replace($result, '(?i)\\\\[^\\\s"'']+\\[^\s"'']+', '<redacted-unc-path>', $cultureInvariant)
    $result = [regex]::Replace($result, '(?i)\b[A-Z]:[\\/][^\s"''<>|]+', '<redacted-path>', $cultureInvariant)
    $result = [regex]::Replace($result, '(?i)\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b', '<redacted-ipv4>', $cultureInvariant)
    $result = [regex]::Replace($result, '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', '<redacted-guid>', $cultureInvariant)
    $ipv6CandidatePattern = '(?i)(?<![0-9a-f:.])(?=[0-9a-f:.]*:)[0-9a-f:.]{2,45}(?![0-9a-f:.])'
    $result = [regex]::Replace(
        $result,
        $ipv6CandidatePattern,
        [System.Text.RegularExpressions.MatchEvaluator]{
            param($match)
            $address = $null
            if ([Net.IPAddress]::TryParse($match.Value, [ref]$address) -and
                $address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
                return '<redacted-ipv6>'
            }
            return $match.Value
        },
        $cultureInvariant
    )
    $result = [regex]::Replace($result, '(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b', '<redacted-mac>', $cultureInvariant)
    $result = [regex]::Replace($result, '(?i)\b(?:[A-Z0-9-]+\.)+(?:local|lan|internal|corp|home|home\.arpa)\b', '<redacted-private-domain>', $cultureInvariant)
    $result = [regex]::Replace(
        $result,
        '(?im)((?:Proxy-)?Authorization\s*:)[^\r\n]*$',
        '$1 <redacted>',
        $cultureInvariant
    )
    $result = [regex]::Replace(
        $result,
        '(?is)-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----[\s\S]{0,1048576}?-----END \1-----',
        '<redacted-private-key-block>',
        $cultureInvariant
    )
    $result = [regex]::Replace($result, '(?i)-----(?:BEGIN|END) [^-\r\n]*PRIVATE KEY-----', '<redacted-private-key-marker>', $cultureInvariant)
    $result = [regex]::Replace($result, '(?i)\bgh[pousr]_[A-Za-z0-9]{20,}\b', '<redacted-github-token>', $cultureInvariant)
    $result = [regex]::Replace($result, '(?i)\bAKIA[0-9A-Z]{16}\b', '<redacted-aws-key>', $cultureInvariant)
    $result = [regex]::Replace($result, '(?i)\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b', '<redacted-jwt>', $cultureInvariant)
    $result = [regex]::Replace(
        $result,
        '(?im)^(?<prefix>.*?(?<![A-Z0-9_-])["'']?(?:password|passwd|pwd|secret|token|api[-_]?key|client[-_]?secret|sig|signature|sas)["'']?(?![A-Z0-9_-])[ \t]*[:=])(?<value>[^\r\n]*)$',
        [System.Text.RegularExpressions.MatchEvaluator]{
            param($match)
            $trimmedValue = $match.Groups['value'].Value.Trim()
            if ($trimmedValue -match '^[|>]') {
                # A single-line replacement cannot prove that a multiline
                # block body was removed, so leave it for fail-closed scanning.
                return $match.Value
            }
            return "$($match.Groups['prefix'].Value)<redacted>"
        },
        $cultureInvariant
    )
    $result = [regex]::Replace($result, '(?i)(https?://[^\s?"'']+)\?[^\s"'']+', '$1?<redacted-query>', $cultureInvariant)
    $result = [regex]::Replace(
        $result,
        '(?i)(?<![0-9a-f])[0-9a-f]{512,}(?![0-9a-f])',
        '<redacted-hex-payload>',
        $cultureInvariant
    )
    $result = [regex]::Replace(
        $result,
        '(?i)(?<![A-Z0-9+/_-])[A-Z0-9+/_-]{256,}={0,2}(?![A-Z0-9+/_=-])',
        '<redacted-base64-payload>',
        $cultureInvariant
    )
    $result = [regex]::Replace(
        $result,
        '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F\p{Cf}]+',
        '<redacted-binary-control>',
        $cultureInvariant
    )
    $sanitizedBuilder = [Text.StringBuilder]::new($result.Length)
    $encodedRunBuilder = [Text.StringBuilder]::new()
    $encodedRunLength = 0
    $encodedRunTerminator = ''
    foreach ($lineMatch in [regex]::Matches($result, '[^\r\n]*(?:\r\n|\r|\n|\z)')) {
        if ($lineMatch.Length -eq 0) {
            continue
        }

        $line = $lineMatch.Value
        $terminator = if ($line.EndsWith("`r`n", [StringComparison]::Ordinal)) {
            "`r`n"
        }
        elseif ($line.EndsWith("`r", [StringComparison]::Ordinal)) {
            "`r"
        }
        elseif ($line.EndsWith("`n", [StringComparison]::Ordinal)) {
            "`n"
        }
        else {
            ''
        }
        $contentLength = $line.Length - $terminator.Length
        $content = $line.Substring(0, $contentLength)
        $encodedCandidate = ConvertTo-CMTraceEncodedPayloadCandidate -Text $content
        $isEncodedCandidate = Test-CMTraceEncodedPayloadLine -Text $encodedCandidate

        if ($isEncodedCandidate) {
            [void]$encodedRunBuilder.Append($line)
            $encodedRunLength += $encodedCandidate.Length
            $encodedRunTerminator = $terminator
            continue
        }

        if ($encodedCandidate.Length -eq 0 -and $encodedRunBuilder.Length -gt 0) {
            [void]$encodedRunBuilder.Append($line)
            $encodedRunTerminator = $terminator
            continue
        }

        if ($encodedRunBuilder.Length -gt 0) {
            if ($encodedRunLength -ge 256) {
                [void]$sanitizedBuilder.Append('<redacted-line-wrapped-payload>')
                [void]$sanitizedBuilder.Append($encodedRunTerminator)
            }
            else {
                [void]$sanitizedBuilder.Append($encodedRunBuilder)
            }
            [void]$encodedRunBuilder.Clear()
            $encodedRunLength = 0
            $encodedRunTerminator = ''
        }
        [void]$sanitizedBuilder.Append($line)
    }
    if ($encodedRunBuilder.Length -gt 0) {
        if ($encodedRunLength -ge 256) {
            [void]$sanitizedBuilder.Append('<redacted-line-wrapped-payload>')
            [void]$sanitizedBuilder.Append($encodedRunTerminator)
        }
        else {
            [void]$sanitizedBuilder.Append($encodedRunBuilder)
        }
    }
    $result = $sanitizedBuilder.ToString()

    if ($result.Length -gt $maximumSanitizedCharacters) {
        return '<redacted-oversized-text>'
    }
    return $result
}

function ConvertTo-CMTraceSanitizedGateLog {
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[a-z0-9][a-z0-9-]{0,63}$')]
        [string]$GateId,

        [Parameter(Mandatory = $true)]
        [ValidateSet('passed', 'failed', 'blocked')]
        [string]$GateStatus,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text,

        [System.Collections.IDictionary]$LiteralReplacements = [ordered]@{}
    )

    $gatePattern = '\Agate=' + [regex]::Escape($GateId) + '(?:\r\n|\r|\n|\z)'
    $gateMatch = [regex]::Match($Text, $gatePattern)
    if (-not $gateMatch.Success) {
        throw "Gate log does not begin with its exact canonical gate line: $GateId"
    }
    $body = $Text.Remove($gateMatch.Index, $gateMatch.Length)
    $statusMatch = [regex]::Match($body, '(?m)^status=(passed|failed|blocked)(?:\r\n|\r|\n|\z)')
    if (-not $statusMatch.Success -or $statusMatch.Groups[1].Value -cne $GateStatus) {
        throw "Gate log does not contain its exact canonical status line: $GateId"
    }
    $body = $body.Remove($statusMatch.Index, $statusMatch.Length)

    $sanitizedBody = ConvertTo-CMTraceSanitizedText -Text $body -LiteralReplacements $LiteralReplacements
    if ($sanitizedBody -ceq '<redacted-oversized-text>') {
        return "gate=$GateId`nstatus=$GateStatus`nresult=sanitized-log-body-withheld-after-size-limit`nThe complete raw log remains target-private."
    }
    if ([string]::IsNullOrEmpty($sanitizedBody)) {
        return "gate=$GateId`nstatus=$GateStatus"
    }
    return "gate=$GateId`nstatus=$GateStatus`n$sanitizedBody"
}

function Assert-CMTracePrivacySafeText {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $patterns = [ordered]@{
        'email address' = '(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b'
        'Windows SID' = '(?i)\bS-1-(?:\d{1,15}|0x[0-9a-f]{12})(?:-\d{1,10}){1,15}\b'
        'UNC path' = '(?i)\\\\[^\\\s"'']+\\[^\s"'']+'
        'absolute Windows path' = '(?i)\b[A-Z]:[\\/][^\s"''<>|]+'
        'IPv4 address' = '(?i)\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b'
        'GUID-like identifier' = '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b'
        'MAC address' = '(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b'
        'private DNS name' = '(?i)\b(?:[A-Z0-9-]+\.)+(?:local|lan|internal|corp|home|home\.arpa)\b'
        'authorization header' = '(?im)(?:Proxy-)?Authorization\s*:(?![ \t]*<redacted>[ \t]*\r?$)[ \t]*\S[^\r\n]*$'
        'private-key marker' = '(?i)-----(?:BEGIN|END) [^-\r\n]*PRIVATE KEY-----'
        'GitHub token' = '(?i)\bgh[pousr]_[A-Za-z0-9]{20,}\b'
        'AWS access key' = '(?i)\bAKIA[0-9A-Z]{16}\b'
        'JWT token' = '(?i)\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'
        'secret-like assignment' = '(?im)(?<![A-Z0-9_-])["'']?(password|passwd|pwd|secret|token|api[-_]?key|client[-_]?secret|sig|signature|sas)["'']?(?![A-Z0-9_-])[ \t]*[:=][ \t]*(?!<redacted>[ \t]*$)[^\r\n]*\S[^\r\n]*$'
        'URL query string' = '(?i)https?://[^\s?"'']+\?(?!<redacted-query>)[^\s"'']+'
        'long Base64 payload' = '(?i)(?<![A-Z0-9+/_-])[A-Z0-9+/_-]{256,}={0,2}(?![A-Z0-9+/_=-])'
        'long hexadecimal payload' = '(?i)(?<![0-9a-f])[0-9a-f]{512,}(?![0-9a-f])'
        'binary control character' = '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F\p{Cf}]'
    }

    $canonicalScanText = ConvertTo-CMTracePrivacyCanonicalScanText -Text $Text
    if ([regex]::IsMatch(
            $canonicalScanText,
            '(?i)<redacted(?:-[a-z0-9]+)*>|%[A-Z0-9_]+%',
            [Text.RegularExpressions.RegexOptions]::CultureInvariant
        )) {
        throw "Evidence privacy scan failed for ${Label}: detected an unrecognized sanitizer token."
    }
    $scanTexts = if ([string]::Equals($canonicalScanText, $Text, [StringComparison]::Ordinal)) {
        @($Text)
    }
    else {
        @($Text, $canonicalScanText)
    }

    foreach ($scanText in $scanTexts) {
        foreach ($entry in $patterns.GetEnumerator()) {
            if ([regex]::IsMatch(
                    $scanText,
                    $entry.Value,
                    [Text.RegularExpressions.RegexOptions]::CultureInvariant
                )) {
                throw "Evidence privacy scan failed for ${Label}: detected $($entry.Key)."
            }
        }
    }

    $encodedRunLength = 0
    foreach ($lineMatch in [regex]::Matches($Text, '[^\r\n]*(?:\r\n|\r|\n|\z)')) {
        if ($lineMatch.Length -eq 0) {
            continue
        }
        $candidate = ConvertTo-CMTraceEncodedPayloadCandidate -Text $lineMatch.Value.TrimEnd([char]"`r", [char]"`n")
        if (Test-CMTraceEncodedPayloadLine -Text $candidate) {
            $encodedRunLength += $candidate.Length
            if ($encodedRunLength -ge 256) {
                throw "Evidence privacy scan failed for ${Label}: detected line-wrapped encoded payload."
            }
        }
        elseif ($candidate.Length -gt 0) {
            $encodedRunLength = 0
        }
    }

    $ipv6CandidatePattern = '(?i)(?<![0-9a-f:.])(?=[0-9a-f:.]*:)[0-9a-f:.]{2,45}(?![0-9a-f:.])'
    foreach ($scanText in $scanTexts) {
        foreach ($candidate in [regex]::Matches(
                $scanText,
                $ipv6CandidatePattern,
                [Text.RegularExpressions.RegexOptions]::CultureInvariant
            )) {
            $address = $null
            if ([Net.IPAddress]::TryParse($candidate.Value, [ref]$address) -and
                $address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
                throw "Evidence privacy scan failed for ${Label}: detected IPv6 address."
            }
        }
    }
}

function ConvertTo-CMTraceEncodedPayloadCandidate {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )

    $candidate = (ConvertTo-CMTraceSanitizerTokenFreeText -Text $Text).Normalize([Text.NormalizationForm]::FormD)
    $candidate = [regex]::Replace($candidate, '[\s\p{Cc}\p{Cf}\p{M}]', '')
    if ($candidate -match '^[A-Za-z0-9+/_-]+={0,2}$') {
        return $candidate
    }
    if ($candidate -in @('{', '}', '},', '[', ']', '],')) {
        return ''
    }

    # Recognize narrow chunks only when the wrapper has an unambiguous
    # sequence field distinct from the payload. Keeping that distinction is
    # important: a generic "number somewhere before a token" rule treats
    # ordinary inventory scalars such as physicalMemoryBytes as chunks.
    $sequencedPayload = [regex]::Match(
        $candidate,
        '(?ix)\A(?:
            (?:DATA|PAYLOAD|CHUNK|BASE64)(?:->|[=:])
            |
            [A-Z][A-Z0-9_.-]{0,31}(?:
                [=:]\d{1,9}(?:/\d{1,9})?[=:]
                |
                \[\d{1,9}(?:/\d{1,9})?\][=:]
                |
                \(\d{1,9}(?:/\d{1,9})?\)[=:]
                |
                \#\d{1,9}(?:/\d{1,9})?(?:->|[:=])
                |
                \d{1,9}(?:/\d{1,9})?(?:->|[:;,|.])
            )
            |
            \[\d{1,9}(?:/\d{1,9})?\][=:]?
            |
            (?:[A-Z][A-Z0-9_.-]{0,31}[:;,|])?\d{1,9}(?:/\d{1,9})?(?:->|[:;,|.])
        )
        (?:(?:DATA|PAYLOAD|CHUNK|BASE64)[:=])?
        ["''(]?
        (?<payload>[A-Z0-9+/_-]+={0,2})
        ["'')]?
        (?:[.;,|\#].{0,96})?
        \z',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if ($sequencedPayload.Success) {
        return $sequencedPayload.Groups['payload'].Value
    }

    # Compact JSON payload wrappers are allowed with or without a separate
    # sequence property and in any property order. The recognized payload key
    # keeps unrelated JSON inventory records out of encoded-run accounting.
    if ($candidate.StartsWith('{', [StringComparison]::Ordinal) -and
        ($candidate.EndsWith('}', [StringComparison]::Ordinal) -or
            $candidate.EndsWith('},', [StringComparison]::Ordinal))) {
        $jsonPayload = [regex]::Match(
            $candidate,
            '(?i)"(?:data|payload|chunk|base64)":"(?<payload>(?:[A-Z0-9+/_-]|\\/)+={0,2})"',
            [Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
        if ($jsonPayload.Success) {
            return $jsonPayload.Groups['payload'].Value.Replace('\/', '/')
        }
        $jsonPayloadArray = [regex]::Match(
            $candidate,
            '(?i)"(?:data|payload|chunk|base64)":\[(?<items>[^\]]*)\]',
            [Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
        if ($jsonPayloadArray.Success) {
            $jsonArrayElements = @([regex]::Matches(
                    $jsonPayloadArray.Groups['items'].Value,
                    '"(?<payload>(?:[A-Za-z0-9+/_-]|\\/)+={0,2})"',
                    [Text.RegularExpressions.RegexOptions]::CultureInvariant
                ))
            if ($jsonArrayElements.Count -gt 0) {
                return (($jsonArrayElements | ForEach-Object {
                            $_.Groups['payload'].Value.Replace('\/', '/').TrimEnd([char]'=')
                        }) -join '')
            }
        }
    }

    # Other compact JSON objects are structured records, not arbitrary line
    # framing. Their individual long values remain covered by the global
    # payload guard; do not concatenate unrelated keys, hashes, and prose.
    if ($candidate.StartsWith('{', [StringComparison]::Ordinal) -and
        ($candidate.EndsWith('}', [StringComparison]::Ordinal) -or
            $candidate.EndsWith('},', [StringComparison]::Ordinal))) {
        return ''
    }

    # Preserve JSON property boundaries. Explicit payload-like keys continue
    # encoded-run accounting, while unrelated contract fields (for example,
    # hashes and evidence IDs) cannot be concatenated into a false payload.
    # A single 256-character value is still caught by the global guard above.
    $jsonProperty = [regex]::Match(
        $candidate,
        '\A"(?<key>[^"\r\n]{1,64})":(?<value>.*?)(?:,)?\z',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if ($jsonProperty.Success) {
        if ($jsonProperty.Groups['key'].Value -match '^(?i:seq|sequence|part|index)$' -and
            $jsonProperty.Groups['value'].Value -match '^"?\d{1,9}"?$') {
            return ''
        }
        if ($jsonProperty.Groups['key'].Value -match '^(?i:data|payload|chunk|base64)$') {
            $jsonPropertyPayload = [regex]::Match(
                $jsonProperty.Groups['value'].Value,
                '\A"(?<payload>(?:[A-Za-z0-9+/_-]|\\/)+={0,2})"\z',
                [Text.RegularExpressions.RegexOptions]::CultureInvariant
            )
            if ($jsonPropertyPayload.Success) {
                return $jsonPropertyPayload.Groups['payload'].Value.Replace('\/', '/')
            }
        }
        return ''
    }

    # Pretty-printed JSON payload arrays place each encoded string on its own
    # line. Treat line-only string elements as chunks; surrounding properties
    # and structural lines are neutral and therefore cannot reset the run.
    $jsonStringElement = [regex]::Match(
        $candidate,
        '\A"(?<payload>(?:[A-Za-z0-9+/_-]|\\/)+={0,2})",?\z',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if ($jsonStringElement.Success) {
        return $jsonStringElement.Groups['payload'].Value.Replace('\/', '/')
    }

    # Wrapped encoders commonly prefix or frame each chunk with a sequence
    # marker. Accumulate substantial Base64/Base64URL tokens under arbitrary
    # non-JSON framing so that framing cannot reset run accounting.
    $embeddedPayloads = @([regex]::Matches(
        $candidate,
        '(?i)(?<![A-Z0-9+/_-])(?<payload>[A-Z0-9+/_-]{16,}={0,2})(?![A-Z0-9+/_=-])',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    ))
    if ($embeddedPayloads.Count -gt 0) {
        return (($embeddedPayloads | ForEach-Object { $_.Groups['payload'].Value.TrimEnd([char]'=') }) -join '')
    }
    return $candidate
}

function Test-CMTraceEncodedPayloadLine {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )

    if ($Text.Length -lt 1 -or $Text -notmatch '^[A-Za-z0-9+/_-]+={0,2}$') {
        return $false
    }
    return $true
}

function Assert-CMTraceWindows11Arm64 {
    if (-not $IsWindows) {
        throw 'Windows 11 ARM64 is required; this host is not Windows.'
    }

    $osArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    $processArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
    $build = [Environment]::OSVersion.Version.Build

    if ($osArchitecture -ne 'Arm64' -or $processArchitecture -ne 'Arm64' -or $build -lt 22000) {
        throw "Windows 11 ARM64 with a native ARM64 PowerShell process is required. OSArchitecture=$osArchitecture; ProcessArchitecture=$processArchitecture; Build=$build."
    }
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -OperationTimeoutSec 5 -ErrorAction Stop
    if ([int]$operatingSystem.ProductType -ne 1 -or [string]$operatingSystem.Caption -notmatch '(?i)Windows 11') {
        throw 'A Windows 11 client SKU is required; Windows Server and non-client SKUs are not accepted.'
    }
}

function Assert-CMTraceGitIndexVisibility {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Inventory
    )

    $records = @($Inventory.Split([char]0, [StringSplitOptions]::RemoveEmptyEntries))
    if ($records.Count -eq 0) {
        throw 'The exact source index did not contain any tracked files.'
    }
    foreach ($record in $records) {
        if ($record.Length -lt 3 -or $record[1] -ne ' ' -or $record[0] -cne 'H') {
            throw 'The exact source index contains an assume-unchanged, skip-worktree, unmerged, or otherwise nonordinary tracked entry.'
        }
    }
    return $records.Count
}

function Get-CMTraceTrackedHashPlan {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$StageInventory
    )

    $paths = [Collections.Generic.List[string]]::new()
    $expectedHashes = [Collections.Generic.List[string]]::new()
    foreach ($record in @($StageInventory.Split([char]0, [StringSplitOptions]::RemoveEmptyEntries))) {
        $match = [regex]::Match(
            $record,
            '\A(?<mode>100644|100755|120000) (?<hash>[0-9a-f]{40}) 0\t(?<path>.+)\z',
            [Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
        if (-not $match.Success) {
            throw 'The exact source index contains an unsupported mode, stage, hash, or path record.'
        }
        $path = $match.Groups['path'].Value
        if ($path.IndexOfAny([char[]]@("`r", "`n")) -ge 0) {
            throw 'The exact source contains a tracked path that cannot be hashed through the bounded line protocol.'
        }
        $paths.Add($path)
        $expectedHashes.Add($match.Groups['hash'].Value)
    }
    if ($paths.Count -eq 0) {
        throw 'The exact source index did not contain any hashable tracked files.'
    }
    [pscustomobject]@{
        Paths = @($paths)
        ExpectedHashes = @($expectedHashes)
        StandardInputText = ($paths -join "`n") + "`n"
    }
}

function Assert-CMTraceTrackedHashOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ExpectedHashes,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ActualOutput
    )

    $actualHashes = if ([string]::IsNullOrWhiteSpace($ActualOutput)) {
        @()
    }
    else {
        @($ActualOutput -split '\r?\n')
    }
    $actualHashes = @($actualHashes)
    if ($actualHashes.Count -ne $ExpectedHashes.Count) {
        throw 'Tracked worktree hashing returned an incomplete or extra result set.'
    }
    for ($index = 0; $index -lt $ExpectedHashes.Count; $index++) {
        if ($actualHashes[$index] -cnotmatch '\A[0-9a-f]{40}\z' -or
            $actualHashes[$index] -cne $ExpectedHashes[$index]) {
            throw 'A tracked worktree file does not hash to its exact index blob.'
        }
    }
    return $actualHashes.Count
}

function Assert-CMTraceCargoConfigurationBoundary {
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,

        [string[]]$AllowedConfigurationPaths = @()
    )

    $resolvedWorkingDirectory = (Resolve-Path -LiteralPath $WorkingDirectory).Path
    $allowed = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($path in $AllowedConfigurationPaths) {
        $fullPath = [IO.Path]::GetFullPath($path)
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf -ErrorAction Stop)) {
            throw 'The authenticated Cargo configuration file is missing.'
        }
        [void](Assert-CMTraceNoReparseAncestor -Path $fullPath -Label 'Authenticated Cargo configuration')
        [void]$allowed.Add($fullPath)
    }

    $encountered = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $cargoHome = Join-Path $env:USERPROFILE '.cargo'
        foreach ($name in @('config', 'config.toml', 'credentials', 'credentials.toml')) {
            if (Test-Path -LiteralPath (Join-Path $cargoHome $name) -PathType Any -ErrorAction Stop) {
                throw 'The disposable lab Cargo home contains configuration or credential state.'
            }
        }
    }
    $volumeRoot = [IO.Path]::GetPathRoot($resolvedWorkingDirectory)
    $cursor = $resolvedWorkingDirectory
    while ($true) {
        $cargoDirectory = Join-Path $cursor '.cargo'
        foreach ($name in @('config', 'config.toml')) {
            $candidate = [IO.Path]::GetFullPath((Join-Path $cargoDirectory $name))
            if (Test-Path -LiteralPath $candidate -PathType Any -ErrorAction Stop) {
                if (-not (Test-Path -LiteralPath $candidate -PathType Leaf -ErrorAction Stop) -or
                    -not $allowed.Contains($candidate)) {
                    throw 'Cargo configuration was discovered outside the authenticated source configuration boundary.'
                }
                [void](Assert-CMTraceNoReparseAncestor -Path $candidate -Label 'Authenticated Cargo configuration')
                [void]$encountered.Add($candidate)
            }
        }
        foreach ($name in @('rust-toolchain', 'rust-toolchain.toml')) {
            if (Test-Path -LiteralPath (Join-Path $cursor $name) -PathType Any -ErrorAction Stop) {
                throw 'An unsealed Rust toolchain override was discovered in a validation working-directory ancestor.'
            }
        }
        if ($cursor.Equals($volumeRoot, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $parentEntry = [IO.Directory]::GetParent($cursor)
        if ($null -eq $parentEntry -or $parentEntry.FullName.Equals($cursor, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Could not complete the Cargo ancestor configuration scan.'
        }
        $cursor = $parentEntry.FullName
    }

    if ($encountered.Count -ne $allowed.Count) {
        throw 'The authenticated Cargo configuration is not discoverable from the requested working directory.'
    }
    return $resolvedWorkingDirectory
}

function Assert-CMTraceActiveRustToolchain {
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory
    )

    $capture = Invoke-CMTraceOwnedProcessCapture -FilePath 'rustup.exe' `
        -Arguments @('show', 'active-toolchain') -WorkingDirectory $WorkingDirectory
    if ($capture.ExitCode -ne 0) {
        throw "Could not read the active Rust toolchain; rustup exited with code $($capture.ExitCode)."
    }
    if (-not [string]::IsNullOrWhiteSpace($capture.StdErr)) {
        throw 'Could not read the active Rust toolchain; rustup emitted unexpected stderr.'
    }
    $activeToolchain = ConvertTo-CMTraceNormalizedNativeOutput -Text $capture.StdOut
    if ([string]::IsNullOrWhiteSpace($activeToolchain) -or $activeToolchain -match '[\r\n]') {
        throw 'Could not read the active Rust toolchain; rustup did not return exactly one normalized stdout line.'
    }
    if ($activeToolchain -cne 'stable-aarch64-pc-windows-msvc (default)') {
        throw 'The sealed default native ARM64 Rust toolchain has been overridden.'
    }
    return $true
}

function Assert-CMTraceRepositoryControlBoundary {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryPath,

        [Parameter(Mandatory = $true)]
        [string]$GitMetadataPath
    )

    $unexpectedRootControls = @(Get-ChildItem -LiteralPath $RepositoryPath -Force -ErrorAction Stop | Where-Object {
        ($_.Name.StartsWith('.env', [StringComparison]::OrdinalIgnoreCase) -and
            -not $_.Name.Equals('.env.example', [StringComparison]::OrdinalIgnoreCase)) -or
        $_.Name.Equals('.npmrc', [StringComparison]::OrdinalIgnoreCase) -or
        $_.Name.Equals('rust-toolchain', [StringComparison]::OrdinalIgnoreCase) -or
        $_.Name.Equals('rust-toolchain.toml', [StringComparison]::OrdinalIgnoreCase)
    })
    if ($unexpectedRootControls.Count -gt 0) {
        throw 'The source root contains an unsealed environment or toolchain control file.'
    }

    $gitInfo = Join-Path $GitMetadataPath 'info'
    foreach ($name in @('exclude', 'attributes')) {
        $path = Join-Path $gitInfo $name
        if (Test-Path -LiteralPath $path -PathType Any -ErrorAction Stop) {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf -ErrorAction Stop)) {
                throw 'Git metadata contains an invalid local control path.'
            }
            [void](Assert-CMTraceNoReparseAncestor -Path $path -Label 'Git metadata control file')
            foreach ($line in @(Get-Content -LiteralPath $path -ErrorAction Stop)) {
                $trimmed = ([string]$line).Trim()
                if (-not [string]::IsNullOrWhiteSpace($trimmed) -and -not $trimmed.StartsWith('#', [StringComparison]::Ordinal)) {
                    throw 'Git metadata contains active local exclude or attribute rules.'
                }
            }
        }
    }
    if (Test-Path -LiteralPath (Join-Path $gitInfo 'sparse-checkout') -PathType Any -ErrorAction Stop) {
        throw 'Git sparse-checkout metadata is not accepted for the exact validation source.'
    }
    if (Test-Path -LiteralPath (Join-Path $GitMetadataPath 'config.worktree') -PathType Any -ErrorAction Stop) {
        throw 'Git worktree-specific configuration is not accepted for the exact validation source.'
    }
}

function Assert-CMTraceSourceIntegrity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryPath,

        [switch]$RequireNoIgnoredFiles
    )

    $resolved = (Resolve-Path -LiteralPath $RepositoryPath).Path
    $git = (Get-Command git.exe -ErrorAction Stop).Source
    $gitIsolation = Get-CMTraceGitIsolationContext -ForbiddenRoots @($resolved, (Get-CMTraceHandoffRoot))
    $gitEnvironment = $gitIsolation.Environment
    $gitArguments = @('--no-replace-objects', '-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false', '-C', $resolved)

    function Invoke-CMTraceSourceGit {
        param(
            [Parameter(Mandatory = $true)]
            [string[]]$Arguments,

            [string]$ExpectedStdErrPattern,

            [string]$CaptureLimitMessage,

            [ValidateRange(1, 1048576)]
            [int]$MaximumCaptureBytes = 65536,

            [ValidateLength(1, 1048576)]
            [string]$StandardInputText
        )

        $gitConfigGuard = $null
        try {
            $gitConfigGuard = Open-CMTraceGitIsolationGuard -Context $gitIsolation `
                -ForbiddenRoots @($resolved, (Get-CMTraceHandoffRoot))
            try {
                $captureParameters = @{
                    FilePath = $git
                    Arguments = $Arguments
                    WorkingDirectory = $resolved
                    Environment = $gitEnvironment
                    TimeoutSeconds = 60
                    MaximumCaptureBytes = $MaximumCaptureBytes
                }
                if ($PSBoundParameters.ContainsKey('StandardInputText')) {
                    $captureParameters.StandardInputText = $StandardInputText
                }
                $capture = Invoke-CMTraceOwnedProcessCapture @captureParameters
            }
            catch {
                if (-not [string]::IsNullOrWhiteSpace($CaptureLimitMessage) -and
                    $_.Exception.Message -ceq "Owned process output exceeded the strict $MaximumCaptureBytes-byte aggregate capture limit.") {
                    throw $CaptureLimitMessage
                }
                throw
            }
        }
        finally {
            if ($null -ne $gitConfigGuard) { $gitConfigGuard.Dispose() }
        }
        $stdout = $capture.StdOut.Trim()
        $stderr = $capture.StdErr.Trim()
        if ([string]::IsNullOrWhiteSpace($ExpectedStdErrPattern)) {
            if (-not [string]::IsNullOrWhiteSpace($stderr)) {
                throw 'Git emitted unexpected stderr while verifying the isolated source.'
            }
        }
        elseif ($stderr -cnotmatch $ExpectedStdErrPattern) {
            throw 'Git signature verification emitted unexpected status output.'
        }
        $lines = if ([string]::IsNullOrWhiteSpace($stdout)) { @() } else { @($stdout -split '\r?\n') }
        return [pscustomobject]@{
            ExitCode = $capture.ExitCode
            Text = $stdout
            StdErr = $stderr
            Lines = @($lines)
        }
    }

    [void](Assert-CMTraceNoReparseAncestor -Path $resolved -Label 'Repository path')
    $gitMetadataPath = Join-Path $resolved '.git'
    if (-not (Test-Path -LiteralPath $gitMetadataPath -PathType Container)) {
        throw 'Validation checkout must be a normal isolated clone with a .git directory; linked worktrees are not accepted.'
    }
    [void](Assert-CMTraceNoReparseAncestor -Path $gitMetadataPath -Label 'Repository Git metadata')
    $expectedGitMetadata = [IO.Path]::GetFullPath($gitMetadataPath).TrimEnd([char]'\', [char]'/')
    Assert-CMTraceRepositoryControlBoundary -RepositoryPath $resolved -GitMetadataPath $gitMetadataPath

    $replacementRefs = Invoke-CMTraceSourceGit -Arguments @($gitArguments + @('for-each-ref', '--format=%(refname)', 'refs/replace/'))
    if ($replacementRefs.ExitCode -ne 0) {
        throw 'Could not inspect source replacement references.'
    }
    if ($replacementRefs.Lines.Count -gt 0) {
        throw 'Git replacement references are not accepted for the exact validation source.'
    }

    $absoluteGitDir = Invoke-CMTraceSourceGit -Arguments @($gitArguments + @('rev-parse', '--absolute-git-dir'))
    if ($absoluteGitDir.ExitCode -ne 0 -or
        -not [IO.Path]::GetFullPath($absoluteGitDir.Text).TrimEnd([char]'\', [char]'/').Equals($expectedGitMetadata, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Validation checkout Git directory escapes the isolated source root.'
    }
    $commonGitDir = Invoke-CMTraceSourceGit -Arguments @($gitArguments + @('rev-parse', '--git-common-dir'))
    if ($commonGitDir.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($commonGitDir.Text)) {
        throw 'Validation checkout common Git directory escapes the isolated source root.'
    }
    $resolvedCommonGitDir = if ([IO.Path]::IsPathRooted($commonGitDir.Text)) {
        [IO.Path]::GetFullPath($commonGitDir.Text)
    }
    else {
        [IO.Path]::GetFullPath((Join-Path $resolved $commonGitDir.Text))
    }
    if (-not $resolvedCommonGitDir.TrimEnd([char]'\', [char]'/').Equals($expectedGitMetadata, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Validation checkout common Git directory escapes the isolated source root.'
    }

    $result = Invoke-CMTraceSourceGit -Arguments @($gitArguments + @('rev-parse', '--show-toplevel'))
    if ($result.ExitCode -ne 0 -or -not [IO.Path]::GetFullPath($result.Text).Equals($resolved, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Repository path does not match the isolated Git worktree root.'
    }

    $result = Invoke-CMTraceSourceGit -Arguments @($gitArguments + @('rev-parse', 'HEAD'))
    if ($result.ExitCode -ne 0 -or $result.Text -cne $script:CMTraceExpectedSourceCommit) {
        throw "Expected source commit $script:CMTraceExpectedSourceCommit, found '$($result.Text)'."
    }

    $result = Invoke-CMTraceSourceGit -Arguments @($gitArguments + @('rev-parse', 'HEAD^{tree}'))
    if ($result.ExitCode -ne 0 -or $result.Text -cne $script:CMTraceExpectedSourceTree) {
        throw "Expected source tree $script:CMTraceExpectedSourceTree, found '$($result.Text)'."
    }

    $indexInventory = Invoke-CMTraceSourceGit -Arguments @($gitArguments + @('ls-files', '-v', '-z', '--cached')) `
        -MaximumCaptureBytes 1048576 `
        -CaptureLimitMessage 'Tracked source index inventory exceeded its exact-tree bound and is not accepted.'
    if ($indexInventory.ExitCode -ne 0) {
        throw 'Could not inspect tracked source index visibility flags.'
    }
    [void](Assert-CMTraceGitIndexVisibility -Inventory $indexInventory.Text)

    $autocrlf = Invoke-CMTraceSourceGit -Arguments @($gitArguments + @('config', '--get', 'core.autocrlf'))
    $longpaths = Invoke-CMTraceSourceGit -Arguments @($gitArguments + @('config', '--get', 'core.longpaths'))
    if ($autocrlf.ExitCode -ne 0 -or $longpaths.ExitCode -ne 0 -or $autocrlf.Text -cne 'false' -or $longpaths.Text -cne 'true') {
        throw 'Validation checkout must set core.autocrlf=false and core.longpaths=true.'
    }

    $unsafeLocalConfig = Invoke-CMTraceSourceGit -Arguments @($gitArguments + @('config', '--local', '--get-regexp', '^(credential\.|http\..*extraheader|url\..*insteadof|core\.(sshcommand|hookspath|fsmonitor|worktree|attributesfile|excludesfile)|extensions\.worktreeconfig|gpg\.|user\.signingkey|include(if)?\.|filter\.|diff\.external)'))
    if ($unsafeLocalConfig.ExitCode -notin @(0, 1)) {
        throw 'Could not inspect validation checkout local Git configuration.'
    }
    if ($unsafeLocalConfig.Lines.Count -gt 0) {
        throw 'Validation checkout contains unsafe local Git authentication, rewrite, hook, filter, include, or worktree configuration.'
    }

    $stageInventory = Invoke-CMTraceSourceGit -Arguments @($gitArguments + @('ls-files', '--stage', '-z', '--cached')) `
        -MaximumCaptureBytes 1048576 `
        -CaptureLimitMessage 'Tracked source stage inventory exceeded its exact-tree bound and is not accepted.'
    if ($stageInventory.ExitCode -ne 0) {
        throw 'Could not inspect the exact tracked source stage inventory.'
    }
    $trackedHashPlan = Get-CMTraceTrackedHashPlan -StageInventory $stageInventory.Text
    $indexTree = Invoke-CMTraceSourceGit -Arguments @($gitArguments + @('write-tree'))
    if ($indexTree.ExitCode -ne 0 -or $indexTree.Text -cne $script:CMTraceExpectedSourceTree) {
        throw 'The exact source index does not reproduce the sealed source tree.'
    }
    $trackedHashes = Invoke-CMTraceSourceGit -Arguments @($gitArguments + @('hash-object', '--stdin-paths')) `
        -StandardInputText $trackedHashPlan.StandardInputText `
        -MaximumCaptureBytes 1048576 `
        -CaptureLimitMessage 'Tracked worktree hash output exceeded its exact-tree bound and is not accepted.'
    if ($trackedHashes.ExitCode -ne 0) {
        throw 'Could not hash every tracked worktree file against the exact index.'
    }
    [void](Assert-CMTraceTrackedHashOutput -ExpectedHashes $trackedHashPlan.ExpectedHashes -ActualOutput $trackedHashes.Text)

    foreach ($lock in @(
        [pscustomobject]@{ Path = 'Cargo.lock'; Blob = $script:CMTraceExpectedCargoLockBlob },
        [pscustomobject]@{ Path = 'package-lock.json'; Blob = $script:CMTraceExpectedPackageLockBlob }
    )) {
        $result = Invoke-CMTraceSourceGit -Arguments @($gitArguments + @('hash-object', $lock.Path))
        if ($result.ExitCode -ne 0 -or $result.Text -cne $lock.Blob) {
            throw "Lockfile coordinate mismatch for $($lock.Path)."
        }
    }

    $result = Invoke-CMTraceSourceGit -Arguments @($gitArguments + @('submodule', 'status'))
    if ($result.ExitCode -ne 0 -or $result.Lines.Count -gt 0) {
        throw 'Exact validation source must contain no Git submodules.'
    }

    $result = Invoke-CMTraceSourceGit -Arguments @($gitArguments + @('remote', 'get-url', 'origin'))
    if ($result.ExitCode -ne 0 -or $result.Text -cne $script:CMTraceExpectedRemote) {
        throw "Unexpected origin remote: '$($result.Text)'."
    }

    $result = Invoke-CMTraceSourceGit -Arguments @($gitArguments + @('remote', 'get-url', '--push', 'origin'))
    if ($result.ExitCode -ne 0 -or $result.Text -cne 'DISABLED') {
        throw 'Origin push URL must be disabled for the validation checkout.'
    }

    $result = Invoke-CMTraceSourceGit -Arguments @($gitArguments + @('branch', '--show-current'))
    if ($result.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($result.Text)) {
        throw 'Validation checkout must be detached at the exact source commit.'
    }

    $allowedSigners = Join-Path (Get-CMTraceHandoffRoot) 'PUBLIC_ALLOWED_SIGNERS'
    $result = Invoke-CMTraceSourceGit -Arguments @($gitArguments + @('-c', "gpg.ssh.allowedSignersFile=$allowedSigners", 'verify-commit', $script:CMTraceExpectedSourceCommit)) `
        -ExpectedStdErrPattern '\AGood "git" signature for me@adamgell\.com with ED25519 key SHA256:[A-Za-z0-9+/]{43}\z'
    if ($result.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($result.Text)) {
        throw 'Exact source commit signature did not verify against PUBLIC_ALLOWED_SIGNERS.'
    }

    $status = Invoke-CMTraceSourceGit -Arguments @($gitArguments + @('status', '--porcelain=v1', '--untracked-files=all')) `
        -CaptureLimitMessage 'Source worktree status exceeded the bounded capture limit and is not accepted as clean; preserve it and initialize a fresh exact-SHA checkout.'
    if ($status.ExitCode -ne 0) {
        throw 'Could not read source worktree status.'
    }
    $trackedStatus = Invoke-CMTraceSourceGit -Arguments @($gitArguments + @('status', '--porcelain=v1', '--untracked-files=no')) `
        -CaptureLimitMessage 'Tracked source worktree status exceeded the bounded capture limit and is not accepted as clean; preserve it and initialize a fresh exact-SHA checkout.'
    if ($trackedStatus.ExitCode -ne 0) {
        throw 'Could not inspect tracked source worktree changes.'
    }
    if ($trackedStatus.Lines.Count -gt 0) {
        throw 'Source worktree contains tracked or staged changes; preserve it and initialize a fresh exact-SHA checkout.'
    }
    if ($status.Lines.Count -gt 0) {
        throw 'Source worktree is not clean; preserve it and initialize a fresh exact-SHA checkout.'
    }

    if ($RequireNoIgnoredFiles) {
        $ignored = Invoke-CMTraceSourceGit -Arguments @($gitArguments + @('ls-files', '--others', '--ignored', '--exclude-standard', '--directory')) `
            -CaptureLimitMessage 'Ignored source file inventory exceeded the bounded capture limit and is not accepted; initialize a fresh exact-SHA checkout.'
        if ($ignored.ExitCode -ne 0) {
            throw 'Could not inspect ignored source files.'
        }
        if ($ignored.Lines.Count -gt 0) {
            throw 'Source checkout contains ignored files before validation; initialize a new exact-SHA checkout.'
        }
    }

    [void](Assert-CMTraceCargoConfigurationBoundary -WorkingDirectory $resolved `
        -AllowedConfigurationPaths @((Join-Path $resolved '.cargo\config.toml')))

    return $resolved
}
