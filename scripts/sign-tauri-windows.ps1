param([Parameter(Position = 0)][string]$Path)

function Import-VerifiedArtifactSigning {
    [CmdletBinding()]
    param()
    $ErrorActionPreference = 'Stop'
    if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { throw 'Missing private runner directory.' }
    $package = Join-Path $env:RUNNER_TEMP 'cmtrace-artifact-signing-0.1.8.nupkg'
    # Official PSGallery 0.1.8 nupkg, retrieved 2026-10-20 from:
    # https://www.powershellgallery.com/api/v2/package/ArtifactSigning/0.1.8
    $expected = '3221344b8c627915d3870f23e80816f31a5d8c2bae1d7c0cdd6c9652f6c4e089'
    $packageFile = Get-Item -LiteralPath $package -ErrorAction Stop
    if ($packageFile.PSIsContainer -or $packageFile.LinkType) {
        throw 'ArtifactSigning package SHA256 verification failed.'
    }
    # Hold the same read-only stream through verification and extraction so
    # changed on-disk bytes cannot replace the verified package between steps.
    $stream = [IO.File]::Open($packageFile.FullName, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ((Get-FileHash -InputStream $stream -Algorithm SHA256).Hash -ne $expected) {
            throw 'ArtifactSigning package SHA256 verification failed.'
        }
        $stream.Position = 0
        $moduleRoot = Join-Path $env:RUNNER_TEMP ('cmtrace-artifact-signing-' + [guid]::NewGuid())
        $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Read, $true)
        try { [IO.Compression.ZipFileExtensions]::ExtractToDirectory($archive, $moduleRoot) }
        finally { $archive.Dispose() }
    } finally { $stream.Dispose() }
    $manifest = Join-Path $moduleRoot 'ArtifactSigning.psd1'
    $module = Import-Module -Name $manifest -RequiredVersion 0.1.8 -Force -PassThru -ErrorAction Stop
    if (-not $module -or -not $module.ExportedCommands.ContainsKey('Invoke-ArtifactSigning')) {
        throw 'Verified ArtifactSigning module did not export its signing command.'
    }
    return $module
}

function Invoke-TauriWindowsSigning {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LiteralPath)

    $ErrorActionPreference = 'Stop'
    foreach ($name in @('AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET',
            'SIGNING_ENDPOINT', 'SIGNING_ACCOUNT_NAME', 'SIGNING_PROFILE_NAME')) {
        if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
            throw "Missing existing signing setting: $name"
        }
    }
    $file = Get-Item -LiteralPath $LiteralPath -ErrorAction Stop
    if ($file.PSIsContainer -or ($file.LinkType -and $file.LinkType -ne 'HardLink') -or $file.Extension -notin @('.exe', '.dll') -or
            $file.FullName.Contains(',')) {
        throw 'The bundler signing hook requires one regular EXE or DLL.'
    }
    if ($file.LinkType -eq 'HardLink') {
        # Cargo may hardlink the release executable to deps. Replace only the
        # bundler-selected directory entry with a regular copy before signing.
        $copy = Join-Path $file.DirectoryName ([guid]::NewGuid().ToString() + $file.Extension)
        try {
            [IO.File]::Copy($file.FullName, $copy, $false)
            [IO.File]::Move($copy, $file.FullName, $true)
        } finally {
            if (Test-Path -LiteralPath $copy) { Remove-Item -LiteralPath $copy -Force }
        }
        $file = Get-Item -LiteralPath $file.FullName -ErrorAction Stop
        if ($file.PSIsContainer -or $file.LinkType) { throw 'Signing payload detachment failed.' }
    }
    $module = Import-VerifiedArtifactSigning
    & $module.ExportedCommands['Invoke-ArtifactSigning'] -Endpoint $env:SIGNING_ENDPOINT `
        -CodeSigningAccountName $env:SIGNING_ACCOUNT_NAME `
        -CertificateProfileName $env:SIGNING_PROFILE_NAME -Files $file.FullName `
        -FileDigest SHA256 -TimestampRfc3161 'http://timestamp.acs.microsoft.com' `
        -TimestampDigest SHA256 -Timeout 300 `
        -ExcludeEnvironmentCredential:$false -ExcludeWorkloadIdentityCredential:$true `
        -ExcludeManagedIdentityCredential:$true -ExcludeSharedTokenCacheCredential:$true `
        -ExcludeVisualStudioCredential:$true -ExcludeVisualStudioCodeCredential:$true `
        -ExcludeAzureCliCredential:$true -ExcludeAzurePowerShellCredential:$true `
        -ExcludeAzureDeveloperCliCredential:$true -ExcludeInteractiveBrowserCredential:$true
    if ((Get-AuthenticodeSignature -LiteralPath $file.FullName).Status -ne 'Valid') {
        throw 'Bundler signing did not produce a valid Authenticode signature.'
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'Missing bundler file path.' }
    Invoke-TauriWindowsSigning -LiteralPath $Path
}
