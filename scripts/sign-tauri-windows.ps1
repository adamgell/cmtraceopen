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

function Test-NsisTemporaryPe {
    param([IO.FileInfo]$File)
    if ($File.LinkType -or $File.Name -notmatch '^nst[0-9a-f]{4}\.tmp$') { return $false }
    $comparison = if ($IsWindows) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
    $parent = [IO.Path]::GetFullPath($File.DirectoryName).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $temp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if (-not [string]::Equals($parent, $temp, $comparison)) { return $false }
    $stream = [IO.File]::OpenRead($File.FullName)
    $reader = [IO.BinaryReader]::new($stream)
    try {
        if ($stream.Length -lt 88 -or $reader.ReadUInt16() -ne 0x5a4d) { return $false }
        $stream.Position = 0x3c
        $peOffset = $reader.ReadUInt32()
        if ($peOffset -lt 64 -or $peOffset -gt $stream.Length - 26) { return $false }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { return $false }
        $stream.Position = $peOffset + 20
        $optionalSize = $reader.ReadUInt16()
        $characteristics = $reader.ReadUInt16()
        if ($optionalSize -lt 2 -or $optionalSize -gt $stream.Length - $peOffset - 24 -or
            ($characteristics -band 0x0002) -eq 0) { return $false }
        return $reader.ReadUInt16() -in @(0x10b, 0x20b)
    } finally { $reader.Dispose() }
}

function Get-SigningHookByteEvidence {
    param([string]$LiteralPath, [string]$SignatureState = 'NotInspected')
    $item = Get-Item -LiteralPath $LiteralPath -ErrorAction Stop
    return [ordered]@{
        bytes = $item.Length
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        authenticodeStatus = $SignatureState
    }
}

function Write-SigningHookDiagnostic {
    param([string]$LiteralPath, [System.Collections.IDictionary]$Receipt)
    $json = $Receipt | ConvertTo-Json -Depth 5 -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 2048) { throw 'Signing diagnostic exceeded its byte limit.' }
    [IO.File]::WriteAllText($LiteralPath, $json, [Text.UTF8Encoding]::new($false))
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
    if ($file.PSIsContainer -or ($file.LinkType -and $file.LinkType -ne 'HardLink') -or
            $file.FullName.Contains(',')) {
        throw 'The bundler signing hook requires one regular EXE or DLL.'
    }
    $temporaryPe = $file.Extension -eq '.tmp' -and (Test-NsisTemporaryPe -File $file)
    if ($file.Extension -notin @('.exe', '.dll') -and -not $temporaryPe) {
        throw 'The bundler signing hook requires one regular EXE or DLL.'
    }
    if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { throw 'Missing private runner directory.' }
    $diagnosticRoot = Join-Path $env:RUNNER_TEMP 'cmtrace-signing-hooks'
    [void][IO.Directory]::CreateDirectory($diagnosticRoot)
    if ((Get-Item -LiteralPath $diagnosticRoot).LinkType) { throw 'Signing diagnostic directory must not be a link.' }
    $diagnosticPath = Join-Path $diagnosticRoot ([guid]::NewGuid().ToString('N') + '.json')
    $reservation = [IO.File]::Open($diagnosticPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    $reservation.Dispose()
    $receipt = [ordered]@{
        schemaVersion = 1
        selectedKind = $(if ($temporaryPe) { 'nsis-uninstaller' } else { $file.Extension.TrimStart('.').ToLowerInvariant() })
        entry = (Get-SigningHookByteEvidence -LiteralPath $file.FullName)
        post = $null
        phase = 'validated'
        outcome = 'entered'
        error = $null
    }
    Write-SigningHookDiagnostic -LiteralPath $diagnosticPath -Receipt $receipt
    try {
        if ($file.LinkType -eq 'HardLink') {
            $receipt.phase = 'hardlink-detachment'
            Write-SigningHookDiagnostic -LiteralPath $diagnosticPath -Receipt $receipt
            # Replace only the bundler-selected directory entry, preserving aliases.
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
        $receipt.phase = 'provider-import'
        Write-SigningHookDiagnostic -LiteralPath $diagnosticPath -Receipt $receipt
        $module = Import-VerifiedArtifactSigning
        $receipt.phase = 'provider-call'
        Write-SigningHookDiagnostic -LiteralPath $diagnosticPath -Receipt $receipt
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
        $receipt.phase = 'signature-check'
        Write-SigningHookDiagnostic -LiteralPath $diagnosticPath -Receipt $receipt
        $status = [string](Get-AuthenticodeSignature -LiteralPath $file.FullName).Status
        $receipt.post = Get-SigningHookByteEvidence -LiteralPath $file.FullName -SignatureState $status
        if ($status -ne 'Valid') { throw 'Bundler signing did not produce a valid Authenticode signature.' }
        $receipt.phase = 'complete'
        $receipt.outcome = 'signed'
        Write-SigningHookDiagnostic -LiteralPath $diagnosticPath -Receipt $receipt
    } catch {
        $receipt.error = switch ($receipt.phase) {
            'provider-call' { 'provider-failed' }
            'provider-import' { 'provider-import-failed' }
            'signature-check' { 'signature-verification-failed' }
            'hardlink-detachment' { 'hardlink-detachment-failed' }
            default { 'hook-failed' }
        }
        $receipt.outcome = 'failed'
        if ($null -eq $receipt.post) { $receipt.post = Get-SigningHookByteEvidence -LiteralPath $file.FullName }
        Write-SigningHookDiagnostic -LiteralPath $diagnosticPath -Receipt $receipt
        throw
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'Missing bundler file path.' }
    Invoke-TauriWindowsSigning -LiteralPath $Path
}
