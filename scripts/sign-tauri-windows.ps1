param([Parameter(Position = 0)][string]$Path)

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
    if ($file.PSIsContainer -or $file.LinkType -or $file.Extension -notin @('.exe', '.dll') -or
            $file.FullName.Contains(',')) {
        throw 'The bundler signing hook requires one regular EXE or DLL.'
    }
    # Match the module pinned by azure/trusted-signing-action c7ab2a8.
    Import-Module ArtifactSigning -RequiredVersion 0.1.8 -ErrorAction Stop
    Invoke-ArtifactSigning -Endpoint $env:SIGNING_ENDPOINT `
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
