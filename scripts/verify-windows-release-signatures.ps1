#Requires -Version 7.3
# Dot-source this file in the existing hosted Windows release jobs. Verification
# uses the installed SDK and Windows trust APIs; it never signs or changes trust.

function Get-WindowsSignTool {
    param([string]$SdkRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\bin")
    $tool = Get-ChildItem -LiteralPath $SdkRoot -Directory -ErrorAction Stop | ForEach-Object {
        $version = $null
        if ([version]::TryParse($_.Name, [ref]$version)) {
            $path = Join-Path $_.FullName 'x64/signtool.exe'
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                [pscustomobject]@{ Path = $path; SdkVersion = $version }
            }
        }
    } | Sort-Object SdkVersion -Descending | Select-Object -First 1
    if ($null -eq $tool) { throw "Windows SDK x64 SignTool is missing from $SdkRoot" }
    [pscustomobject]@{
        Path = $tool.Path
        Version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($tool.Path).FileVersion
    }
}

function Get-WindowsReleaseContext {
    param([string]$Target)
    if ($env:GITHUB_SHA -cnotmatch '^[0-9a-f]{40}$' -or
        $env:GITHUB_RUN_ID -notmatch '^[1-9][0-9]*$' -or
        $env:GITHUB_RUN_ATTEMPT -notmatch '^[1-9][0-9]*$') {
        throw 'Missing or invalid GitHub source/run context.'
    }
    $checkout = (& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $checkout -cne $env:GITHUB_SHA) {
        throw 'The checkout does not match the GitHub source commit.'
    }
    [ordered]@{
        sourceCommit = $checkout
        runId = $env:GITHUB_RUN_ID
        runAttempt = $env:GITHUB_RUN_ATTEMPT
        target = $Target
    }
}

function Assert-CertificateName {
    param($Name, [hashtable]$Expected, [string]$Label)
    # Decode ASN.1 RDNs with .NET, not commas or the display order of Subject.
    # Only required identity fields must be unique; TSA device OUs may repeat.
    $found = @{}
    foreach ($rdn in $Name.EnumerateRelativeDistinguishedNames()) {
        if ($rdn.HasMultipleElements) { throw "Ambiguous $Label name." }
        $oid = $rdn.GetSingleElementType().Value
        if ($Expected.ContainsKey($oid)) {
            if ($found.ContainsKey($oid)) { throw "Duplicate $Label identity field $oid." }
            $found[$oid] = $rdn.GetSingleElementValue()
        }
    }
    foreach ($oid in $Expected.Keys) {
        if (-not $found.ContainsKey($oid) -or $found[$oid] -cne $Expected[$oid]) {
            throw "Unexpected $Label identity field $oid."
        }
    }
}

function Assert-CertificateUsage {
    param($Certificate, [string]$Oid, [string]$Label)
    $extensions = @($Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
    if ($extensions.Count -ne 1) { throw "Missing or ambiguous $Label extended key usage." }
    $usage = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
        $extensions[0], $extensions[0].Critical)
    if ($Oid -notin @($usage.EnhancedKeyUsages | ForEach-Object { $_.Value })) {
        throw "Unexpected $Label extended key usage."
    }
}

function Get-CertificateReceipt {
    param($Certificate)
    [ordered]@{
        subject = $Certificate.Subject
        issuer = $Certificate.Issuer
        serialNumber = $Certificate.SerialNumber
        thumbprint = $Certificate.Thumbprint
        notBeforeUtc = $Certificate.NotBefore.ToUniversalTime().ToString('o')
        notAfterUtc = $Certificate.NotAfter.ToUniversalTime().ToString('o')
    }
}

function Get-ReleaseFileEvidence {
    param([string]$Path)
    $file = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($file -isnot [System.IO.FileInfo] -or
        ($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "Artifact must be a regular file: $Path"
    }
    [ordered]@{
        path = $file.FullName
        bytes = $file.Length
        sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    }
}

function Assert-VerifiedReleaseBytes {
    param([object[]]$Files)
    foreach ($file in $Files) {
        $actual = Get-ReleaseFileEvidence -Path $file.path
        if ($actual.sha256 -cne $file.sha256 -or $actual.bytes -ne $file.bytes) {
            throw "Verified artifact bytes changed: $($file.path)"
        }
    }
}

function Write-WindowsReleaseSignatureReceipt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$Paths,
        [Parameter(Mandatory)][string]$ReceiptPath,
        [Parameter(Mandatory)][ValidateSet('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')][string]$Target
    )
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    # Capture the native result ourselves, including SignTool warning exit 2.
    $PSNativeCommandUseErrorActionPreference = $false
    $context = Get-WindowsReleaseContext -Target $Target
    $receipt = [System.IO.Path]::GetFullPath($ReceiptPath)
    if (Test-Path -LiteralPath $receipt) { throw "Receipt already exists: $receipt" }
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $files = @(foreach ($path in $Paths) {
        $file = Get-ReleaseFileEvidence -Path $path
        if (-not $seen.Add($file.path)) { throw "Duplicate artifact: $($file.path)" }
        $file
    })
    $tool = Get-WindowsSignTool
    [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($receipt))
    $index = 0
    foreach ($file in $files) {
        $logPath = "$receipt.$index.signtool.log"
        $output = & $tool.Path verify /pa /all /v /tw $file.path 2>&1
        $exitCode = $LASTEXITCODE
        $output | Out-File -LiteralPath $logPath -Encoding utf8
        if ($exitCode -ne 0) { throw "SignTool verification failed ($exitCode): $($file.path). See $logPath" }
        $signature = Get-AuthenticodeSignature -LiteralPath $file.path
        if ($signature.Status -ne 'Valid') {
            throw "Authenticode verification failed for $($file.path): $($signature.Status) ($($signature.StatusMessage))"
        }
        if ($signature.SignatureType -ne 'Authenticode') { throw 'Expected an embedded Authenticode signature.' }
        if ($null -eq $signature.SignerCertificate) { throw 'Publisher certificate is missing.' }
        if ($null -eq $signature.TimeStamperCertificate) { throw 'Timestamp certificate is missing.' }

        # Grounded in the existing release certificate profile, not a leaf pin.
        Assert-CertificateName $signature.SignerCertificate.SubjectName @{
            '2.5.4.3' = 'Adam Gell'; '2.5.4.10' = 'Adam Gell'; '2.5.4.7' = 'Elizabethtown'
            '2.5.4.8' = 'pa'; '2.5.4.6' = 'US'
        } 'publisher'
        Assert-CertificateUsage $signature.SignerCertificate '1.3.6.1.5.5.7.3.3' 'publisher'
        Assert-CertificateName $signature.TimeStamperCertificate.SubjectName @{
            '2.5.4.3' = 'Microsoft Public RSA Time Stamping Authority'
            '2.5.4.10' = 'Microsoft Corporation'; '2.5.4.6' = 'US'
        } 'timestamp authority'
        Assert-CertificateName $signature.TimeStamperCertificate.IssuerName @{
            '2.5.4.3' = 'Microsoft Public RSA Timestamping CA 2020'
            '2.5.4.10' = 'Microsoft Corporation'; '2.5.4.6' = 'US'
        } 'timestamp issuer'
        Assert-CertificateUsage $signature.TimeStamperCertificate '1.3.6.1.5.5.7.3.8' 'timestamp'
        # Native trust verifies chains and timestamp validity. Checking leaf
        # expiry against today's date would reject legitimate timestamped files.
        $file.signtoolExitCode = $exitCode
        $file.signtoolLog = $logPath
        $file.authenticodeStatus = [string]$signature.Status
        $file.signatureType = [string]$signature.SignatureType
        $file.signer = Get-CertificateReceipt $signature.SignerCertificate
        $file.timestamp = Get-CertificateReceipt $signature.TimeStamperCertificate
        $index++
    }
    # Recheck the whole batch, including files verified before later commands ran.
    Assert-VerifiedReleaseBytes $files
    $document = [ordered]@{ schemaVersion = 1 }
    foreach ($key in $context.Keys) { $document[$key] = $context[$key] }
    $document.verifiedAtUtc = [datetime]::UtcNow.ToString('o')
    $document.signtool = $tool
    $document.files = $files
    $stream = [System.IO.File]::Open($receipt, [System.IO.FileMode]::CreateNew)
    $writer = [System.IO.StreamWriter]::new($stream)
    try { $writer.WriteLine(($document | ConvertTo-Json -Depth 8)) }
    finally { $writer.Dispose() }
}

function Assert-WindowsReleaseSignatureReceipts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$ReceiptPaths,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$Paths,
        [Parameter(Mandatory)][ValidateSet('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')][string]$Target
    )
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    $context = Get-WindowsReleaseContext -Target $Target
    $expected = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($path in $Paths) {
        $file = Get-ReleaseFileEvidence -Path $path
        if (-not $expected.Add($file.path)) { throw "Duplicate artifact: $($file.path)" }
    }
    $covered = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($receiptPath in $ReceiptPaths) {
        $receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
        if ($receipt.schemaVersion -ne 1) { throw 'Unsupported signature receipt schema.' }
        foreach ($key in $context.Keys) {
            if ($receipt.$key -cne $context[$key]) { throw "Signature receipt $key does not match this build." }
        }
        foreach ($file in $receipt.files) {
            if (-not $covered.Add($file.path)) { throw "Duplicate receipt artifact: $($file.path)" }
            if (-not $expected.Contains($file.path)) { throw "Unexpected receipt coverage: $($file.path)" }
            if ($file.signtoolExitCode -ne 0 -or $file.authenticodeStatus -ne 'Valid' -or $file.signatureType -ne 'Authenticode') {
                throw 'Signature receipt does not record successful verification.'
            }
        }
        Assert-VerifiedReleaseBytes $receipt.files
    }
    if (-not $covered.SetEquals($expected)) { throw 'Signature receipt coverage is incomplete.' }
}
