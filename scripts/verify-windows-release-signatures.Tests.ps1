BeforeAll {
    . (Join-Path $PSScriptRoot 'verify-windows-release-signatures.ps1')

    # Certificates are ephemeral test data, never installed in a trust store.
    # Only the Windows trust API and SDK location are replaced; name decoding,
    # certificate EKUs, process exits, file hashes and receipts use real code.
    function New-TestCertificate {
        param(
            [string]$Subject = 'CN=Adam Gell, O=Adam Gell, L=Elizabethtown, S=pa, C=US',
            [string]$Issuer = 'CN=Microsoft ID Verified CS AOC CA 03, O=Microsoft Corporation, C=US',
            [string]$Eku = '1.3.6.1.5.5.7.3.3'
        )
        $key = [System.Security.Cryptography.ECDsa]::Create()
        try {
            $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                $Subject, $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
            $usages = [System.Security.Cryptography.OidCollection]::new()
            [void]$usages.Add([System.Security.Cryptography.Oid]::new($Eku))
            $request.CertificateExtensions.Add(
                [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($usages, $true))
            $generator = [System.Security.Cryptography.X509Certificates.X509SignatureGenerator]::CreateForECDsa($key)
            # Expired leaves are deliberate: native trust validates the timestamp,
            # not a new comparison between today's date and leaf NotAfter.
            return $request.Create(
                [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new($Issuer),
                $generator, [datetimeoffset]::UtcNow.AddDays(-3), [datetimeoffset]::UtcNow.AddDays(-1),
                [guid]::NewGuid().ToByteArray())
        }
        finally { $key.Dispose() }
    }

    function New-TestTimestamp {
        param(
            [string]$Subject = 'CN=Microsoft Public RSA Time Stamping Authority, OU=nShield TSS ESN:test-one, OU=Microsoft America Operations, O=Microsoft Corporation, C=US',
            [string]$Issuer = 'CN=Microsoft Public RSA Timestamping CA 2020, O=Microsoft Corporation, C=US',
            [string]$Eku = '1.3.6.1.5.5.7.3.8'
        )
        New-TestCertificate -Subject $Subject -Issuer $Issuer -Eku $Eku
    }

    if (-not (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) {
        function Get-AuthenticodeSignature { param($LiteralPath) throw 'Windows trust API must be mocked in this test.' }
    }
    $originalEnvironment = @{}
    foreach ($name in @('GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'SIGNATURE_TEST_EXIT_CODE', 'SIGNATURE_TEST_ARGUMENTS')) {
        $originalEnvironment[$name] = [Environment]::GetEnvironmentVariable($name)
    }
    $env:GITHUB_SHA = (& git rev-parse HEAD).Trim()
    $env:GITHUB_RUN_ID = '123456'
    $env:GITHUB_RUN_ATTEMPT = '1'
}

AfterAll {
    foreach ($name in $originalEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $originalEnvironment[$name])
    }
}

Describe 'Windows release signature verification' {
    BeforeEach {
        $root = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        [void](New-Item -ItemType Directory -Path $root)
        $paths = @('Full.exe', 'Lite.exe', 'Setup.exe') | ForEach-Object {
            $path = Join-Path $root $_
            [System.IO.File]::WriteAllText($path, 'signed fixture bytes')
            $path
        }
        $receipt = Join-Path $root 'evidence/exes.json'
        $parameters = @{ Paths = $paths; ReceiptPath = $receipt; Target = 'x86_64-pc-windows-msvc' }
        $tool = Join-Path $root 'fake signtool.ps1'
        @'
[System.IO.File]::WriteAllText($env:SIGNATURE_TEST_ARGUMENTS, (ConvertTo-Json @($args)))
Write-Output 'fixture verification output'
exit [int]$env:SIGNATURE_TEST_EXIT_CODE
'@ | Set-Content -LiteralPath $tool
        $env:SIGNATURE_TEST_EXIT_CODE = '0'
        $env:SIGNATURE_TEST_ARGUMENTS = Join-Path $root 'arguments.json'
        $signature = [pscustomobject]@{
            Status = 'Valid'
            StatusMessage = 'fixture native trust result'
            SignatureType = 'Authenticode'
            SignerCertificate = New-TestCertificate
            TimeStamperCertificate = New-TestTimestamp
        }
        Mock Get-WindowsSignTool { [pscustomobject]@{ Path = $tool; Version = 'test-sdk' } }
        Mock Get-AuthenticodeSignature { $signature }
    }

    It 'verifies every explicit EXE and binds real hashes to source and run before writing a receipt' {
        Write-WindowsReleaseSignatureReceipt @parameters
        $result = Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
        $result.sourceCommit | Should -BeExactly $env:GITHUB_SHA
        $result.runId | Should -BeExactly '123456'
        $result.runAttempt | Should -BeExactly '1'
        $result.target | Should -BeExactly 'x86_64-pc-windows-msvc'
        $result.files.Count | Should -Be 3
        foreach ($file in $result.files) {
            $file.sha256 | Should -BeExactly (Get-FileHash -LiteralPath $file.path -Algorithm SHA256).Hash.ToLowerInvariant()
            $file.authenticodeStatus | Should -BeExactly 'Valid'
            $file.signtoolExitCode | Should -Be 0
            Get-Content -LiteralPath $file.signtoolLog | Should -Contain 'fixture verification output'
        }
        $arguments = Get-Content -LiteralPath $env:SIGNATURE_TEST_ARGUMENTS -Raw | ConvertFrom-Json
        ($arguments -join '|') | Should -BeExactly "verify|/pa|/all|/v|/tw|$($paths[2])"
        Should -Invoke Get-AuthenticodeSignature -Times 3 -Exactly
        Assert-WindowsReleaseSignatureReceipts -ReceiptPaths @($receipt) -Paths $paths -Target $parameters.Target
    }

    It 'accepts an explicit MSI and ARM64 evidence without executing the artifact' {
        $msi = Join-Path $root 'Application.msi'
        [System.IO.File]::WriteAllText($msi, 'MSI fixture')
        Write-WindowsReleaseSignatureReceipt -Paths @($msi) -ReceiptPath $receipt -Target 'aarch64-pc-windows-msvc'
        Assert-WindowsReleaseSignatureReceipts -ReceiptPaths @($receipt) -Paths @($msi) -Target 'aarch64-pc-windows-msvc'
    }

    It 'accepts reordered names and rotated publisher and timestamp leaves' {
        $oldPublisher = $signature.SignerCertificate.Thumbprint
        $oldTimestamp = $signature.TimeStamperCertificate.Thumbprint
        $signature.SignerCertificate = New-TestCertificate -Subject 'C=US, S=pa, L=Elizabethtown, O=Adam Gell, CN=Adam Gell'
        $signature.TimeStamperCertificate = New-TestTimestamp -Subject 'O=Microsoft Corporation, OU=nShield TSS ESN:rotated, C=US, CN=Microsoft Public RSA Time Stamping Authority'
        $signature.SignerCertificate.Thumbprint | Should -Not -Be $oldPublisher
        $signature.TimeStamperCertificate.Thumbprint | Should -Not -Be $oldTimestamp
        Write-WindowsReleaseSignatureReceipt @parameters
        $result = Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
        $result.files[0].signer.thumbprint | Should -BeExactly $signature.SignerCertificate.Thumbprint
        $result.files[0].timestamp.thumbprint | Should -BeExactly $signature.TimeStamperCertificate.Thumbprint
    }

    It 'rejects native verification exit <_> without a success receipt' -ForEach @(1, 2, 3) {
        $env:SIGNATURE_TEST_EXIT_CODE = "$_"
        { Write-WindowsReleaseSignatureReceipt @parameters } | Should -Throw '*SignTool verification failed*'
        Test-Path -LiteralPath $receipt | Should -BeFalse
    }

    It 'rejects Authenticode status <_>' -ForEach @('NotSigned', 'HashMismatch', 'NotTrusted', 'UnknownError', 'NotSupportedFileFormat', 'Incompatible') {
        $signature.Status = $_
        { Write-WindowsReleaseSignatureReceipt @parameters } | Should -Throw '*Authenticode verification failed*'
        Test-Path -LiteralPath $receipt | Should -BeFalse
    }

    It 'rejects a missing <_> certificate' -ForEach @('SignerCertificate', 'TimeStamperCertificate') {
        $signature.$_ = $null
        { Write-WindowsReleaseSignatureReceipt @parameters } | Should -Throw '*certificate is missing*'
        Test-Path -LiteralPath $receipt | Should -BeFalse
    }

    It 'rejects a catalog signature instead of the embedded signature' {
        $signature.SignatureType = 'Catalog'
        { Write-WindowsReleaseSignatureReceipt @parameters } | Should -Throw '*embedded Authenticode*'
    }

    It 'rejects wrong or ambiguous publisher fields: <Subject>' -ForEach @(
        @{ Subject = 'CN=Someone Else, O=Adam Gell, L=Elizabethtown, S=pa, C=US' },
        @{ Subject = 'CN=Adam Gell, O=Someone Else, L=Elizabethtown, S=pa, C=US' },
        @{ Subject = 'CN=Adam Gell, O=Adam Gell, L=Elsewhere, S=pa, C=US' },
        @{ Subject = 'CN=Adam Gell, O=Adam Gell, L=Elizabethtown, S=other, C=US' },
        @{ Subject = 'CN=Adam Gell, O=Adam Gell, L=Elizabethtown, S=pa, C=GB' },
        @{ Subject = 'CN=Adam Gell, O=Adam Gell, C=US' },
        @{ Subject = 'CN=Adam Gell, CN=Someone Else, O=Adam Gell, L=Elizabethtown, S=pa, C=US' }
    ) {
        $signature.SignerCertificate = New-TestCertificate -Subject $Subject
        { Write-WindowsReleaseSignatureReceipt @parameters } | Should -Throw '*publisher*'
        Test-Path -LiteralPath $receipt | Should -BeFalse
    }

    It 'rejects an unexpected timestamp authority' {
        $signature.TimeStamperCertificate = New-TestTimestamp -Subject 'CN=Other Authority, O=Microsoft Corporation, C=US'
        { Write-WindowsReleaseSignatureReceipt @parameters } | Should -Throw '*timestamp authority*'
    }

    It 'rejects an unexpected timestamp issuer' {
        $signature.TimeStamperCertificate = New-TestTimestamp -Issuer 'CN=Other Issuer, O=Microsoft Corporation, C=US'
        { Write-WindowsReleaseSignatureReceipt @parameters } | Should -Throw '*timestamp issuer*'
    }

    It 'rejects an incorrect <Kind> EKU' -ForEach @(@{ Kind = 'publisher' }, @{ Kind = 'timestamp' }) {
        if ($Kind -eq 'publisher') { $signature.SignerCertificate = New-TestCertificate -Eku '1.3.6.1.5.5.7.3.1' }
        else { $signature.TimeStamperCertificate = New-TestTimestamp -Eku '1.3.6.1.5.5.7.3.1' }
        { Write-WindowsReleaseSignatureReceipt @parameters } | Should -Throw '*extended key usage*'
    }

    It 'rejects a missing artifact before verification' {
        Remove-Item -LiteralPath $paths[1]
        { Write-WindowsReleaseSignatureReceipt @parameters } | Should -Throw
        Should -Invoke Get-AuthenticodeSignature -Times 0 -Exactly
        Test-Path -LiteralPath $receipt | Should -BeFalse
    }

    It 'rejects duplicate explicit paths' {
        $parameters.Paths = @($paths[0], $paths[0])
        { Write-WindowsReleaseSignatureReceipt @parameters } | Should -Throw '*Duplicate artifact*'
    }

    It 'rejects bytes changed during native verification' {
        Mock Get-AuthenticodeSignature {
            param($LiteralPath)
            [System.IO.File]::AppendAllText($LiteralPath, 'modified')
            $signature
        }
        { Write-WindowsReleaseSignatureReceipt @parameters } | Should -Throw '*changed*'
        Test-Path -LiteralPath $receipt | Should -BeFalse
    }

    It 'rechecks earlier files after the entire batch is verified' {
        Mock Get-AuthenticodeSignature {
            param($LiteralPath)
            if ($LiteralPath -eq $paths[2]) { [System.IO.File]::AppendAllText($paths[0], 'modified later') }
            $signature
        }
        { Write-WindowsReleaseSignatureReceipt @parameters } | Should -Throw '*changed*'
        Test-Path -LiteralPath $receipt | Should -BeFalse
    }

    It 'refuses to overwrite an existing receipt' {
        Write-WindowsReleaseSignatureReceipt @parameters
        { Write-WindowsReleaseSignatureReceipt @parameters } | Should -Throw '*already exists*'
    }

    It 'rejects a source SHA that differs from the actual checkout' {
        $saved = $env:GITHUB_SHA
        try {
            $env:GITHUB_SHA = 'a' * 40
            { Write-WindowsReleaseSignatureReceipt @parameters } | Should -Throw '*checkout*'
        }
        finally { $env:GITHUB_SHA = $saved }
    }

    It 'rejects artifacts changed after their signature receipt was written' {
        Write-WindowsReleaseSignatureReceipt @parameters
        [System.IO.File]::AppendAllText($paths[0], 'changed after attestation')
        { Assert-WindowsReleaseSignatureReceipts -ReceiptPaths @($receipt) -Paths $paths -Target $parameters.Target } | Should -Throw '*changed*'
    }

    It 'rejects artifacts missing at upload time' {
        Write-WindowsReleaseSignatureReceipt @parameters
        Remove-Item -LiteralPath $paths[0]
        { Assert-WindowsReleaseSignatureReceipts -ReceiptPaths @($receipt) -Paths $paths -Target $parameters.Target } | Should -Throw
    }

    It 'rejects incomplete receipt coverage' {
        Write-WindowsReleaseSignatureReceipt @parameters
        $extra = Join-Path $root 'Unverified.msi'
        [System.IO.File]::WriteAllText($extra, 'not verified')
        { Assert-WindowsReleaseSignatureReceipts -ReceiptPaths @($receipt) -Paths @($paths + $extra) -Target $parameters.Target } | Should -Throw '*coverage*'
    }

    It 'rejects duplicate receipt coverage' {
        Write-WindowsReleaseSignatureReceipt @parameters
        { Assert-WindowsReleaseSignatureReceipts -ReceiptPaths @($receipt, $receipt) -Paths $paths -Target $parameters.Target } | Should -Throw '*Duplicate*'
    }

    It 'rejects receipt metadata from another <_>' -ForEach @('sourceCommit', 'runId', 'runAttempt', 'target', 'schemaVersion') {
        Write-WindowsReleaseSignatureReceipt @parameters
        $data = Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
        $data.$_ = 'wrong'
        $data | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receipt
        { Assert-WindowsReleaseSignatureReceipts -ReceiptPaths @($receipt) -Paths $paths -Target $parameters.Target } | Should -Throw '*receipt*'
    }

    It 'combines the EXE and MSI receipts for the exact four-file upload set' {
        Write-WindowsReleaseSignatureReceipt @parameters
        $msi = Join-Path $root 'Application.msi'
        [System.IO.File]::WriteAllText($msi, 'MSI fixture')
        $msiReceipt = Join-Path $root 'evidence/msi.json'
        Write-WindowsReleaseSignatureReceipt -Paths @($msi) -ReceiptPath $msiReceipt -Target $parameters.Target
        Assert-WindowsReleaseSignatureReceipts -ReceiptPaths @($receipt, $msiReceipt) -Paths @($paths + $msi) -Target $parameters.Target
    }

    It 'rejects a trust API exception without a receipt' {
        Mock Get-AuthenticodeSignature { throw 'trust API failed' }
        { Write-WindowsReleaseSignatureReceipt @parameters } | Should -Throw '*trust API failed*'
        Test-Path -LiteralPath $receipt | Should -BeFalse
    }

    It 'rejects a receipt with unsuccessful <Field>' -ForEach @(
        @{ Field = 'signtoolExitCode'; Value = 2 },
        @{ Field = 'authenticodeStatus'; Value = 'NotTrusted' },
        @{ Field = 'signatureType'; Value = 'Catalog' }
    ) {
        Write-WindowsReleaseSignatureReceipt @parameters
        $data = Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
        $data.files[0].$Field = $Value
        $data | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receipt
        { Assert-WindowsReleaseSignatureReceipts -ReceiptPaths @($receipt) -Paths $paths -Target $parameters.Target } | Should -Throw '*successful verification*'
    }
}

Describe 'Windows SDK SignTool selection' {
    It 'selects the newest installed x64 SDK numerically without using PATH' {
        $sdk = Join-Path $TestDrive 'sdk'
        foreach ($version in @('10.0.9.0', '10.0.10.0', 'not-a-version')) {
            $directory = Join-Path $sdk "$version/x64"
            [void](New-Item -ItemType Directory -Path $directory -Force)
            [System.IO.File]::WriteAllText((Join-Path $directory 'signtool.exe'), 'SDK fixture')
        }
        $result = Get-WindowsSignTool -SdkRoot $sdk
        $result.Path | Should -BeExactly (Join-Path $sdk '10.0.10.0/x64/signtool.exe')
    }

    It 'rejects an SDK with no SignTool executable' {
        $sdk = Join-Path $TestDrive 'missing-tool'
        [void](New-Item -ItemType Directory -Path $sdk)
        { Get-WindowsSignTool -SdkRoot $sdk } | Should -Throw '*SignTool is missing*'
    }
}
