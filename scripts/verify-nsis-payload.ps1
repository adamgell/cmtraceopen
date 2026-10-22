#Requires -Version 7.3
# Inspect shipped NSIS payload bytes without executing the installer or app.
. (Join-Path $PSScriptRoot 'verify-windows-release-signatures.ps1')

function Expand-NsisVerificationPayload {
    param([string]$InstallerPath, [string]$ExtractionRoot, [string]$LogPath)
    $tool = Join-Path $env:ProgramFiles '7-Zip/7z.exe'
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw 'Hosted image 7-Zip is missing.' }
    $process = Start-Process -FilePath $tool -ArgumentList @(
        'x', '-y', "-o`"$ExtractionRoot`"", "`"$InstallerPath`"") -PassThru -NoNewWindow `
        -RedirectStandardOutput $LogPath -RedirectStandardError "$LogPath.stderr"
    if (-not $process.WaitForExit(120000)) {
        $process.Kill($true)
        $process.WaitForExit()
        throw 'NSIS payload extraction exceeded 120 seconds.'
    }
    if ($process.ExitCode -ne 0) { throw "NSIS payload extraction failed: $($process.ExitCode)" }
}

function Write-NsisPayloadReceipt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InstallerPath,
        [Parameter(Mandatory)][string]$ExtractionRoot,
        [Parameter(Mandatory)][string]$ReceiptRoot,
        [Parameter(Mandatory)][ValidateSet('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')][string]$Target
    )
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    $installer = Get-ReleaseFileEvidence -Path $InstallerPath
    if (Test-Path -LiteralPath $ExtractionRoot) { throw 'NSIS extraction directory already exists.' }
    [void][IO.Directory]::CreateDirectory($ReceiptRoot)
    $receiptPath = Join-Path $ReceiptRoot 'nsis-bundled-payload.json'
    if (Test-Path -LiteralPath $receiptPath) { throw 'NSIS payload receipt already exists.' }
    $context = Get-WindowsReleaseContext -Target $Target
    Expand-NsisVerificationPayload -InstallerPath $installer.path -ExtractionRoot $ExtractionRoot `
        -LogPath (Join-Path $ReceiptRoot 'nsis-extraction.log')
    $candidates = @(Get-ChildItem -LiteralPath $ExtractionRoot -Filter 'cmtrace-open.exe' -File -Recurse)
    if ($candidates.Count -ne 1) { throw "Expected exactly one NSIS application payload; found $($candidates.Count)." }
    $payload = Get-ReleaseFileEvidence -Path $candidates[0].FullName
    $signatureReceipt = Join-Path $ReceiptRoot 'nsis-payload-signature.json'
    Write-WindowsReleaseSignatureReceipt -Paths @($payload.path) -ReceiptPath $signatureReceipt -Target $Target
    Assert-VerifiedReleaseBytes @($installer, $payload)
    $document = [ordered]@{ schemaVersion = 1; evidenceKind = 'bundled-payload-signature'; nativeAcceptance = $false }
    foreach ($key in $context.Keys) { $document[$key] = $context[$key] }
    $document.installer = $installer
    $document.payload = $payload
    $document.signatureReceipt = $signatureReceipt
    $document | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receiptPath -Encoding utf8
}
