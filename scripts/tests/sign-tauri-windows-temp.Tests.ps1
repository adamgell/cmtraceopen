BeforeAll {
    . (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'sign-tauri-windows.ps1')
    function Invoke-ArtifactSigning { param($Files) }
    if (-not (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) {
        function Get-AuthenticodeSignature { param($LiteralPath) }
    }
}

Describe 'NSIS temporary PE signing boundary and diagnostic receipts' {
    BeforeEach {
        $settings = @('AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET',
            'SIGNING_ENDPOINT', 'SIGNING_ACCOUNT_NAME', 'SIGNING_PROFILE_NAME', 'RUNNER_TEMP')
        $previous = @{}
        foreach ($name in $settings) {
            $previous[$name] = [Environment]::GetEnvironmentVariable($name)
            [Environment]::SetEnvironmentVariable($name, 'offline-fixture')
        }
        $env:RUNNER_TEMP = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        [void][IO.Directory]::CreateDirectory($env:RUNNER_TEMP)
        $ownedFiles = [Collections.Generic.List[string]]::new()
        Mock Import-VerifiedArtifactSigning {
            [pscustomobject]@{ ExportedCommands = @{ 'Invoke-ArtifactSigning' = (Get-Command Invoke-ArtifactSigning) } }
        }
        Mock Invoke-ArtifactSigning { }
        Mock Get-AuthenticodeSignature { [pscustomobject]@{ Status = 'Valid' } }
        # A real PE assembly shipped with PowerShell supplies the fixture bytes.
        $peSource = [System.Management.Automation.PSObject].Assembly.Location
        $pePath = Join-Path $TestDrive ('payload-' + [guid]::NewGuid().ToString('N') + '.exe')
        [IO.File]::Copy($peSource, $pePath)
    }
    AfterEach {
        foreach ($path in $ownedFiles) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
        foreach ($name in $settings) { [Environment]::SetEnvironmentVariable($name, $previous[$name]) }
    }

    It 'signs a regular NSIS nst temporary PE in the current OS temporary directory' {
        $name = 'nst' + [guid]::NewGuid().ToString('N').Substring(0, 4) + '.tmp'
        $path = Join-Path ([IO.Path]::GetTempPath()) $name
        $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
        $ownedFiles.Add($path)
        try { $bytes = [IO.File]::ReadAllBytes($peSource); $stream.Write($bytes) }
        finally { $stream.Dispose() }
        Invoke-TauriWindowsSigning -LiteralPath $path
        Should -Invoke Invoke-ArtifactSigning -Times 1 -Exactly
        Should -Invoke Get-AuthenticodeSignature -Times 1 -Exactly
    }

    It 'rejects non-PE bytes even when the NSIS temporary name and parent match' {
        $path = Join-Path ([IO.Path]::GetTempPath()) ('nst' + [guid]::NewGuid().ToString('N').Substring(0, 4) + '.tmp')
        $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
        $ownedFiles.Add($path)
        try { $stream.Write([Text.Encoding]::UTF8.GetBytes('not a portable executable')) }
        finally { $stream.Dispose() }
        { Invoke-TauriWindowsSigning -LiteralPath $path } | Should -Throw
        Should -Invoke Invoke-ArtifactSigning -Times 0
    }

    It 'rejects a valid PE temporary file outside the current OS temporary directory' {
        $path = Join-Path $TestDrive 'nstABCD.tmp'
        [IO.File]::Copy($peSource, $path)
        { Invoke-TauriWindowsSigning -LiteralPath $path } | Should -Throw
        Should -Invoke Invoke-ArtifactSigning -Times 0
    }

    It 'rejects an NSIS-shaped symbolic link before importing the provider' {
        $path = Join-Path ([IO.Path]::GetTempPath()) ('nst' + [guid]::NewGuid().ToString('N').Substring(0, 4) + '.tmp')
        New-Item -ItemType SymbolicLink -Path $path -Target $pePath | Out-Null
        $ownedFiles.Add($path)
        { Invoke-TauriWindowsSigning -LiteralPath $path } | Should -Throw
        Should -Invoke Import-VerifiedArtifactSigning -Times 0
        Should -Invoke Invoke-ArtifactSigning -Times 0
    }

    It 'records bounded selected-kind and entry/post byte evidence without credentials or full paths' {
        Invoke-TauriWindowsSigning -LiteralPath $pePath
        $receipts = @(Get-ChildItem -LiteralPath (Join-Path $env:RUNNER_TEMP 'cmtrace-signing-hooks') -Filter '*.json' -File)
        $receipts.Count | Should -Be 1
        $raw = Get-Content -LiteralPath $receipts[0].FullName -Raw
        $receipt = $raw | ConvertFrom-Json
        $receipt.selectedKind | Should -Be 'exe'
        $receipt.entry.bytes | Should -Be ([IO.FileInfo]$pePath).Length
        $receipt.entry.sha256 | Should -Match '^[0-9a-f]{64}$'
        $receipt.post.sha256 | Should -Match '^[0-9a-f]{64}$'
        $receipt.post.authenticodeStatus | Should -Be 'Valid'
        $receipt.outcome | Should -Be 'signed'
        $raw | Should -Not -Match 'offline-fixture|AZURE_CLIENT_SECRET|SIGNING_ENDPOINT'
        $raw.Contains($pePath) | Should -BeFalse
    }

    It 'records a sanitized provider failure while preserving the thrown error' {
        Mock Invoke-ArtifactSigning { throw 'synthetic-private-provider-detail-9182' }
        { Invoke-TauriWindowsSigning -LiteralPath $pePath } | Should -Throw '*synthetic-private-provider-detail-9182*'
        $receipts = @(Get-ChildItem -LiteralPath (Join-Path $env:RUNNER_TEMP 'cmtrace-signing-hooks') -Filter '*.json' -File)
        $receipts.Count | Should -Be 1
        $raw = Get-Content -LiteralPath $receipts[0].FullName -Raw
        $receipt = $raw | ConvertFrom-Json
        $receipt.outcome | Should -Be 'failed'
        $receipt.error | Should -Be 'provider-failed'
        $raw | Should -Not -Match 'synthetic-private-provider-detail-9182|offline-fixture|AZURE_CLIENT_SECRET'
    }
}
