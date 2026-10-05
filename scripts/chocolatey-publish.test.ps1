$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ('cmtrace-choco-publish-test-' + [guid]::NewGuid())
$names = @('PACKAGE_VERSION', 'PACKAGE_SHA256', 'GITHUB_OUTPUT', 'GITHUB_STEP_SUMMARY')
$saved = @{}
foreach ($name in $names) { $saved[$name] = [Environment]::GetEnvironmentVariable($name) }
New-Item -ItemType Directory -Path $root | Out-Null
Push-Location $root
try {
  $workflow = Get-Content (Join-Path $PSScriptRoot '../.github/workflows/chocolatey-publish.yml') -Raw
  $match = [regex]::Match($workflow, '(?s)# BEGIN existing-version guard[^\r\n]*\r?\n(.*?)\s*# END existing-version guard')
  if (-not $match.Success) { throw 'Missing existing-version guard' }
  $guard = [scriptblock]::Create($match.Groups[1].Value)
  $env:PACKAGE_VERSION = '2.0.3'
  [IO.File]::WriteAllText((Join-Path $root 'fixture.nupkg'), 'inert package fixture')
  $env:PACKAGE_SHA256 = (Get-FileHash fixture.nupkg -Algorithm SHA256).Hash.ToLowerInvariant()
  $env:GITHUB_OUTPUT = Join-Path $root 'output.txt'
  $env:GITHUB_STEP_SUMMARY = Join-Path $root 'summary.txt'
  function Invoke-WebRequest {
    param($Uri, $OutFile, [switch]$PassThru, [switch]$SkipHttpErrorCheck, $TimeoutSec)
    if ($Uri -cne 'https://community.chocolatey.org/api/v2/package/cmtraceopen/2.0.3') { throw 'Wrong existing-version endpoint' }
    if ($script:status -eq 'network-error') { throw 'Simulated network failure' }
    Copy-Item fixture.nupkg $OutFile -Force
    if ($script:different) { Add-Content $OutFile 'different bytes' }
    [pscustomobject]@{StatusCode=$script:status}
  }
  foreach ($case in @(
    @{Status=404; Different=$false; Expected='needs_push=true'; Label='absent version'},
    @{Status=200; Different=$false; Expected='needs_push=false'; Label='identical existing version'},
    @{Status=200; Different=$true; Expected='reject'; Label='different existing bytes'},
    @{Status=403; Different=$false; Expected='reject'; Label='access denied'},
    @{Status=429; Different=$false; Expected='reject'; Label='rate limited'},
    @{Status=500; Different=$false; Expected='reject'; Label='server error'},
    @{Status='network-error'; Different=$false; Expected='reject'; Label='network failure'}
  )) {
    $script:status = $case.Status
    $script:different = $case.Different
    [IO.File]::WriteAllText($env:GITHUB_OUTPUT, '')
    $rejected = $false
    try { & $guard } catch { $rejected = $true }
    $output = Get-Content $env:GITHUB_OUTPUT -Raw
    if ($output) { $output = $output.Trim() } else { $output = '' }
    if ($case.Expected -eq 'reject') {
      if (-not $rejected -or $output) { throw "Guard did not fail closed: $($case.Label)" }
    } elseif ($rejected -or $output -cne $case.Expected) { throw "Guard decision mismatched: $($case.Label)" }
    Write-Output "PASS existing-version guard: $($case.Label)"
  }
} finally {
  Pop-Location
  foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $saved[$name]) }
  Remove-Item $root -Recurse -Force
}
