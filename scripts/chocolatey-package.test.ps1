param(
  [string]$PackageRoot = (Join-Path $PSScriptRoot '../packaging/chocolatey/cmtraceopen')
)
$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ('cmtrace-choco-test-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $root | Out-Null
try {
  Copy-Item $PackageRoot (Join-Path $root 'package') -Recurse
  $package = Join-Path $root 'package'
  $nuspec = Join-Path $package 'cmtraceopen.nuspec'
  $xml = Get-Content $nuspec -Raw
  $version = [string]([xml]$xml).package.metadata.version
  $installer = Join-Path $root 'fixture.msi'
  [IO.File]::WriteAllText($installer, 'validation fixture, never executed')
  $digest = (Get-FileHash $installer -Algorithm SHA256).Hash.ToLowerInvariant()
  $scriptPath = Join-Path $package 'tools/chocolateyinstall.ps1'
  $source = Get-Content $scriptPath -Raw
  $checksumMatch = [regex]::Match($source, "checksum\s*=\s*'([0-9a-f]{64})'")
  if (-not $checksumMatch.Success) { throw 'Expected package checksum fixture anchor' }
  $source = $source.Replace($checksumMatch.Groups[1].Value, $digest)
  [IO.File]::WriteAllText($scriptPath, $source)
  $releasePath = Join-Path $root 'release.json'
  $assetName = "CMTrace-Open_${version}_x64.msi"
  $url = "https://github.com/adamgell/cmtraceopen/releases/download/v$version/$assetName"
  $release = @{
    tag_name = "v$version"; draft = $false; prerelease = $false
    assets = @(@{name = $assetName; digest = "sha256:$digest"; size = (Get-Item $installer).Length; browser_download_url = $url})
  }
  function Save-Release { $release | ConvertTo-Json -Depth 6 | Set-Content $releasePath }
  function Check { & (Join-Path $PSScriptRoot 'validate-chocolatey-package.ps1') -PackageRoot $package -ReleaseMetadataPath $releasePath -InstallerPath $installer }
  function Reject([string]$label) {
    $rejected = $false
    try { $null = Check } catch { $rejected = $true }
    if (-not $rejected) { throw "Accepted invalid case: $label" }
    Write-Output "PASS reject: $label"
  }
  Save-Release
  $result = Check
  if ($result.Version -ne $version -or $result.Sha256 -ne $digest) { throw 'Valid package result mismatched' }
  Write-Output 'PASS: valid release/package/download agreement'
  [IO.File]::AppendAllText($installer, 'tampered')
  Reject 'tampered MSI'
  [IO.File]::WriteAllText($installer, 'validation fixture, never executed')
  $release.draft = $true; Save-Release; Reject 'draft release'; $release.draft = $false
  $release.prerelease = $true; Save-Release; Reject 'prerelease'; $release.prerelease = $false
  $release.tag_name = 'v0.0.0-invalid'; Save-Release; Reject 'wrong release tag'; $release.tag_name = "v$version"
  $release.assets[0].digest = 'sha256:' + ('0' * 64); Save-Release; Reject 'release digest mismatch'; $release.assets[0].digest = "sha256:$digest"
  $release.assets[0].browser_download_url = 'https://example.invalid/installer.msi'; Save-Release; Reject 'asset origin mismatch'; $release.assets[0].browser_download_url = $url
  $asset = $release.assets[0]; $release.assets = @($asset, $asset); Save-Release; Reject 'ambiguous assets'; $release.assets = @($asset)
  Save-Release
  [IO.File]::WriteAllText($scriptPath, $source.Replace('/qn', '/passive'))
  Reject 'changed silent-install contract'
  [IO.File]::WriteAllText($scriptPath, $source)
  [IO.File]::WriteAllText($scriptPath, $source.Replace('Install-ChocolateyPackage @packageArgs', "`$packageArgs.url = 'https://example.invalid/different.msi'`nInstall-ChocolateyPackage @packageArgs"))
  Reject 'later installer argument mutation'
  [IO.File]::WriteAllText($scriptPath, $source.Replace('checksumType  =', "url64bit = 'https://example.invalid/different.msi'`n  checksum64 = '" + ('0' * 64) + "'`n  checksumType64 = 'sha256'`n  checksumType  ="))
  Reject 'additional architecture download arguments'
  [IO.File]::WriteAllText($scriptPath, $source)
  [IO.File]::WriteAllText($nuspec, $xml.Replace("<version>$version</version>", "<version>$version-beta</version>"))
  Reject 'nonstable package version'

  # Future releases render from the checked-in template without a version-edit PR.
  $release.tag_name = 'v2.0.3'
  $release.assets[0].name = 'CMTrace-Open_2.0.3_x64.msi'
  $release.assets[0].browser_download_url = 'https://github.com/adamgell/cmtraceopen/releases/download/v2.0.3/CMTrace-Open_2.0.3_x64.msi'
  Save-Release
  $rendered = & (Join-Path $PSScriptRoot 'prepare-chocolatey-package.ps1') -Tag 'v2.0.3' -ReleaseMetadataPath $releasePath -InstallerPath $installer -OutputDirectory (Join-Path $root 'rendered') -TemplateRoot $PackageRoot
  if ($rendered.Version -ne '2.0.3' -or $rendered.Sha256 -ne $digest) { throw 'Future release rendering mismatched' }
  $renderedNuspec = [xml](Get-Content (Join-Path $root 'rendered/cmtraceopen.nuspec') -Raw)
  if ($renderedNuspec.package.metadata.tags -cne 'cmtraceopen 2.0.3 log viewer cmtrace intune') { throw 'Rendered package tags mismatched' }
  if ($renderedNuspec.package.metadata.iconUrl -cne 'https://cdn.jsdelivr.net/gh/adamgell/cmtraceopen@v2.0.3/logo.png') { throw 'Rendered package icon must use the selected release tag' }
  if ($renderedNuspec.package.metadata.copyright -cne 'Copyright (c) 2026 Adam') { throw 'Rendered package copyright mismatched' }
  Write-Output 'PASS: future stable release renders and validates without source edits'
  foreach ($fragment in @(
    @{From='<version>'; To='<version >'; Label='version fragment'},
    @{From='<tags>cmtraceopen '; To='<tags>logviewer '; Label='tags fragment'},
    @{From='https://cdn.jsdelivr.net/gh/adamgell/cmtraceopen@'; To='https://example.invalid/cmtraceopen@'; Label='icon fragment'}
  )) {
    $badTemplate = Join-Path $root ('template-' + [guid]::NewGuid())
    Copy-Item $PackageRoot $badTemplate -Recurse
    $badNuspec = Join-Path $badTemplate 'cmtraceopen.nuspec'
    [IO.File]::WriteAllText($badNuspec, (Get-Content $badNuspec -Raw).Replace($fragment.From, $fragment.To))
    $badOutput = Join-Path $root ('output-' + [guid]::NewGuid())
    $rejected = $false
    try {
      $null = & (Join-Path $PSScriptRoot 'prepare-chocolatey-package.ps1') -Tag 'v2.0.3' -ReleaseMetadataPath $releasePath -InstallerPath $installer -OutputDirectory $badOutput -TemplateRoot $badTemplate
    } catch { $rejected = $true }
    if (-not $rejected -or (Test-Path $badOutput)) { throw "Accepted missing template $($fragment.Label) or wrote output before rejecting it" }
    Write-Output "PASS reject rendering: missing template $($fragment.Label)"
  }
  foreach ($badTag in @('v2.0.3-beta', 'v2.0.4', 'v2.0.3;Write-Host injected')) {
    $rejected = $false
    try {
      $null = & (Join-Path $PSScriptRoot 'prepare-chocolatey-package.ps1') -Tag $badTag -ReleaseMetadataPath $releasePath -InstallerPath $installer -OutputDirectory (Join-Path $root 'invalid-render') -TemplateRoot $PackageRoot
    } catch { $rejected = $true }
    if (-not $rejected -or (Test-Path (Join-Path $root 'invalid-render'))) { throw "Accepted invalid rendering tag: $badTag" }
    Write-Output "PASS reject rendering: $badTag"
  }
} finally {
  Remove-Item $root -Recurse -Force
}
