$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$guard = Join-Path $PSScriptRoot 'chocolatey-submission-guard.ps1'
$baseline = Join-Path $PSScriptRoot 'fixtures/chocolatey/cmtraceopen.1.6.2.original.nupkg'
$root = Join-Path ([IO.Path]::GetTempPath()) ('cmtrace-choco-publish-test-' + [guid]::NewGuid())
$names = @('GITHUB_REPOSITORY', 'GITHUB_EVENT_NAME', 'GITHUB_REF', 'GH_TOKEN', 'PACKAGE_VERSION', 'PACKAGE_SHA256', 'GUARD_SHA256', 'SUBMISSION_MODE', 'RELEASE_TAG', 'PUBLISH_REQUESTED', 'GITHUB_OUTPUT', 'GITHUB_STEP_SUMMARY', 'CHOCOLATEY_API_KEY')
$saved = @{}
$fixtureState = @{}
foreach ($name in $names) { $saved[$name] = [Environment]::GetEnvironmentVariable($name) }
New-Item -ItemType Directory -Path $root | Out-Null
try {
  $candidate = Join-Path $root 'candidate.nupkg'
  $server = Join-Path $root 'server.nupkg'
  function Edit-Package([string]$path, [scriptblock]$edit) {
    $zip = [IO.Compression.ZipFile]::Open($path, [IO.Compression.ZipArchiveMode]::Update)
    try { & $edit $zip } finally { $zip.Dispose() }
  }
  function Set-Metadata([string]$path, [scriptblock]$metadataEdit) {
    Edit-Package $path {
      param($zip)
      $entry = $zip.GetEntry('cmtraceopen.nuspec')
      $reader = [IO.StreamReader]::new($entry.Open())
      try { [xml]$xml = $reader.ReadToEnd() } finally { $reader.Dispose() }
      & $metadataEdit $xml
      $entry.Delete()
      $writer = [IO.StreamWriter]::new($zip.CreateEntry('cmtraceopen.nuspec').Open())
      try { $writer.Write($xml.OuterXml) } finally { $writer.Dispose() }
    }
  }
  function Reset-Fixture {
    Copy-Item $baseline $server -Force
    Copy-Item $baseline $candidate -Force
    Set-Metadata $candidate {
      param($xml)
      $xml.package.metadata.iconUrl = 'https://cdn.jsdelivr.net/gh/adamgell/cmtraceopen@v1.6.2/logo.png'
      $xml.package.metadata.tags = 'cmtraceopen 1.6.2 log viewer cmtrace intune'
      $copyright = $xml.CreateElement('copyright', $xml.DocumentElement.NamespaceURI)
      $copyright.InnerText = 'Copyright (c) 2026 Adam'
      $null = $xml.package.metadata.AppendChild($copyright)
    }
    $env:GITHUB_REPOSITORY = 'adamgell/cmtraceopen'
    $env:GITHUB_EVENT_NAME = 'workflow_dispatch'
    $env:GITHUB_REF = 'refs/heads/main'
    $env:GH_TOKEN = 'inert-test-token'
    $fixtureState.mode = 'moderator-correction'
    $fixtureState.version = '1.6.2'
    $fixtureState.tag = 'v1.6.2'
    $fixtureState.publish = $true
    $fixtureState.status = 200
    $fixtureState.metadataStatus = 200
    $fixtureState.githubStatus = 200
    $hash = [Convert]::ToBase64String([Security.Cryptography.SHA512]::HashData([IO.File]::ReadAllBytes($server)))
    $fixtureState.metadata = @"
<entry xmlns="http://www.w3.org/2005/Atom" xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices" xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata"><id>https://community.chocolatey.org/api/v2/Packages(Id='cmtraceopen',Version='1.6.2')</id><title>cmtraceopen</title><m:properties><d:Version>1.6.2</d:Version><d:IsApproved m:type="Edm.Boolean">false</d:IsApproved><d:PackageStatus>Submitted</d:PackageStatus><d:PackageSubmittedStatus>Waiting</d:PackageSubmittedStatus><d:PackageApprovedDate m:null="true"/><d:PackageHashAlgorithm>SHA512</d:PackageHashAlgorithm><d:PackageHash>$hash</d:PackageHash></m:properties></entry>
"@
    $fixtureState.release = @{
      id=403346505; tag_name='v1.6.2'; draft=$false; prerelease=$false; published_at='2026-10-05T19:24:37Z'
      assets=@(@{id=611417257; name='CMTrace-Open_1.6.2_x64.msi'; size=17838080; digest='sha256:12166bd88a2e4f4c2faa216dcce950e1b4eedc33f64aed48e171d11e63bc32d2'; browser_download_url='https://github.com/adamgell/cmtraceopen/releases/download/v1.6.2/CMTrace-Open_1.6.2_x64.msi'})
    }
    $fixtureState.tagRef = @{ref='refs/tags/v1.6.2'; object=@{type='tag'; sha='7d7cb1bec8b372fbaf08845c2ac6bab6668ba6c0'}}
  }
  function Invoke-WebRequest {
    param($Uri, $OutFile, [switch]$PassThru, [switch]$SkipHttpErrorCheck, $TimeoutSec, $Headers)
    if ($fixtureState.status -eq 'network-error') { throw 'Simulated network failure' }
    if ($Uri -ceq "https://community.chocolatey.org/api/v2/package/cmtraceopen/$($fixtureState.version)") {
      Copy-Item $server $OutFile -Force
      return [pscustomobject]@{StatusCode=$fixtureState.status}
    }
    if ($Uri -ceq "https://community.chocolatey.org/api/v2/Packages(Id='cmtraceopen',Version='1.6.2')") {
      return [pscustomobject]@{StatusCode=$fixtureState.metadataStatus; Content=$fixtureState.metadata}
    }
    if ($Uri -ceq 'https://api.github.com/repos/adamgell/cmtraceopen/releases/tags/v1.6.2') {
      return [pscustomobject]@{StatusCode=$fixtureState.githubStatus; Content=($fixtureState.release | ConvertTo-Json -Depth 6)}
    }
    if ($Uri -ceq 'https://api.github.com/repos/adamgell/cmtraceopen/git/ref/tags/v1.6.2') {
      return [pscustomobject]@{StatusCode=$fixtureState.githubStatus; Content=($fixtureState.tagRef | ConvertTo-Json -Depth 6)}
    }
    throw "Unexpected endpoint: $Uri"
  }
  function Check {
    & $guard -PackagePath $candidate -Version $fixtureState.version -Sha256 (Get-FileHash $candidate -Algorithm SHA256).Hash.ToLowerInvariant() -Mode $fixtureState.mode -Tag $fixtureState.tag -PublishRequested:$fixtureState.publish
  }
  function Case([string]$label, [scriptblock]$arrange, [string]$expected) {
    Reset-Fixture
    & $arrange
    $rejected = $false
    $result = $null
    $reason = ''
    try { $result = Check } catch { $rejected = $true; $reason = $_.Exception.Message }
    if ($expected -eq 'reject') {
      if (-not $rejected -or $null -ne $result) { throw "Guard did not fail closed: $label" }
    } elseif ($rejected -or $result -isnot [bool] -or $result.ToString() -cne $expected) {
      throw "Guard decision mismatched: $label ($reason)"
    }
    Write-Output "PASS submission guard: $label"
  }
  Case 'normal absent version' { $fixtureState.mode='normal'; $fixtureState.version='2.0.3'; $fixtureState.status=404 } 'True'
  Case 'normal identical version' { $fixtureState.mode='normal'; $fixtureState.version='2.0.3'; Copy-Item $candidate $server -Force } 'False'
  Case 'normal different bytes' { $fixtureState.mode='normal'; $fixtureState.version='2.0.3' } 'reject'
  foreach ($status in @(403,429,500,'network-error')) { Case "normal HTTP/network $status" { $fixtureState.mode='normal'; $fixtureState.status=$status } 'reject' }
  Case 'authorized moderation correction' {} 'True'
  Case 'release event' { $env:GITHUB_EVENT_NAME='release' } 'reject'
  Case 'non-main ref' { $env:GITHUB_REF='refs/heads/other' } 'reject'
  Case 'other repository' { $env:GITHUB_REPOSITORY='other/cmtraceopen' } 'reject'
  Case 'other version' { $fixtureState.version='1.6.3' } 'reject'
  Case 'other tag' { $fixtureState.tag='v1.6.3' } 'reject'
  Case 'publish not selected' { $fixtureState.publish=$false } 'reject'
  Case 'missing existing version' { $fixtureState.status=404 } 'reject'
  Case 'changed previous package' { Copy-Item $candidate $server -Force } 'reject'
  Case 'approved version' { $fixtureState.metadata=$fixtureState.metadata.Replace('>false</d:IsApproved>','>true</d:IsApproved>') } 'reject'
  Case 'ambiguous approval flag' { $fixtureState.metadata=$fixtureState.metadata.Replace('>false</d:IsApproved>','></d:IsApproved>') } 'reject'
  Case 'null approval flag' { $fixtureState.metadata=$fixtureState.metadata.Replace('m:type="Edm.Boolean"','m:type="Edm.Boolean" m:null="true"') } 'reject'
  Case 'wrong approval type' { $fixtureState.metadata=$fixtureState.metadata.Replace('m:type="Edm.Boolean"','m:type="Edm.String"') } 'reject'
  Case 'nested approval value' { $fixtureState.metadata=$fixtureState.metadata.Replace('>false</d:IsApproved>','><d:value>false</d:value></d:IsApproved>') } 'reject'
  Case 'already updated' { $fixtureState.metadata=$fixtureState.metadata.Replace('>Waiting<','>Updated<') } 'reject'
  Case 'rejected status' { $fixtureState.metadata=$fixtureState.metadata.Replace('>Submitted<','>Rejected<') } 'reject'
  Case 'approval date present' { $fixtureState.metadata=$fixtureState.metadata.Replace('<d:PackageApprovedDate m:null="true"/>','<d:PackageApprovedDate>2026-10-07T17:00:00Z</d:PackageApprovedDate>') } 'reject'
  Case 'wrong metadata identity' { $fixtureState.metadata=$fixtureState.metadata.Replace("Version='1.6.2'","Version='1.6.3'") } 'reject'
  Case 'wrong metadata version' { $fixtureState.metadata=$fixtureState.metadata.Replace('<d:Version>1.6.2<','<d:Version>1.6.3<') } 'reject'
  Case 'wrong server digest' { $fixtureState.metadata=$fixtureState.metadata.Replace('<d:PackageHash>','<d:PackageHash>bad') } 'reject'
  Case 'malformed metadata' { $fixtureState.metadata='<broken' } 'reject'
  Case 'duplicate status field' { $fixtureState.metadata=$fixtureState.metadata.Replace('</m:properties>','<d:PackageStatus>Submitted</d:PackageStatus></m:properties>') } 'reject'
  foreach ($status in @(403,404,429,500)) { Case "metadata HTTP $status" { $fixtureState.metadataStatus=$status } 'reject' }
  Case 'release identity changed' { $fixtureState.release.id=1 } 'reject'
  Case 'draft release' { $fixtureState.release.draft=$true } 'reject'
  Case 'release asset identity changed' { $fixtureState.release.assets[0].id=1 } 'reject'
  Case 'MSI digest changed' { $fixtureState.release.assets[0].digest='sha256:' + ('0' * 64) } 'reject'
  Case 'prerelease' { $fixtureState.release.prerelease=$true } 'reject'
  Case 'ambiguous MSI assets' { $fixtureState.release.assets=@($fixtureState.release.assets[0],$fixtureState.release.assets[0]) } 'reject'
  Case 'MSI URL changed' { $fixtureState.release.assets[0].browser_download_url='https://example.invalid/installer.msi' } 'reject'
  Case 'MSI size changed' { $fixtureState.release.assets[0].size=1 } 'reject'
  Case 'tag moved' { $fixtureState.tagRef.object.sha='0' * 40 } 'reject'
  Case 'GitHub unavailable' { $fixtureState.githubStatus=503 } 'reject'
  Case 'wrong icon correction' { Set-Metadata $candidate { param($xml) $xml.package.metadata.iconUrl='https://example.invalid/logo.png' } } 'reject'
  Case 'wrong tags correction' { Set-Metadata $candidate { param($xml) $xml.package.metadata.tags='changed' } } 'reject'
  Case 'wrong copyright correction' { Set-Metadata $candidate { param($xml) $xml.package.metadata.copyright='changed' } } 'reject'
  Case 'duplicate correction field' { Set-Metadata $candidate { param($xml) $null=$xml.package.metadata.AppendChild($xml.package.metadata.SelectSingleNode('*[local-name()="iconUrl"]').CloneNode($true)) } } 'reject'
  Case 'extra metadata change' { Set-Metadata $candidate { param($xml) $xml.package.metadata.authors='Changed' } } 'reject'
  Case 'installer bytes changed' { Edit-Package $candidate { param($zip) $writer=[IO.StreamWriter]::new($zip.GetEntry('tools/chocolateyinstall.ps1').Open()); try { $writer.Write('changed') } finally { $writer.Dispose() } } } 'reject'
  Case 'extra package payload' { Edit-Package $candidate { param($zip) $null=$zip.CreateEntry('tools/extra.ps1') } } 'reject'
  Case 'duplicate package entry' { Edit-Package $candidate { param($zip) $null=$zip.CreateEntry('tools/chocolateyinstall.ps1') } } 'reject'
  Case 'changed state before final push' {
    if ((Check) -ne $true) { throw 'Initial correction should pass' }
    $fixtureState.metadata=$fixtureState.metadata.Replace('>false</d:IsApproved>','>true</d:IsApproved>')
  } 'reject'

  # Exercise the actual workflow commands, including the second guard invocation.
  $workflow = Get-Content (Join-Path $PSScriptRoot '../.github/workflows/chocolatey-publish.yml') -Raw
  function Workflow-Step([string]$name) {
    $pattern = '(?ms)^      - name: ' + [regex]::Escape($name) + '\r?\n(.*?)(?=^      - name:|\z)'
    $step = [regex]::Match($workflow, $pattern)
    if (-not $step.Success) { throw "Missing workflow step: $name" }
    $run = [regex]::Match($step.Groups[1].Value, '(?ms)^        run: \|\r?\n(.*)$')
    if (-not $run.Success) { throw "Missing workflow commands: $name" }
    return [scriptblock]::Create(($run.Groups[1].Value -replace '(?m)^          ', ''))
  }
  $preflight = Workflow-Step 'Verify package and check existing version'
  $submit = Workflow-Step 'Submit to Chocolatey Community Repository'
  function choco {
    if ($args[0] -cne 'push' -or '--force' -in $args -or '-f' -in $args) { throw 'Unexpected Chocolatey command' }
    $fixtureState.pushes++
    $global:LASTEXITCODE = 0
  }
  New-Item -ItemType Directory -Path (Join-Path $root 'package') | Out-Null
  Push-Location $root
  try {
    foreach ($scenario in @('valid correction', 'state changed', 'guard changed', 'package changed')) {
      Reset-Fixture
      $fixtureState.pushes = 0
      Copy-Item $candidate 'package/cmtraceopen.1.6.2.nupkg' -Force
      Copy-Item $guard 'package/chocolatey-submission-guard.ps1' -Force
      $env:PACKAGE_VERSION = '1.6.2'
      $env:PACKAGE_SHA256 = (Get-FileHash 'package/cmtraceopen.1.6.2.nupkg' -Algorithm SHA256).Hash.ToLowerInvariant()
      $env:GUARD_SHA256 = (Get-FileHash 'package/chocolatey-submission-guard.ps1' -Algorithm SHA256).Hash.ToLowerInvariant()
      $env:SUBMISSION_MODE = 'moderator-correction'
      $env:RELEASE_TAG = 'v1.6.2'
      $env:PUBLISH_REQUESTED = 'true'
      $env:GITHUB_OUTPUT = Join-Path $root 'output.txt'
      $env:GITHUB_STEP_SUMMARY = Join-Path $root 'summary.txt'
      $env:CHOCOLATEY_API_KEY = 'inert-test-key'
      [IO.File]::WriteAllText($env:GITHUB_OUTPUT, '')
      & $preflight
      if ((Get-Content $env:GITHUB_OUTPUT -Raw).Trim() -cne 'needs_push=true') { throw 'Workflow preflight decision mismatched' }
      switch ($scenario) {
        'state changed' { $fixtureState.metadata=$fixtureState.metadata.Replace('>false</d:IsApproved>','>true</d:IsApproved>') }
        'guard changed' { Add-Content 'package/chocolatey-submission-guard.ps1' '# changed' }
        'package changed' { Add-Content 'package/cmtraceopen.1.6.2.nupkg' 'changed' }
      }
      $rejected = $false
      try { & $submit } catch { $rejected = $true }
      if ($scenario -eq 'valid correction') {
        if ($rejected -or $fixtureState.pushes -ne 1) { throw 'Valid workflow submission did not reach the ordinary push' }
      } elseif (-not $rejected -or $fixtureState.pushes -ne 0) { throw "Workflow did not stop before push: $scenario" }
      Write-Output "PASS workflow submission: $scenario"
    }
  } finally { Pop-Location }
} finally {
  foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $saved[$name]) }
  Remove-Item $root -Recurse -Force
}
