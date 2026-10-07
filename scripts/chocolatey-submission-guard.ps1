param(
  [Parameter(Mandatory)][string]$PackagePath,
  [Parameter(Mandatory)][string]$Version,
  [Parameter(Mandatory)][string]$Sha256,
  [ValidateSet('normal', 'moderator-correction')][string]$Mode = 'normal',
  [string]$Tag,
  [switch]$PublishRequested
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$PackagePath = (Resolve-Path -LiteralPath $PackagePath).ProviderPath

if ($Version -cnotmatch '^\d+\.\d+\.\d+$' -or $Sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Invalid package identity' }
if ((Get-FileHash $PackagePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Sha256) { throw 'Package changed after validation' }
$correction = $Mode -ceq 'moderator-correction'
if ($correction -and ($env:GITHUB_REPOSITORY -cne 'adamgell/cmtraceopen' -or
    $env:GITHUB_EVENT_NAME -cne 'workflow_dispatch' -or $env:GITHUB_REF -cne 'refs/heads/main' -or
    $Version -cne '1.6.2' -or $Tag -cne 'v1.6.2' -or -not $PublishRequested)) {
  throw 'Moderation correction requires an explicit main-only manual v1.6.2 submission'
}

function Read-Xml([string]$text) {
  $settings = [Xml.XmlReaderSettings]::new()
  $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
  $settings.XmlResolver = $null
  $reader = [Xml.XmlReader]::Create([IO.StringReader]::new($text), $settings)
  try {
    $document = [Xml.XmlDocument]::new()
    $document.XmlResolver = $null
    $document.Load($reader)
    return $document
  } finally { $reader.Dispose() }
}
function Read-Package([string]$path) {
  $zip = [IO.Compression.ZipFile]::OpenRead($path)
  try {
    $names = @($zip.Entries | ForEach-Object { $_.FullName })
    if ($names.Count -ne 5 -or @($names | Sort-Object -Unique).Count -ne 5 -or
        @($names | Where-Object { $_ -cnotmatch '^(_rels/\.rels|cmtraceopen\.nuspec|tools/chocolateyinstall\.ps1|\[Content_Types\]\.xml|package/services/metadata/core-properties/[0-9a-f]{32}\.psmdcp)$' }).Count -ne 0) {
      throw 'Unexpected or ambiguous package payload'
    }
    $reader = [IO.StreamReader]::new($zip.GetEntry('cmtraceopen.nuspec').Open())
    try { $nuspec = Read-Xml $reader.ReadToEnd() } finally { $reader.Dispose() }
    $stream = $zip.GetEntry('tools/chocolateyinstall.ps1').Open()
    $memory = [IO.MemoryStream]::new()
    try { $stream.CopyTo($memory); $installer = $memory.ToArray() } finally { $stream.Dispose(); $memory.Dispose() }
    return [pscustomobject]@{Nuspec=$nuspec; Installer=$installer}
  } finally { $zip.Dispose() }
}
function Read-GitHub([string]$path) {
  if ([string]::IsNullOrWhiteSpace($env:GH_TOKEN)) { throw 'GitHub read token is missing' }
  $response = Invoke-WebRequest -Uri "https://api.github.com/repos/adamgell/cmtraceopen/$path" -Headers @{Authorization="Bearer $env:GH_TOKEN"; Accept='application/vnd.github+json'} -SkipHttpErrorCheck -TimeoutSec 30
  if ($response.StatusCode -ne 200) { throw "Cannot verify release identity (HTTP $($response.StatusCode))" }
  return ($response.Content | ConvertFrom-Json)
}

$existing = New-TemporaryFile
try {
  $response = Invoke-WebRequest -Uri "https://community.chocolatey.org/api/v2/package/cmtraceopen/$Version" -OutFile $existing.FullName -PassThru -Headers @{'Cache-Control'='no-cache'} -SkipHttpErrorCheck -TimeoutSec 60
  if (-not $correction) {
    if ($response.StatusCode -eq 404) { return $true }
    if ($response.StatusCode -ne 200) { throw "Cannot determine existing package state (HTTP $($response.StatusCode)); refusing to publish" }
    if ((Get-FileHash $existing.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Sha256) { throw 'This version already exists with different package bytes; refusing to replace it' }
    return $false
  }
  # A one-time correction of this captured, still-unapproved package only.
  if ($response.StatusCode -ne 200 -or (Get-FileHash $existing.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne '9caa3a7885c985e441862d1a785d8abf756fc8c3c55c1f8a5ef0e189820a4451') {
    throw 'The expected original 1.6.2 package is absent or changed'
  }
  $release = Read-GitHub 'releases/tags/v1.6.2'
  if ($release.id -ne 403346505 -or $release.tag_name -cne 'v1.6.2' -or
      $release.draft -isnot [bool] -or $release.draft -ne $false -or
      $release.prerelease -isnot [bool] -or $release.prerelease -ne $false) { throw 'Published release identity changed' }
  $assets = @($release.assets | Where-Object { $_.name -ceq 'CMTrace-Open_1.6.2_x64.msi' })
  if ($assets.Count -ne 1 -or $assets[0].id -ne 611417257 -or $assets[0].size -ne 17838080 -or
      $assets[0].digest -cne 'sha256:12166bd88a2e4f4c2faa216dcce950e1b4eedc33f64aed48e171d11e63bc32d2' -or
      $assets[0].browser_download_url -cne 'https://github.com/adamgell/cmtraceopen/releases/download/v1.6.2/CMTrace-Open_1.6.2_x64.msi') { throw 'Published MSI identity changed' }
  $tagRef = Read-GitHub 'git/ref/tags/v1.6.2'
  if ($tagRef.ref -cne 'refs/tags/v1.6.2' -or $tagRef.object.type -cne 'tag' -or
      $tagRef.object.sha -cne '7d7cb1bec8b372fbaf08845c2ac6bab6668ba6c0') { throw 'Release tag identity changed' }

  $before = Read-Package $existing.FullName
  $after = Read-Package $PackagePath
  $installerHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($after.Installer)).ToLowerInvariant()
  if ($installerHash -cne '004ee6538ae44c1701c15ee66906cfea89bb97a3730bc0fefa89067c78baca4a' -or
      [Convert]::ToBase64String($before.Installer) -cne [Convert]::ToBase64String($after.Installer)) { throw 'Installer bytes or MSI binding changed' }
  $nuspecNs = [Xml.XmlNamespaceManager]::new($after.Nuspec.NameTable)
  $nuspecNs.AddNamespace('n', 'http://schemas.microsoft.com/packaging/2011/08/nuspec.xsd')
  $corrections = @{
    iconUrl='https://cdn.jsdelivr.net/gh/adamgell/cmtraceopen@v1.6.2/logo.png'
    tags='cmtraceopen 1.6.2 log viewer cmtrace intune'
    copyright='Copyright (c) 2026 Adam'
  }
  foreach ($field in $corrections.GetEnumerator()) {
    $nodes = $after.Nuspec.SelectNodes("/n:package/n:metadata/n:$($field.Key)", $nuspecNs)
    if ($nodes.Count -ne 1 -or $nodes[0].InnerXml -cne $field.Value -or $nodes[0].Attributes.Count -ne 0) { throw "Unexpected correction: $($field.Key)" }
    $null = $nodes[0].ParentNode.RemoveChild($nodes[0])
    $oldNodes = $before.Nuspec.SelectNodes("/n:package/n:metadata/n:$($field.Key)", $nuspecNs)
    foreach ($node in $oldNodes) { $null = $node.ParentNode.RemoveChild($node) }
  }
  if ($before.Nuspec.OuterXml -cne $after.Nuspec.OuterXml) { throw 'Package metadata changed beyond the authorized correction' }
  # Keep the moderation read last so it also binds the current server package hash.
  $metadataUrl = "https://community.chocolatey.org/api/v2/Packages(Id='cmtraceopen',Version='1.6.2')"
  $response = Invoke-WebRequest -Uri $metadataUrl -Headers @{'Cache-Control'='no-cache'} -SkipHttpErrorCheck -TimeoutSec 30
  if ($response.StatusCode -ne 200) { throw "Cannot verify moderation state (HTTP $($response.StatusCode))" }
  $metadata = Read-Xml $response.Content
  $ns = [Xml.XmlNamespaceManager]::new($metadata.NameTable)
  $ns.AddNamespace('a', 'http://www.w3.org/2005/Atom')
  $ns.AddNamespace('m', 'http://schemas.microsoft.com/ado/2007/08/dataservices/metadata')
  $ns.AddNamespace('d', 'http://schemas.microsoft.com/ado/2007/08/dataservices')
  foreach ($field in @{id=$metadataUrl; title='cmtraceopen'}.GetEnumerator()) {
    $nodes = $metadata.SelectNodes("/a:entry/a:$($field.Key)", $ns)
    if ($nodes.Count -ne 1 -or $nodes[0].InnerText -cne $field.Value) { throw 'Ambiguous moderation package identity' }
  }
  $properties = $metadata.SelectNodes('/a:entry/m:properties | /a:entry/a:content/m:properties', $ns)
  if ($properties.Count -ne 1) { throw 'Ambiguous moderation properties' }
  $serverHash = [Convert]::ToBase64String([Security.Cryptography.SHA512]::HashData([IO.File]::ReadAllBytes($existing.FullName)))
  foreach ($field in @{Version='1.6.2'; IsApproved='false'; PackageStatus='Submitted'; PackageSubmittedStatus='Waiting'; PackageHashAlgorithm='SHA512'; PackageHash=$serverHash}.GetEnumerator()) {
    $nodes = $properties[0].SelectNodes("d:$($field.Key)", $ns)
    if ($nodes.Count -ne 1 -or $nodes[0].InnerXml -cne $field.Value) { throw "Unexpected moderation field: $($field.Key)" }
  }
  $approved = $properties[0].SelectSingleNode('d:IsApproved', $ns)
  if ($approved.GetAttribute('type', $ns.LookupNamespace('m')) -cne 'Edm.Boolean' -or
      $approved.GetAttribute('null', $ns.LookupNamespace('m')) -cnotin @('', 'false')) { throw 'Ambiguous approval flag type' }
  $approvalDate = $properties[0].SelectNodes('d:PackageApprovedDate', $ns)
  if ($approvalDate.Count -ne 1 -or $approvalDate[0].InnerText -cne '' -or $approvalDate[0].GetAttribute('null', $ns.LookupNamespace('m')) -cne 'true') {
    throw 'Package has an approval date or ambiguous approval state'
  }

  return $true
} finally { Remove-Item $existing.FullName -Force }
