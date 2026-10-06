$ErrorActionPreference = 'Stop';
$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url        = 'https://github.com/adamgell/cmtraceopen/releases/download/v1.6.2/CMTrace-Open_1.6.2_x64.msi'
$packageArgs = @{
  packageName   = $env:ChocolateyPackageName
  unzipLocation = $toolsDir
  fileType      = 'msi'
  url           = $url
  softwareName  = 'CMTrace Open'
  checksum      = '12166bd88a2e4f4c2faa216dcce950e1b4eedc33f64aed48e171d11e63bc32d2'
  checksumType  = 'sha256'
  validExitCodes= @(0)
  silentArgs   = '/qn'
}

Install-ChocolateyPackage @packageArgs
