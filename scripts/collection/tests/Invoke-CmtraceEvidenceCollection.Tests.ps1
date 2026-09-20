BeforeAll {
    $collectorPath = Join-Path $PSScriptRoot '..' 'Invoke-CmtraceEvidenceCollection.ps1'
    $stagedProfilePath = Join-Path $PSScriptRoot '..' 'intune-evidence-profile.json'
    $referenceProfilePath = Join-Path $PSScriptRoot '..' '..' '..' 'references' 'collection' 'intune-evidence-profile.json'
    $stagedProfileText = Get-Content -LiteralPath $stagedProfilePath -Raw
    $referenceProfileText = Get-Content -LiteralPath $referenceProfilePath -Raw
    $stagedProfile = $stagedProfileText | ConvertFrom-Json
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $collectorPath,
        [ref]$tokens,
        [ref]$parseErrors
    )
    $parseErrors | Should -BeNullOrEmpty

    $functionNames = @(
        'Get-ObjectPropertyValue',
        'Test-ArrayValue',
        'ConvertTo-UtcTimestamp',
        'Assert-ProfileRequiredString',
        'Assert-ProfileRequiredArray',
        'Assert-CollectorProfileShape',
        'ConvertTo-SafeFileName',
        'New-CollectorBundleId',
        'Join-RelativePath',
        'Get-LocaleMetadataRelativePath',
        'Get-LocaleMetadataLcid',
        'Protect-SecretText',
        'Get-FileSha256',
        'New-ArtifactId',
        'Get-UtcTimestamp',
        'New-ArtifactRecord',
        'Add-ObservedGap',
        'Export-EventChannelLocaleMetadata'
    )
    foreach ($functionName in $functionNames) {
        $definition = $ast.FindAll(
            {
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq $functionName
            },
            $true
        ) | Select-Object -First 1
        $definition | Should -Not -BeNullOrEmpty
        Invoke-Expression $definition.Extent.Text
    }

    # The collector initializes this at its own top level, which AST-loading individual functions
    # skips. New-ArtifactId increments through it, so without it every record build faults.
    $script:ArtifactCounters = @{}

    function New-TestCollectorProfile {
        param(
            [string]$LogId = 'logs-primary',
            [string]$CommandId = 'commands-primary'
        )

        return [pscustomobject]@{
            profileName    = 'test-profile'
            profileVersion = '1.0.0'
            logs           = @(
                [pscustomobject]@{
                    id                = $LogId
                    family            = 'logs'
                    sourcePattern     = 'C:\Logs\*.log'
                    destinationFolder = 'logs'
                    parseHints        = @()
                }
            )
            registry       = @()
            eventLogs      = @()
            exports        = @()
            commands       = @(
                [pscustomobject]@{
                    id         = $CommandId
                    family     = 'commands'
                    command    = 'whoami.exe'
                    fileName   = 'whoami.txt'
                    arguments  = @()
                    parseHints = @()
                }
            )
        }
    }
}

Describe 'New-CollectorBundleId' {
    It 'emits the canonical collector format with a unique lowercase nonce' {
        $first = New-CollectorBundleId -DeviceName 'DEVICE-01'
        $second = New-CollectorBundleId -DeviceName 'DEVICE-01'

        $first | Should -Match '^CMTRACE-\d{8}-\d{6}-DEVICE-01-[0-9a-f]{32}$'
        $second | Should -Match '^CMTRACE-\d{8}-\d{6}-DEVICE-01-[0-9a-f]{32}$'
        $second | Should -Not -BeExactly $first
    }

    It 'uses the invariant Gregorian calendar under a non-Gregorian culture' {
        $originalCulture = [System.Globalization.CultureInfo]::CurrentCulture
        $originalUiCulture = [System.Globalization.CultureInfo]::CurrentUICulture
        $testDate = [datetime]::new(2026, 5, 21, 12, 34, 56)
        Mock Get-Date {
            param([string]$Format)
            if ([string]::IsNullOrEmpty($Format)) {
                return $testDate
            }
            return $testDate.ToString($Format, [System.Globalization.CultureInfo]::CurrentCulture)
        }

        try {
            [System.Globalization.CultureInfo]::CurrentCulture =
                [System.Globalization.CultureInfo]::GetCultureInfo('fa-IR')
            [System.Globalization.CultureInfo]::CurrentUICulture =
                [System.Globalization.CultureInfo]::GetCultureInfo('fa-IR')

            $bundleId = New-CollectorBundleId -DeviceName 'DEVICE-01'
        }
        finally {
            [System.Globalization.CultureInfo]::CurrentCulture = $originalCulture
            [System.Globalization.CultureInfo]::CurrentUICulture = $originalUiCulture
        }

        $bundleId | Should -Match '^CMTRACE-20260521-123456-DEVICE-01-[0-9a-f]{32}$'
    }
}

Describe 'Get-UtcTimestamp' {
    It 'serializes UTC with the invariant Gregorian calendar' {
        $originalCulture = [System.Globalization.CultureInfo]::CurrentCulture
        $originalUiCulture = [System.Globalization.CultureInfo]::CurrentUICulture
        Mock Get-Date {
            [datetime]::new(2026, 5, 21, 12, 34, 56, [DateTimeKind]::Utc)
        }

        try {
            [System.Globalization.CultureInfo]::CurrentCulture =
                [System.Globalization.CultureInfo]::GetCultureInfo('fa-IR')
            [System.Globalization.CultureInfo]::CurrentUICulture =
                [System.Globalization.CultureInfo]::GetCultureInfo('fa-IR')

            $timestamp = Get-UtcTimestamp
        }
        finally {
            [System.Globalization.CultureInfo]::CurrentCulture = $originalCulture
            [System.Globalization.CultureInfo]::CurrentUICulture = $originalUiCulture
        }

        $timestamp | Should -BeExactly '2026-05-21T12:34:56Z'
    }
}

Describe 'Intune evidence profile contracts' {
    It 'keeps the staged and reference profiles byte-for-byte synchronized' {
        $stagedProfileText | Should -BeExactly $referenceProfileText
    }

    It 'does not capture current-user registry paths from the SYSTEM collector context' {
        $currentUserRegistryItems = @(
            $stagedProfile.registry |
                Where-Object { $_.path -match '^(?:HKCU|HKEY_CURRENT_USER)(?:\\|$)' }
        )

        $currentUserRegistryItems | Should -BeNullOrEmpty
    }

    It 'serializes an empty Delivery Optimization status query as an array' {
        $statusCommand = @(
            $stagedProfile.commands |
                Where-Object { $_.id -eq 'delivery-optimization-status' }
        )
        $statusCommand | Should -HaveCount 1

        $expectedCommand = 'ConvertTo-Json -InputObject @(Get-DeliveryOptimizationStatus | Select-Object FileId,Status,Priority,BytesFromHttp,BytesFromLanPeers,BytesFromInternetPeers,BytesFromCacheServer,BytesFromGroupPeers,BytesTotal,DownloadDuration,PercentPeerCaching) -Compress'
        $statusCommand[0].arguments[-1] | Should -BeExactly $expectedCommand

        function Get-DeliveryOptimizationStatus {
            return
        }

        Invoke-Expression $statusCommand[0].arguments[-1] | Should -BeExactly '[]'
    }
}

Describe 'Optional array validation' {
    It 'accepts a single-element optional array such as arguments: ["/status"]' {
        $testProfile = New-TestCollectorProfile
        $testProfile.commands[0].arguments = @('/status')

        { Assert-CollectorProfileShape -CollectorProfile $testProfile -Path 'profile.json' } |
            Should -Not -Throw
    }

    It 'still accepts an empty optional array' {
        $testProfile = New-TestCollectorProfile
        $testProfile.commands[0].arguments = @()

        { Assert-CollectorProfileShape -CollectorProfile $testProfile -Path 'profile.json' } |
            Should -Not -Throw
    }

    It 'still rejects a scalar where an array is required' {
        $testProfile = New-TestCollectorProfile
        $testProfile.commands[0].arguments = '/status'

        { Assert-CollectorProfileShape -CollectorProfile $testProfile -Path 'profile.json' } |
            Should -Throw -ExpectedMessage '*commands[[]0[]].arguments must be an array when present*'
    }
}

Describe 'Read-CollectorProfile host compatibility' {
    It 'does not pass -Depth to ConvertFrom-Json, which Windows PowerShell 5.1 rejects' {
        $collectorText = Get-Content -LiteralPath $collectorPath -Raw

        $collectorText | Should -Not -Match 'ConvertFrom-Json[^\r\n]*-Depth'
    }

    It 'accepts the shipped profile, including its single-element argument arrays' {
        $shippedProfile = Get-Content -LiteralPath $stagedProfilePath -Raw | ConvertFrom-Json

        { Assert-CollectorProfileShape -CollectorProfile $shippedProfile -Path $stagedProfilePath } |
            Should -Not -Throw
    }
}

Describe 'Get-LocaleMetadataRelativePath' {
    It 'places LocaleMetaData beside the exported channel' {
        Get-LocaleMetadataRelativePath -EvtxRelativePath 'evidence/event-logs/device-management-admin.evtx' |
            Should -BeExactly 'evidence/event-logs/LocaleMetaData'
    }

    It 'handles a channel exported at the bundle root' {
        Get-LocaleMetadataRelativePath -EvtxRelativePath 'autopilot.evtx' |
            Should -BeExactly 'LocaleMetaData'
    }

    It 'normalizes backslash separators to the manifest convention' {
        Get-LocaleMetadataRelativePath -EvtxRelativePath 'evidence\event-logs\aad-operational.evtx' |
            Should -BeExactly 'evidence/event-logs/LocaleMetaData'
    }

    It 'does not depend on the file extension' {
        Get-LocaleMetadataRelativePath -EvtxRelativePath 'evidence/event-logs/no-extension' |
            Should -BeExactly 'evidence/event-logs/LocaleMetaData'
    }
}

Describe 'Get-LocaleMetadataLcid' {
    It 'reads the LCID wevtutil appends to the sidecar name' {
        Get-LocaleMetadataLcid -MetadataFileName 'device-management-admin_1033.MTA' |
            Should -BeExactly '1033'
    }

    It 'takes the final segment when the exported log name itself contains underscores' {
        Get-LocaleMetadataLcid -MetadataFileName 'user_device_registration_2057.MTA' |
            Should -BeExactly '2057'
    }

    It 'reports unknown rather than guessing when the suffix is not numeric' {
        Get-LocaleMetadataLcid -MetadataFileName 'autopilot_enUS.MTA' | Should -BeExactly 'unknown'
    }

    It 'reports unknown when there is no suffix at all' {
        Get-LocaleMetadataLcid -MetadataFileName 'autopilot.MTA' | Should -BeExactly 'unknown'
        Get-LocaleMetadataLcid -MetadataFileName 'autopilot_.MTA' | Should -BeExactly 'unknown'
    }
}

Describe 'Export-EventChannelLocaleMetadata' {
    # These invoke the function rather than pattern-matching the collector's source. Asserting that
    # the code reads a certain way passes just as happily when the behaviour is wrong, and breaks on
    # a harmless reformat. wevtutil.exe is stubbed, which also lets these run off Windows.

    BeforeAll {
        function Set-WevtutilStub {
            param(
                [int]$ExitCode = 0,
                [string[]]$SidecarNames = @(),
                [switch]$Throw
            )
            $folder = Join-Path $script:channelFolder 'LocaleMetaData'
            $shouldThrow = [bool]$Throw
            $names = $SidecarNames
            $code = $ExitCode
            # Function definitions win over external commands in PowerShell's resolution order, so the
            # collector's own `& wevtutil.exe` call reaches this.
            Set-Item -Path 'function:global:wevtutil.exe' -Value {
                if ($shouldThrow) { throw 'wevtutil.exe is not recognized' }
                if ($names.Count -gt 0) {
                    New-Item -ItemType Directory -Path $folder -Force | Out-Null
                    foreach ($name in $names) {
                        Set-Content -LiteralPath (Join-Path $folder $name) -Value 'sidecar' -Encoding ascii
                    }
                }
                $global:LASTEXITCODE = $code
            }.GetNewClosure()
        }

        function Invoke-Subject {
            Export-EventChannelLocaleMetadata `
                -EvtxPath $script:evtxPath `
                -EvtxRelativePath 'eventlogs/Application.evtx' `
                -Family 'eventlogs' `
                -Channel 'Application' `
                -ObservedGaps $script:gaps
        }
    }

    BeforeEach {
        $script:sandbox = Join-Path ([IO.Path]::GetTempPath()) ('cmt-locale-' + [Guid]::NewGuid().ToString('N'))
        $script:channelFolder = Join-Path $script:sandbox 'eventlogs'
        New-Item -ItemType Directory -Path $script:channelFolder -Force | Out-Null
        $script:evtxPath = Join-Path $script:channelFolder 'Application.evtx'
        Set-Content -LiteralPath $script:evtxPath -Value 'not a real evtx' -Encoding ascii
        $script:gaps = New-Object 'System.Collections.Generic.List[string]'
    }

    AfterEach {
        if (Test-Path -LiteralPath $script:sandbox) {
            Remove-Item -LiteralPath $script:sandbox -Recurse -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -Path 'function:wevtutil.exe' -ErrorAction SilentlyContinue
    }

    It 'records the produced sidecar with its LCID and a hash' {
        Set-WevtutilStub -SidecarNames @('Application_1033.MTA')

        $records = @(Invoke-Subject)

        $records.Count | Should -Be 1
        $records[0].status | Should -BeExactly 'collected'
        $records[0].relativePath | Should -BeExactly 'eventlogs/LocaleMetaData/Application_1033.MTA'
        $records[0].notes | Should -BeLike '*LCID 1033*'
        $records[0].hashes.sha256 | Should -Not -BeNullOrEmpty
        $script:gaps.Count | Should -Be 0
    }

    It 'records every sidecar when the machine emitted more than one locale' {
        Set-WevtutilStub -SidecarNames @('Application_1033.MTA', 'Application_2057.MTA')

        $records = @(Invoke-Subject)

        $records.Count | Should -Be 2
        @($records.relativePath) | Should -Contain 'eventlogs/LocaleMetaData/Application_2057.MTA'
    }

    It 'reports a nonzero exit code as failed, not as a missing file' {
        Set-WevtutilStub -ExitCode 5

        $records = @(Invoke-Subject)

        $records.Count | Should -Be 1
        $records[0].status | Should -BeExactly 'failed'
        $records[0].notes | Should -BeLike '*exit code 5*'
        $script:gaps.Count | Should -Be 1
        $script:gaps[0] | Should -BeLike 'Collection failed for Application*'
    }

    It 'survives wevtutil.exe being absent instead of aborting the collection' {
        # $ErrorActionPreference is 'Stop', so an unguarded invocation would take the whole run down
        # over one channel. The other artifacts in the bundle matter more than this sidecar.
        Set-WevtutilStub -Throw

        { Invoke-Subject } | Should -Not -Throw

        $records = @(Invoke-Subject)
        $records[0].status | Should -BeExactly 'failed'
        $records[0].notes | Should -BeLike '*Could not run wevtutil.exe*'
    }

    It 'reports success with no sidecar as missing rather than collected' {
        Set-WevtutilStub -SidecarNames @()

        $records = @(Invoke-Subject)

        $records.Count | Should -Be 1
        $records[0].status | Should -BeExactly 'missing'
        $script:gaps[0] | Should -BeLike 'Missing expected artifact*'
    }

    It 'keeps an unresolved outcome file-shaped rather than pointing at the folder' {
        # Bundle inspection treats relativePath as a file and tests it on disk. Pointing a failure
        # at the LocaleMetaData folder would read as present-on-disk whenever the folder exists,
        # and would collide across channels.
        Set-WevtutilStub -ExitCode 5

        $records = @(Invoke-Subject)

        $records[0].relativePath | Should -BeExactly 'eventlogs/LocaleMetaData/Application_unknown-lcid.MTA'
    }

    It 'treats an unreadable sidecar folder as failed rather than missing' {
        # An access fault is not an absence. Calling it 'missing' would claim the sidecar was never
        # produced when it may simply be unreadable.
        Set-WevtutilStub -SidecarNames @('Application_1033.MTA')
        $folder = Join-Path $script:channelFolder 'LocaleMetaData'
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        # A file where the folder is expected makes enumeration fault rather than return empty.
        Mock -CommandName Get-ChildItem -MockWith { throw 'Access to the path is denied.' }

        $records = @(Invoke-Subject)

        $records[0].status | Should -BeExactly 'failed'
        $records[0].notes | Should -BeLike 'Could not enumerate*'
        $script:gaps[0] | Should -BeLike 'Collection failed for Application*'
    }
}

Describe 'Locale metadata opt-out' {
    It 'exposes a switch for operators who need a smaller bundle' {
        # The switch is a parameter on the script itself rather than on a function, so the
        # declaration is the thing to assert; there is no unit to invoke.
        $collectorText = Get-Content -LiteralPath $collectorPath -Raw

        $collectorText | Should -Match '\[switch\]\$SkipLocaleMetadata'
        $collectorText | Should -Match '\$SkipLocaleMetadata\)\s*\{\s*continue'
    }
}

Describe 'Assert-CollectorProfileShape' {
    It 'accepts unique artifact IDs across all sections' {
        $testProfile = New-TestCollectorProfile

        { Assert-CollectorProfileShape -CollectorProfile $testProfile -Path 'profile.json' } |
            Should -Not -Throw
    }

    It 'rejects case-insensitive duplicate artifact IDs across sections' {
        $testProfile = New-TestCollectorProfile -LogId 'shared-artifact' -CommandId 'SHARED-ARTIFACT'

        { Assert-CollectorProfileShape -CollectorProfile $testProfile -Path 'profile.json' } |
            Should -Throw -ExpectedMessage '*duplicate artifact id*shared-artifact*first declared at logs*repeated at commands*'
    }
}
