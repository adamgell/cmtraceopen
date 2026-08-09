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
        'Assert-ProfileRequiredString',
        'Assert-ProfileRequiredArray',
        'Assert-CollectorProfileShape',
        'Join-RelativePath',
        'Get-LocaleMetadataRelativePath',
        'Get-LocaleMetadataLcid'
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
        $profile = New-TestCollectorProfile
        $profile.commands[0].arguments = @('/status')

        { Assert-CollectorProfileShape -CollectorProfile $profile -Path 'profile.json' } |
            Should -Not -Throw
    }

    It 'still accepts an empty optional array' {
        $profile = New-TestCollectorProfile
        $profile.commands[0].arguments = @()

        { Assert-CollectorProfileShape -CollectorProfile $profile -Path 'profile.json' } |
            Should -Not -Throw
    }

    It 'still rejects a scalar where an array is required' {
        $profile = New-TestCollectorProfile
        $profile.commands[0].arguments = '/status'

        { Assert-CollectorProfileShape -CollectorProfile $profile -Path 'profile.json' } |
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

Describe 'Locale metadata artifact contract' {
    It 'keeps the unresolved-outcome path file-shaped rather than pointing at the folder' {
        # Bundle inspection treats relativePath as a file and tests it on disk. Pointing failure
        # and missing records at the LocaleMetaData folder would read as present-on-disk whenever
        # the folder exists, and would collide across channels.
        $collectorText = Get-Content -LiteralPath $collectorPath -Raw

        $collectorText | Should -Match 'unknown-lcid\.MTA'
        $collectorText | Should -Not -Match "RelativePath \`$metadataRelativeFolder"
    }

    It 'probes the sidecar folder inside the try, so a fault cannot abort collection' {
        # $ErrorActionPreference is 'Stop', so a Test-Path outside the try would take down the whole
        # run instead of recording one failed artifact.
        $collectorText = Get-Content -LiteralPath $collectorPath -Raw

        $collectorText | Should -Match "try \{\s*\r?\n\s*if \(Test-Path -LiteralPath \`$metadataFolder -ErrorAction Stop\)"
    }

    It 'treats a sidecar enumeration fault as failed rather than missing' {
        $collectorText = Get-Content -LiteralPath $collectorPath -Raw

        # -ErrorAction Stop inside try/catch, so an unreadable folder cannot masquerade as absent.
        $collectorText | Should -Match "Get-ChildItem -LiteralPath \`$metadataFolder[^\r\n]*-ErrorAction Stop"
        $collectorText | Should -Match 'Could not enumerate'
    }

    It 'exposes an opt-out switch for operators who need a smaller bundle' {
        $collectorText = Get-Content -LiteralPath $collectorPath -Raw

        $collectorText | Should -Match '\[switch\]\$SkipLocaleMetadata'
        $collectorText | Should -Match '\$SkipLocaleMetadata\)\s*\{\s*continue'
    }

    It 'records the LCID in the collected artifact notes' {
        $collectorText = Get-Content -LiteralPath $collectorPath -Raw

        $collectorText | Should -Match 'Locale metadata \(LCID \{0\}\)'
    }
}

Describe 'Assert-CollectorProfileShape' {
    It 'accepts unique artifact IDs across all sections' {
        $profile = New-TestCollectorProfile

        { Assert-CollectorProfileShape -CollectorProfile $profile -Path 'profile.json' } |
            Should -Not -Throw
    }

    It 'rejects case-insensitive duplicate artifact IDs across sections' {
        $profile = New-TestCollectorProfile -LogId 'shared-artifact' -CommandId 'SHARED-ARTIFACT'

        { Assert-CollectorProfileShape -CollectorProfile $profile -Path 'profile.json' } |
            Should -Throw -ExpectedMessage '*duplicate artifact id*shared-artifact*first declared at logs*repeated at commands*'
    }
}
