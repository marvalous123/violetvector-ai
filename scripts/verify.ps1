[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root

function Test-ExactBoolean {
    param(
        [object]$Value,
        [string]$Property,
        [bool]$Expected
    )
    if ($null -eq $Value) {
        return $false
    }
    $candidate = $Value.PSObject.Properties[$Property]
    return (
        $null -ne $candidate -and
        $candidate.Value -is [bool] -and
        $candidate.Value -eq $Expected
    )
}

function Invoke-JsonScript {
    param(
        [string]$Path,
        [string[]]$Arguments
    )
    $lines = & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $Path @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Guarded JSON check failed: $Path"
    }
    try {
        return (($lines -join "`n") | ConvertFrom-Json)
    }
    catch {
        throw "Guarded JSON check returned invalid JSON: $Path"
    }
}

function Test-TrackedPowerShellSyntax {
    $trackedScripts = @(& git ls-files -- '*.ps1')
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to enumerate tracked PowerShell scripts.'
    }
    if ($trackedScripts.Count -eq 0) {
        throw 'No tracked PowerShell scripts were found.'
    }

    $failures = @()
    foreach ($relativePath in $trackedScripts) {
        $tokens = $null
        $parseErrors = $null
        $fullPath = Join-Path $root $relativePath
        [System.Management.Automation.Language.Parser]::ParseFile(
            $fullPath,
            [ref]$tokens,
            [ref]$parseErrors
        ) | Out-Null
        if ($parseErrors.Count -gt 0) {
            $failures += "$relativePath ($($parseErrors.Count) parse errors)"
        }
    }
    if ($failures.Count -gt 0) {
        throw "Tracked PowerShell syntax check failed: $($failures -join '; ')"
    }
    return $trackedScripts.Count
}

try {
    & npm.cmd run check:repository-safety
    if ($LASTEXITCODE -ne 0) {
        throw "npm run check:repository-safety failed with exit code $LASTEXITCODE"
    }
    $powerShellScriptCount = Test-TrackedPowerShellSyntax

    & npm.cmd run test:demo-launcher
    if ($LASTEXITCODE -ne 0) { throw 'Demo launcher verification failed.' }

    foreach ($command in @('test', 'typecheck', 'lint', 'build')) {
        & npm.cmd run $command
        if ($LASTEXITCODE -ne 0) {
            throw "npm run $command failed with exit code $LASTEXITCODE"
        }
    }

    & npm.cmd run test:security-mutations
    if ($LASTEXITCODE -ne 0) {
        throw "npm run test:security-mutations failed with exit code $LASTEXITCODE"
    }

    & npm.cmd run test:audit-witness-sqlite-reader-source-receipt
    if ($LASTEXITCODE -ne 0) {
        throw (
            'npm run test:audit-witness-sqlite-reader-source-receipt ' +
            "failed with exit code $LASTEXITCODE"
        )
    }

    & npm.cmd run test:audit-witness-database-read-ceremony
    if ($LASTEXITCODE -ne 0) {
        throw (
            'npm run test:audit-witness-database-read-ceremony ' +
            "failed with exit code $LASTEXITCODE"
        )
    }

    & npm.cmd run test:windows-security-4663-live-exercise-receipt
    if ($LASTEXITCODE -ne 0) {
        throw (
            'npm run test:windows-security-4663-live-exercise-receipt ' +
            "failed with exit code $LASTEXITCODE"
        )
    }
    & npm.cmd run test:windows-security-4663-genuine-match-receipt
    if ($LASTEXITCODE -ne 0) {
        throw (
            'npm run test:windows-security-4663-genuine-match-receipt ' +
            "failed with exit code $LASTEXITCODE"
        )
    }

    $guardedChecks = @(
        @{
            Path = (Join-Path $root 'scripts\provision-windows-sensor-identity.ps1')
            Arguments = @('-Command', 'provision', '-WhatIf')
        },
        @{
            Path = (Join-Path $root 'scripts\install-windows-sensor-service.ps1')
            Arguments = @('-Command', 'install', '-WhatIf')
        },
        @{
            Path = (Join-Path $root 'scripts\build-windows-sensor-install-bundle.ps1')
            Arguments = @('-Command', 'plan')
        },
        @{
            Path = (Join-Path $root 'scripts\install-windows-sensor-service.ps1')
            Arguments = @('-Command', 'runtime-check')
        },
        @{
            Path = (Join-Path $root 'scripts\invoke-windows-sensor-dotnet.ps1')
            Arguments = @('-Command', 'readiness-plan')
        },
        @{
            Path = (Join-Path $root 'scripts\install-windows-sensor-service.ps1')
            Arguments = @('-Command', 'package-check')
        },
        @{
            Path = (Join-Path $root 'scripts\provision-windows-sensor-identity.ps1')
            Arguments = @('-Command', 'probe-cleanup', '-WhatIf')
        },
        @{
            Path = (Join-Path $root 'scripts\provision-windows-sensor-identity.ps1')
            Arguments = @('-Command', 'probe-status')
        },
        @{
            Path = (Join-Path $root 'scripts\install-windows-sensor-service.ps1')
            Arguments = @('-Command', 'restart-check', '-WhatIf')
        },
        @{
            Path = (Join-Path $root 'scripts\install-windows-sensor-service.ps1')
            Arguments = @('-Command', 'source-readiness-check', '-WhatIf')
        },
        @{
            Path = (Join-Path $root 'scripts\install-windows-sensor-service.ps1')
            Arguments = @('-Command', 'local-batch-check', '-WhatIf')
        },
        @{
            Path = (Join-Path $root 'scripts\install-windows-sensor-service.ps1')
            Arguments = @('-Command', 'genuine-batch-check', '-WhatIf')
        },
        @{
            Path = (Join-Path $root 'scripts\install-windows-sensor-service.ps1')
            Arguments = @('-Command', 'uninstall', '-WhatIf')
        },
        @{
            Path = (Join-Path $root 'scripts\install-windows-sensor-service.ps1')
            Arguments = @('-Command', 'orphaned-install-cleanup', '-WhatIf')
        },
        @{
            Path = (Join-Path $root 'scripts\install-windows-sensor-service.ps1')
            Arguments = @('-Command', 'orphaned-state-cleanup', '-WhatIf')
        },
        @{
            Path = (Join-Path $root 'scripts\install-windows-sensor-service.ps1')
            Arguments = @('-Command', 'bounded-collector-check', '-WhatIf')
        },
        @{
            Path = (Join-Path $root 'scripts\manage-windows-sensor-endpoint-binding.ps1')
            Arguments = @('-Command', 'plan')
        },
        @{
            Path = (Join-Path $root 'scripts\manage-windows-security-4663-result.ps1')
            Arguments = @('-Command', 'plan')
        },
        @{
            Path = (Join-Path $root 'scripts\manage-windows-security-4663-result.ps1')
            Arguments = @('-Command', 'slot-exercise', '-WhatIf')
        },
        @{
            Path = (Join-Path $root 'scripts\manage-windows-security-4663-live-approval.ps1')
            Arguments = @('-Command', 'plan')
        },
        @{
            Path = (Join-Path $root 'scripts\manage-windows-security-4663-live-approval.ps1')
            Arguments = @('-Command', 'exercise', '-WhatIf')
        },
        @{
            Path = (Join-Path $root 'scripts\manage-windows-security-4663-live-result.ps1')
            Arguments = @('-Command', 'plan')
        },
        @{
            Path = (Join-Path $root 'scripts\manage-windows-security-4663-live-result.ps1')
            Arguments = @('-Command', 'slot-exercise', '-WhatIf')
        },
        @{
            Path = (Join-Path $root 'scripts\manage-windows-security-4663-live-result.ps1')
            Arguments = @('-Command', 'live-exercise', '-WhatIf')
        },
        @{
            Path = (Join-Path $root 'scripts\manage-windows-security-4663-live-result.ps1')
            Arguments = @('-Command', 'genuine-match-exercise', '-WhatIf')
        }
    )
    foreach ($check in $guardedChecks) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $check.Path @($check.Arguments) | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Guarded non-mutating check failed: $($check.Path)"
        }
    }

    $c2eResultPlan = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\manage-windows-security-4663-result.ps1'
    ) -Arguments @('-Command', 'plan')
    $expectedC2eResultPath =
        'C:\ProgramData\WAR-R00M\Windows Sensor\C2\security-4663-one-shot-result.json'
    $expectedC2eResultCommands =
        'plan,prepare-slot,empty-check,check,consume,absent-check,cleanup'
    if (
        -not (Test-ExactBoolean -Value $c2eResultPlan -Property 'ok' `
            -Expected $true) -or
        $c2eResultPlan.command -ne 'plan' -or
        $c2eResultPlan.result.schemaVersion -ne 1 -or
        $c2eResultPlan.result.checkpoint -ne
            'gate-c2e-security-4663-one-shot-plan' -or
        (@($c2eResultPlan.result.commands) -join ',') -ne
            $expectedC2eResultCommands -or
        $c2eResultPlan.result.resultPath -ne $expectedC2eResultPath -or
        $c2eResultPlan.result.maximumDocumentBytes -ne 4096 -or
        $c2eResultPlan.result.maximumResultAgeSeconds -ne 300 -or
        -not (Test-ExactBoolean -Value $c2eResultPlan.result `
            -Property 'requiresAdministrator' -Expected $true) -or
        -not (Test-ExactBoolean -Value $c2eResultPlan.result `
            -Property 'checksProtectedRootAndFileAcl' -Expected $true) -or
        -not (Test-ExactBoolean -Value $c2eResultPlan.result `
            -Property 'rejectsReparsePoints' -Expected $true) -or
        -not (Test-ExactBoolean -Value $c2eResultPlan.result `
            -Property 'rejectsHardLinks' -Expected $true) -or
        -not (Test-ExactBoolean -Value $c2eResultPlan.result `
            -Property 'requiresStrictUtf8' -Expected $true) -or
        -not (Test-ExactBoolean -Value $c2eResultPlan.result `
            -Property 'validatesManifestIdentitySignatureAndFreshness' `
            -Expected $true) -or
        -not (Test-ExactBoolean -Value $c2eResultPlan.result `
            -Property 'checkIsReadOnly' -Expected $true) -or
        -not (Test-ExactBoolean -Value $c2eResultPlan.result `
            -Property 'consumeUsesExactAtomicHandleDelete' -Expected $true) -or
        -not (Test-ExactBoolean -Value $c2eResultPlan.result `
            -Property 'cleanupIsFixedPathAndIdempotent' -Expected $true) -or
        -not (Test-ExactBoolean -Value $c2eResultPlan.result `
            -Property 'cleanupAllowsBoundedEmptyPartialOrValidFile' `
            -Expected $true) -or
        -not (Test-ExactBoolean -Value $c2eResultPlan.result `
            -Property 'readsEvents' -Expected $false) -or
        -not (Test-ExactBoolean -Value $c2eResultPlan.result `
            -Property 'signsData' -Expected $false) -or
        -not (Test-ExactBoolean -Value $c2eResultPlan.result `
            -Property 'startsOrMutatesService' -Expected $false) -or
        -not (Test-ExactBoolean -Value $c2eResultPlan.result `
            -Property 'mutatesRegistry' -Expected $false) -or
        -not (Test-ExactBoolean -Value $c2eResultPlan.result `
            -Property 'mutatesAuditPolicy' -Expected $false) -or
        -not (Test-ExactBoolean -Value $c2eResultPlan.result `
            -Property 'retryEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $c2eResultPlan.result `
            -Property 'pollingEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $c2eResultPlan.result `
            -Property 'transportEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $c2eResultPlan.result `
            -Property 'inboundListenerEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $c2eResultPlan.result `
            -Property 'commandChannelEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $c2eResultPlan.result `
            -Property 'responseActionEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $c2eResultPlan.result `
            -Property 'runtimeWired' -Expected $false)
    ) {
        throw 'Windows Gate C2e result operator plan exceeded its exact boundary.'
    }

    $c2fApprovalPlan = Invoke-JsonScript -Path (
        Join-Path $root `
            'scripts\manage-windows-security-4663-live-approval.ps1'
    ) -Arguments @('-Command', 'plan')
    $expectedC2fApprovalPath =
        'C:\ProgramData\WAR-R00M\Windows Sensor\C2\security-4663-live-one-shot-approval.json'
    $expectedC2fApprovalCommands = 'plan,write,check,absent-check,cleanup'
    if (
        -not (Test-ExactBoolean -Value $c2fApprovalPlan -Property 'ok' `
            -Expected $true) -or
        $c2fApprovalPlan.command -ne 'plan' -or
        $c2fApprovalPlan.result.schemaVersion -ne 1 -or
        $c2fApprovalPlan.result.checkpoint -ne
            'gate-c2f-security-4663-live-one-shot' -or
        (@($c2fApprovalPlan.result.commands) -join ',') -ne
            $expectedC2fApprovalCommands -or
        $c2fApprovalPlan.result.approvalPath -ne $expectedC2fApprovalPath -or
        -not (Test-ExactBoolean -Value $c2fApprovalPlan.result `
            -Property 'requiresAdministratorForMutation' -Expected $true) -or
        -not (Test-ExactBoolean -Value $c2fApprovalPlan.result `
            -Property 'requiresAdministratorForProtectedRead' -Expected $true) -or
        -not (Test-ExactBoolean -Value $c2fApprovalPlan.result `
            -Property 'derivesInstalledCommitFromProtectedManifest' `
            -Expected $true) -or
        -not (Test-ExactBoolean -Value $c2fApprovalPlan.result `
            -Property 'derivesIdentityFromMachineKey' -Expected $true) -or
        -not (Test-ExactBoolean -Value $c2fApprovalPlan.result `
            -Property 'externalCheckerHasSigningAuthority' -Expected $false) -or
        -not (Test-ExactBoolean -Value $c2fApprovalPlan.result `
            -Property 'verifiesExactC2dReadiness' -Expected $true) -or
        -not (Test-ExactBoolean -Value $c2fApprovalPlan.result `
            -Property 'capturesBaselineFromMetadataOnly' -Expected $true) -or
        -not (Test-ExactBoolean -Value $c2fApprovalPlan.result `
            -Property 'acceptsCallerInput' -Expected $false) -or
        -not (Test-ExactBoolean -Value $c2fApprovalPlan.result `
            -Property 'readsEvents' -Expected $false) -or
        $c2fApprovalPlan.result.maximumEventsRead -ne 0 -or
        -not (Test-ExactBoolean -Value $c2fApprovalPlan.result `
            -Property 'startsService' -Expected $false) -or
        -not (Test-ExactBoolean -Value $c2fApprovalPlan.result `
            -Property 'mutatesService' -Expected $false) -or
        -not (Test-ExactBoolean -Value $c2fApprovalPlan.result `
            -Property 'cleanupRequiresIdentityOrManifest' -Expected $false) -or
        -not (Test-ExactBoolean -Value $c2fApprovalPlan.result `
            -Property 'cleanupUsesOnlyFixedApprovalPath' -Expected $true) -or
        @('retryEnabled', 'pollingEnabled', 'transportEnabled',
            'inboundListenerEnabled', 'commandChannelEnabled',
            'responseActionEnabled', 'runtimeWired').Where({
                -not (Test-ExactBoolean -Value $c2fApprovalPlan.result `
                    -Property $_ -Expected $false)
            }).Count -ne 0
    ) {
        throw 'Windows Gate C2f approval operator plan exceeded its exact boundary.'
    }

    $c2fResultPlan = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\manage-windows-security-4663-live-result.ps1'
    ) -Arguments @('-Command', 'plan')
    $expectedC2fResultPath =
        'C:\ProgramData\WAR-R00M\Windows Sensor\C2\security-4663-live-one-shot-result.json'
    $expectedC2fResultCommands =
        'plan,prepare-slot,empty-check,check,consume,absent-check,cleanup'
    $c2fResultTrueProperties = @(
        'requiresAdministrator', 'checksProtectedRootAndFileAcl',
        'rejectsReparsePoints', 'rejectsHardLinks', 'requiresStrictUtf8',
        'validatesManifestIdentitySignatureAndFreshness', 'checkIsReadOnly',
        'consumeUsesExactAtomicHandleDelete', 'cleanupIsFixedPathAndIdempotent',
        'cleanupAllowsBoundedEmptyPartialOrValidFile'
    )
    $c2fResultFalseProperties = @(
        'readsEvents', 'signsData', 'startsOrMutatesService',
        'mutatesRegistry', 'mutatesAuditPolicy', 'retryEnabled',
        'pollingEnabled', 'transportEnabled', 'inboundListenerEnabled',
        'commandChannelEnabled', 'responseActionEnabled', 'runtimeWired'
    )
    if (
        -not (Test-ExactBoolean -Value $c2fResultPlan -Property 'ok' `
            -Expected $true) -or
        $c2fResultPlan.command -ne 'plan' -or
        $c2fResultPlan.result.schemaVersion -ne 1 -or
        $c2fResultPlan.result.checkpoint -ne
            'gate-c2f-security-4663-live-one-shot' -or
        (@($c2fResultPlan.result.commands) -join ',') -ne
            $expectedC2fResultCommands -or
        $c2fResultPlan.result.resultPath -ne $expectedC2fResultPath -or
        $c2fResultPlan.result.maximumDocumentBytes -ne 4096 -or
        $c2fResultPlan.result.maximumResultAgeSeconds -ne 300 -or
        @($c2fResultTrueProperties | Where-Object {
            -not (Test-ExactBoolean -Value $c2fResultPlan.result `
                -Property $_ -Expected $true)
        }).Count -ne 0 -or
        @($c2fResultFalseProperties | Where-Object {
            -not (Test-ExactBoolean -Value $c2fResultPlan.result `
                -Property $_ -Expected $false)
        }).Count -ne 0
    ) {
        throw 'Windows Gate C2f result operator plan exceeded its exact boundary.'
    }

    $c2fExecutionPlan = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\manage-windows-security-4663-live-result.ps1'
    ) -Arguments @('-Command', 'live-exercise', '-WhatIf')
    $c2fExecutionTrueProperties = @(
        'requiresLocalServiceBeforeProtectedAccess',
        'requiresPreStartOperatorTrigger', 'consumesApprovalExactlyOnce',
        'writesResultExactlyOnce', 'nativeEventAccessEnabled', 'runtimeWired'
    )
    $c2fExecutionFalseProperties = @(
        'workerTriggersTarget', 'rawEventContentRetained',
        'persistsClassificationKey', 'continuousCollectionEnabled',
        'retryEnabled', 'pollingEnabled', 'transportEnabled',
        'inboundListenerEnabled', 'commandChannelEnabled',
        'responseActionEnabled'
    )
    if (
        -not (Test-ExactBoolean -Value $c2fExecutionPlan -Property 'ok' `
            -Expected $true) -or
        $c2fExecutionPlan.command -ne 'execution-plan' -or
        $c2fExecutionPlan.result.schemaVersion -ne 1 -or
        $c2fExecutionPlan.result.checkpoint -ne
            'gate-c2f-security-4663-live-one-shot' -or
        $c2fExecutionPlan.result.startupArgument -ne
            '--security-4663-live-one-shot' -or
        $c2fExecutionPlan.result.serviceIdentity -ne
            'NT AUTHORITY\LocalService' -or
        $c2fExecutionPlan.result.approvalPath -ne $expectedC2fApprovalPath -or
        $c2fExecutionPlan.result.resultPath -ne $expectedC2fResultPath -or
        $c2fExecutionPlan.result.fixedTargetPath -ne
            'C:\ProgramData\WAR-R00M\Windows Sensor\C2\credential-store.fixture' -or
        $c2fExecutionPlan.result.profileId -ne 'credential-store-read' -or
        $c2fExecutionPlan.result.maximumEventsRead -ne 1 -or
        $c2fExecutionPlan.result.maximumQueryMilliseconds -ne 2000 -or
        $c2fExecutionPlan.result.maximumTriggerWindowSeconds -ne 10 -or
        @($c2fExecutionTrueProperties | Where-Object {
            -not (Test-ExactBoolean -Value $c2fExecutionPlan.result `
                -Property $_ -Expected $true)
        }).Count -ne 0 -or
        @($c2fExecutionFalseProperties | Where-Object {
            -not (Test-ExactBoolean -Value $c2fExecutionPlan.result `
                -Property $_ -Expected $false)
        }).Count -ne 0
    ) {
        throw 'Windows Gate C2f live execution plan exceeded its exact boundary.'
    }

    $c2gPlan = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\manage-windows-security-4663-live-result.ps1'
    ) -Arguments @('-Command', 'genuine-match-exercise', '-WhatIf')
    $c2gTrueProperties = @(
        'requiresLocalServiceBeforeProtectedAccess',
        'requiresPreStartOperatorTrigger',
        'requiresFixedPostTriggerSettlement', 'requiresGenuineMatch',
        'requiresStrictRollback'
    )
    $c2gFalseProperties = @(
        'rawEventContentRetained', 'continuousCollectionEnabled',
        'retryEnabled', 'pollingEnabled', 'telemetryEnabled',
        'transportEnabled', 'ipcEnabled', 'inboundListenerEnabled',
        'commandChannelEnabled', 'responseActionEnabled', 'runtimeWired'
    )
    if (
        -not (Test-ExactBoolean -Value $c2gPlan -Property 'ok' `
            -Expected $true) -or
        $c2gPlan.command -ne 'genuine-match-plan' -or
        $c2gPlan.result.schemaVersion -ne 1 -or
        $c2gPlan.result.checkpoint -ne
            'gate-c2g-security-4663-genuine-match' -or
        $c2gPlan.result.serviceIdentity -ne
            'NT AUTHORITY\LocalService' -or
        $c2gPlan.result.triggerSettlementMilliseconds -ne 2000 -or
        $c2gPlan.result.maximumEventsRead -ne 1 -or
        $c2gPlan.result.maximumQueries -ne 1 -or
        $c2gPlan.result.maximumQueryMilliseconds -ne 2000 -or
        $c2gPlan.result.maximumTriggerWindowSeconds -ne 10 -or
        $c2gPlan.result.requiredEventsRead -ne 1 -or
        @($c2gTrueProperties | Where-Object {
            -not (Test-ExactBoolean -Value $c2gPlan.result `
                -Property $_ -Expected $true)
        }).Count -ne 0 -or
        @($c2gFalseProperties | Where-Object {
            -not (Test-ExactBoolean -Value $c2gPlan.result `
                -Property $_ -Expected $false)
        }).Count -ne 0
    ) {
        throw 'Windows Gate C2g plan exceeded its exact boundary.'
    }

    $c2eResultLifecycleSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\windows-sensor\src\Security4663OneShotResultLifecycle.cs'
    )
    $c2eResultSlotSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\windows-sensor\src\Security4663OneShotResultFileSlot.cs'
    )
    $c2eResultOperatorSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\windows-sensor\src\Security4663OneShotResultOperator.cs'
    )
    $c2eResultToolSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\windows-sensor\security-4663-result-tool\Program.cs'
    )
    $c2eIdentityDescriptorSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\windows-sensor\src\CngMachineIdentityDescriptorReader.cs'
    )
    $c2eResultWrapperSource = Get-Content -Raw -LiteralPath (
        Join-Path $root 'scripts\manage-windows-security-4663-result.ps1'
    )
    $c2eResultForbidden = @(
        'System\.Diagnostics\.Eventing\.Reader',
        'EventLogReader\b',
        'EventLogQuery\b',
        '\.ReadEvent\s*\(',
        'HttpClient\b',
        'HttpMessageInvoker\b',
        'Process\.Start\b',
        'ServiceController\b',
        'Start-Service|Stop-Service',
        'TcpListener\b',
        'HttpListener\b'
    )
    $sensorHostSource = Get-Content -Raw -LiteralPath (
        Join-Path $root 'apps\windows-sensor\src\Program.cs'
    )
    if (
        @($c2eResultForbidden | Where-Object {
            $c2eResultLifecycleSource -match $_ -or
            $c2eResultSlotSource -match $_ -or
            $c2eResultOperatorSource -match $_ -or
            $c2eResultToolSource -match $_ -or
            $c2eIdentityDescriptorSource -match $_
        }).Count -ne 0 -or
        $c2eResultLifecycleSource -notmatch
            'MaximumDocumentBytes\s*=\s*4_096' -or
        $c2eResultLifecycleSource -notmatch
            'MaximumResultAgeSeconds\s*=\s*300' -or
        $c2eResultLifecycleSource -notmatch
            'RandomNumberGenerator\.GetBytes\(32\)' -or
        $c2eResultLifecycleSource -match '"baselineRecordId"' -or
        $c2eResultSlotSource -notmatch
            'LocalServiceWriteData\s*=\s*0x00000002' -or
        $c2eResultSlotSource -notmatch 'OpenExisting\s*=\s*3' -or
        $c2eResultSlotSource -notmatch
            'FileFlagWriteThrough\s*=\s*0x80000000' -or
        $c2eResultSlotSource -notmatch
            'FileFlagOpenReparsePoint\s*=\s*0x00200000' -or
        $c2eResultOperatorSource -match '\.SignUtf8Payload\s*\(' -or
        $c2eResultToolSource -match '\.SignUtf8Payload\s*\(' -or
        $c2eResultToolSource -match '\bCngMachineKeySigner\b|\bECDsaCng\b' -or
        $c2eIdentityDescriptorSource -match
            '\bCngMachineKeySigner\b|\bECDsaCng\b' -or
        $sensorHostSource -match
            'Security4663OneShotResult(File|Operator|Lifecycle)'
    ) {
        throw 'Windows Gate C2e result lifecycle or operator exceeded its source-only boundary.'
    }

    $c2fApprovalSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\windows-sensor\src\Security4663LiveOneShotApprovalLifecycle.cs'
    )
    $c2fApprovalFileSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\windows-sensor\src\Security4663LiveOneShotApprovalFileStore.cs'
    )
    $c2fApprovalOperatorSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\windows-sensor\src\Security4663LiveOneShotApprovalOperator.cs'
    )
    $c2fApprovalToolSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\windows-sensor\security-4663-live-approval-tool\Program.cs'
    )
    $c2fApprovalWrapperSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'scripts\manage-windows-security-4663-live-approval.ps1'
    )
    $c2fResultSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\windows-sensor\src\Security4663LiveOneShotResultLifecycle.cs'
    )
    $c2fResultSlotSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\windows-sensor\src\Security4663LiveOneShotResultFileSlot.cs'
    )
    $c2fResultOperatorSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\windows-sensor\src\Security4663LiveOneShotResultOperator.cs'
    )
    $c2fResultToolSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\windows-sensor\security-4663-live-result-tool\Program.cs'
    )
    $c2fResultWrapperSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'scripts\manage-windows-security-4663-live-result.ps1'
    )
    $c2fExecutionSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\windows-sensor\src\Security4663LiveOneShotExecution.cs'
    )
    $c2fApprovalForbidden = @(
        'System\.Diagnostics\.Eventing\.Reader',
        'EventLogReader\b',
        'EventLogQuery\b',
        '\.ReadEvent\s*\(',
        'HttpClient\b',
        'HttpMessageInvoker\b',
        'Process\.Start\b',
        'ServiceController\b',
        'Microsoft\.Win32\.(Registry|RegistryKey)\b',
        'TcpListener\b',
        'HttpListener\b'
    )
    if (
        @($c2fApprovalForbidden | Where-Object {
            $c2fApprovalSource -match $_ -or
            $c2fApprovalFileSource -match $_ -or
            $c2fApprovalOperatorSource -match $_ -or
            $c2fApprovalToolSource -match $_ -or
            $c2fResultSource -match $_ -or
            $c2fResultSlotSource -match $_ -or
            $c2fResultOperatorSource -match $_ -or
            $c2fResultToolSource -match $_
        }).Count -ne 0 -or
        $c2fApprovalSource -notmatch
            'gate-c2f-security-4663-live-one-shot-approval-v1' -or
        $c2fApprovalSource -notmatch
            'fixed-inert-security-4663-read-and-normalize' -or
        $c2fApprovalSource -notmatch
            '--security-4663-live-one-shot' -or
        $c2fApprovalSource -notmatch
            'MaximumQueryMilliseconds\s*=\s*2_000' -or
        $c2fApprovalSource -notmatch
            'MaximumEventsRead\s*=\s*1' -or
        $c2fApprovalSource -notmatch
            'MaximumTriggerWindowSeconds\s*=\s*10' -or
        $c2fApprovalSource -notmatch
            'RuntimeWired\s*=\s*true' -or
        $c2fApprovalSource -notmatch
            'ISecurity4663LiveOneShotApprovalStore' -or
        $c2fApprovalSource -match
            '\bISecurity4663OneShotApprovalStore\b' -or
        $c2fApprovalFileSource -notmatch
            'security-4663-live-one-shot-approval\.json' -or
        $c2fApprovalFileSource -notmatch
            'LocalServiceReadDelete\s*=\s*0x00130089' -or
        $c2fApprovalFileSource -notmatch
            'FileFlagOpenReparsePoint\s*=\s*0x00200000' -or
        $c2fApprovalFileSource -notmatch
            'CreateFileWithSecurityW\s*\(' -or
        $c2fApprovalFileSource -notmatch
            'FileStandardInfoClass\s*=\s*1' -or
        $c2fApprovalFileSource -notmatch 'NumberOfLinks\s*!=\s*1' -or
        $c2fApprovalFileSource -notmatch 'RuntimeWired\s*=\s*true' -or
        $c2fApprovalOperatorSource -notmatch
            'Security4663ReadinessCheck\.Check\(readinessProbe\)' -or
        $c2fApprovalOperatorSource -notmatch
            'Security4663OneShotBaseline\.Capture\(baselineSource\)' -or
        $c2fApprovalOperatorSource -match
            'ConsumeEnvelope\s*\(|ConsumeExact\s*\(' -or
        $c2fApprovalToolSource -notmatch
            'CngMachineIdentityDescriptorReader\(\)\.ReadProvisioned\(\)' -or
        $c2fApprovalToolSource -match
            'ConsumeEnvelope\s*\(|ConsumeExact\s*\(' -or
        $c2fApprovalWrapperSource -match
            'Start-Service|Stop-Service|ServiceController|EventLogReader|EventLogQuery|Invoke-WebRequest|Invoke-RestMethod' -or
        $c2fResultSource -notmatch
            'gate-c2f-security-4663-live-one-shot-result-v1' -or
        $c2fResultSource -notmatch
            'ConsumedSecurity4663LiveOneShotApproval' -or
        $c2fResultSource -notmatch
            'MaximumDocumentBytes\s*=\s*4_096' -or
        $c2fResultSource -notmatch
            'MaximumResultAgeSeconds\s*=\s*300' -or
        $c2fResultSource -notmatch
            'MaximumCompletionDelaySeconds\s*=\s*5' -or
        $c2fResultSource -notmatch
            'RandomNumberGenerator\.GetBytes\(32\)' -or
        $c2fResultSource -notmatch
            'ISecurity4663LiveOneShotResultStore' -or
        $c2fResultSource -match
            '\bISecurity4663OneShotResultStore\b|ConsumeExact\s*\(' -or
        $c2fResultSource -match '"baselineRecordId"' -or
        $c2fResultSource -match
            '\bFile(Stream|Info)\b|\bDirectory(Info)?\b' -or
        $c2fResultSource -notmatch 'RuntimeWired\s*=\s*true' -or
        $c2fResultSlotSource -notmatch
            'security-4663-live-one-shot-result\.json' -or
        $c2fResultSlotSource -notmatch
            'LocalServiceSynchronousWriteAndReadAttributes\s*=\s*' +
            '0x00100082' -or
        $c2fResultSlotSource -notmatch 'OpenExisting\s*=\s*3' -or
        $c2fResultSlotSource -notmatch
            'FileFlagWriteThrough\s*=\s*0x80000000' -or
        $c2fResultSlotSource -notmatch
            'FileFlagOpenReparsePoint\s*=\s*0x00200000' -or
        $c2fResultSlotSource -notmatch 'NumberOfLinks\s*!=\s*1' -or
        $c2fResultSlotSource -notmatch 'RuntimeWired\s*=\s*true' -or
        $c2fResultSlotSource -notmatch 'ServiceRegistered\s*=\s*true' -or
        $c2fResultOperatorSource -match '\.SignUtf8Payload\s*\(' -or
        $c2fResultToolSource -notmatch
            'CngMachineIdentityDescriptorReader\(\)\.ReadProvisioned\(\)' -or
        $c2fResultToolSource -match
            '\bCngMachineKeySigner\b|\bECDsaCng\b|\.SignUtf8Payload\s*\('
    ) {
        throw 'Windows Gate C2f live approval exceeded its source-only boundary.'
    }

    $c2fExecutionForbidden = @(
        'HttpClient\b', 'HttpMessageInvoker\b', 'Process\.Start\b',
        'TcpListener\b', 'HttpListener\b', 'Socket\b',
        '\bwhile\s*\(', '\bfor\s*\(\s*;;', 'Task\.Run\s*\('
    )
    if (
        @($c2fExecutionForbidden | Where-Object {
            $c2fExecutionSource -match $_
        }).Count -ne 0 -or
        $c2fExecutionSource -notmatch
            'RequiresLocalServiceBeforeProtectedAccess' -or
        $c2fExecutionSource -notmatch
            'MaximumEventsRead' -or
        $c2fExecutionSource -notmatch
            'RandomNumberGenerator\.GetBytes\(32\)' -or
        $c2fExecutionSource -notmatch
            'CryptographicOperations\.ZeroMemory\(key\)' -or
        $c2fExecutionSource -notmatch
            'NativeSecurity4663LiveOneShotEventSource' -or
        $c2fExecutionSource -notmatch
            'Security4663LiveOneShotExecutionWorker' -or
        $c2fExecutionSource -match
            'RawEventXml|Event\.ToXml|\.FormatDescription\s*\(' -or
        $sensorHostSource -notmatch
            'startupMode\s*==\s*SensorStartupMode\.Security4663LiveOneShot' -or
        $sensorHostSource -notmatch
            'AddSingleton<ISecurity4663LiveOneShotApprovalStore,\s*\r?\n\s*NativeSecurity4663LiveOneShotApprovalFileStore>' -or
        $sensorHostSource -notmatch
            'AddSingleton<ISecurity4663OneShotEventSource,\s*\r?\n\s*NativeSecurity4663LiveOneShotEventSource>' -or
        $sensorHostSource -notmatch
            'AddSingleton<ISecurity4663OneShotReader,\s*\r?\n\s*Security4663LiveOneShotBoundedReader>' -or
        $sensorHostSource -notmatch
            'AddSingleton<ISecurity4663LiveOneShotResultStore,\s*\r?\n\s*NativeSecurity4663LiveOneShotResultFileStore>' -or
        $sensorHostSource -notmatch
            'AddHostedService<Security4663LiveOneShotExecutionWorker>\(\)' -or
        $sensorHostSource -notmatch
            'await builder\.Build\(\)\.RunAsync\(\);\s*\r?\n\s*return;'
    ) {
        throw 'Windows Gate C2f live execution wiring exceeded its exact boundary.'
    }

    $c2fApplyIndex = $c2fApprovalWrapperSource.IndexOf(
        "-NativeCommand 'security-4663-apply'",
        [StringComparison]::Ordinal
    )
    $c2fWriteIndex = $c2fApprovalWrapperSource.IndexOf(
        "-NativeCommand 'write'",
        [StringComparison]::Ordinal
    )
    $c2fCheckIndex = $c2fApprovalWrapperSource.IndexOf(
        "-NativeCommand 'check'",
        [StringComparison]::Ordinal
    )
    $c2fCleanupIndex = $c2fApprovalWrapperSource.IndexOf(
        "-NativeCommand 'cleanup'",
        [StringComparison]::Ordinal
    )
    $c2fAbsentIndex = $c2fApprovalWrapperSource.IndexOf(
        "-NativeCommand 'absent-check'",
        [StringComparison]::Ordinal
    )
    $c2fRollbackIndex = $c2fApprovalWrapperSource.IndexOf(
        "-NativeCommand 'security-4663-rollback'",
        [StringComparison]::Ordinal
    )
    if (
        $c2fApplyIndex -lt 0 -or
        $c2fWriteIndex -le $c2fApplyIndex -or
        $c2fCheckIndex -le $c2fWriteIndex -or
        $c2fCleanupIndex -le $c2fCheckIndex -or
        $c2fAbsentIndex -le $c2fCleanupIndex -or
        $c2fRollbackIndex -le $c2fAbsentIndex
    ) {
        throw 'Windows Gate C2f approval exercise ordering is not fail-closed.'
    }

    $c2fLiveExerciseStart = $c2fResultWrapperSource.IndexOf(
        "if (`$Command -in @('live-exercise', 'genuine-match-exercise'))",
        [StringComparison]::Ordinal)
    $c2fSlotExerciseStart = $c2fResultWrapperSource.IndexOf(
        "if (`$Command -eq 'slot-exercise')", [StringComparison]::Ordinal)
    if ($c2fLiveExerciseStart -lt 0 -or
        $c2fSlotExerciseStart -le $c2fLiveExerciseStart) {
        throw 'Windows Gate C2f exercise command boundaries are missing.'
    }
    $c2fLiveExerciseSource = $c2fResultWrapperSource.Substring(
        $c2fLiveExerciseStart,
        $c2fSlotExerciseStart - $c2fLiveExerciseStart
    )
    $c2fSlotExerciseSource = $c2fResultWrapperSource.Substring(
        $c2fSlotExerciseStart
    )
    if (
        $c2fResultWrapperSource -match
            '\[Environment\]::GetFolderPath\([\s\S]*SpecialFolder\]::ProgramFiles' -or
        $c2fResultWrapperSource -notmatch
            '\[Microsoft\.Win32\.RegistryView\]::Registry64' -or
        $c2fResultWrapperSource -notmatch "'ProgramFilesDir'"
    ) {
        throw 'Windows Gate C2f live exercise did not use the native Program Files root.'
    }
    if (
        $c2fResultWrapperSource -notmatch '--disable-build-servers' -or
        $c2fResultWrapperSource -notmatch "'-m:1'" -or
        $c2fResultWrapperSource -notmatch
            "'-p:UseSharedCompilation=false'" -or
        $c2fResultWrapperSource -notmatch
            '\$nativeErrorActionPreference\s*=\s*\$ErrorActionPreference' -or
        $c2fResultWrapperSource -notmatch
            '\$ErrorActionPreference\s*=\s*''Continue''' -or
        $c2fResultWrapperSource -notmatch
            '\$ErrorActionPreference\s*=\s*\$nativeErrorActionPreference' -or
        $c2fResultWrapperSource -notmatch
            "'SENSOR_C2F_SECURITY_4663_INERT_TRIGGER_FAILED'" -or
        $c2fResultWrapperSource -notmatch
            "'SENSOR_C2F_SECURITY_4663_SERVICE_RUN_FAILED'"
    ) {
        throw 'Windows Gate C2f live exercise build or stage diagnostics drifted.'
    }

    $c2fResultApplyIndex = $c2fSlotExerciseSource.IndexOf(
        "-NativeCommand 'security-4663-apply'", [StringComparison]::Ordinal)
    $c2fResultPrepareIndex = $c2fSlotExerciseSource.IndexOf(
        "-NativeCommand 'prepare-slot'", [StringComparison]::Ordinal)
    $c2fResultEmptyIndex = $c2fSlotExerciseSource.IndexOf(
        "-NativeCommand 'empty-check'", [StringComparison]::Ordinal)
    $c2fResultCleanupIndex = $c2fSlotExerciseSource.IndexOf(
        "-NativeCommand 'cleanup'", [StringComparison]::Ordinal)
    $c2fResultAbsentIndex = $c2fSlotExerciseSource.IndexOf(
        "-NativeCommand 'absent-check'", [StringComparison]::Ordinal)
    $c2fResultRollbackIndex = $c2fSlotExerciseSource.IndexOf(
        "-NativeCommand 'security-4663-rollback'", [StringComparison]::Ordinal)
    if (
        $c2fResultApplyIndex -lt 0 -or
        $c2fResultPrepareIndex -le $c2fResultApplyIndex -or
        $c2fResultEmptyIndex -le $c2fResultPrepareIndex -or
        $c2fResultCleanupIndex -le $c2fResultEmptyIndex -or
        $c2fResultAbsentIndex -le $c2fResultCleanupIndex -or
        $c2fResultRollbackIndex -le $c2fResultAbsentIndex -or
        $c2fSlotExerciseSource -notmatch '\$WhatIfPreference' -or
        $c2fSlotExerciseSource -notmatch '\bShouldProcess\s*\(' -or
        $c2fSlotExerciseSource -notmatch '\bfinally\s*\{' -or
        $c2fSlotExerciseSource -notmatch 'eventsRead\s*=\s*0' -or
        $c2fSlotExerciseSource -notmatch 'eventContentRead\s*=\s*\$false' -or
        $c2fSlotExerciseSource -notmatch 'serviceStarted\s*=\s*\$false' -or
        $c2fSlotExerciseSource -notmatch 'serviceMutated\s*=\s*\$false' -or
        $c2fSlotExerciseSource -notmatch 'telemetryEnabled\s*=\s*\$false' -or
        $c2fSlotExerciseSource -notmatch 'transportEnabled\s*=\s*\$false' -or
        $c2fSlotExerciseSource -notmatch 'commandChannelEnabled\s*=\s*\$false'
    ) {
        throw 'Windows Gate C2f empty-slot exercise exceeded its guarded boundary.'
    }

    $c2fLiveApplyIndex = $c2fLiveExerciseSource.IndexOf(
        "-NativeCommand 'security-4663-apply'", [StringComparison]::Ordinal)
    $c2fLivePrepareIndex = $c2fLiveExerciseSource.IndexOf(
        "-NativeCommand 'prepare-slot'", [StringComparison]::Ordinal)
    $c2fLiveApprovalWriteIndex = $c2fLiveExerciseSource.IndexOf(
        "-NativeCommand 'write'", [StringComparison]::Ordinal)
    $c2fLiveTriggerIndex = $c2fLiveExerciseSource.IndexOf(
        'Invoke-FixedInertTrigger', [StringComparison]::Ordinal)
    $c2gSettlementIndex = $c2fLiveExerciseSource.IndexOf(
        'Start-Sleep -Milliseconds $settlementMilliseconds',
        [StringComparison]::Ordinal)
    $c2fLiveMarkerIndex = $c2fLiveExerciseSource.IndexOf(
        'Set-LiveStartupMode', [StringComparison]::Ordinal)
    $c2fLiveStartIndex = $c2fLiveExerciseSource.IndexOf(
        '$controller.Start()', [StringComparison]::Ordinal)
    $c2fLiveCheckIndex = $c2fLiveExerciseSource.IndexOf(
        "-NativeCommand 'check'", $c2fLiveStartIndex,
        [StringComparison]::Ordinal)
    $c2fLiveConsumeIndex = $c2fLiveExerciseSource.IndexOf(
        "-NativeCommand 'consume'", [StringComparison]::Ordinal)
    $c2fLiveAbsentIndex = $c2fLiveExerciseSource.IndexOf(
        "-NativeCommand 'absent-check'", $c2fLiveConsumeIndex,
        [StringComparison]::Ordinal)
    $c2fLiveCleanupIndex = $c2fLiveExerciseSource.IndexOf(
        "Command = 'cleanup'", [StringComparison]::Ordinal)
    $c2fLiveRollbackIndex = $c2fLiveExerciseSource.IndexOf(
        "-NativeCommand 'security-4663-rollback'", [StringComparison]::Ordinal)
    $c2gNoMatchFailureIndex = $c2fLiveExerciseSource.IndexOf(
        '$null -eq $failure -and $isGenuineMatchExercise',
        [StringComparison]::Ordinal)
    if (
        $c2fLiveApplyIndex -lt 0 -or
        $c2fLivePrepareIndex -le $c2fLiveApplyIndex -or
        $c2fLiveApprovalWriteIndex -le $c2fLivePrepareIndex -or
        $c2fLiveTriggerIndex -le $c2fLiveApprovalWriteIndex -or
        $c2gSettlementIndex -le $c2fLiveTriggerIndex -or
        $c2fLiveMarkerIndex -le $c2gSettlementIndex -or
        $c2fLiveStartIndex -le $c2fLiveMarkerIndex -or
        $c2fLiveCheckIndex -le $c2fLiveStartIndex -or
        $c2fLiveConsumeIndex -le $c2fLiveCheckIndex -or
        $c2fLiveAbsentIndex -le $c2fLiveConsumeIndex -or
        $c2fLiveCleanupIndex -le $c2fLiveAbsentIndex -or
        $c2fLiveRollbackIndex -le $c2fLiveCleanupIndex -or
        $c2gNoMatchFailureIndex -le $c2fLiveRollbackIndex -or
        ([regex]::Matches($c2fLiveExerciseSource,
            [regex]::Escape('$controller.Start()'))).Count -ne 1 -or
        ([regex]::Matches($c2fLiveExerciseSource,
            [regex]::Escape(
                'Start-Sleep -Milliseconds $settlementMilliseconds'))).Count -ne 1 -or
        $c2fLiveExerciseSource -notmatch '\bfinally\s*\{' -or
        $c2fLiveExerciseSource -notmatch
            "Get-LiveServiceContext" -or
        $c2fLiveExerciseSource -notmatch
            'resultExternallyChecked\s*=\s*\$resultChecked' -or
        $c2fLiveExerciseSource -notmatch 'maximumEventsRead\s*=\s*1' -or
        $c2fLiveExerciseSource -notmatch 'maximumQueries\s*=\s*1' -or
        $c2fLiveExerciseSource -notmatch
            'SENSOR_C2G_SECURITY_4663_GENUINE_MATCH_REQUIRED' -or
        $c2fLiveExerciseSource -notmatch
            'rawEventContentRetained\s*=\s*\$false' -or
        $c2fLiveExerciseSource -notmatch
            'continuousCollectionEnabled\s*=\s*\$false' -or
        $c2fLiveExerciseSource -notmatch 'retryEnabled\s*=\s*\$false' -or
        $c2fLiveExerciseSource -notmatch 'pollingEnabled\s*=\s*\$false' -or
        $c2fLiveExerciseSource -notmatch 'telemetryEnabled\s*=\s*\$false' -or
        $c2fLiveExerciseSource -notmatch 'transportEnabled\s*=\s*\$false' -or
        $c2fLiveExerciseSource -notmatch
            'inboundListenerEnabled\s*=\s*\$false' -or
        $c2fLiveExerciseSource -notmatch
            'commandChannelEnabled\s*=\s*\$false' -or
        $c2fLiveExerciseSource -notmatch
            'responseActionEnabled\s*=\s*\$false' -or
        $c2fLiveExerciseSource -match
            'EventLogReader|EventLogQuery|Invoke-WebRequest|Invoke-RestMethod'
    ) {
        throw 'Windows Gate C2f live exercise exceeded its guarded boundary.'
    }

    $c2eApplyIndex = $c2eResultWrapperSource.IndexOf(
        "-NativeCommand 'security-4663-apply'",
        [StringComparison]::Ordinal
    )
    $c2ePrepareIndex = $c2eResultWrapperSource.IndexOf(
        "-NativeCommand 'prepare-slot'",
        [StringComparison]::Ordinal
    )
    $c2eEmptyIndex = $c2eResultWrapperSource.IndexOf(
        "-NativeCommand 'empty-check'",
        [StringComparison]::Ordinal
    )
    $c2eCleanupIndex = $c2eResultWrapperSource.IndexOf(
        "-NativeCommand 'cleanup'",
        [StringComparison]::Ordinal
    )
    $c2eAbsentIndex = $c2eResultWrapperSource.IndexOf(
        "-NativeCommand 'absent-check'",
        [StringComparison]::Ordinal
    )
    $c2eRollbackIndex = $c2eResultWrapperSource.IndexOf(
        "-NativeCommand 'security-4663-rollback'",
        [StringComparison]::Ordinal
    )
    if (
        $c2eApplyIndex -lt 0 -or
        $c2ePrepareIndex -le $c2eApplyIndex -or
        $c2eEmptyIndex -le $c2ePrepareIndex -or
        $c2eCleanupIndex -le $c2eEmptyIndex -or
        $c2eAbsentIndex -le $c2eCleanupIndex -or
        $c2eRollbackIndex -le $c2eAbsentIndex -or
        $c2eResultWrapperSource -notmatch
            "if \(\`$Command -eq 'slot-exercise'\)" -or
        $c2eResultWrapperSource -notmatch '\$WhatIfPreference' -or
        $c2eResultWrapperSource -notmatch '\bShouldProcess\s*\(' -or
        $c2eResultWrapperSource -notmatch '\bfinally\s*\{' -or
        $c2eResultWrapperSource -notmatch 'eventsRead\s*=\s*0' -or
        $c2eResultWrapperSource -notmatch 'eventContentRead\s*=\s*\$false' -or
        $c2eResultWrapperSource -notmatch 'serviceStarted\s*=\s*\$false' -or
        $c2eResultWrapperSource -notmatch 'serviceMutated\s*=\s*\$false' -or
        $c2eResultWrapperSource -notmatch 'telemetryEnabled\s*=\s*\$false' -or
        $c2eResultWrapperSource -notmatch 'transportEnabled\s*=\s*\$false' -or
        $c2eResultWrapperSource -notmatch 'commandChannelEnabled\s*=\s*\$false'
    ) {
        throw 'Windows Gate C2e empty-slot exercise exceeded its guarded boundary.'
    }

    $installPlan = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\install-windows-sensor-service.ps1'
    ) -Arguments @('-Command', 'install', '-WhatIf')
    $expectedStateRoot = Join-Path (
        [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::CommonApplicationData
        )
    ) 'WAR-R00M\Windows Sensor'
    $expectedB0Proof = Join-Path $expectedStateRoot `
        'local-synthetic-batch-proof.json'
    $expectedB1Proof = Join-Path $expectedStateRoot `
        'local-genuine-batch-proof.json'
    $expectedB1Salt = Join-Path $expectedStateRoot `
        'local-genuine-source-salt.bin'
    $expectedC0bBinding = Join-Path $expectedStateRoot `
        'endpoint-binding.json'
    $expectedC0bProof = Join-Path $expectedStateRoot `
        'local-capability-proof.json'
    $expectedC0cDelivery = Join-Path $expectedStateRoot `
        'local-loopback-delivery.json'
    $expectedC1Proof = Join-Path $expectedStateRoot `
        'local-bounded-collector-proof.json'
    $bundlePlan = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\build-windows-sensor-install-bundle.ps1'
    ) -Arguments @('-Command', 'plan')
    if (
        $bundlePlan.command -ne 'plan' -or
        -not (Test-ExactBoolean -Value $bundlePlan.result `
            -Property 'runsElevated' -Expected $false) -or
        -not (Test-ExactBoolean -Value $bundlePlan.result `
            -Property 'buildsSensor' -Expected $true) -or
        -not (Test-ExactBoolean -Value $bundlePlan.result `
            -Property 'buildsIdentityStatusTool' -Expected $true) -or
        -not (Test-ExactBoolean -Value $bundlePlan.result `
            -Property 'buildsServiceSidTool' -Expected $true) -or
        -not (Test-ExactBoolean -Value $bundlePlan.result `
            -Property 'emitsContentSealedBundle' -Expected $true) -or
        -not (Test-ExactBoolean -Value $bundlePlan.result `
            -Property 'installOrServiceMutation' -Expected $false) -or
        $installPlan.command -ne 'plan' -or
        $installPlan.plan.serviceName -ne 'WARRoomWindowsSensor' -or
        $installPlan.plan.startIdentity -ne 'NT AUTHORITY\LocalService' -or
        $installPlan.plan.syntheticBatchCount -ne 2 -or
        $installPlan.plan.localStateRoot -ne $expectedStateRoot -or
        $installPlan.plan.localProofPath -ne $expectedB0Proof -or
        $installPlan.plan.genuineProofPath -ne $expectedB1Proof -or
        $installPlan.plan.genuineSaltPath -ne $expectedB1Salt -or
        $installPlan.plan.endpointBindingPath -ne $expectedC0bBinding -or
        $installPlan.plan.capabilityProofPath -ne $expectedC0bProof -or
        $installPlan.plan.loopbackDeliveryPath -ne $expectedC0cDelivery -or
        $installPlan.plan.boundedProofPath -ne $expectedC1Proof -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'requiresSealedPackage' -Expected $true) -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'packageBuiltUnelevated' -Expected $true) -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'buildToolchainRunsElevated' -Expected $false) -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'sourceTreeExecutableRunsElevated' -Expected $false) -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'configuresFixedServiceSidFromSealedTool' `
            -Expected $true) -or
        $installPlan.plan.serviceSidType -ne
            'SERVICE_SID_TYPE_UNRESTRICTED' -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'serviceSidConfiguredBeforeResourceAcls' `
            -Expected $true) -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'serviceSidIndependentReadbackRequired' `
            -Expected $true) -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'serviceSidRollbackRequiredOnFailure' `
            -Expected $true) -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'acceptsCallerServiceSid' -Expected $false) -or
        $installPlan.plan.genuineSaltBytes -ne 32 -or
        $installPlan.plan.genuineMaximumProofBytes -ne 32768 -or
        $installPlan.plan.boundedMaximumProofBytes -ne 32768 -or
        $installPlan.plan.maximumGenuineBatchCount -ne 1 -or
        $installPlan.plan.maximumGenuineFactCount -ne 1 -or
        $installPlan.plan.genuineLog -ne 'System' -or
        $installPlan.plan.genuineProvider -ne 'Service Control Manager' -or
        $installPlan.plan.genuineEventId -ne 7045 -or
        $installPlan.plan.genuineLevel -ne 4 -or
        $installPlan.plan.genuineMaximumRecords -ne 1 -or
        (@($installPlan.plan.genuineAllowedFields) -join ',') -ne
            'providerName,eventId,level,timeCreatedUtc,recordId' -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'genuineNewestFirst' -Expected $true) -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'genuineSaltReadableByLocalService' -Expected $true) -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'genuineSaltWritableByLocalService' -Expected $false) -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'genuineSaltIncludedInOutput' -Expected $false) -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'rawEventContentRead' -Expected $false) -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'oneShotEventReaderEnabled' -Expected $true) -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'boundedOneShotCollectorEnabled' -Expected $true) -or
        $installPlan.plan.boundedMaximumFamilies -ne 2 -or
        $installPlan.plan.boundedMaximumEventsRead -ne 2 -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'continuousCollectorEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'oneShotLoopbackTransportRegistered' -Expected $true) -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'automaticRetryEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'remoteTransportEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'networkTransportEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'inboundListenerEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $installPlan.plan `
            -Property 'commandChannelEnabled' -Expected $false)
    ) {
        throw 'Windows sensor install plan exceeded the Gate C0c boundary.'
    }

    $bindingPlan = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\manage-windows-sensor-endpoint-binding.ps1'
    ) -Arguments @('-Command', 'plan')
    $pendingBindingPlan = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\manage-windows-sensor-endpoint-binding.ps1'
    ) -Arguments @('-Command', 'install-pending', '-WhatIf')
    if (
        -not (Test-ExactBoolean -Value $bindingPlan -Property 'ok' `
            -Expected $true) -or
        $bindingPlan.command -ne 'plan' -or
        $bindingPlan.plan.fixedBindingPath -ne $expectedC0bBinding -or
        $bindingPlan.plan.fixedCapabilityProofPath -ne $expectedC0bProof -or
        $bindingPlan.plan.fixedDeliveryReceiptPath -ne $expectedC0cDelivery -or
        $bindingPlan.plan.maximumInputBytes -ne 32768 -or
        -not (Test-ExactBoolean -Value $bindingPlan.plan `
            -Property 'requiresElevation' -Expected $true) -or
        -not (Test-ExactBoolean -Value $bindingPlan.plan `
            -Property 'requiresCleanMatchingInstalledCommit' -Expected $true) -or
        -not (Test-ExactBoolean -Value $bindingPlan.plan `
            -Property 'changesServiceConfiguration' -Expected $false) -or
        $bindingPlan.plan.maximumEventReads -ne 0 -or
        -not (Test-ExactBoolean -Value $bindingPlan.plan `
            -Property 'networkTransportEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $bindingPlan.plan `
            -Property 'collectorEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $bindingPlan.plan `
            -Property 'telemetryEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $bindingPlan.plan `
            -Property 'commandChannelEnabled' -Expected $false)
    ) {
        throw 'Windows Gate C0b binding plan exceeded its disabled boundary.'
    }
    if (
        $pendingBindingPlan.command -ne 'plan' -or
        $pendingBindingPlan.plan.maximumEventReads -ne 1 -or
        -not (Test-ExactBoolean -Value $pendingBindingPlan.plan `
            -Property 'oneNormalServiceStart' -Expected $true) -or
        -not (Test-ExactBoolean -Value $pendingBindingPlan.plan `
            -Property 'networkTransportEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $pendingBindingPlan.plan `
            -Property 'telemetryEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $pendingBindingPlan.plan `
            -Property 'commandChannelEnabled' -Expected $false)
    ) {
        throw 'Windows Gate C0b pending plan exceeded its one-shot boundary.'
    }

    $deliveryPlan = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\manage-windows-sensor-endpoint-binding.ps1'
    ) -Arguments @('-Command', 'deliver-once', '-WhatIf')
    if (
        $deliveryPlan.command -ne 'deliver-once-plan' -or
        $deliveryPlan.plan.fixedDestination -ne
            'http://127.0.0.1:4315/api/endpoints/facts' -or
        $deliveryPlan.plan.fixedDeliveryReceiptPath -ne $expectedC0cDelivery -or
        $deliveryPlan.plan.maximumNetworkAttempts -ne 1 -or
        $deliveryPlan.plan.maximumEventReads -ne 0 -or
        -not (Test-ExactBoolean -Value $deliveryPlan.plan `
            -Property 'requiresElevation' -Expected $true) -or
        -not (Test-ExactBoolean -Value $deliveryPlan.plan `
            -Property 'requiresFreshFinalBinding' -Expected $true) -or
        -not (Test-ExactBoolean -Value $deliveryPlan.plan `
            -Property 'requiresEmptyProtectedReceipt' -Expected $true) -or
        -not (Test-ExactBoolean -Value $deliveryPlan.plan `
            -Property 'oneNormalServiceStart' -Expected $true) -or
        -not (Test-ExactBoolean -Value $deliveryPlan.plan `
            -Property 'automaticRetryEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $deliveryPlan.plan `
            -Property 'remoteTransportEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $deliveryPlan.plan `
            -Property 'inboundListenerEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $deliveryPlan.plan `
            -Property 'pollingEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $deliveryPlan.plan `
            -Property 'commandChannelEnabled' -Expected $false)
    ) {
        throw 'Windows Gate C0c delivery plan exceeded its one-shot boundary.'
    }

    $runtimeCheck = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\install-windows-sensor-service.ps1'
    ) -Arguments @('-Command', 'runtime-check')
    if (
        -not (Test-ExactBoolean -Value $runtimeCheck -Property 'ok' `
            -Expected $true) -or
        $runtimeCheck.command -ne 'runtime-check' -or
        -not (Test-ExactBoolean -Value $runtimeCheck.result `
            -Property 'is64BitOperatingSystem' -Expected $true) -or
        -not (Test-ExactBoolean -Value $runtimeCheck.result `
            -Property 'is64BitProcess' -Expected $true) -or
        $runtimeCheck.result.processArchitecture -ne 'X64' -or
        $runtimeCheck.result.operatingSystemArchitecture -ne 'X64' -or
        -not (Test-ExactBoolean -Value $runtimeCheck.result `
            -Property 'hostProcessArchitectureRequired' -Expected $false) -or
        -not (Test-ExactBoolean -Value $runtimeCheck.result `
            -Property 'supported' -Expected $true)
    ) {
        throw 'Windows sensor runtime check did not prove the native x64 OS boundary.'
    }

    $windowsPowerShell32 = Join-Path $env:SystemRoot `
        'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $windowsPowerShell32 -PathType Leaf)) {
        throw 'Windows 32-bit PowerShell runtime probe is unavailable.'
    }
    $runtime32Lines = & $windowsPowerShell32 -NoProfile `
        -ExecutionPolicy Bypass -File (
            Join-Path $root 'scripts\install-windows-sensor-service.ps1'
        ) -Command runtime-check
    if ($LASTEXITCODE -ne 0) {
        throw 'Windows sensor 32-bit host runtime check failed.'
    }
    $runtime32Check = ($runtime32Lines -join "`n") | ConvertFrom-Json
    if (
        -not (Test-ExactBoolean -Value $runtime32Check -Property 'ok' `
            -Expected $true) -or
        $runtime32Check.command -ne 'runtime-check' -or
        -not (Test-ExactBoolean -Value $runtime32Check.result `
            -Property 'is64BitOperatingSystem' -Expected $true) -or
        -not (Test-ExactBoolean -Value $runtime32Check.result `
            -Property 'is64BitProcess' -Expected $false) -or
        $runtime32Check.result.processArchitecture -ne 'X86' -or
        $runtime32Check.result.operatingSystemArchitecture -ne 'X64' -or
        -not (Test-ExactBoolean -Value $runtime32Check.result `
            -Property 'hostProcessArchitectureRequired' -Expected $false) -or
        -not (Test-ExactBoolean -Value $runtime32Check.result `
            -Property 'supported' -Expected $true)
    ) {
        throw 'Windows sensor runtime check rejected the safe 32-bit host on x64 Windows.'
    }

    $runtime32PlanLines = & $windowsPowerShell32 -NoProfile `
        -ExecutionPolicy Bypass -File (
            Join-Path $root 'scripts\install-windows-sensor-service.ps1'
        ) -Command install -WhatIf -NativeHostConfirmFalse
    if ($LASTEXITCODE -ne 0) {
        throw 'Windows sensor 32-bit host native trampoline failed.'
    }
    $runtime32Plan = ($runtime32PlanLines -join "`n") | ConvertFrom-Json
    if (
        -not (Test-ExactBoolean -Value $runtime32Plan -Property 'ok' `
            -Expected $true) -or
        $runtime32Plan.command -ne 'plan' -or
        $runtime32Plan.plan.installRoot -ne
            'C:\Program Files\WAR-R00M\Windows Sensor' -or
        $runtime32Plan.plan.runtimeIdentifier -ne 'win-x64' -or
        $runtime32Plan.plan.runtimeProfile -ne 'self-contained-win-x64' -or
        -not (Test-ExactBoolean -Value $runtime32Plan.plan `
            -Property 'requiresElevation' -Expected $true)
    ) {
        throw 'Windows sensor 32-bit host did not reach the native x64 install plan.'
    }

    $sourceReadinessPlan = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\invoke-windows-sensor-dotnet.ps1'
    ) -Arguments @('-Command', 'readiness-plan')
    $sourceDefinitions = @($sourceReadinessPlan.result.sources)
    $expectedSourceFields = @(
        'providerName',
        'eventId',
        'level',
        'timeCreatedUtc',
        'recordId'
    )
    if (
        -not (Test-ExactBoolean -Value $sourceReadinessPlan `
            -Property 'ok' -Expected $true) -or
        $sourceReadinessPlan.command -ne 'source-readiness-plan' -or
        $sourceReadinessPlan.result.schemaVersion -ne 1 -or
        $sourceReadinessPlan.result.probeContext -ne
            'operator-session-metadata-only' -or
        -not (Test-ExactBoolean -Value $sourceReadinessPlan.result `
            -Property 'serviceIdentityValidated' -Expected $false) -or
        -not (Test-ExactBoolean -Value $sourceReadinessPlan.result `
            -Property 'runtimeCollectionEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $sourceReadinessPlan.result `
            -Property 'transportEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $sourceReadinessPlan.result `
            -Property 'inboundListenerEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $sourceReadinessPlan.result `
            -Property 'commandChannelEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $sourceReadinessPlan.result `
            -Property 'arbitraryChannelsAllowed' -Expected $false) -or
        -not (Test-ExactBoolean -Value $sourceReadinessPlan.result `
            -Property 'rawEventContentAllowed' -Expected $false) -or
        $sourceReadinessPlan.result.eventsRead -ne 0 -or
        $sourceDefinitions.Count -ne 2 -or
        $sourceDefinitions[0].sourceId -ne 'windows-system' -or
        $sourceDefinitions[0].logName -ne 'System' -or
        $sourceDefinitions[1].sourceId -ne 'windows-application' -or
        $sourceDefinitions[1].logName -ne 'Application' -or
        (
            @($sourceDefinitions[0].permittedFutureEventMetadataFields) -join
                ','
        ) -ne ($expectedSourceFields -join ',') -or
        (
            @($sourceDefinitions[1].permittedFutureEventMetadataFields) -join
                ','
        ) -ne ($expectedSourceFields -join ',')
    ) {
        throw 'Windows source-readiness plan exceeded its metadata-only boundary.'
    }

    $security4663Plan = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\invoke-windows-sensor-dotnet.ps1'
    ) -Arguments @('-Command', 'security4663-readiness-plan')
    $security4663Targets = @($security4663Plan.result.targets)
    if (
        -not (Test-ExactBoolean -Value $security4663Plan `
            -Property 'ok' -Expected $true) -or
        $security4663Plan.command -ne 'security-4663-readiness-plan' -or
        $security4663Plan.result.schemaVersion -ne 1 -or
        $security4663Plan.result.checkpoint -ne
            'gate-c2d-security-4663-machine-readiness' -or
        $security4663Plan.result.serviceName -ne 'WARRoomWindowsSensor' -or
        $security4663Plan.result.startIdentity -ne
            'NT AUTHORITY\LocalService' -or
        $security4663Plan.result.localServiceSid -ne 'S-1-5-19' -or
        $security4663Plan.result.logName -ne 'Security' -or
        $security4663Plan.result.providerName -ne
            'Microsoft-Windows-Security-Auditing' -or
        $security4663Plan.result.eventId -ne 4663 -or
        $security4663Plan.result.level -ne 0 -or
        $security4663Plan.result.requiredChannelReadAce -ne
            '(A;;0x1;;;LS)' -or
        $security4663Plan.result.auditSubcategory -ne 'File System' -or
        -not (Test-ExactBoolean -Value $security4663Plan.result `
            -Property 'requiresElevation' -Expected $true) -or
        -not (Test-ExactBoolean -Value $security4663Plan.result `
            -Property 'requiresSecurityLogReadAccess' -Expected $true) -or
        -not (Test-ExactBoolean -Value $security4663Plan.result `
            -Property 'securityLogWriteAllowed' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663Plan.result `
            -Property 'securityLogClearAllowed' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663Plan.result `
            -Property 'eventLogReadersMembershipAllowed' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663Plan.result `
            -Property 'seSecurityPrivilegeAssignmentAllowed' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663Plan.result `
            -Property 'auditSuccessRequired' -Expected $true) -or
        -not (Test-ExactBoolean -Value $security4663Plan.result `
            -Property 'auditFailureRequired' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663Plan.result `
            -Property 'realCredentialLocationsAllowed' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663Plan.result `
            -Property 'reparsePointsAllowed' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663Plan.result `
            -Property 'changesChannelAccess' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663Plan.result `
            -Property 'changesAuditPolicy' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663Plan.result `
            -Property 'changesTargetSacl' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663Plan.result `
            -Property 'readsEvents' -Expected $false) -or
        $security4663Plan.result.eventsRead -ne 0 -or
        -not (Test-ExactBoolean -Value $security4663Plan.result `
            -Property 'runtimeCollectionEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663Plan.result `
            -Property 'transportEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663Plan.result `
            -Property 'inboundListenerEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663Plan.result `
            -Property 'commandChannelEnabled' -Expected $false) -or
        $security4663Targets.Count -ne 3 -or
        (@($security4663Targets.profileId) -join ',') -ne
            'credential-store-read,unsecured-secret-read,hidden-attribute-write' -or
        (@($security4663Targets.requiredAccessMask) -join ',') -ne
            '0x00000001,0x00000001,0x00000100' -or
        @($security4663Targets | Where-Object {
            $_.inertTargetPath -notlike
                'C:\ProgramData\WAR-R00M\Windows Sensor\C2\*.fixture' -or
            $_.auditPrincipalSid -ne 'S-1-1-0' -or
            -not $_.successAuditRequired -or
            $_.failureAuditRequired
        }).Count -ne 0
    ) {
        throw 'Windows Security 4663 readiness plan exceeded its non-mutating boundary.'
    }

    $security4663CeremonyPlan = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\manage-windows-security-4663-readiness.ps1'
    ) -Arguments @('-Command', 'apply', '-WhatIf')
    if (
        -not (Test-ExactBoolean -Value $security4663CeremonyPlan `
            -Property 'ok' -Expected $true) -or
        $security4663CeremonyPlan.command -ne
            'security-4663-ceremony-plan' -or
        $security4663CeremonyPlan.result.schemaVersion -ne 1 -or
        $security4663CeremonyPlan.result.checkpoint -ne
            'gate-c2d-security-4663-machine-readiness' -or
        $security4663CeremonyPlan.result.statePath -ne
            'C:\ProgramData\WAR-R00M\Windows Sensor\C2\security-4663-ceremony-state.json' -or
        -not (Test-ExactBoolean -Value $security4663CeremonyPlan.result `
            -Property 'requiresElevation' -Expected $true) -or
        -not (Test-ExactBoolean -Value $security4663CeremonyPlan.result `
            -Property 'temporarilyEnablesOperatorSecurityPrivilege' `
            -Expected $true) -or
        -not (Test-ExactBoolean -Value $security4663CeremonyPlan.result `
            -Property 'assignsPrivilegeToService' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663CeremonyPlan.result `
            -Property 'requiresExactLocalServiceIdentity' -Expected $true) -or
        -not (Test-ExactBoolean -Value $security4663CeremonyPlan.result `
            -Property 'requiresFixtureRootAbsent' -Expected $true) -or
        -not (Test-ExactBoolean -Value $security4663CeremonyPlan.result `
            -Property 'preservesOriginalChannelDescriptor' -Expected $true) -or
        -not (Test-ExactBoolean -Value $security4663CeremonyPlan.result `
            -Property 'preservesOriginalAuditPolicy' -Expected $true) -or
        -not (Test-ExactBoolean -Value $security4663CeremonyPlan.result `
            -Property 'appliesLocalServiceReadOnlyChannelAce' -Expected $true) -or
        -not (Test-ExactBoolean -Value $security4663CeremonyPlan.result `
            -Property 'appliesAuditSuccessOnly' -Expected $true) -or
        -not (Test-ExactBoolean -Value $security4663CeremonyPlan.result `
            -Property 'createsOnlyFixedInertTargets' -Expected $true) -or
        -not (Test-ExactBoolean -Value $security4663CeremonyPlan.result `
            -Property 'rollbackRequired' -Expected $true) -or
        -not (Test-ExactBoolean -Value $security4663CeremonyPlan.result `
            -Property 'readsEvents' -Expected $false) -or
        $security4663CeremonyPlan.result.eventsRead -ne 0 -or
        -not (Test-ExactBoolean -Value $security4663CeremonyPlan.result `
            -Property 'runtimeCollectionEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663CeremonyPlan.result `
            -Property 'transportEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663CeremonyPlan.result `
            -Property 'inboundListenerEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663CeremonyPlan.result `
            -Property 'commandChannelEnabled' -Expected $false)
    ) {
        throw 'Windows Security 4663 ceremony plan exceeded its reversible boundary.'
    }

    $security4663OneShotPlan = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\invoke-windows-sensor-dotnet.ps1'
    ) -Arguments @('-Command', 'security4663-one-shot-plan')
    if (
        -not (Test-ExactBoolean -Value $security4663OneShotPlan `
            -Property 'ok' -Expected $true) -or
        $security4663OneShotPlan.command -ne
            'security-4663-one-shot-plan' -or
        $security4663OneShotPlan.result.schemaVersion -ne 1 -or
        $security4663OneShotPlan.result.checkpoint -ne
            'gate-c2e-security-4663-one-shot-plan' -or
        $security4663OneShotPlan.result.prerequisiteCheckpoint -ne
            'gate-c2d-security-4663-machine-readiness' -or
        $security4663OneShotPlan.result.serviceName -ne
            'WARRoomWindowsSensor' -or
        $security4663OneShotPlan.result.serviceIdentity -ne
            'NT AUTHORITY\LocalService' -or
        $security4663OneShotPlan.result.providerName -ne
            'Microsoft-Windows-Security-Auditing' -or
        $security4663OneShotPlan.result.channelName -ne 'Security' -or
        $security4663OneShotPlan.result.eventId -ne 4663 -or
        $security4663OneShotPlan.result.level -ne 0 -or
        $security4663OneShotPlan.result.profileId -ne
            'credential-store-read' -or
        $security4663OneShotPlan.result.inertTargetPath -ne
            'C:\ProgramData\WAR-R00M\Windows Sensor\C2\credential-store.fixture' -or
        $security4663OneShotPlan.result.requiredAccessMask -ne
            '0x00000001' -or
        -not (Test-ExactBoolean -Value $security4663OneShotPlan.result `
            -Property 'requiresFreshOperatorApproval' -Expected $true) -or
        -not (Test-ExactBoolean -Value $security4663OneShotPlan.result `
            -Property 'requiresC2dReadiness' -Expected $true) -or
        -not (Test-ExactBoolean -Value $security4663OneShotPlan.result `
            -Property 'requiresBaselineRecordId' -Expected $true) -or
        $security4663OneShotPlan.result.maximumTriggerWindowSeconds -ne 10 -or
        $security4663OneShotPlan.result.maximumQuerySeconds -ne 2 -or
        $security4663OneShotPlan.result.maximumEventsRead -ne 1 -or
        $security4663OneShotPlan.result.maximumNormalizedOutputBytes -ne 4096 -or
        -not (Test-ExactBoolean -Value $security4663OneShotPlan.result `
            -Property 'requiresRecordIdAfterBaseline' -Expected $true) -or
        -not (Test-ExactBoolean -Value $security4663OneShotPlan.result `
            -Property 'requiresEventTimeWithinTriggerWindow' -Expected $true) -or
        -not (Test-ExactBoolean -Value $security4663OneShotPlan.result `
            -Property 'requiresExactTargetHmacBinding' -Expected $true) -or
        -not (Test-ExactBoolean -Value $security4663OneShotPlan.result `
            -Property 'retainsRawAccount' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663OneShotPlan.result `
            -Property 'retainsRawObjectPath' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663OneShotPlan.result `
            -Property 'retainsRawProcessPath' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663OneShotPlan.result `
            -Property 'changesChannelAccess' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663OneShotPlan.result `
            -Property 'changesAuditPolicy' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663OneShotPlan.result `
            -Property 'changesTargetSacl' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663OneShotPlan.result `
            -Property 'planReadsEvents' -Expected $false) -or
        $security4663OneShotPlan.result.planEventsRead -ne 0 -or
        -not (Test-ExactBoolean -Value $security4663OneShotPlan.result `
            -Property 'retryEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663OneShotPlan.result `
            -Property 'pollingEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663OneShotPlan.result `
            -Property 'runtimeCollectionEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663OneShotPlan.result `
            -Property 'transportEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663OneShotPlan.result `
            -Property 'inboundListenerEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663OneShotPlan.result `
            -Property 'commandChannelEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663OneShotPlan.result `
            -Property 'responseActionEnabled' -Expected $false)
    ) {
        throw 'Windows Security 4663 one-shot plan exceeded its disabled boundary.'
    }

    $security4663ConsumePlan = Invoke-JsonScript -Path (
        Join-Path $root `
            'scripts\manage-windows-security-4663-approval.ps1'
    ) -Arguments @('-Command', 'service-consume-exercise', '-WhatIf')
    $consumeProgramSource = Get-Content -Raw -LiteralPath (
        Join-Path $root 'apps\windows-sensor\src\Program.cs'
    )
    $consumeBranch = [regex]::Match(
        $consumeProgramSource,
        '(?s)if \(startupMode == SensorStartupMode\.Security4663ApprovalConsumeProof\).*?\r?\n\}'
    )
    $consumeScriptSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'scripts\manage-windows-security-4663-approval.ps1'
    )
    if (
        -not (Test-ExactBoolean -Value $security4663ConsumePlan `
            -Property 'ok' -Expected $true) -or
        $security4663ConsumePlan.command -ne 'consume-proof-plan' -or
        $security4663ConsumePlan.result.schemaVersion -ne 1 -or
        $security4663ConsumePlan.result.checkpoint -ne
            'gate-c2e-security-4663-one-shot-plan' -or
        $security4663ConsumePlan.result.startupArgument -ne
            '--security-4663-one-shot' -or
        $security4663ConsumePlan.result.startupModeRegistryPath -ne
            'SYSTEM\CurrentControlSet\Services\WARRoomWindowsSensor\Parameters' -or
        $security4663ConsumePlan.result.startupModeRegistryValueName -ne
            'StartupMode' -or
        $security4663ConsumePlan.result.serviceIdentity -ne
            'NT AUTHORITY\LocalService' -or
        -not (Test-ExactBoolean -Value $security4663ConsumePlan.result `
            -Property 'requiresLocalServiceBeforeProtectedRead' `
            -Expected $true) -or
        -not (Test-ExactBoolean -Value $security4663ConsumePlan.result `
            -Property 'consumesApprovalExactlyOnce' -Expected $true) -or
        -not (Test-ExactBoolean -Value $security4663ConsumePlan.result `
            -Property 'writesResult' -Expected $false) -or
        $security4663ConsumePlan.result.maximumEventsRead -ne 0 -or
        -not (Test-ExactBoolean -Value $security4663ConsumePlan.result `
            -Property 'rawEventContentRead' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663ConsumePlan.result `
            -Property 'eventReaderEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663ConsumePlan.result `
            -Property 'retryEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663ConsumePlan.result `
            -Property 'pollingEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663ConsumePlan.result `
            -Property 'transportEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663ConsumePlan.result `
            -Property 'inboundListenerEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663ConsumePlan.result `
            -Property 'commandChannelEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663ConsumePlan.result `
            -Property 'responseActionEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663ConsumePlan.result `
            -Property 'changesServiceImagePath' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663ConsumePlan.result `
            -Property 'requiresStartupModeRollback' -Expected $true) -or
        -not (Test-ExactBoolean -Value $security4663ConsumePlan.result `
            -Property 'normalStartupEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $security4663ConsumePlan.result `
            -Property 'guardedOperatorInvocationWired' -Expected $true) -or
        -not $consumeBranch.Success -or
        $consumeBranch.Value -match
            'EventLog|EventReader|IGenuineScmEventReader|IBoundedEventMetadataReader|LoopbackFactTransport|HttpClient|Process\.Start' -or
        ([regex]::Matches(
            $consumeScriptSource,
            '\.Start\(\)'
        )).Count -ne 1 -or
        ([regex]::Matches(
            $consumeScriptSource,
            '\.SetValue\(\s*''StartupMode'''
        )).Count -ne 1 -or
        ([regex]::Matches(
            $consumeScriptSource,
            '\.DeleteValue\(''StartupMode'',\s*\$true\)'
        )).Count -ne 2 -or
        $consumeScriptSource -match
            '(?m)^\s*Set-Service\b|ChangeStartMode|Win32_Service.*Change|sc\.exe\s+config|ImagePath.{0,80}(SetValue|DeleteValue)'
    ) {
        throw 'Windows Security 4663 consume-only proof exceeded its disabled boundary.'
    }

    $probePlan = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\provision-windows-sensor-identity.ps1'
    ) -Arguments @('-Command', 'probe-cleanup', '-WhatIf')
    if (
        -not (Test-ExactBoolean -Value $probePlan -Property 'ok' `
            -Expected $true) -or
        $probePlan.command -ne 'probe-plan' -or
        $probePlan.plan.probeName -ne
            'WAR-R00M-Acl-Probe-397bf4da663d4a7b985eab7565aa2806' -or
        $probePlan.plan.provider -ne
            'Microsoft Software Key Storage Provider' -or
        $probePlan.plan.algorithm -ne 'ecdsa-p256-sha256' -or
        $probePlan.plan.scope -ne 'current-user' -or
        -not (Test-ExactBoolean -Value $probePlan.plan `
            -Property 'requiresElevation' -Expected $true) -or
        -not (Test-ExactBoolean -Value $probePlan.plan `
            -Property 'removesOnlyExactProbe' -Expected $true) -or
        -not (Test-ExactBoolean -Value $probePlan.plan `
            -Property 'deletesProductionMachineIdentity' -Expected $false)
    ) {
        throw 'Diagnostic probe cleanup plan exceeded its exact boundary.'
    }

    $enrollmentSource = Get-Content -Raw -LiteralPath (
        Join-Path $root 'apps\windows-sensor\src\NativeEnrollmentChallenge.cs'
    )
    $provisionerSource = Get-Content -Raw -LiteralPath (
        Join-Path $root 'apps\windows-sensor\provisioner\Program.cs'
    )
    $sensorProgramSource = Get-Content -Raw -LiteralPath (
        Join-Path $root 'apps\windows-sensor\src\Program.cs'
    )
    $deliverySource = Get-Content -Raw -LiteralPath (
        Join-Path $root 'apps\windows-sensor\src\EndpointOneShotDelivery.cs'
    )
    $deliveryClaimIndex = $deliverySource.IndexOf(
        'deliveryStore.Write(EndpointOneShotDelivery.Claimed',
        [StringComparison]::Ordinal
    )
    $deliverySendIndex = $deliverySource.IndexOf(
        'transport.SendOnceAsync',
        [StringComparison]::Ordinal
    )
    if (
        $enrollmentSource -notmatch 'MaximumInputBytes\s*=\s*8_192' -or
        $enrollmentSource -notmatch 'MaximumChallengeSeconds\s*=\s*900' -or
        $enrollmentSource -notmatch 'MaximumIdentitySeconds\s*=\s*604_800' -or
        ([regex]::Matches(
            $enrollmentSource,
            '\.SignUtf8Payload\s*\('
        )).Count -ne 1 -or
        $provisionerSource -match 'ReadToEnd\s*\(' -or
        $sensorProgramSource -match 'NativeEnrollmentChallenge'
    ) {
        throw 'Windows Gate C0b challenge signer exceeded its disabled boundary.'
    }

    $restartPlan = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\install-windows-sensor-service.ps1'
    ) -Arguments @('-Command', 'restart-check', '-WhatIf')
    if (
        -not (Test-ExactBoolean -Value $restartPlan -Property 'ok' `
            -Expected $true) -or
        $restartPlan.command -ne 'restart-check-plan' -or
        $restartPlan.plan.serviceName -ne 'WARRoomWindowsSensor' -or
        $restartPlan.plan.startIdentity -ne
            'NT AUTHORITY\LocalService' -or
        -not (Test-ExactBoolean -Value $restartPlan.plan `
            -Property 'requiresElevation' -Expected $true) -or
        -not (Test-ExactBoolean -Value $restartPlan.plan `
            -Property 'requiresBootAfterInstall' -Expected $true) -or
        -not (Test-ExactBoolean -Value $restartPlan.plan `
            -Property 'requiresExactManifestAndHashes' -Expected $true) -or
        -not (Test-ExactBoolean -Value $restartPlan.plan `
            -Property 'startsOnlyExactService' -Expected $true) -or
        -not (Test-ExactBoolean -Value $restartPlan.plan `
            -Property 'changesStartMode' -Expected $false) -or
        -not (Test-ExactBoolean -Value $restartPlan.plan `
            -Property 'deletesInstalledFiles' -Expected $false) -or
        -not (Test-ExactBoolean -Value $restartPlan.plan `
            -Property 'deletesMachineIdentity' -Expected $false) -or
        -not (Test-ExactBoolean -Value $restartPlan.plan `
            -Property 'collectorEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $restartPlan.plan `
            -Property 'telemetryEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $restartPlan.plan `
            -Property 'commandChannelEnabled' -Expected $false)
    ) {
        throw 'Windows sensor restart plan exceeded its identity-only boundary.'
    }

    $localServiceReadinessPlan = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\install-windows-sensor-service.ps1'
    ) -Arguments @('-Command', 'source-readiness-check', '-WhatIf')
    if (
        -not (Test-ExactBoolean -Value $localServiceReadinessPlan `
            -Property 'ok' -Expected $true) -or
        $localServiceReadinessPlan.command -ne
            'source-readiness-check-plan' -or
        $localServiceReadinessPlan.plan.serviceName -ne
            'WARRoomWindowsSensor' -or
        $localServiceReadinessPlan.plan.startIdentity -ne
            'NT AUTHORITY\LocalService' -or
        -not (Test-ExactBoolean -Value $localServiceReadinessPlan.plan `
            -Property 'requiresElevation' -Expected $true) -or
        -not (Test-ExactBoolean -Value $localServiceReadinessPlan.plan `
            -Property 'requiresExactManifestAndMatchingServiceSource' -Expected $true) -or
        -not (Test-ExactBoolean -Value $localServiceReadinessPlan.plan `
            -Property 'startsOnlyExactService' -Expected $true) -or
        -not (Test-ExactBoolean -Value $localServiceReadinessPlan.plan `
            -Property 'changesServicePath' -Expected $false) -or
        -not (Test-ExactBoolean -Value $localServiceReadinessPlan.plan `
            -Property 'normalStartupIncludesFixedGateA' -Expected $true) -or
        (@($localServiceReadinessPlan.plan.allowedLogs) -join ',') -ne
            'System,Application' -or
        $localServiceReadinessPlan.plan.gateAEventsRead -ne 0 -or
        $localServiceReadinessPlan.plan.maximumNormalStartupEventsRead -ne 3 -or
        -not (Test-ExactBoolean -Value $localServiceReadinessPlan.plan `
            -Property 'genuineEventReaderMayRunIfProofEmpty' -Expected $true) -or
        -not (Test-ExactBoolean -Value $localServiceReadinessPlan.plan `
            -Property 'boundedCollectorMayRunIfProofEmpty' -Expected $true) -or
        -not (Test-ExactBoolean -Value $localServiceReadinessPlan.plan `
            -Property 'rawEventContentRead' -Expected $false) -or
        -not (Test-ExactBoolean -Value $localServiceReadinessPlan.plan `
            -Property 'collectorEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $localServiceReadinessPlan.plan `
            -Property 'telemetryEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $localServiceReadinessPlan.plan `
            -Property 'commandChannelEnabled' -Expected $false)
    ) {
        throw 'Windows LocalService source-readiness plan exceeded its exact boundary.'
    }

    $localBatchPlan = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\install-windows-sensor-service.ps1'
    ) -Arguments @('-Command', 'local-batch-check', '-WhatIf')
    if (
        -not (Test-ExactBoolean -Value $localBatchPlan `
            -Property 'ok' -Expected $true) -or
        $localBatchPlan.command -ne 'local-batch-check-plan' -or
        $localBatchPlan.plan.serviceName -ne
            'WARRoomWindowsSensor' -or
        $localBatchPlan.plan.startIdentity -ne
            'NT AUTHORITY\LocalService' -or
        -not (Test-ExactBoolean -Value $localBatchPlan.plan `
            -Property 'requiresElevation' -Expected $true) -or
        -not (Test-ExactBoolean -Value $localBatchPlan.plan `
            -Property 'requiresExactManifestAndMatchingServiceSource' `
            -Expected $true) -or
        -not (Test-ExactBoolean -Value $localBatchPlan.plan `
            -Property 'readsOnlyFixedProofFile' -Expected $true) -or
        -not (Test-ExactBoolean -Value $localBatchPlan.plan `
            -Property 'validatesRealMachineKeySignature' -Expected $true) -or
        -not (Test-ExactBoolean -Value $localBatchPlan.plan `
            -Property 'validatesTwoBatchHashChain' -Expected $true) -or
        -not (Test-ExactBoolean -Value $localBatchPlan.plan `
            -Property 'mutatesService' -Expected $false) -or
        $localBatchPlan.plan.syntheticBatchCount -ne 2 -or
        $localBatchPlan.plan.eventsRead -ne 0 -or
        -not (Test-ExactBoolean -Value $localBatchPlan.plan `
            -Property 'eventReaderEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $localBatchPlan.plan `
            -Property 'networkTransportEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $localBatchPlan.plan `
            -Property 'inboundListenerEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $localBatchPlan.plan `
            -Property 'commandChannelEnabled' -Expected $false)
    ) {
        throw 'Windows local synthetic batch plan exceeded its exact boundary.'
    }

    $genuineBatchPlan = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\install-windows-sensor-service.ps1'
    ) -Arguments @('-Command', 'genuine-batch-check', '-WhatIf')
    if (
        -not (Test-ExactBoolean -Value $genuineBatchPlan `
            -Property 'ok' -Expected $true) -or
        $genuineBatchPlan.command -ne 'genuine-batch-check-plan' -or
        $genuineBatchPlan.plan.serviceName -ne 'WARRoomWindowsSensor' -or
        $genuineBatchPlan.plan.startIdentity -ne
            'NT AUTHORITY\LocalService' -or
        $genuineBatchPlan.plan.proofPath -ne $expectedB1Proof -or
        $genuineBatchPlan.plan.saltPath -ne $expectedB1Salt -or
        $genuineBatchPlan.plan.saltBytes -ne 32 -or
        $genuineBatchPlan.plan.maximumProofBytes -ne 32768 -or
        -not (Test-ExactBoolean -Value $genuineBatchPlan.plan `
            -Property 'requiresElevation' -Expected $true) -or
        -not (Test-ExactBoolean -Value $genuineBatchPlan.plan `
            -Property 'requiresExactManifestAndMatchingServiceSource' `
            -Expected $true) -or
        -not (Test-ExactBoolean -Value $genuineBatchPlan.plan `
            -Property 'readsOnlyFixedProofFile' -Expected $true) -or
        -not (Test-ExactBoolean -Value $genuineBatchPlan.plan `
            -Property 'validatesFixedSaltAclAndSize' -Expected $true) -or
        -not (Test-ExactBoolean -Value $genuineBatchPlan.plan `
            -Property 'saltReadableByLocalService' -Expected $true) -or
        -not (Test-ExactBoolean -Value $genuineBatchPlan.plan `
            -Property 'saltWritableByLocalService' -Expected $false) -or
        -not (Test-ExactBoolean -Value $genuineBatchPlan.plan `
            -Property 'saltIncludedInOutput' -Expected $false) -or
        -not (Test-ExactBoolean -Value $genuineBatchPlan.plan `
            -Property 'queriesWindowsEventLog' -Expected $false) -or
        -not (Test-ExactBoolean -Value $genuineBatchPlan.plan `
            -Property 'validatesRealMachineKeySignature' -Expected $true) -or
        -not (Test-ExactBoolean -Value $genuineBatchPlan.plan `
            -Property 'mutatesService' -Expected $false) -or
        $genuineBatchPlan.plan.maximumBatchCount -ne 1 -or
        $genuineBatchPlan.plan.maximumFactCount -ne 1 -or
        $genuineBatchPlan.plan.maximumEventsRead -ne 1 -or
        -not (Test-ExactBoolean -Value $genuineBatchPlan.plan `
            -Property 'rawEventContentRead' -Expected $false) -or
        -not (Test-ExactBoolean -Value $genuineBatchPlan.plan `
            -Property 'runtimeProofEventReaderEnabled' -Expected $true) -or
        -not (Test-ExactBoolean -Value $genuineBatchPlan.plan `
            -Property 'checkerEventReaderEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $genuineBatchPlan.plan `
            -Property 'networkTransportEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $genuineBatchPlan.plan `
            -Property 'inboundListenerEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $genuineBatchPlan.plan `
            -Property 'pollingEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $genuineBatchPlan.plan `
            -Property 'commandChannelEnabled' -Expected $false)
    ) {
        throw 'Windows genuine batch check plan exceeded its exact boundary.'
    }

    $boundedCollectorPlan = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\install-windows-sensor-service.ps1'
    ) -Arguments @('-Command', 'bounded-collector-check', '-WhatIf')
    if (
        -not (Test-ExactBoolean -Value $boundedCollectorPlan `
            -Property 'ok' -Expected $true) -or
        $boundedCollectorPlan.command -ne 'bounded-collector-check-plan' -or
        $boundedCollectorPlan.plan.serviceName -ne 'WARRoomWindowsSensor' -or
        $boundedCollectorPlan.plan.startIdentity -ne
            'NT AUTHORITY\LocalService' -or
        $boundedCollectorPlan.plan.proofPath -ne $expectedC1Proof -or
        $boundedCollectorPlan.plan.saltPath -ne $expectedB1Salt -or
        $boundedCollectorPlan.plan.maximumProofBytes -ne 32768 -or
        $boundedCollectorPlan.plan.maximumFamiliesQueried -ne 2 -or
        $boundedCollectorPlan.plan.maximumEventsRead -ne 2 -or
        $boundedCollectorPlan.plan.lossState -ne 'unknown' -or
        $boundedCollectorPlan.plan.continuityState -ne 'unknown' -or
        -not (Test-ExactBoolean -Value $boundedCollectorPlan.plan `
            -Property 'requiresElevation' -Expected $true) -or
        -not (Test-ExactBoolean -Value $boundedCollectorPlan.plan `
            -Property 'requiresExactManifestAndMatchingServiceSource' `
            -Expected $true) -or
        -not (Test-ExactBoolean -Value $boundedCollectorPlan.plan `
            -Property 'readsOnlyFixedProofAndManifest' -Expected $true) -or
        -not (Test-ExactBoolean -Value $boundedCollectorPlan.plan `
            -Property 'queriesWindowsEventLog' -Expected $false) -or
        -not (Test-ExactBoolean -Value $boundedCollectorPlan.plan `
            -Property 'validatesRealMachineKeySignature' -Expected $true) -or
        -not (Test-ExactBoolean -Value $boundedCollectorPlan.plan `
            -Property 'mutatesService' -Expected $false) -or
        -not (Test-ExactBoolean -Value $boundedCollectorPlan.plan `
            -Property 'rawEventContentRead' -Expected $false) -or
        -not (Test-ExactBoolean -Value $boundedCollectorPlan.plan `
            -Property 'runtimeProofEventReaderEnabled' -Expected $true) -or
        -not (Test-ExactBoolean -Value $boundedCollectorPlan.plan `
            -Property 'checkerEventReaderEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $boundedCollectorPlan.plan `
            -Property 'networkTransportEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $boundedCollectorPlan.plan `
            -Property 'automaticRetryEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $boundedCollectorPlan.plan `
            -Property 'pollingEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $boundedCollectorPlan.plan `
            -Property 'inboundListenerEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $boundedCollectorPlan.plan `
            -Property 'commandChannelEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $boundedCollectorPlan.plan `
            -Property 'responseActionsEnabled' -Expected $false)
    ) {
        throw 'Windows bounded collector check plan exceeded its exact boundary.'
    }

    $genuineReaderPath = Join-Path $root `
        'apps\windows-sensor\src\GenuineScmBatchProof.cs'
    $genuineReaderSource = Get-Content -Raw -LiteralPath $genuineReaderPath
    $readerClass = [regex]::Match(
        $genuineReaderSource,
        '(?s)public sealed class NativeGenuineScmEventReader.*?(?=public sealed record GenuineScmProofDocument)'
    )
    $recordAccessors = @(
        [regex]::Matches(
            $readerClass.Value,
            '\brecord\.(?<name>[A-Za-z][A-Za-z0-9]*)'
        ) | ForEach-Object { $_.Groups['name'].Value } | Sort-Object -Unique
    )
    $forbiddenReaderApis = @(
        '\.Message\b',
        'FormatDescription\s*\(',
        'ToXml\s*\(',
        '\.Properties\b',
        'EventBookmark\b',
        'EventLogWatcher\b',
        'EventLogSubscription\b'
    )
    if (
        @($forbiddenReaderApis | Where-Object {
            $genuineReaderSource -match $_
        }).Count -ne 0 -or
        -not $readerClass.Success -or
        ($recordAccessors -join ',') -ne
            'Id,Level,ProviderName,RecordId,TimeCreated' -or
        ([regex]::Matches($genuineReaderSource, '\.ReadEvent\s*\(')).Count -ne 1 -or
        $readerClass.Value -notmatch
            'ReadEvent\s*\(\s*TimeSpan\.FromMilliseconds\(MaximumReadMilliseconds\)\s*\)' -or
        $readerClass.Value -notmatch
            'MaximumReadMilliseconds\s*=\s*2_000' -or
        ([regex]::Matches(
            $readerClass.Value,
            'cancellationToken\.ThrowIfCancellationRequested\s*\(\s*\)'
        )).Count -ne 2 -or
        $readerClass.Value -notmatch
            'BatchSize\s*=\s*MaximumRecords' -or
        $genuineReaderSource -notmatch 'ReverseDirection\s*=\s*true' -or
        $genuineReaderSource -notmatch 'TolerateQueryErrors\s*=\s*false'
    ) {
        throw 'Windows genuine SCM reader exceeded its metadata-only boundary.'
    }

    $c1ContractPath = Join-Path $root `
        'apps\windows-sensor\src\BoundedMultiEventCollector.cs'
    $c1ContractSource = Get-Content -Raw -LiteralPath $c1ContractPath
    $c1ProgramSource = Get-Content -Raw -LiteralPath (
        Join-Path $root 'apps\windows-sensor\src\Program.cs'
    )
    $c1ForbiddenApis = @(
        'System\.Diagnostics\.Eventing\.Reader',
        'EventLogReader\b',
        'EventLogQuery\b',
        '\.ReadEvent\s*\(',
        '\.Message\b',
        'FormatDescription\s*\(',
        'ToXml\s*\(',
        '\.Properties\b',
        'EventBookmark\b',
        'EventLogWatcher\b',
        'EventLogSubscription\b',
        'HttpClient\b',
        'HttpMessageInvoker\b',
        'Process\.Start\b',
        'Security'
    )
    if (
        @($c1ForbiddenApis | Where-Object {
            $c1ContractSource -match $_
        }).Count -ne 0 -or
        ([regex]::Matches(
            $c1ProgramSource,
            'AddSingleton<IBoundedEventMetadataReader,\s*NativeBoundedEventMetadataReader>'
        )).Count -ne 1 -or
        ([regex]::Matches(
            $c1ProgramSource,
            'AddSingleton<IMultiEventCollector,\s*BoundedMultiEventCollector>'
        )).Count -ne 1 -or
        ([regex]::Matches(
            $c1ProgramSource,
            'AddSingleton<IBoundedCollectorProofStore,\s*FixedBoundedCollectorProofStore>'
        )).Count -ne 1 -or
        ([regex]::Matches(
            $c1ProgramSource,
            'AddHostedService<BoundedCollectorProofWorker>'
        )).Count -ne 1 -or
        ([regex]::Matches(
            $c1ContractSource,
            'new BoundedEventFamilyContract\('
        )).Count -ne 2 -or
        $c1ContractSource -notmatch 'MaximumFamilies\s*=\s*2' -or
        $c1ContractSource -notmatch 'MaximumRecordsPerFamily\s*=\s*1' -or
        $c1ContractSource -notmatch 'MaximumEvents\s*=\s*2' -or
        $c1ContractSource -notmatch
            'MaximumReadMillisecondsPerFamily\s*=\s*2_000' -or
        $c1ContractSource -notmatch
            'MaximumTotalReadMilliseconds\s*=\s*4_000' -or
        $c1ContractSource -notmatch '"unknown",\s*"unknown"' -or
        $c1ContractSource -notmatch '"explicit-one-shot-contract"'
    ) {
        throw 'Windows Gate C1 collector registration exceeded its one-shot boundary.'
    }

    $c1NativePath = Join-Path $root `
        'apps\windows-sensor\src\NativeBoundedEventMetadataReader.cs'
    $c1NativeSource = Get-Content -Raw -LiteralPath $c1NativePath
    $c1NativeClass = [regex]::Match(
        $c1NativeSource,
        '(?s)public sealed class NativeBoundedEventMetadataReader.*'
    )
    $c1NativeAccessors = @(
        [regex]::Matches(
            $c1NativeClass.Value,
            '\brecord\.(?<name>[A-Za-z][A-Za-z0-9]*)'
        ) | ForEach-Object { $_.Groups['name'].Value } | Sort-Object -Unique
    )
    $c1NativeForbiddenApis = @(
        '\.Message\b',
        'FormatDescription\s*\(',
        'ToXml\s*\(',
        '\.Properties\b',
        'EventBookmark\b',
        'EventLogWatcher\b',
        'EventLogSubscription\b',
        'PathType\.FilePath',
        'TolerateQueryErrors\s*=\s*true',
        'HttpClient\b',
        'HttpMessageInvoker\b',
        'Process\.Start\b',
        '"Security"'
    )
    if (
        -not $c1NativeClass.Success -or
        @($c1NativeForbiddenApis | Where-Object {
            $c1NativeSource -match $_
        }).Count -ne 0 -or
        ($c1NativeAccessors -join ',') -ne
            'Id,Level,ProviderName,RecordId,TimeCreated' -or
        ([regex]::Matches($c1NativeSource, '\.ReadEvent\s*\(')).Count -ne 1 -or
        ([regex]::Matches(
            $c1NativeSource,
            'cancellationToken\.ThrowIfCancellationRequested\s*\(\s*\)'
        )).Count -ne 2 -or
        $c1NativeSource -notmatch 'ReverseDirection\s*=\s*true' -or
        $c1NativeSource -notmatch 'TolerateQueryErrors\s*=\s*false' -or
        $c1NativeSource -notmatch
            'BatchSize\s*=\s*\r?\n\s*BoundedMultiEventCollector\.MaximumRecordsPerFamily' -or
        $c1NativeSource -notmatch
            'BoundedMultiEventCollector\.MaximumReadMillisecondsPerFamily' -or
        $c1NativeSource -notmatch 'BoundedEventReadState\.NoMatch' -or
        $c1NativeSource -notmatch 'BoundedEventReadState\.AccessDenied' -or
        $c1NativeSource -notmatch 'BoundedEventReadState\.SourceUnavailable' -or
        $c1NativeSource -notmatch 'BoundedEventReadState\.QueryFailed' -or
        $c1NativeSource -notmatch 'SENSOR_C1_EVENT_FAMILY_INVALID'
    ) {
        throw 'Windows Gate C1b native reader exceeded its metadata-only boundary.'
    }

    $c1ProofSource = Get-Content -Raw -LiteralPath (
        Join-Path $root 'apps\windows-sensor\src\BoundedCollectorProof.cs'
    )
    $c1CheckerSource = Get-Content -Raw -LiteralPath (
        Join-Path $root 'apps\windows-sensor\bounded-proof\Program.cs'
    )
    $c1CheckerForbiddenApis = @(
        'System\.Diagnostics\.Eventing\.Reader',
        'EventLogReader\b',
        'EventLogQuery\b',
        '\.ReadEvent\s*\(',
        'HttpClient\b',
        'HttpMessageInvoker\b',
        'Process\.Start\b',
        'ServiceController\b',
        'Start-Service|Stop-Service'
    )
    if (
        @($c1CheckerForbiddenApis | Where-Object {
            $c1CheckerSource -match $_
        }).Count -ne 0 -or
        $c1ProofSource -notmatch 'MaximumProofBytes\s*=\s*32_768' -or
        $c1ProofSource -notmatch
            'ProofMode\s*=\s*"local-bounded-gate-c1"' -or
        ([regex]::Matches(
            $c1ProofSource,
            '\.SignUtf8Payload\s*\('
        )).Count -ne 1 -or
        ([regex]::Matches(
            $c1ProofSource,
            'collector\.CollectOnce\s*\('
        )).Count -ne 1 -or
        ([regex]::Matches(
            $c1ProofSource,
            'store\.Write\s*\('
        )).Count -ne 1 -or
        $c1ProofSource -notmatch 'LocalProofNativeFileAccess\.OpenExistingForOverwrite' -or
        $c1ProofSource -notmatch 'RuntimeProofEventReaderEnabled' -or
        $c1ProofSource -notmatch 'AutomaticRetryEnabled' -or
        $c1CheckerSource -notmatch 'checkerEventReaderEnabled\s*=\s*false' -or
        $c1CheckerSource -notmatch 'serviceMutated\s*=\s*false'
    ) {
        throw 'Windows Gate C1c protected proof or external checker exceeded its boundary.'
    }

    $transportPath = Join-Path $root `
        'apps\windows-sensor\src\LoopbackFactTransport.cs'
    $transportSource = Get-Content -Raw -LiteralPath $transportPath
    $sensorProgramSource = Get-Content -Raw -LiteralPath (
        Join-Path $root 'apps\windows-sensor\src\Program.cs'
    )
    if (
        $transportSource -notmatch
            'http://127\.0\.0\.1:4315/api/endpoints/facts' -or
        $transportSource -notmatch 'MaximumRequestBytes\s*=\s*32_768' -or
        $transportSource -notmatch 'MaximumResponseBytes\s*=\s*1_024' -or
        $transportSource -notmatch 'TimeoutMilliseconds\s*=\s*5_000' -or
        $transportSource -notmatch 'AllowAutoRedirect\s*=\s*false' -or
        $transportSource -notmatch 'UseProxy\s*=\s*false' -or
        $transportSource -notmatch 'UseCookies\s*=\s*false' -or
        $transportSource -notmatch 'UseDefaultCredentials\s*=\s*false' -or
        $transportSource -notmatch
            'AutomaticDecompression\s*=\s*DecompressionMethods\.None' -or
        $transportSource -notmatch 'MaxConnectionsPerServer\s*=\s*1' -or
        ([regex]::Matches($transportSource, '\.SendAsync\s*\(')).Count -ne 1 -or
        ([regex]::Matches(
            $sensorProgramSource,
            'AddSingleton<LoopbackFactTransport>'
        )).Count -ne 1 -or
        ([regex]::Matches(
            $sensorProgramSource,
            'AddHostedService<EndpointOneShotDeliveryWorker>'
        )).Count -ne 1 -or
        ([regex]::Matches($deliverySource, '\.SendOnceAsync\s*\(')).Count -ne 1 -or
        $deliveryClaimIndex -lt 0 -or
        $deliverySendIndex -lt 0 -or
        $deliveryClaimIndex -ge $deliverySendIndex -or
        $deliverySource -notmatch
            'requireFreshCapability:\s*existing is null' -or
        $deliverySource -notmatch
            'SENSOR_DELIVERY_PREVIOUS_FAILURE' -or
        $deliverySource -notmatch
            'SENSOR_DELIVERY_PREVIOUS_INCOMPLETE' -or
        $deliverySource -match
            'https?://(?!127\.0\.0\.1:4315/api/endpoints/facts)' -or
        $deliverySource -match
            'PeriodicTimer|Task\.Delay|TcpListener|HttpListener|NamedPipe|Process\.Start'
    ) {
        throw 'Windows Gate C0 transport exceeded its one-shot loopback boundary.'
    }

    $uninstallPlan = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\install-windows-sensor-service.ps1'
    ) -Arguments @('-Command', 'uninstall', '-WhatIf')
    if (
        -not (Test-ExactBoolean -Value $uninstallPlan -Property 'ok' `
            -Expected $true) -or
        $uninstallPlan.command -ne 'uninstall-plan' -or
        $uninstallPlan.plan.serviceName -ne 'WARRoomWindowsSensor' -or
        $uninstallPlan.plan.installRoot -ne
            'C:\Program Files\WAR-R00M\Windows Sensor' -or
        -not (Test-ExactBoolean -Value $uninstallPlan.plan `
            -Property 'requiresElevation' -Expected $true) -or
        -not (Test-ExactBoolean -Value $uninstallPlan.plan `
            -Property 'requiresExactManifestAndHashes' -Expected $true) -or
        -not (Test-ExactBoolean -Value $uninstallPlan.plan `
            -Property 'requiresSealedPackage' -Expected $true) -or
        -not (Test-ExactBoolean -Value $uninstallPlan.plan `
            -Property 'buildToolchainRunsElevated' -Expected $false) -or
        -not (Test-ExactBoolean -Value $uninstallPlan.plan `
            -Property 'sourceTreeExecutableRunsElevated' -Expected $false) -or
        -not (Test-ExactBoolean -Value $uninstallPlan.plan `
            -Property 'removesOnlyExactService' -Expected $true) -or
        -not (Test-ExactBoolean -Value $uninstallPlan.plan `
            -Property 'removesOnlyExactInstallRoot' -Expected $true) -or
        -not (Test-ExactBoolean -Value $uninstallPlan.plan `
            -Property 'removesOnlyExactLocalStateRoot' -Expected $true) -or
        $uninstallPlan.plan.allowsOnlyRecordedGateACommitWithoutLocalState -ne
            'b1632a05b48e890fa3133cc3265c5f46394feb33' -or
        (@($uninstallPlan.plan.allowedLocalStateFiles) -join ',') -ne
            'local-synthetic-batch-proof.json,local-genuine-batch-proof.json,local-genuine-source-salt.bin,local-bounded-collector-proof.json,endpoint-binding.json,local-capability-proof.json,local-loopback-delivery.json' -or
        (@($uninstallPlan.plan.supportedLocalStateProfiles) -join ',') -ne
            'gate-b0,gate-b1,gate-c0b,gate-c0c,gate-c1' -or
        -not (Test-ExactBoolean -Value $uninstallPlan.plan `
            -Property 'deletesMachineIdentity' -Expected $false) -or
        -not (Test-ExactBoolean -Value $uninstallPlan.plan `
            -Property 'preservesMachineIdentityByDefault' -Expected $true) -or
        -not (Test-ExactBoolean -Value $uninstallPlan.plan `
            -Property 'collectorEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $uninstallPlan.plan `
            -Property 'telemetryEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $uninstallPlan.plan `
            -Property 'commandChannelEnabled' -Expected $false)
    ) {
        throw 'Windows sensor uninstall plan exceeded its exact boundary.'
    }

    $installerSource = Get-Content -Raw -LiteralPath (
        Join-Path $root 'scripts\install-windows-sensor-service.ps1'
    )
    if (
        $installerSource -match
            "Join-Path \`$env:ProgramFiles 'WAR-R00M\\Windows Sensor'" -or
        $installerSource -notmatch
            "Join-Path \`$nativeProgramFiles 'WAR-R00M\\Windows Sensor'"
    ) {
        throw 'Windows sensor cleanup did not use the native Program Files root.'
    }
    $installMutationMarker = '$sealedPackage = Read-SealedPackageManifest'
    $installMutationIndex = $installerSource.LastIndexOf(
        $installMutationMarker,
        [StringComparison]::Ordinal
    )
    if ($installMutationIndex -lt 0) {
        throw 'Windows sensor sealed install boundary was not found.'
    }
    $uninstallMutationMarker =
        '$sealedPackage = Read-SealedPackageManifest -Root $PackageRoot'
    $uninstallMutationIndex = $installerSource.IndexOf(
        $uninstallMutationMarker,
        [StringComparison]::Ordinal
    )
    if (
        $uninstallMutationIndex -lt 0 -or
        $uninstallMutationIndex -ge $installMutationIndex
    ) {
        throw 'Windows sensor sealed uninstall boundary was not found.'
    }
    $uninstallMutationSource = $installerSource.Substring(
        $uninstallMutationIndex,
        $installMutationIndex - $uninstallMutationIndex
    )
    if (
        $uninstallMutationSource -match '&\s*\$dotnet\b' -or
        $uninstallMutationSource -match '&\s*git\.exe\b' -or
        $uninstallMutationSource -match '\bAssert-CleanSource\b' -or
        $uninstallMutationSource -match '\bAssert-IdentityStatus\b'
    ) {
        throw 'Windows sensor uninstall still executes a user-writable build boundary.'
    }
    $installMutationSource = $installerSource.Substring($installMutationIndex)
    if (
        $installMutationSource -match '&\s*\$dotnet\b' -or
        $installMutationSource -match '&\s*git\.exe\b' -or
        $installMutationSource -match '\bNew-ValidatedPublishPackage\b' -or
        $installMutationSource -match '\bAssert-CleanSource\b' -or
        $installMutationSource -match '\bAssert-IdentityStatus\b' -or
        $installMutationSource -match '\bInvoke-Local(?:Synthetic|Genuine|Bounded)'
    ) {
        throw 'Windows sensor install still executes a user-writable build boundary.'
    }
    $serviceSidToolSource = Get-Content -Raw -LiteralPath (
        Join-Path $root 'apps\windows-sensor\service-sid-tool\Program.cs'
    )
    $serviceSidCreateIndex = $installMutationSource.IndexOf(
        '$createResult = Invoke-CimMethod',
        [StringComparison]::Ordinal
    )
    $serviceSidApplyIndex = $installMutationSource.IndexOf(
        "-ToolCommand 'apply-unrestricted'",
        [StringComparison]::Ordinal
    )
    $resourceAclIndex = $installMutationSource.IndexOf(
        '$stateParent = Split-Path -Parent $stateRoot',
        [StringComparison]::Ordinal
    )
    if (
        $serviceSidCreateIndex -lt 0 -or
        $serviceSidApplyIndex -le $serviceSidCreateIndex -or
        $resourceAclIndex -le $serviceSidApplyIndex -or
        $installerSource -notmatch
            "'service-sid\\WARRoom\.WindowsSensor\.ServiceSidTool\.exe'" -or
        $installMutationSource -notmatch "'restore-none'" -or
        $installMutationSource -notmatch "'restore-restricted'" -or
        $serviceSidToolSource -match 'Console\.In' -or
        $serviceSidToolSource -match 'Process\.Start' -or
        $serviceSidToolSource -match 'HttpClient' -or
        $serviceSidToolSource -match 'Socket' -or
        $serviceSidToolSource -match 'Environment\.GetCommandLineArgs'
    ) {
        throw 'Windows sensor sealed service SID boundary was not preserved.'
    }

    $nativeAuditHeadSource = Get-Content -Raw -LiteralPath (
        Join-Path $root 'apps\windows-sensor\src\AuditHeadCheckpoint.cs'
    )
    $apiAuditHeadSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\api\src\services\audit-head-checkpoint-contract.ts'
    )
    if (
        $nativeAuditHeadSource -notmatch
            'project15\.audit-head-checkpoint\.v1' -or
        $nativeAuditHeadSource -notmatch
            'project15-audit-head-signer-v1' -or
        $nativeAuditHeadSource -notmatch
            '08c170dd7f52550d6acc9a14f8351369f642c5dfec15d8d4f4933402ce334a72' -and
            (Get-Content -Raw -LiteralPath (
                Join-Path $root 'apps\windows-sensor\tests\Program.cs'
            )) -notmatch
            '08c170dd7f52550d6acc9a14f8351369f642c5dfec15d8d4f4933402ce334a72' -or
        $nativeAuditHeadSource -match
            '(?i)\b(File|Directory|Process|Socket|HttpClient|Sqlite|Database|ServiceController|NamedPipe|DllImport|OpenSCManager|CreateFile)\b' -or
        $apiAuditHeadSource -notmatch
            'project15\.audit-head-checkpoint\.v1' -or
        $apiAuditHeadSource -notmatch
            'project15-audit-head-signer-v1' -or
        $apiAuditHeadSource -match
            '(?i)node:(fs|child_process|net|http)|\b(Sqlite|Database|fetch)\b'
    ) {
        throw 'Audit-head checkpoint exceeded its pure source-only boundary.'
    }

    $nativeAuditWitnessSource = Get-Content -Raw -LiteralPath (
        Join-Path $root 'apps\windows-sensor\src\AuditWitnessContract.cs'
    )
    $apiAuditWitnessSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\api\src\services\audit-witness-contract.ts'
    )
    $apiAuditWitnessBootstrapSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\api\src\services\audit-witness-bootstrap.ts'
    )
    $apiAuditWitnessDatabaseHeadSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\api\src\services\audit-witness-database-head.ts'
    )
    $apiAuditWitnessDatabaseReadAdapterSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\api\src\services\audit-witness-database-read-adapter.ts'
    )
    $apiAuditWitnessSqliteReaderSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\api\src\services\audit-witness-sqlite-reader.ts'
    )
    $auditWitnessSqliteReceiptBuilderSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'scripts\build-audit-witness-sqlite-reader-source-receipt.mjs'
    )
    $auditWitnessSqliteReceiptCheckerSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'scripts\check-audit-witness-sqlite-reader-source-receipt.mjs'
    )
    $auditWitnessDatabaseCeremonySource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\api\scripts\audit-witness-database-read-ceremony.ts'
    )
    $auditWitnessDatabaseCeremonyCheckerSource = `
        Get-Content -Raw -LiteralPath (
            Join-Path $root `
                'scripts\check-audit-witness-database-read-ceremony-receipt.mjs'
        )
    $rootPackageSource = Get-Content -Raw -LiteralPath (
        Join-Path $root 'package.json'
    )
    $apiAuditWitnessAppendSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\api\src\services\audit-witness-append-file.ts'
    )
    $nativeAuditWitnessAppendSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\windows-sensor\src\AuditWitnessAppendFilePolicy.cs'
    )
    $nativeAuditWitnessCheckerSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\windows-sensor\src\AuditWitnessProtectedFileStore.cs'
    )
    $nativeAuditWitnessInstallerSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\windows-sensor\audit-witness-installer\AuditWitnessProtectedFileInstaller.cs'
    )
    $nativeAuditWitnessInstallerProgram = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\windows-sensor\audit-witness-installer\Program.cs'
    )
    $nativeAuditWitnessCheckerProgram = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\windows-sensor\audit-witness-checker\Program.cs'
    )
    $sealedBundleSource = Get-Content -Raw -LiteralPath (
        Join-Path $root 'scripts\build-windows-sensor-install-bundle.ps1'
    )
    $sensorInstallerSource = Get-Content -Raw -LiteralPath (
        Join-Path $root 'scripts\install-windows-sensor-service.ps1'
    )
    $apiAuditWitnessRuntimeSource = (
        Get-ChildItem -LiteralPath (Join-Path $root 'apps\api\src') `
            -Recurse -File -Filter '*.ts' |
            Where-Object {
                $_.Name -notlike '*.test.ts' -and
                $_.Name -notin @(
                    'audit-witness-contract.ts',
                    'audit-witness-bootstrap.ts',
                    'audit-witness-database-head.ts',
                    'audit-witness-database-read-adapter.ts',
                    'audit-witness-sqlite-reader.ts',
                    'audit-witness-append-file.ts'
                )
            } |
            ForEach-Object { Get-Content -Raw -LiteralPath $_.FullName }
    ) -join "`n"
    $nativeAuditWitnessRuntimeSource = (
        Get-ChildItem -LiteralPath (
            Join-Path $root 'apps\windows-sensor\src'
        ) -File -Filter '*.cs' |
            Where-Object {
                $_.Name -notin @(
                    'AuditWitnessContract.cs',
                    'AuditWitnessAppendFilePolicy.cs',
                    'AuditWitnessProtectedFileStore.cs'
                )
            } |
            ForEach-Object { Get-Content -Raw -LiteralPath $_.FullName }
    ) -join "`n"
    if (
        $nativeAuditWitnessSource -notmatch
            'project15\.audit-witness-record\.v1' -or
        $nativeAuditWitnessSource -notmatch 'PreparePhase = "PREPARE"' -or
        $nativeAuditWitnessSource -notmatch 'CommitPhase = "COMMIT"' -or
        $nativeAuditWitnessSource -notmatch 'AbortPhase = "ABORT"' -or
        $nativeAuditWitnessSource -notmatch
            'Claim = "historical-rewrite-detection-only"' -or
        $nativeAuditWitnessSource -notmatch
            'SENSOR_AUDIT_WITNESS_DATABASE_AHEAD_WITHOUT_PREPARE' -or
        $nativeAuditWitnessSource -notmatch
            'SENSOR_AUDIT_WITNESS_ABORT_OPERATOR_REVIEW_REQUIRED' -or
        $nativeAuditWitnessSource -match
            '(?i)\b(File|Directory|Process|Socket|HttpClient|Sqlite|ServiceController|NamedPipe|DllImport|CreateFile|WriteFile)\b' -or
        $apiAuditWitnessSource -notmatch
            'project15\.audit-witness-record\.v1' -or
        $apiAuditWitnessSource -notmatch 'phase: z\.literal\("PREPARE"\)' -or
        $apiAuditWitnessSource -notmatch 'phase: z\.literal\("COMMIT"\)' -or
        $apiAuditWitnessSource -notmatch 'phase: z\.literal\("ABORT"\)' -or
        $apiAuditWitnessSource -notmatch
            'historical-rewrite-detection-only' -or
        $apiAuditWitnessSource -notmatch
            'AUDIT_WITNESS_DATABASE_AHEAD_WITHOUT_PREPARE' -or
        $apiAuditWitnessSource -notmatch
            'AUDIT_WITNESS_ABORT_OPERATOR_REVIEW_REQUIRED' -or
        $apiAuditWitnessSource -match
            '(?i)node:(fs|child_process|net|http)|\b(Sqlite|fetch|writeFile|appendFile|createWriteStream)\b' -or
        $apiAuditWitnessRuntimeSource -match
            'audit-witness-(contract|bootstrap|database-head|database-read-adapter|sqlite-reader|append-file)' -or
        $nativeAuditWitnessRuntimeSource -match
            'AuditWitness(Contract|AppendFilePolicy)' -or
        $apiAuditWitnessBootstrapSource -notmatch
            'verifyAuditHeadProtectedDocumentV1' -or
        $apiAuditWitnessBootstrapSource -notmatch
            'expectedSignerPublicKeyFingerprintSha256' -or
        $apiAuditWitnessBootstrapSource -notmatch
            'AUDIT_WITNESS_BOOTSTRAP_DATABASE_MISMATCH' -or
        $apiAuditWitnessBootstrapSource -match
            '(?i)node:(fs|child_process|net|http)|\b(Sqlite|fetch|writeFile|appendFile|createWriteStream)\b' -or
        $apiAuditWitnessDatabaseHeadSource -notmatch
            'project15\.audit-witness-database-snapshot\.v1' -or
        $apiAuditWitnessDatabaseHeadSource -notmatch
            'single-read-transaction-complete-prefix' -or
        $apiAuditWitnessDatabaseHeadSource -notmatch
            'verified-complete-prefix-input-only' -or
        $apiAuditWitnessDatabaseHeadSource -notmatch
            'AUDIT_WITNESS_DATABASE_ACQUISITION_CHAIN_BROKEN' -or
        $apiAuditWitnessDatabaseHeadSource -notmatch
            'AUDIT_WITNESS_DATABASE_ACQUISITION_HASH_INVALID' -or
        $apiAuditWitnessDatabaseHeadSource -match
            '(?i)node:(fs|child_process|net|http|sqlite)|\b(DatabaseSync|fetch|writeFile|appendFile|createWriteStream)\b|\.prepare\s*\(' -or
        $apiAuditWitnessDatabaseReadAdapterSource -notmatch
            'project15\.audit-witness-database-read\.v1' -or
        $apiAuditWitnessDatabaseReadAdapterSource -notmatch
            'readCompletePrefixSnapshot' -or
        $apiAuditWitnessDatabaseReadAdapterSource -notmatch
            'runtimeWiringEnabled: false' -or
        $apiAuditWitnessDatabaseReadAdapterSource -notmatch
            'readOnly: true' -or
        $apiAuditWitnessDatabaseReadAdapterSource -notmatch
            'AUDIT_WITNESS_DATABASE_READ_FAILED' -or
        $apiAuditWitnessDatabaseReadAdapterSource -notmatch
            'AUDIT_WITNESS_DATABASE_READ_RESPONSE_INVALID' -or
        $apiAuditWitnessDatabaseReadAdapterSource -match
            '(?i)node:(fs|child_process|net|http|sqlite)|\b(DatabaseSync|fetch|writeFile|appendFile|createWriteStream|SELECT|INSERT|UPDATE|DELETE|BEGIN|COMMIT|ROLLBACK)\b|\.prepare\s*\(' -or
        $apiAuditWitnessSqliteReaderSource -notmatch
            'UnwiredAuditWitnessSqliteReaderV1' -or
        $apiAuditWitnessSqliteReaderSource -notmatch
            'AUDIT_WITNESS_SQLITE_READER_RUNTIME_WIRING_ENABLED = false' -or
        $apiAuditWitnessSqliteReaderSource -notmatch
            'AUDIT_WITNESS_DATABASE_READ_REQUEST_V1' -or
        $apiAuditWitnessSqliteReaderSource -notmatch
            'BEGIN DEFERRED' -or
        $apiAuditWitnessSqliteReaderSource -notmatch
            'PRAGMA query_only' -or
        $apiAuditWitnessSqliteReaderSource -notmatch
            'ROLLBACK' -or
        $apiAuditWitnessSqliteReaderSource -notmatch
            'audit_events' -or
        $apiAuditWitnessSqliteReaderSource -notmatch
            'ORDER BY sequence ASC' -or
        $apiAuditWitnessSqliteReaderSource -notmatch
            'LIMIT' -or
        $apiAuditWitnessSqliteReaderSource -notmatch
            'request\.maximumRows \+ 1' -or
        $apiAuditWitnessSqliteReaderSource -notmatch
            'AUDIT_WITNESS_DATABASE_SNAPSHOT_MAXIMUM_BYTES' -or
        $apiAuditWitnessSqliteReaderSource -notmatch
            'length\(CAST\(' -or
        $apiAuditWitnessSqliteReaderSource -notmatch
            'AUDIT_WITNESS_DATABASE_SQLITE_QUERY_ONLY_REQUIRED' -or
        $apiAuditWitnessSqliteReaderSource -notmatch
            'AUDIT_WITNESS_DATABASE_SQLITE_TOO_LARGE' -or
        $apiAuditWitnessSqliteReaderSource -notmatch
            'AUDIT_WITNESS_DATABASE_SQLITE_ROW_INVALID' -or
        $apiAuditWitnessSqliteReaderSource -notmatch
            'AUDIT_WITNESS_DATABASE_SQLITE_ROLLBACK_FAILED' -or
        $apiAuditWitnessSqliteReaderSource -match
            '(?i)COUNT\s*\(\s*\*\s*\)|openDatabase|node:(fs|child_process|net|http)|\b(fetch|writeFile|appendFile|createWriteStream|COMMIT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|REPLACE|ATTACH|DETACH|retry|poll|listen|fetch)\b' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'project15\.audit-witness-sqlite-reader-source-receipt\.v1' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'historical-rewrite-detection-only' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'build-audit-witness-sqlite-reader-source-receipt\.mjs' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'check-audit-witness-sqlite-reader-source-receipt\.mjs' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'audit-witness-sqlite-reader\.ts' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'audit-witness-contract\.ts' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'audit-witness-database-read-ceremony\.ts' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'check-audit-witness-database-read-ceremony-receipt\.mjs' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'scripts/verify\.ps1' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'runtimeWiringEnabled: false' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'databaseOpened: false' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'databaseRowsRead: 0' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'pathInputAccepted: false' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'signerExecuted: false' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'serviceMutated: false' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'ipcEnabled: false' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'telemetryEnabled: false' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'transportEnabled: false' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'commandChannelEnabled: false' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'dirname\(dirname\(fileURLToPath\(import\.meta\.url\)\)\)' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'spawnSync\("git", args' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'status", "--porcelain=v1", "--untracked-files=all"' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            '"hash-object", "--stdin", "--path", path' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'AUDIT_WITNESS_SQLITE_SOURCE_HEAD_BLOB_MISMATCH' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'maximumFileBytes = 2_097_152' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'maximumTotalBytes = 8_388_608' -or
        $auditWitnessSqliteReceiptBuilderSource -notmatch
            'AUDIT_WITNESS_SQLITE_SOURCE_BUILD_FAILED' -or
        $auditWitnessSqliteReceiptBuilderSource -match
            '(?i)node:(sqlite|net|http|https|dgram|tls)|\b(DatabaseSync|fetch|writeFile|appendFile|createWriteStream|mkdir|rm|unlink|rename|copyFile|execSync|execFileSync|fork|Date|generatedAt)\b' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'project15\.audit-witness-sqlite-reader-source-receipt\.v1' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'historical-rewrite-detection-only' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'audit-witness-contract\.ts' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'audit-witness-database-read-ceremony\.ts' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'check-audit-witness-database-read-ceremony-receipt\.mjs' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'runtimeWiringEnabled: false' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'databaseOpened: false' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'databaseRowsRead: 0' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'pathInputAccepted: false' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'signerExecuted: false' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'serviceMutated: false' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'ipcEnabled: false' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'telemetryEnabled: false' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'transportEnabled: false' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'commandChannelEnabled: false' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'maximumReceiptBytes = 65_536' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'process\.stdin' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'args\[0\] !== "--expected-sha256"' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'AUDIT_WITNESS_SQLITE_RECEIPT_EXPECTED_HASH_MISMATCH' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'AUDIT_WITNESS_SQLITE_RECEIPT_CANONICAL_INVALID' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'AUDIT_WITNESS_SQLITE_RECEIPT_BOUNDARY_INVALID' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            '"hash-object", "--stdin", "--path", path' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'AUDIT_WITNESS_SQLITE_RECEIPT_HEAD_BLOB_MISMATCH' -or
        $auditWitnessSqliteReceiptCheckerSource -notmatch
            'AUDIT_WITNESS_SQLITE_RECEIPT_CHECK_FAILED' -or
        $auditWitnessSqliteReceiptCheckerSource -match
            '(?i)from\s+["''].*build-audit-witness|node:(sqlite|net|http|https|dgram|tls)|\b(DatabaseSync|fetch|writeFile|appendFile|createWriteStream|mkdir|rm|unlink|rename|copyFile|execSync|execFileSync|fork|Date|generatedAt)\b' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'project15\.audit-witness-database-read-ceremony\.v1' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'database-self-consistency-observation-only' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'I_ACKNOWLEDGE_PROJECT15_DATABASE_SELF_CONSISTENCY_READ_ONCE' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'process\.env\.WAR_ROOM_DATA_ROOT' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'dataRootOverride !== undefined' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'userInfo\(\)\.homedir' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'AUDIT_WITNESS_DATABASE_READ_CEREMONY_HOME_MISMATCH' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            '\.war-room-project15' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'war-room\.sqlite' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'databaseEntry\.nlink !== 1' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'readOnly: true' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'timeout: 1000' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'allowExtension: false' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'enableDefensive\(true\)' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'PRAGMA query_only = ON' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'setAuthorizer\(authorizeAuditWitnessDatabaseReadV1\)' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'SQLITE_DENY' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'UnwiredAuditWitnessSqliteReaderV1' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'acquireAuditWitnessDatabaseHeadV1' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'authoritativeBootstrapCreated: false' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'protectedAnchorCompared: false' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'sourceReceiptVerifiedByCeremony: false' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'logicalAuditRowsWritten: false' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'sqliteSharedMemoryMayMutate: true' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'filesystemWriteFreeClaimed: false' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'witnessWritten: false' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'signerExecuted: false' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'runtimeWiringEnabled: false' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'serviceMutated: false' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'ipcEnabled: false' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'telemetryEnabled: false' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'transportEnabled: false' -or
        $auditWitnessDatabaseCeremonySource -notmatch
            'commandChannelEnabled: false' -or
        $auditWitnessDatabaseCeremonySource -match
            '(?i)node:(child_process|net|http|https|dgram|tls)|\b(fetch|writeFile|appendFile|createWriteStream|mkdir|rm|unlink|rename|copyFile|execSync|execFileSync|fork|loadExtension)\b|\.prepare\s*\(' -or
        $auditWitnessDatabaseCeremonyCheckerSource -notmatch
            'project15\.audit-witness-database-read-ceremony\.v1' -or
        $auditWitnessDatabaseCeremonyCheckerSource -notmatch
            'database-self-consistency-observation-only' -or
        $auditWitnessDatabaseCeremonyCheckerSource -notmatch
            'AUDIT_WITNESS_DATABASE_CEREMONY_RECEIPT_EXPECTED_HASH_MISMATCH' -or
        $auditWitnessDatabaseCeremonyCheckerSource -notmatch
            'AUDIT_WITNESS_DATABASE_CEREMONY_SOURCE_RECEIPT_MISMATCH' -or
        $auditWitnessDatabaseCeremonyCheckerSource -notmatch
            'AUDIT_WITNESS_DATABASE_CEREMONY_RECEIPT_BOUNDARY_INVALID' -or
        $auditWitnessDatabaseCeremonyCheckerSource -notmatch
            'maximumReceiptBytes = 16_384' -or
        $auditWitnessDatabaseCeremonyCheckerSource -match
            '(?i)node:(fs|child_process|sqlite|net|http|https|dgram|tls)|\b(fetch|writeFile|appendFile|createWriteStream|DatabaseSync|spawn|exec|fork)\b' -or
        $apiAuditWitnessRuntimeSource -match
            'audit-witness-database-read-ceremony' -or
        $rootPackageSource -notmatch
            '"plan:audit-witness-sqlite-reader-source-receipt"' -or
        $rootPackageSource -notmatch
            '"build:audit-witness-sqlite-reader-source-receipt"' -or
        $rootPackageSource -notmatch
            '"check:audit-witness-sqlite-reader-source-receipt"' -or
        $rootPackageSource -notmatch
            '"test:audit-witness-sqlite-reader-source-receipt"' -or
        $rootPackageSource -notmatch
            '"plan:audit-witness-database-read-ceremony"' -or
        $rootPackageSource -notmatch
            '"read:audit-witness-database-read-ceremony"' -or
        $rootPackageSource -notmatch
            '"check:audit-witness-database-read-ceremony-receipt"' -or
        $rootPackageSource -notmatch
            '"test:audit-witness-database-read-ceremony"' -or
        $apiAuditWitnessAppendSource -notmatch
            'C:\\\\ProgramData\\\\Project15 Audit Head\\\\Witness' -or
        $apiAuditWitnessAppendSource -notmatch
            'audit-witness-v1\.log' -or
        $apiAuditWitnessAppendSource -notmatch '\bO_APPEND\b' -or
        $apiAuditWitnessAppendSource -notmatch '\bO_WRONLY\b' -or
        $apiAuditWitnessAppendSource -notmatch '\bO_SYNC\b' -or
        $apiAuditWitnessAppendSource -notmatch '\bO_NOFOLLOW\b' -or
        $apiAuditWitnessAppendSource -notmatch '\bfsync\b' -or
        $apiAuditWitnessAppendSource -notmatch
            'AUDIT_WITNESS_APPEND_POSTCONDITION_FAILED' -or
        $apiAuditWitnessAppendSource -match
            '(?i)\b(O_CREAT|O_TRUNC|truncateSync|writeFileSync|appendFileSync|createWriteStream|renameSync|unlinkSync|rmSync|mkdirSync)\b|node:(child_process|net|http)|\b(Sqlite|fetch)\b' -or
        $nativeAuditWitnessAppendSource -notmatch
            'historical-rewrite-detection-only' -or
        $nativeAuditWitnessAppendSource -notmatch
            'UsersAppendFileMask = 0x0012008D' -or
        $nativeAuditWitnessAppendSource -notmatch
            'UsersDirectoryMask = 0x001200A9' -or
        $nativeAuditWitnessAppendSource -notmatch
            'InstallerWiringEnabled: false' -or
        $nativeAuditWitnessAppendSource -notmatch
            'RuntimeWiringEnabled: false' -or
        $nativeAuditWitnessAppendSource -notmatch
            'CanTruncate: false' -or
        $nativeAuditWitnessAppendSource -notmatch
            'CanReplace: false' -or
        $nativeAuditWitnessAppendSource -match
            '(?i)\b(Process|Socket|HttpClient|Sqlite|ServiceController|NamedPipe|DllImport|CreateFile|WriteFile)\b' -or
        $nativeAuditWitnessCheckerSource -notmatch
            'FileFlagOpenReparsePoint = 0x00200000' -or
        $nativeAuditWitnessCheckerSource -notmatch
            'FileShareRead \| FileShareWrite' -or
        $nativeAuditWitnessCheckerSource -notmatch
            'GetFileInformationByHandle\(handle, out var before\)' -or
        $nativeAuditWitnessCheckerSource -notmatch
            'GetFileInformationByHandle\(handle, out var after\)' -or
        $nativeAuditWitnessCheckerSource -notmatch
            'FileAppendData = 0x00000004' -or
        $nativeAuditWitnessCheckerSource -notmatch
            'FileWriteData = 0x00000002' -or
        $nativeAuditWitnessCheckerSource -notmatch
            'DeleteAccess = 0x00010000' -or
        $nativeAuditWitnessCheckerSource -notmatch
            'WriteDac = 0x00040000' -or
        $nativeAuditWitnessCheckerSource -notmatch
            'WriteOwner = 0x00080000' -or
        $nativeAuditWitnessCheckerSource -notmatch
            'RequireStandardUser\(\)' -or
        $nativeAuditWitnessCheckerSource -notmatch
            'BytesWritten: false' -or
        $nativeAuditWitnessCheckerSource -notmatch
            'RequireAccessDenied' -or
        $nativeAuditWitnessCheckerSource -match
            '(?i)\b(FileMode\.(Create|CreateNew|OpenOrCreate|Truncate|Append)|File\.Delete|File\.Move|Directory\.Delete|WriteAll|WriteAsync|Write\(|Socket|HttpClient|Sqlite|ServiceController|NamedPipe)\b' -or
        $nativeAuditWitnessInstallerSource -notmatch
            'FileMode\.CreateNew' -or
        $nativeAuditWitnessInstallerSource -notmatch
            'FileOptions\.WriteThrough' -or
        $nativeAuditWitnessInstallerSource -notmatch
            'ExistingFileNeverTruncated: true' -or
        $nativeAuditWitnessInstallerSource -notmatch
            'ExistingFileNeverReplaced: true' -or
        $nativeAuditWitnessInstallerSource -notmatch
            'fileCreated && File\.Exists' -or
        $nativeAuditWitnessInstallerSource -notmatch
            'file\.Length == 0' -or
        $nativeAuditWitnessInstallerSource -match
            '(?i)\b(FileMode\.(Create\b|OpenOrCreate|Truncate|Append)|File\.Move|Socket|HttpClient|Sqlite|ServiceController|NamedPipe|Process)\b' -or
        $nativeAuditWitnessInstallerProgram -notmatch
            '"plan"' -or
        $nativeAuditWitnessInstallerProgram -notmatch
            '"install"' -or
        $nativeAuditWitnessInstallerProgram -notmatch
            'RequireAdministrator\(\)' -or
        $nativeAuditWitnessInstallerProgram -match
            '(?i)\b(Process|Socket|HttpClient|Sqlite|ServiceController|NamedPipe)\b' -or
        $nativeAuditWitnessCheckerProgram -notmatch '"check"' -or
        $nativeAuditWitnessCheckerProgram -notmatch '"check-access"' -or
        $nativeAuditWitnessCheckerProgram -notmatch
            'CheckEffectiveAccess\(\)' -or
        $nativeAuditWitnessCheckerProgram -match
            '(?i)\b(File|Directory|Process|Socket|HttpClient|Sqlite|ServiceController|NamedPipe|DllImport)\b' -or
        $sealedBundleSource -notmatch
            'audit-witness-installer' -or
        $sealedBundleSource -notmatch
            'audit-witness-checker' -or
        $sealedBundleSource -notmatch
            'WARRoom\.WindowsSensor\.AuditWitnessInstaller\.exe' -or
        $sealedBundleSource -notmatch
            'WARRoom\.WindowsSensor\.AuditWitnessChecker\.exe' -or
        $sensorInstallerSource -notmatch
            'Invoke-ProtectedAuditWitnessInstaller' -or
        $sensorInstallerSource -notmatch
            'Invoke-ProtectedAuditWitnessChecker' -or
        $sensorInstallerSource -notmatch
            'SENSOR_AUDIT_WITNESS_INDEPENDENT_CHECK_MISMATCH' -or
        $sensorInstallerSource -notmatch
            'auditWitnessRuntimeWiringEnabled = \$false'
    ) {
        throw 'Audit-witness contract or protected append boundary exceeded its pure unwired authority.'
    }

    $nativeAuditHeadWriterSource = Get-Content -Raw -LiteralPath (
        Join-Path $root 'apps\windows-sensor\src\NativeAuditHeadWriter.cs'
    )
    $nativeAuditHeadWriterFilesSource = Get-Content -Raw -LiteralPath (
        Join-Path $root 'apps\windows-sensor\src\NativeAuditHeadWriterFiles.cs'
    )
    $nativeAuditHeadToolSource = Get-Content -Raw -LiteralPath (
        Join-Path $root 'apps\windows-sensor\audit-head-tool\Program.cs'
    )
    $apiAuditHeadProofSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\api\src\services\audit-head-checkpoint-proof.ts'
    )
    $apiAuditHeadProtectedFileSource = Get-Content -Raw -LiteralPath (
        Join-Path $root `
            'apps\api\src\services\audit-head-protected-file.ts'
    )
    if (
        $nativeAuditHeadWriterSource -notmatch
            'Project15\.AuditHeadSigner\.v1' -or
        $nativeAuditHeadWriterSource -match
            'WAR-R00M\.WindowsSensor\.Identity\.v1' -or
        $nativeAuditHeadWriterSource -notmatch
            'C:\\ProgramData\\Project15 Audit Head\\Pending\\audit-head-pending-v1\.json' -or
        $nativeAuditHeadWriterSource -notmatch
            'C:\\ProgramData\\Project15 Audit Head\\Protected\\audit-head-state-v1\.json' -or
        $nativeAuditHeadWriterSource -notmatch 'MaximumPendingBytes = 131_072' -or
        $nativeAuditHeadWriterSource -notmatch
            '"sequence", "occurredAt", "eventType", "payloadJson"' -or
        $nativeAuditHeadWriterSource -notmatch
            'SENSOR_AUDIT_HEAD_PENDING_HASH_INVALID' -or
        $nativeAuditHeadWriterSource -notmatch
            'CheckpointEnabled: false' -or
        $nativeAuditHeadWriterSource -match
            '(?i)\b(Process|Socket|HttpClient|Sqlite|Database|ServiceController|NamedPipe)\b' -or
        $nativeAuditHeadWriterFilesSource -match
            '(?i)\b(Process|Socket|HttpClient|Sqlite|Database|ServiceController|NamedPipe)\b' -or
        $nativeAuditHeadToolSource -match
            '(?i)Console\.In|Process\.Start|HttpClient|Socket|NamedPipe|NativeAuditHeadWriterCommand\.Checkpoint' -or
        $nativeAuditHeadToolSource -notmatch
            'NativeAuditHeadWriterStorage\.ValidateFixedRoots' -or
        $apiAuditHeadProofSource -notmatch
            'AUDIT_HEAD_MAXIMUM_PENDING_BYTES = 131_072' -or
        $apiAuditHeadProofSource -notmatch
            'occurredAt: row\.occurred_at' -or
        $apiAuditHeadProofSource -notmatch
            'verifyAuditHeadProtectedDocumentV1' -or
        $apiAuditHeadProofSource -notmatch
            'expectedSignerPublicKeyFingerprintSha256' -or
        $apiAuditHeadProofSource -notmatch
            'AUDIT_HEAD_PROTECTED_SIGNER_MISMATCH' -or
        $apiAuditHeadProofSource -match
            '(?i)node:(fs|child_process|net|http)|\b(Sqlite|Database|fetch)\b' -or
        $apiAuditHeadProtectedFileSource -notmatch
            'C:\\\\ProgramData\\\\Project15 Audit Head\\\\Protected\\\\audit-head-state-v1\.json' -or
        $apiAuditHeadProtectedFileSource -notmatch
            'AUDIT_HEAD_MAXIMUM_PROTECTED_STATE_BYTES = 8192' -or
        $apiAuditHeadProtectedFileSource -notmatch 'O_NOFOLLOW' -or
        $apiAuditHeadProtectedFileSource -notmatch
            'lstatSync|realpathSync|openSync|fstatSync|readSync|closeSync' -or
        $apiAuditHeadProtectedFileSource -notmatch
            'expectedSignerPublicKeyFingerprintSha256' -or
        $apiAuditHeadProtectedFileSource -notmatch
            'verifyAuditHeadProtectedDocumentV1' -or
        $apiAuditHeadProtectedFileSource -match
            '(?i)write(File|Sync)|append(File|Sync)|rename|unlink|mkdir|node:(child_process|net|http)|\b(Sqlite|Database|fetch)\b'
    ) {
        throw 'Protected audit-head writer boundary was not preserved.'
    }

    $orphanedInstallPlan = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\install-windows-sensor-service.ps1'
    ) -Arguments @('-Command', 'orphaned-install-cleanup', '-WhatIf')
    if (
        -not (Test-ExactBoolean -Value $orphanedInstallPlan -Property 'ok' `
            -Expected $true) -or
        $orphanedInstallPlan.command -ne 'orphaned-install-cleanup-plan' -or
        $orphanedInstallPlan.plan.serviceName -ne 'WARRoomWindowsSensor' -or
        $orphanedInstallPlan.plan.installRoot -ne
            'C:\Program Files\WAR-R00M\Windows Sensor' -or
        $orphanedInstallPlan.plan.localStateRoot -ne
            'C:\ProgramData\WAR-R00M\Windows Sensor' -or
        -not (Test-ExactBoolean -Value $orphanedInstallPlan.plan `
            -Property 'requiresElevation' -Expected $true) -or
        -not (Test-ExactBoolean -Value $orphanedInstallPlan.plan `
            -Property 'requiresCleanSource' -Expected $true) -or
        -not (Test-ExactBoolean -Value $orphanedInstallPlan.plan `
            -Property 'requiresServiceAbsent' -Expected $true) -or
        -not (Test-ExactBoolean -Value $orphanedInstallPlan.plan `
            -Property 'requiresExactManifestAndHashes' -Expected $true) -or
        -not (Test-ExactBoolean -Value $orphanedInstallPlan.plan `
            -Property 'requiresExactProtectedStateLayout' -Expected $true) -or
        -not (Test-ExactBoolean -Value $orphanedInstallPlan.plan `
            -Property 'removesOnlyExactInstallRoot' -Expected $true) -or
        -not (Test-ExactBoolean -Value $orphanedInstallPlan.plan `
            -Property 'removesOnlyExactLocalStateRoot' -Expected $true) -or
        -not (Test-ExactBoolean -Value $orphanedInstallPlan.plan `
            -Property 'deletesMachineIdentity' -Expected $false) -or
        -not (Test-ExactBoolean -Value $orphanedInstallPlan.plan `
            -Property 'networkTransportEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $orphanedInstallPlan.plan `
            -Property 'collectorEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $orphanedInstallPlan.plan `
            -Property 'telemetryEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $orphanedInstallPlan.plan `
            -Property 'commandChannelEnabled' -Expected $false)
    ) {
        throw 'Windows sensor orphaned-install cleanup plan exceeded its exact boundary.'
    }

    $orphanedStatePlan = Invoke-JsonScript -Path (
        Join-Path $root 'scripts\install-windows-sensor-service.ps1'
    ) -Arguments @('-Command', 'orphaned-state-cleanup', '-WhatIf')
    if (
        -not (Test-ExactBoolean -Value $orphanedStatePlan -Property 'ok' `
            -Expected $true) -or
        $orphanedStatePlan.command -ne 'orphaned-state-cleanup-plan' -or
        $orphanedStatePlan.plan.serviceName -ne 'WARRoomWindowsSensor' -or
        $orphanedStatePlan.plan.installRoot -ne
            'C:\Program Files\WAR-R00M\Windows Sensor' -or
        -not (Test-ExactBoolean -Value $orphanedStatePlan.plan `
            -Property 'requiresElevation' -Expected $true) -or
        -not (Test-ExactBoolean -Value $orphanedStatePlan.plan `
            -Property 'requiresCleanSource' -Expected $true) -or
        -not (Test-ExactBoolean -Value $orphanedStatePlan.plan `
            -Property 'requiresServiceAbsent' -Expected $true) -or
        -not (Test-ExactBoolean -Value $orphanedStatePlan.plan `
            -Property 'requiresInstallRootAbsent' -Expected $true) -or
        -not (Test-ExactBoolean -Value $orphanedStatePlan.plan `
            -Property 'requiresExactProtectedStateLayout' -Expected $true) -or
        (@($orphanedStatePlan.plan.allowedLocalStateFiles) -join ',') -ne
            'local-synthetic-batch-proof.json,local-genuine-batch-proof.json,local-genuine-source-salt.bin,local-bounded-collector-proof.json,endpoint-binding.json,local-capability-proof.json,local-loopback-delivery.json' -or
        -not (Test-ExactBoolean -Value $orphanedStatePlan.plan `
            -Property 'removesOnlyExactLocalStateRoot' -Expected $true) -or
        -not (Test-ExactBoolean -Value $orphanedStatePlan.plan `
            -Property 'deletesMachineIdentity' -Expected $false) -or
        -not (Test-ExactBoolean -Value $orphanedStatePlan.plan `
            -Property 'networkTransportEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $orphanedStatePlan.plan `
            -Property 'collectorEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $orphanedStatePlan.plan `
            -Property 'telemetryEnabled' -Expected $false) -or
        -not (Test-ExactBoolean -Value $orphanedStatePlan.plan `
            -Property 'commandChannelEnabled' -Expected $false)
    ) {
        throw 'Windows sensor orphaned-state cleanup plan exceeded its exact boundary.'
    }

    & git diff --check
    if ($LASTEXITCODE -ne 0) {
        throw 'git diff --check failed'
    }
    & git diff --cached --check
    if ($LASTEXITCODE -ne 0) {
        throw 'git diff --cached --check failed'
    }
    & git fsck --no-dangling | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'git fsck --no-dangling failed'
    }

    Write-Host (
        "Project 15 verification passed; $powerShellScriptCount " +
        'tracked PowerShell scripts parsed.'
    ) -ForegroundColor Green
}
finally {
    Pop-Location
}
