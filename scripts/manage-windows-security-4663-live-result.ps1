[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateSet(
        'plan',
        'prepare-slot',
        'empty-check',
        'check',
        'consume',
        'absent-check',
        'cleanup',
        'slot-exercise',
        'live-exercise',
        'genuine-match-exercise'
    )]
    [string]$Command
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$portableDotnet = Join-Path $HOME '.codex-build\toolchains\dotnet8\dotnet.exe'
$dotnet = if ($env:WAR_ROOM_DOTNET) {
    $env:WAR_ROOM_DOTNET
}
elseif (Test-Path -LiteralPath $portableDotnet -PathType Leaf) {
    $portableDotnet
}
else {
    (Get-Command dotnet -ErrorAction Stop).Source
}

$sdkList = (& $dotnet --list-sdks) -join "`n"
if ($LASTEXITCODE -ne 0 -or $sdkList -notmatch '(?m)^8\.') {
    throw 'WAR-R00M Windows sensor requires a .NET 8 SDK.'
}

$buildRoot = Join-Path $HOME '.codex-build\project15\windows-sensor'
$project = Join-Path $root (
    'apps\windows-sensor\security-4663-live-result-tool\' +
    'WARRoom.WindowsSensor.Security4663LiveResultTool.csproj'
)
& $dotnet build $project --nologo -c Release --disable-build-servers `
    '-m:1' "-p:WarRoomBuildRoot=$buildRoot" '-p:NuGetAudit=false' `
    '-p:UseSharedCompilation=false' | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'SENSOR_C2F_SECURITY_4663_RESULT_TOOL_BUILD_FAILED'
}

$assembly = Join-Path $buildRoot (
    'bin\WARRoom.WindowsSensor.Security4663LiveResultTool\Release\' +
    'net8.0-windows\WARRoom.WindowsSensor.Security4663LiveResultTool.dll'
)
if (-not (Test-Path -LiteralPath $assembly -PathType Leaf)) {
    throw 'SENSOR_C2F_SECURITY_4663_RESULT_TOOL_MISSING'
}

function Invoke-NativeJson {
    param(
        [string]$NativeCommand,
        [string]$NativeAssembly = $assembly
    )
    # Windows PowerShell 5.1 promotes native stderr records under Stop before
    # this wrapper can parse the tool's bounded JSON error. Capture only this
    # direct invocation under Continue, then immediately restore fail-closed
    # script behavior.
    $nativeErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $dotnet $NativeAssembly $NativeCommand 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $nativeErrorActionPreference
    }
    if ($exitCode -ne 0) {
        $joined = $output -join "`n"
        $publicError = 'SENSOR_C2F_SECURITY_4663_RESULT_NATIVE_FAILED'
        try {
            $errorJson = $joined | ConvertFrom-Json
            if ([string]$errorJson.error -match '^SENSOR_[A-Z0-9_]+$') {
                $publicError = [string]$errorJson.error
            }
        }
        catch {
            $last = @($output | ForEach-Object {
                ([string]$_).Trim()
            } | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            } | Select-Object -Last 1)
            if ($last.Count -eq 1 -and
                $last[0] -match '^SENSOR_[A-Z0-9_]+$') {
                $publicError = $last[0]
            }
        }
        throw $publicError
    }
    try {
        return (($output -join "`n") | ConvertFrom-Json)
    }
    catch {
        throw 'SENSOR_C2F_SECURITY_4663_RESULT_OUTPUT_INVALID'
    }
}

function Get-LiveServiceContext {
    $principal = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'SENSOR_ADMINISTRATOR_REQUIRED'
    }
    $git = (Get-Command git -ErrorAction Stop).Source
    $sourceCommit = (& $git -C $root rev-parse HEAD).Trim()
    $sourceState = @(& $git -C $root status --porcelain=v1 `
        --untracked-files=all)
    if (
        $LASTEXITCODE -ne 0 -or
        $sourceCommit -notmatch '^[a-f0-9]{40}$' -or
        $sourceState.Count -ne 0
    ) {
        throw 'SENSOR_C2F_SECURITY_4663_SOURCE_NOT_CLEAN'
    }
    $registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64
    )
    try {
        $currentVersion = $registry.OpenSubKey(
            'SOFTWARE\Microsoft\Windows\CurrentVersion',
            $false
        )
        if ($null -eq $currentVersion) {
            throw 'SENSOR_C2F_SECURITY_4663_NATIVE_PROGRAM_FILES_UNAVAILABLE'
        }
        try {
            $programFiles = [string]$currentVersion.GetValue(
                'ProgramFilesDir',
                $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            )
        }
        finally {
            $currentVersion.Dispose()
        }
    }
    finally {
        $registry.Dispose()
    }
    if (
        [string]::IsNullOrWhiteSpace($programFiles) -or
        $programFiles -notmatch '^[A-Za-z]:\\'
    ) {
        throw 'SENSOR_C2F_SECURITY_4663_NATIVE_PROGRAM_FILES_INVALID'
    }
    $installRoot = [IO.Path]::GetFullPath(
        (Join-Path $programFiles 'WAR-R00M\Windows Sensor')
    )
    $executable = Join-Path $installRoot 'WARRoom.WindowsSensor.exe'
    $manifestPath = Join-Path $installRoot 'install-manifest.json'
    if (
        -not (Test-Path -LiteralPath $executable -PathType Leaf) -or
        -not (Test-Path -LiteralPath $manifestPath -PathType Leaf)
    ) {
        throw 'SENSOR_C2F_SECURITY_4663_INSTALL_MISSING'
    }
    $manifestRaw = [IO.File]::ReadAllText($manifestPath)
    $commitMatches = [regex]::Matches(
        $manifestRaw,
        '"commit"\s*:\s*"([a-f0-9]{40})"'
    )
    if (
        $commitMatches.Count -ne 1 -or
        $commitMatches[0].Groups[1].Value -ne $sourceCommit
    ) {
        throw 'SENSOR_C2F_SECURITY_4663_INSTALLED_COMMIT_MISMATCH'
    }
    $service = Get-CimInstance -ClassName Win32_Service `
        -Filter "Name='WARRoomWindowsSensor'"
    $expectedPath = '"' + $executable + '"'
    if (
        $null -eq $service -or
        [string]$service.DisplayName -ne 'WAR-R00M Windows Sensor' -or
        [string]$service.StartName -ne 'NT AUTHORITY\LocalService' -or
        [string]$service.StartMode -ne 'Manual' -or
        [string]$service.State -ne 'Stopped' -or
        [string]$service.PathName -ne $expectedPath
    ) {
        throw 'SENSOR_C2F_SECURITY_4663_SERVICE_CONTEXT_INVALID'
    }
    $machine = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64
    )
    try {
        $parameters = $machine.OpenSubKey(
            'SYSTEM\CurrentControlSet\Services\WARRoomWindowsSensor\Parameters',
            $false
        )
        $parametersExisted = $null -ne $parameters
        if ($null -ne $parameters) {
            try {
                if ($null -ne $parameters.GetValue('StartupMode', $null)) {
                    throw 'SENSOR_C2F_SECURITY_4663_STARTUP_MODE_PRESENT'
                }
            }
            finally {
                $parameters.Dispose()
            }
        }
    }
    finally {
        $machine.Dispose()
    }
    [pscustomobject]@{
        expectedPath = $expectedPath
        parametersExisted = $parametersExisted
    }
}

function Set-LiveStartupMode {
    $machine = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64
    )
    try {
        $serviceKey = $machine.OpenSubKey(
            'SYSTEM\CurrentControlSet\Services\WARRoomWindowsSensor',
            $true
        )
        if ($null -eq $serviceKey) {
            throw 'SENSOR_C2F_SECURITY_4663_SERVICE_REGISTRY_MISSING'
        }
        try {
            $parameters = $serviceKey.OpenSubKey('Parameters', $true)
            if ($null -eq $parameters) {
                $parameters = $serviceKey.CreateSubKey(
                    'Parameters',
                    [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
                )
            }
            try {
                if ($null -ne $parameters.GetValue('StartupMode', $null)) {
                    throw 'SENSOR_C2F_SECURITY_4663_STARTUP_MODE_PRESENT'
                }
                $parameters.SetValue(
                    'StartupMode',
                    '--security-4663-live-one-shot',
                    [Microsoft.Win32.RegistryValueKind]::String
                )
                if (
                    $parameters.GetValueKind('StartupMode') -ne
                        [Microsoft.Win32.RegistryValueKind]::String -or
                    [string]$parameters.GetValue('StartupMode', $null) -ne
                        '--security-4663-live-one-shot'
                ) {
                    throw 'SENSOR_C2F_SECURITY_4663_STARTUP_MODE_APPLY_FAILED'
                }
            }
            finally {
                $parameters.Dispose()
            }
        }
        finally {
            $serviceKey.Dispose()
        }
    }
    finally {
        $machine.Dispose()
    }
}

function Remove-LiveStartupMode {
    param([pscustomobject]$Context)
    $machine = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64
    )
    try {
        $serviceKey = $machine.OpenSubKey(
            'SYSTEM\CurrentControlSet\Services\WARRoomWindowsSensor',
            $true
        )
        if ($null -eq $serviceKey) {
            throw 'SENSOR_C2F_SECURITY_4663_SERVICE_REGISTRY_MISSING'
        }
        try {
            $parameters = $serviceKey.OpenSubKey('Parameters', $true)
            if ($null -eq $parameters) {
                throw 'SENSOR_C2F_SECURITY_4663_STARTUP_MODE_ROLLBACK_FAILED'
            }
            $deleteParameters = $false
            try {
                $value = $parameters.GetValue('StartupMode', $null)
                if (
                    $value -isnot [string] -or
                    [string]$value -ne '--security-4663-live-one-shot' -or
                    $parameters.GetValueKind('StartupMode') -ne
                        [Microsoft.Win32.RegistryValueKind]::String
                ) {
                    throw 'SENSOR_C2F_SECURITY_4663_STARTUP_MODE_ROLLBACK_FAILED'
                }
                $parameters.DeleteValue('StartupMode', $true)
                if (-not [bool]$Context.parametersExisted) {
                    if ($parameters.ValueCount -ne 0 -or
                        $parameters.SubKeyCount -ne 0) {
                        throw 'SENSOR_C2F_SECURITY_4663_STARTUP_MODE_ROOT_CHANGED'
                    }
                    $deleteParameters = $true
                }
            }
            finally {
                $parameters.Dispose()
            }
            if ($deleteParameters) {
                $serviceKey.DeleteSubKey('Parameters', $true)
            }
        }
        finally {
            $serviceKey.Dispose()
        }
    }
    finally {
        $machine.Dispose()
    }
}

function Invoke-FixedInertTrigger {
    $target = 'C:\ProgramData\WAR-R00M\Windows Sensor\C2\credential-store.fixture'
    $file = [IO.FileInfo]::new($target)
    if (
        -not $file.Exists -or
        $file.Length -ne 0 -or
        $file.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)
    ) {
        throw 'SENSOR_C2F_SECURITY_4663_TRIGGER_TARGET_INVALID'
    }
    $stream = [IO.FileStream]::new(
        $target,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read,
        1,
        [IO.FileOptions]::SequentialScan
    )
    try {
        if ($stream.ReadByte() -ne -1) {
            throw 'SENSOR_C2F_SECURITY_4663_TRIGGER_CONTENT_INVALID'
        }
    }
    finally {
        $stream.Dispose()
    }
}

if ($Command -eq 'plan') {
    Invoke-NativeJson -NativeCommand 'plan' | ConvertTo-Json -Depth 6
    return
}

if ($Command -in @('live-exercise', 'genuine-match-exercise')) {
    $isGenuineMatchExercise = $Command -eq 'genuine-match-exercise'
    if ($WhatIfPreference) {
        $planCommand = if ($isGenuineMatchExercise) {
            'genuine-match-plan'
        }
        else {
            'execution-plan'
        }
        Invoke-NativeJson -NativeCommand $planCommand |
            ConvertTo-Json -Depth 6
        return
    }
    $genuineMatchPlan = $null
    $settlementMilliseconds = 0
    if ($isGenuineMatchExercise) {
        $genuineMatchPlan = Invoke-NativeJson `
            -NativeCommand 'genuine-match-plan'
        if (
            $genuineMatchPlan.ok -ne $true -or
            $genuineMatchPlan.command -ne 'genuine-match-plan' -or
            [int]$genuineMatchPlan.result.schemaVersion -ne 1 -or
            $genuineMatchPlan.result.checkpoint -ne
                'gate-c2g-security-4663-genuine-match' -or
            $genuineMatchPlan.result.serviceIdentity -ne
                'NT AUTHORITY\LocalService' -or
            $genuineMatchPlan.result.requiresLocalServiceBeforeProtectedAccess -ne
                $true -or
            $genuineMatchPlan.result.requiresPreStartOperatorTrigger -ne $true -or
            [int]$genuineMatchPlan.result.triggerSettlementMilliseconds -ne 2000 -or
            [int]$genuineMatchPlan.result.maximumEventsRead -ne 1 -or
            [int]$genuineMatchPlan.result.maximumQueries -ne 1 -or
            [int]$genuineMatchPlan.result.maximumQueryMilliseconds -ne 2000 -or
            [int]$genuineMatchPlan.result.maximumTriggerWindowSeconds -ne 10 -or
            $genuineMatchPlan.result.requiresFixedPostTriggerSettlement -ne $true -or
            $genuineMatchPlan.result.requiresGenuineMatch -ne $true -or
            [int]$genuineMatchPlan.result.requiredEventsRead -ne 1 -or
            $genuineMatchPlan.result.requiresStrictRollback -ne $true -or
            $genuineMatchPlan.result.rawEventContentRetained -ne $false -or
            $genuineMatchPlan.result.continuousCollectionEnabled -ne $false -or
            $genuineMatchPlan.result.retryEnabled -ne $false -or
            $genuineMatchPlan.result.pollingEnabled -ne $false -or
            $genuineMatchPlan.result.telemetryEnabled -ne $false -or
            $genuineMatchPlan.result.transportEnabled -ne $false -or
            $genuineMatchPlan.result.ipcEnabled -ne $false -or
            $genuineMatchPlan.result.inboundListenerEnabled -ne $false -or
            $genuineMatchPlan.result.commandChannelEnabled -ne $false -or
            $genuineMatchPlan.result.responseActionEnabled -ne $false -or
            $genuineMatchPlan.result.runtimeWired -ne $false
        ) {
            throw 'SENSOR_C2G_SECURITY_4663_PLAN_INVALID'
        }
        $settlementMilliseconds =
            [int]$genuineMatchPlan.result.triggerSettlementMilliseconds
    }
    if (-not $PSCmdlet.ShouldProcess(
        'Gate C2d readiness, fixed C2f approval/result slots and LocalService',
        "Run one bounded $Command, validate its signed result, and always roll back")) {
        return
    }

    $context = Get-LiveServiceContext
    $approvalProject = Join-Path $root (
        'apps\windows-sensor\security-4663-live-approval-tool\' +
        'WARRoom.WindowsSensor.Security4663LiveApprovalTool.csproj'
    )
    & $dotnet build $approvalProject --nologo -c Release `
        --disable-build-servers '-m:1' `
        "-p:WarRoomBuildRoot=$buildRoot" '-p:NuGetAudit=false' `
        '-p:UseSharedCompilation=false' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'SENSOR_C2F_SECURITY_4663_APPROVAL_TOOL_BUILD_FAILED'
    }
    $approvalAssembly = Join-Path $buildRoot (
        'bin\WARRoom.WindowsSensor.Security4663LiveApprovalTool\Release\' +
        'net8.0-windows\WARRoom.WindowsSensor.Security4663LiveApprovalTool.dll'
    )
    $readinessProject = Join-Path $root (
        'apps\windows-sensor\readiness\' +
        'WARRoom.WindowsSensor.Readiness.csproj'
    )
    & $dotnet build $readinessProject --nologo -c Release `
        --disable-build-servers '-m:1' `
        "-p:WarRoomBuildRoot=$buildRoot" '-p:NuGetAudit=false' `
        '-p:UseSharedCompilation=false' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'SENSOR_C2F_SECURITY_4663_READINESS_TOOL_BUILD_FAILED'
    }
    $readinessAssembly = Join-Path $buildRoot (
        'bin\WARRoom.WindowsSensor.Readiness\Release\net8.0-windows\' +
        'WARRoom.WindowsSensor.Readiness.dll'
    )
    foreach ($required in @($approvalAssembly, $readinessAssembly)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw 'SENSOR_C2F_SECURITY_4663_LIVE_TOOL_MISSING'
        }
    }

    $applied = $false
    $resultPrepared = $false
    $approvalWritten = $false
    $triggered = $false
    $triggerSettlementCompleted = $false
    $startupModeApplied = $false
    $startupModeRestored = $false
    $serviceStarted = $false
    $serviceStopped = $false
    $resultChecked = $false
    $genuineMatchValidated = $false
    $resultConsumed = $false
    $approvalAbsent = $false
    $resultAbsent = $false
    $rolledBack = $false
    $readState = $null
    $eventsRead = 0
    $failure = $null
    $phase = 'readiness-apply'
    try {
        [void](Invoke-NativeJson -NativeAssembly $readinessAssembly `
            -NativeCommand 'security-4663-apply')
        $applied = $true
        $phase = 'result-slot-prepare'
        [void](Invoke-NativeJson -NativeCommand 'prepare-slot')
        [void](Invoke-NativeJson -NativeCommand 'empty-check')
        $resultPrepared = $true
        $phase = 'approval-write'
        [void](Invoke-NativeJson -NativeAssembly $approvalAssembly `
            -NativeCommand 'write')
        [void](Invoke-NativeJson -NativeAssembly $approvalAssembly `
            -NativeCommand 'check')
        $approvalWritten = $true
        $phase = 'inert-trigger'
        Invoke-FixedInertTrigger
        $triggered = $true
        if ($isGenuineMatchExercise) {
            $phase = 'trigger-settlement'
            Start-Sleep -Milliseconds $settlementMilliseconds
            $triggerSettlementCompleted = $true
        }
        $phase = 'startup-mode-apply'
        Set-LiveStartupMode
        $startupModeApplied = $true

        $phase = 'service-run'
        $controller = [System.ServiceProcess.ServiceController]::new(
            'WARRoomWindowsSensor'
        )
        try {
            $controller.Start()
            $serviceStarted = $true
            $controller.WaitForStatus(
                [System.ServiceProcess.ServiceControllerStatus]::Stopped,
                [TimeSpan]::FromSeconds(20)
            )
            $controller.Refresh()
            if ($controller.Status -ne
                [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
                throw 'SENSOR_C2F_SECURITY_4663_SERVICE_DID_NOT_STOP'
            }
            $serviceStopped = $true
        }
        finally {
            $controller.Dispose()
        }
        $service = Get-CimInstance -ClassName Win32_Service `
            -Filter "Name='WARRoomWindowsSensor'"
        if (
            $null -eq $service -or
            [string]$service.State -ne 'Stopped' -or
            [string]$service.StartName -ne 'NT AUTHORITY\LocalService' -or
            [string]$service.StartMode -ne 'Manual' -or
            [string]$service.PathName -ne $context.expectedPath -or
            [uint32]$service.ExitCode -ne 0 -or
            [uint32]$service.ServiceSpecificExitCode -ne 0
        ) {
            throw 'SENSOR_C2F_SECURITY_4663_SERVICE_RESULT_INVALID'
        }
        Remove-LiveStartupMode -Context $context
        $startupModeRestored = $true
        $phase = 'result-check'
        $checkedResult = Invoke-NativeJson -NativeCommand 'check'
        $readState = [string]$checkedResult.result.readState
        $eventsRead = [int]$checkedResult.result.eventsRead
        $resultChecked = $true
        if ($isGenuineMatchExercise) {
            $genuineMatchValidated =
                $readState -eq 'match' -and $eventsRead -eq 1
        }
        $phase = 'result-consume'
        [void](Invoke-NativeJson -NativeCommand 'consume')
        $resultConsumed = $true
        [void](Invoke-NativeJson -NativeCommand 'absent-check')
        $resultAbsent = $true
        $phase = 'approval-absence-check'
        [void](Invoke-NativeJson -NativeAssembly $approvalAssembly `
            -NativeCommand 'absent-check')
        $approvalAbsent = $true
        $phase = 'complete'
    }
    catch {
        $nativeFailure = $_.Exception.Message
        if ($nativeFailure -match '^SENSOR_[A-Z0-9_]+$') {
            $failure = $nativeFailure
        }
        else {
            $failure = switch ($phase) {
                'readiness-apply' {
                    'SENSOR_C2F_SECURITY_4663_READINESS_APPLY_FAILED'
                }
                'result-slot-prepare' {
                    'SENSOR_C2F_SECURITY_4663_RESULT_SLOT_PREPARE_FAILED'
                }
                'approval-write' {
                    'SENSOR_C2F_SECURITY_4663_APPROVAL_WRITE_FAILED'
                }
                'inert-trigger' {
                    'SENSOR_C2F_SECURITY_4663_INERT_TRIGGER_FAILED'
                }
                'trigger-settlement' {
                    'SENSOR_C2G_SECURITY_4663_SETTLEMENT_FAILED'
                }
                'startup-mode-apply' {
                    'SENSOR_C2F_SECURITY_4663_STARTUP_MODE_APPLY_FAILED'
                }
                'service-run' {
                    'SENSOR_C2F_SECURITY_4663_SERVICE_RUN_FAILED'
                }
                'result-check' {
                    'SENSOR_C2F_SECURITY_4663_RESULT_CHECK_FAILED'
                }
                'result-consume' {
                    'SENSOR_C2F_SECURITY_4663_RESULT_CONSUME_FAILED'
                }
                'approval-absence-check' {
                    'SENSOR_C2F_SECURITY_4663_APPROVAL_ABSENCE_CHECK_FAILED'
                }
                default {
                    'SENSOR_C2F_SECURITY_4663_LIVE_EXERCISE_FAILED'
                }
            }
        }
    }
    finally {
        if ($serviceStarted -and -not $serviceStopped) {
            try {
                Stop-Service -Name 'WARRoomWindowsSensor' -ErrorAction Stop
                $serviceStopped = $true
            }
            catch {
                if ($null -eq $failure) {
                    $failure = 'SENSOR_C2F_SECURITY_4663_SERVICE_RECOVERY_FAILED'
                }
            }
        }
        if ($startupModeApplied -and -not $startupModeRestored) {
            try {
                Remove-LiveStartupMode -Context $context
                $startupModeRestored = $true
            }
            catch {
                if ($null -eq $failure) {
                    $failure = 'SENSOR_C2F_SECURITY_4663_STARTUP_MODE_RECOVERY_FAILED'
                }
            }
        }
        if ($applied) {
            foreach ($cleanup in @(
                @{ Assembly = $assembly; Command = 'cleanup' },
                @{ Assembly = $approvalAssembly; Command = 'cleanup' }
            )) {
                try {
                    [void](Invoke-NativeJson `
                        -NativeAssembly $cleanup.Assembly `
                        -NativeCommand $cleanup.Command)
                }
                catch {
                    if ($null -eq $failure) {
                        $failure = $_.Exception.Message
                    }
                }
            }
            try {
                [void](Invoke-NativeJson -NativeAssembly $readinessAssembly `
                    -NativeCommand 'security-4663-rollback')
                $rolledBack = $true
            }
            catch {
                if ($null -eq $failure) {
                    $failure = 'SENSOR_C2F_SECURITY_4663_LIVE_ROLLBACK_FAILED'
                }
            }
        }
    }
    if ($null -eq $failure -and $isGenuineMatchExercise -and
        -not $genuineMatchValidated) {
        $failure = 'SENSOR_C2G_SECURITY_4663_GENUINE_MATCH_REQUIRED'
    }
    if ($null -ne $failure) {
        if ($failure -notmatch '^SENSOR_[A-Z0-9_]+$') {
            $failure = 'SENSOR_C2F_SECURITY_4663_LIVE_EXERCISE_FAILED'
        }
        throw $failure
    }
    if ($isGenuineMatchExercise) {
        [ordered]@{
            ok = $true
            command = 'genuine-match-exercise'
            result = [ordered]@{
                checkpoint = 'gate-c2g-security-4663-genuine-match'
                readinessApplied = $applied
                resultSlotPrepared = $resultPrepared
                approvalWrittenAndChecked = $approvalWritten
                inertTriggerCompleted = $triggered
                triggerSettlementCompleted = $triggerSettlementCompleted
                serviceStartedOnce = $serviceStarted
                serviceStopped = $serviceStopped
                startupModeRestored = $startupModeRestored
                resultExternallyChecked = $resultChecked
                genuineMatchValidated = $genuineMatchValidated
                resultConsumed = $resultConsumed
                approvalAbsent = $approvalAbsent
                resultAbsent = $resultAbsent
                rollbackCompleted = $rolledBack
                triggerSettlementMilliseconds = $settlementMilliseconds
                readState = $readState
                eventsRead = $eventsRead
                maximumEventsRead = 1
                maximumQueries = 1
                maximumQueryMilliseconds = 2000
                maximumTriggerWindowSeconds = 10
                rawEventContentRetained = $false
                continuousCollectionEnabled = $false
                retryEnabled = $false
                pollingEnabled = $false
                telemetryEnabled = $false
                transportEnabled = $false
                ipcEnabled = $false
                inboundListenerEnabled = $false
                commandChannelEnabled = $false
                responseActionEnabled = $false
            }
        } | ConvertTo-Json -Compress -Depth 5
        return
    }
    [ordered]@{
        ok = $true
        command = 'live-exercise'
        result = [ordered]@{
            checkpoint = 'gate-c2f-security-4663-live-one-shot'
            readinessApplied = $applied
            resultSlotPrepared = $resultPrepared
            approvalWrittenAndChecked = $approvalWritten
            inertTriggerCompleted = $triggered
            serviceStartedOnce = $serviceStarted
            serviceStopped = $serviceStopped
            startupModeRestored = $startupModeRestored
            resultExternallyChecked = $resultChecked
            resultConsumed = $resultConsumed
            approvalAbsent = $approvalAbsent
            resultAbsent = $resultAbsent
            rollbackCompleted = $rolledBack
            readState = $readState
            eventsRead = $eventsRead
            maximumEventsRead = 1
            rawEventContentRetained = $false
            continuousCollectionEnabled = $false
            retryEnabled = $false
            pollingEnabled = $false
            telemetryEnabled = $false
            transportEnabled = $false
            inboundListenerEnabled = $false
            commandChannelEnabled = $false
            responseActionEnabled = $false
        }
    } | ConvertTo-Json -Depth 5
    return
}

if ($Command -eq 'slot-exercise') {
    if ($WhatIfPreference) {
        Invoke-NativeJson -NativeCommand 'plan' | ConvertTo-Json -Depth 6
        return
    }
    if (-not $PSCmdlet.ShouldProcess(
        'Gate C2d readiness state and fixed Gate C2f result slot',
        'Apply readiness, prove the empty slot, clean it, and always roll back')) {
        return
    }

    $readinessProject = Join-Path $root (
        'apps\windows-sensor\readiness\' +
        'WARRoom.WindowsSensor.Readiness.csproj'
    )
    & $dotnet build $readinessProject --nologo -c Release `
        "-p:WarRoomBuildRoot=$buildRoot" '-p:NuGetAudit=false' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'SENSOR_C2F_SECURITY_4663_READINESS_TOOL_BUILD_FAILED'
    }
    $readinessAssembly = Join-Path $buildRoot (
        'bin\WARRoom.WindowsSensor.Readiness\Release\net8.0-windows\' +
        'WARRoom.WindowsSensor.Readiness.dll'
    )
    if (-not (Test-Path -LiteralPath $readinessAssembly -PathType Leaf)) {
        throw 'SENSOR_C2F_SECURITY_4663_READINESS_TOOL_MISSING'
    }

    $applied = $false
    $prepared = $false
    $emptyChecked = $false
    $cleaned = $false
    $absentChecked = $false
    $rolledBack = $false
    $failure = $null
    try {
        [void](Invoke-NativeJson -NativeAssembly $readinessAssembly `
            -NativeCommand 'security-4663-apply')
        $applied = $true
        [void](Invoke-NativeJson -NativeCommand 'prepare-slot')
        $prepared = $true
        [void](Invoke-NativeJson -NativeCommand 'empty-check')
        $emptyChecked = $true
    }
    catch {
        $failure = $_.Exception.Message
    }
    finally {
        if ($applied) {
            try {
                $cleanupResult = Invoke-NativeJson -NativeCommand 'cleanup'
                $cleaned = $cleanupResult.result.state -in @('removed', 'absent')
                [void](Invoke-NativeJson -NativeCommand 'absent-check')
                $absentChecked = $true
            }
            catch {
                if ($null -eq $failure) {
                    $failure = $_.Exception.Message
                }
            }
            try {
                [void](Invoke-NativeJson -NativeAssembly $readinessAssembly `
                    -NativeCommand 'security-4663-rollback')
                $rolledBack = $true
            }
            catch {
                $failure = 'SENSOR_C2F_SECURITY_4663_RESULT_ROLLBACK_FAILED'
            }
        }
    }
    if ($null -ne $failure) {
        if ($failure -notmatch '^SENSOR_[A-Z0-9_]+$') {
            $failure = 'SENSOR_C2F_SECURITY_4663_RESULT_EXERCISE_FAILED'
        }
        throw $failure
    }
    [ordered]@{
        ok = $true
        command = 'slot-exercise'
        result = [ordered]@{
            checkpoint = 'gate-c2f-security-4663-live-one-shot'
            readinessApplied = $applied
            slotPrepared = $prepared
            emptySlotChecked = $emptyChecked
            slotCleaned = $cleaned
            externalAbsenceChecked = $absentChecked
            rollbackCompleted = $rolledBack
            eventContentRead = $false
            eventsRead = 0
            serviceStarted = $false
            serviceMutated = $false
            telemetryEnabled = $false
            transportEnabled = $false
            inboundListenerEnabled = $false
            commandChannelEnabled = $false
            responseActionEnabled = $false
        }
    } | ConvertTo-Json -Depth 5
    return
}

if ($Command -in @('empty-check', 'check', 'absent-check')) {
    Invoke-NativeJson -NativeCommand $Command | ConvertTo-Json -Depth 6
    return
}

if ($WhatIfPreference) {
    Invoke-NativeJson -NativeCommand 'plan' | ConvertTo-Json -Depth 6
    return
}

$action = switch ($Command) {
    'prepare-slot' { 'Create only the fixed protected empty result slot' }
    'consume' { 'Validate and atomically consume only the exact signed result' }
    'cleanup' { 'Remove only a bounded protected fixed-path result slot' }
}
if (-not $PSCmdlet.ShouldProcess(
    'Gate C2f fixed Security 4663 live result path',
    $action)) {
    return
}

Invoke-NativeJson -NativeCommand $Command | ConvertTo-Json -Depth 6
