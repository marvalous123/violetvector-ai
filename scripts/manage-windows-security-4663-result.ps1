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
        'slot-exercise'
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
    'apps\windows-sensor\security-4663-result-tool\' +
    'WARRoom.WindowsSensor.Security4663ResultTool.csproj'
)
& $dotnet build $project --nologo -c Release `
    "-p:WarRoomBuildRoot=$buildRoot" '-p:NuGetAudit=false' | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'SENSOR_C2E_SECURITY_4663_RESULT_TOOL_BUILD_FAILED'
}

$assembly = Join-Path $buildRoot (
    'bin\WARRoom.WindowsSensor.Security4663ResultTool\Release\' +
    'net8.0-windows\WARRoom.WindowsSensor.Security4663ResultTool.dll'
)
if (-not (Test-Path -LiteralPath $assembly -PathType Leaf)) {
    throw 'SENSOR_C2E_SECURITY_4663_RESULT_TOOL_MISSING'
}

function Invoke-NativeJson {
    param(
        [string]$NativeCommand,
        [string]$NativeAssembly = $assembly
    )
    $output = @(& $dotnet $NativeAssembly $NativeCommand 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        $joined = $output -join "`n"
        $publicError = 'SENSOR_C2E_SECURITY_4663_RESULT_NATIVE_FAILED'
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
        throw 'SENSOR_C2E_SECURITY_4663_RESULT_OUTPUT_INVALID'
    }
}

if ($Command -eq 'plan') {
    Invoke-NativeJson -NativeCommand 'plan' | ConvertTo-Json -Depth 6
    return
}

if ($Command -eq 'slot-exercise') {
    if ($WhatIfPreference) {
        Invoke-NativeJson -NativeCommand 'plan' | ConvertTo-Json -Depth 6
        return
    }
    if (-not $PSCmdlet.ShouldProcess(
        'Gate C2d reversible readiness state and fixed Gate C2e result slot',
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
        throw 'SENSOR_C2E_SECURITY_4663_READINESS_TOOL_BUILD_FAILED'
    }
    $readinessAssembly = Join-Path $buildRoot (
        'bin\WARRoom.WindowsSensor.Readiness\Release\net8.0-windows\' +
        'WARRoom.WindowsSensor.Readiness.dll'
    )
    if (-not (Test-Path -LiteralPath $readinessAssembly -PathType Leaf)) {
        throw 'SENSOR_C2E_SECURITY_4663_READINESS_TOOL_MISSING'
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
                $failure = 'SENSOR_C2E_SECURITY_4663_RESULT_ROLLBACK_FAILED'
            }
        }
    }
    if ($null -ne $failure) {
        if ($failure -notmatch '^SENSOR_[A-Z0-9_]+$') {
            $failure = 'SENSOR_C2E_SECURITY_4663_RESULT_EXERCISE_FAILED'
        }
        throw $failure
    }
    [ordered]@{
        ok = $true
        command = 'slot-exercise'
        result = [ordered]@{
            checkpoint = 'gate-c2e-security-4663-one-shot'
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
    'Gate C2e fixed Security 4663 result path',
    $action)) {
    return
}

Invoke-NativeJson -NativeCommand $Command | ConvertTo-Json -Depth 6
