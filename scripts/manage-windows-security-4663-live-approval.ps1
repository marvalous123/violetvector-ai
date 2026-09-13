[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateSet(
        'plan',
        'write',
        'check',
        'absent-check',
        'cleanup',
        'exercise'
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
$approvalProject = Join-Path $root (
    'apps\windows-sensor\security-4663-live-approval-tool\' +
    'WARRoom.WindowsSensor.Security4663LiveApprovalTool.csproj'
)
$readinessProject = Join-Path $root (
    'apps\windows-sensor\readiness\' +
    'WARRoom.WindowsSensor.Readiness.csproj'
)

function Build-NativeTool {
    param([string]$Project, [string]$ErrorCode)
    & $dotnet build $Project --nologo -c Release `
        "-p:WarRoomBuildRoot=$buildRoot" '-p:NuGetAudit=false' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw $ErrorCode
    }
}

function Invoke-NativeJson {
    param([string]$Assembly, [string]$NativeCommand)
    $output = @(& $dotnet $Assembly $NativeCommand 2>&1)
    if ($LASTEXITCODE -ne 0) {
        $joined = $output -join "`n"
        $publicError = 'SENSOR_C2F_SECURITY_4663_APPROVAL_NATIVE_FAILED'
        try {
            $errorJson = $joined | ConvertFrom-Json
            if ([string]$errorJson.error -match '^SENSOR_[A-Z0-9_]+$') {
                $publicError = [string]$errorJson.error
            }
        }
        catch { }
        throw $publicError
    }
    try {
        return (($output -join "`n") | ConvertFrom-Json)
    }
    catch {
        throw 'SENSOR_C2F_SECURITY_4663_APPROVAL_OUTPUT_INVALID'
    }
}

Build-NativeTool -Project $approvalProject `
    -ErrorCode 'SENSOR_C2F_SECURITY_4663_APPROVAL_TOOL_BUILD_FAILED'
$approvalAssembly = Join-Path $buildRoot (
    'bin\WARRoom.WindowsSensor.Security4663LiveApprovalTool\Release\' +
    'net8.0-windows\WARRoom.WindowsSensor.Security4663LiveApprovalTool.dll'
)
if (-not (Test-Path -LiteralPath $approvalAssembly -PathType Leaf)) {
    throw 'SENSOR_C2F_SECURITY_4663_APPROVAL_TOOL_MISSING'
}

if ($Command -eq 'plan') {
    Invoke-NativeJson -Assembly $approvalAssembly -NativeCommand 'plan' |
        ConvertTo-Json -Depth 6
    return
}

if ($Command -ne 'exercise') {
    if ($Command -in @('write', 'cleanup')) {
        if ($WhatIfPreference) {
            Invoke-NativeJson -Assembly $approvalAssembly `
                -NativeCommand 'plan' | ConvertTo-Json -Depth 6
            return
        }
        $action = if ($Command -eq 'write') {
            'Create one distinct protected five-minute live-read approval'
        }
        else {
            'Remove only the exact protected live-read approval for recovery'
        }
        if (-not $PSCmdlet.ShouldProcess(
            'Gate C2f fixed Security 4663 live approval path',
            $action)) {
            return
        }
    }
    Invoke-NativeJson -Assembly $approvalAssembly -NativeCommand $Command |
        ConvertTo-Json -Depth 6
    return
}

if ($WhatIfPreference) {
    Invoke-NativeJson -Assembly $approvalAssembly -NativeCommand 'plan' |
        ConvertTo-Json -Depth 6
    return
}
if (-not $PSCmdlet.ShouldProcess(
    'Gate C2d reversible readiness and fixed Gate C2f approval path',
    'Write, externally check, clean up, verify absence and always roll back')) {
    return
}

Build-NativeTool -Project $readinessProject `
    -ErrorCode 'SENSOR_C2F_SECURITY_4663_READINESS_TOOL_BUILD_FAILED'
$readinessAssembly = Join-Path $buildRoot (
    'bin\WARRoom.WindowsSensor.Readiness\Release\net8.0-windows\' +
    'WARRoom.WindowsSensor.Readiness.dll'
)
if (-not (Test-Path -LiteralPath $readinessAssembly -PathType Leaf)) {
    throw 'SENSOR_C2F_SECURITY_4663_READINESS_TOOL_MISSING'
}

$applied = $false
$written = $false
$checked = $false
$removed = $false
$absent = $false
$rolledBack = $false
$failure = $null
try {
    [void](Invoke-NativeJson -Assembly $readinessAssembly `
        -NativeCommand 'security-4663-apply')
    $applied = $true
    [void](Invoke-NativeJson -Assembly $approvalAssembly `
        -NativeCommand 'write')
    $written = $true
    [void](Invoke-NativeJson -Assembly $approvalAssembly `
        -NativeCommand 'check')
    $checked = $true
}
catch {
    $failure = $_.Exception.Message
}
finally {
    if ($applied) {
        try {
            $cleanup = Invoke-NativeJson -Assembly $approvalAssembly `
                -NativeCommand 'cleanup'
            $removed = [bool]$cleanup.result.recoveryRemoved
            [void](Invoke-NativeJson -Assembly $approvalAssembly `
                -NativeCommand 'absent-check')
            $absent = $true
        }
        catch {
            if ($null -eq $failure) {
                $failure = $_.Exception.Message
            }
        }
        try {
            [void](Invoke-NativeJson -Assembly $readinessAssembly `
                -NativeCommand 'security-4663-rollback')
            $rolledBack = $true
        }
        catch {
            $failure = 'SENSOR_C2F_SECURITY_4663_APPROVAL_ROLLBACK_FAILED'
        }
    }
}

if ($null -ne $failure) {
    if ($failure -notmatch '^SENSOR_[A-Z0-9_]+$') {
        $failure = 'SENSOR_C2F_SECURITY_4663_APPROVAL_EXERCISE_FAILED'
    }
    throw $failure
}

[ordered]@{
    ok = $true
    command = 'exercise'
    result = [ordered]@{
        checkpoint = 'gate-c2f-security-4663-live-one-shot'
        readinessApplied = $applied
        approvalWritten = $written
        externallyChecked = $checked
        recoveryRemoved = $removed
        externalAbsenceChecked = $absent
        rollbackCompleted = $rolledBack
        eventContentRead = $false
        eventsRead = 0
        serviceStarted = $false
        serviceMutated = $false
        retryEnabled = $false
        pollingEnabled = $false
        transportEnabled = $false
        inboundListenerEnabled = $false
        commandChannelEnabled = $false
        responseActionEnabled = $false
        runtimeWired = $false
    }
} | ConvertTo-Json -Depth 5
