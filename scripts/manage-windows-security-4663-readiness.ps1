[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateSet('plan', 'check', 'apply', 'rollback', 'exercise')]
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

$nativeCommand = switch ($Command) {
    'plan' { 'security-4663-ceremony-plan' }
    'check' { 'security-4663-check' }
    'apply' { 'security-4663-apply' }
    'rollback' { 'security-4663-rollback' }
    'exercise' { 'security-4663-exercise' }
}

if ($Command -eq 'apply') {
    if ($WhatIfPreference) {
        $nativeCommand = 'security-4663-ceremony-plan'
    }
    elseif (-not $PSCmdlet.ShouldProcess(
        'Security channel, File System audit policy and three fixed inert files',
        'Apply the reversible Gate C2d least-privilege readiness ceremony')) {
        return
    }
}
elseif ($Command -eq 'rollback') {
    if ($WhatIfPreference) {
        $nativeCommand = 'security-4663-ceremony-plan'
    }
    elseif (-not $PSCmdlet.ShouldProcess(
        'Gate C2d protected original-state snapshot',
        'Restore exact original channel/audit state and remove inert files')) {
        return
    }
}
elseif ($Command -eq 'exercise') {
    if ($WhatIfPreference) {
        $nativeCommand = 'security-4663-ceremony-plan'
    }
    elseif (-not $PSCmdlet.ShouldProcess(
        'Security channel, File System audit policy and three fixed inert files',
        'Apply, verify and roll back the reversible Gate C2d ceremony')) {
        return
    }
}

$buildRoot = Join-Path $HOME '.codex-build\project15\windows-sensor'
$project = Join-Path $root `
    'apps\windows-sensor\readiness\WARRoom.WindowsSensor.Readiness.csproj'
$nativeOutput = @(& $dotnet run --project $project -c Release `
    "-p:WarRoomBuildRoot=$buildRoot" `
    '-p:NuGetAudit=false' -- $nativeCommand 2>&1)
$nativeExitCode = $LASTEXITCODE
if ($nativeExitCode -ne 0) {
    $nativeError = @($nativeOutput | ForEach-Object {
        ([string]$_).Trim()
    } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Last 1)
    $publicError = if ($nativeError.Count -eq 1 -and
        $nativeError[0] -match '^SENSOR_[A-Z0-9_]+$') {
        $nativeError[0]
    }
    else { 'SENSOR_SECURITY_4663_NATIVE_FAILURE' }
    throw "Windows Security 4663 ceremony $Command failed: $publicError"
}
$nativeOutput | ForEach-Object { Write-Output $_ }
