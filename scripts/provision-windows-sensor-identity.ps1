[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet(
        'plan',
        'status',
        'provision',
        'enrollment-identity',
        'sign-enrollment-challenge',
        'probe-plan',
        'probe-status',
        'probe-cleanup'
    )]
    [string]$Command = 'plan',
    [string]$ChallengeJson
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

$effectiveCommand = $Command
if (
    $Command -eq 'sign-enrollment-challenge' -and
    (
        [string]::IsNullOrWhiteSpace($ChallengeJson) -or
        [Text.Encoding]::UTF8.GetByteCount($ChallengeJson) -gt 8192
    )
) {
    throw 'SENSOR_ENROLLMENT_CHALLENGE_INPUT_INVALID'
}
if (
    $Command -ne 'sign-enrollment-challenge' -and
    -not [string]::IsNullOrEmpty($ChallengeJson)
) {
    throw 'SENSOR_ENROLLMENT_CHALLENGE_NOT_ALLOWED'
}
if ($Command -eq 'provision') {
    if ($WhatIfPreference) {
        $effectiveCommand = 'plan'
    }
    elseif (-not $PSCmdlet.ShouldProcess(
        'WAR-R00M.WindowsSensor.Identity.v1',
        'Create a non-exportable machine CNG signing key for LocalService')) {
        return
    }
}
elseif ($Command -eq 'probe-cleanup') {
    if ($WhatIfPreference) {
        $effectiveCommand = 'probe-plan'
    }
    elseif (-not $PSCmdlet.ShouldProcess(
        'WAR-R00M-Acl-Probe-397bf4da663d4a7b985eab7565aa2806',
        'Remove only the recorded current-user diagnostic CNG probe key')) {
        return
    }
}

$buildRoot = Join-Path $HOME '.codex-build\project15\windows-sensor'
$project = Join-Path $root 'apps\windows-sensor\provisioner\WARRoom.WindowsSensor.Provisioner.csproj'
if ($effectiveCommand -eq 'sign-enrollment-challenge') {
    $ChallengeJson | & $dotnet run --project $project -c Release `
        "-p:WarRoomBuildRoot=$buildRoot" `
        '-p:NuGetAudit=false' -- $effectiveCommand
}
else {
    & $dotnet run --project $project -c Release `
        "-p:WarRoomBuildRoot=$buildRoot" `
        '-p:NuGetAudit=false' -- $effectiveCommand
}

if ($LASTEXITCODE -ne 0) {
    throw "Windows sensor identity $effectiveCommand failed with exit code $LASTEXITCODE."
}
