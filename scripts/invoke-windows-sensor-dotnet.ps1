[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet(
        'test',
        'build',
        'audit',
        'readiness-plan',
        'readiness-check',
        'security4663-readiness-plan',
        'security4663-readiness-check',
        'security4663-one-shot-plan',
        'local-proof-check',
        'genuine-proof-check',
        'bounded-proof-check'
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
$common = @(
    '--nologo',
    '-c', 'Release',
    "-p:WarRoomBuildRoot=$buildRoot",
    '-p:NuGetAudit=false'
)

if ($Command -eq 'audit') {
    $projects = @(
        (Join-Path $root `
            'apps\windows-sensor\src\WARRoom.WindowsSensor.csproj'),
        (Join-Path $root `
            'apps\windows-sensor\local-proof\WARRoom.WindowsSensor.LocalProof.csproj'),
        (Join-Path $root `
            'apps\windows-sensor\genuine-proof\WARRoom.WindowsSensor.GenuineProof.csproj'),
        (Join-Path $root `
            'apps\windows-sensor\bounded-proof\WARRoom.WindowsSensor.BoundedProof.csproj'),
        (Join-Path $root `
            'apps\windows-sensor\provisioner\WARRoom.WindowsSensor.Provisioner.csproj'),
        (Join-Path $root `
            'apps\windows-sensor\service-sid-tool\WARRoom.WindowsSensor.ServiceSidTool.csproj'),
        (Join-Path $root `
            'apps\windows-sensor\audit-head-tool\WARRoom.WindowsSensor.AuditHeadTool.csproj'),
        (Join-Path $root `
            'apps\windows-sensor\audit-witness-installer\WARRoom.WindowsSensor.AuditWitnessInstaller.csproj'),
        (Join-Path $root `
            'apps\windows-sensor\audit-witness-checker\WARRoom.WindowsSensor.AuditWitnessChecker.csproj'),
        (Join-Path $root `
            'apps\windows-sensor\binding-tool\WARRoom.WindowsSensor.BindingTool.csproj'),
        (Join-Path $root `
            'apps\windows-sensor\security-4663-approval-tool\WARRoom.WindowsSensor.Security4663ApprovalTool.csproj'),
        (Join-Path $root `
            'apps\windows-sensor\security-4663-live-approval-tool\WARRoom.WindowsSensor.Security4663LiveApprovalTool.csproj'),
        (Join-Path $root `
            'apps\windows-sensor\security-4663-live-result-tool\WARRoom.WindowsSensor.Security4663LiveResultTool.csproj'),
        (Join-Path $root `
            'apps\windows-sensor\readiness\WARRoom.WindowsSensor.Readiness.csproj')
    )
    foreach ($project in $projects) {
        & $dotnet list $project package --vulnerable --include-transitive `
            --source 'https://api.nuget.org/v3/index.json'
        if ($LASTEXITCODE -ne 0) {
            throw "Windows sensor audit failed with exit code $LASTEXITCODE."
        }
    }
}
elseif ($Command -eq 'test') {
    $project = Join-Path $root 'apps\windows-sensor\tests\WARRoom.WindowsSensor.BoundaryTests.csproj'
    & $dotnet run --project $project @common
}
elseif ($Command -in @(
    'readiness-plan',
    'readiness-check',
    'security4663-readiness-plan',
    'security4663-readiness-check',
    'security4663-one-shot-plan'
)) {
    $project = Join-Path $root `
        'apps\windows-sensor\readiness\WARRoom.WindowsSensor.Readiness.csproj'
    $readinessCommand = switch ($Command) {
        'readiness-plan' { 'plan' }
        'readiness-check' { 'check' }
        'security4663-readiness-plan' { 'security-4663-plan' }
        'security4663-readiness-check' { 'security-4663-check' }
        'security4663-one-shot-plan' { 'security-4663-one-shot-plan' }
    }
    $readinessCommon = @(
        $common | Where-Object { $_ -ne '--nologo' }
    )
    & $dotnet run --project $project @readinessCommon -- $readinessCommand
}
elseif ($Command -eq 'local-proof-check') {
    $project = Join-Path $root `
        'apps\windows-sensor\local-proof\WARRoom.WindowsSensor.LocalProof.csproj'
    & $dotnet run --project $project @common
}
elseif ($Command -eq 'genuine-proof-check') {
    $project = Join-Path $root `
        'apps\windows-sensor\genuine-proof\WARRoom.WindowsSensor.GenuineProof.csproj'
    & $dotnet run --project $project @common
}
elseif ($Command -eq 'bounded-proof-check') {
    $project = Join-Path $root `
        'apps\windows-sensor\bounded-proof\WARRoom.WindowsSensor.BoundedProof.csproj'
    & $dotnet run --project $project @common
}
else {
    $projects = @(
        (Join-Path $root 'apps\windows-sensor\src\WARRoom.WindowsSensor.csproj'),
        (Join-Path $root 'apps\windows-sensor\local-proof\WARRoom.WindowsSensor.LocalProof.csproj'),
        (Join-Path $root 'apps\windows-sensor\genuine-proof\WARRoom.WindowsSensor.GenuineProof.csproj'),
        (Join-Path $root 'apps\windows-sensor\bounded-proof\WARRoom.WindowsSensor.BoundedProof.csproj'),
        (Join-Path $root 'apps\windows-sensor\provisioner\WARRoom.WindowsSensor.Provisioner.csproj'),
        (Join-Path $root 'apps\windows-sensor\service-sid-tool\WARRoom.WindowsSensor.ServiceSidTool.csproj'),
        (Join-Path $root 'apps\windows-sensor\audit-head-tool\WARRoom.WindowsSensor.AuditHeadTool.csproj'),
        (Join-Path $root 'apps\windows-sensor\audit-witness-installer\WARRoom.WindowsSensor.AuditWitnessInstaller.csproj'),
        (Join-Path $root 'apps\windows-sensor\audit-witness-checker\WARRoom.WindowsSensor.AuditWitnessChecker.csproj'),
        (Join-Path $root 'apps\windows-sensor\binding-tool\WARRoom.WindowsSensor.BindingTool.csproj'),
        (Join-Path $root 'apps\windows-sensor\security-4663-approval-tool\WARRoom.WindowsSensor.Security4663ApprovalTool.csproj'),
        (Join-Path $root 'apps\windows-sensor\security-4663-live-approval-tool\WARRoom.WindowsSensor.Security4663LiveApprovalTool.csproj'),
        (Join-Path $root 'apps\windows-sensor\security-4663-live-result-tool\WARRoom.WindowsSensor.Security4663LiveResultTool.csproj'),
        (Join-Path $root 'apps\windows-sensor\readiness\WARRoom.WindowsSensor.Readiness.csproj')
    )
    foreach ($project in $projects) {
        & $dotnet build $project @common
        if ($LASTEXITCODE -ne 0) {
            throw "Windows sensor build failed with exit code $LASTEXITCODE."
        }
    }
}

if ($LASTEXITCODE -ne 0) {
    throw "Windows sensor $Command failed with exit code $LASTEXITCODE."
}
