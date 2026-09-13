[CmdletBinding()]
param(
    [ValidateSet('plan', 'build')]
    [string]$Command = 'plan'
)

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$runtimeIdentifier = 'win-x64'
$bundleRoot = [IO.Path]::GetFullPath(
    (Join-Path $HOME '.codex-build\project15\windows-sensor\sealed-packages')
)
$buildRoot = [IO.Path]::GetFullPath(
    (Join-Path $HOME '.codex-build\project15\windows-sensor')
)

function Write-Json {
    param([object]$Value)
    $Value | ConvertTo-Json -Depth 8
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Get-DotnetTool {
    $portable = Join-Path $HOME '.codex-build\toolchains\dotnet8\dotnet.exe'
    $candidate = if ($env:WAR_ROOM_DOTNET) {
        $env:WAR_ROOM_DOTNET
    }
    elseif (Test-Path -LiteralPath $portable -PathType Leaf) {
        $portable
    }
    else {
        (Get-Command dotnet.exe -ErrorAction Stop).Source
    }
    $resolved = [IO.Path]::GetFullPath($candidate)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw 'SENSOR_BUNDLE_DOTNET_INVALID'
    }
    return $resolved
}

function Get-GitTool {
    $candidate = (Get-Command git.exe -ErrorAction Stop).Source
    $resolved = [IO.Path]::GetFullPath($candidate)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw 'SENSOR_BUNDLE_GIT_INVALID'
    }
    return $resolved
}

function Get-CleanCommit {
    $git = Get-GitTool
    $status = (& $git -C $projectRoot status --porcelain) -join "`n"
    if ($LASTEXITCODE -ne 0 -or -not [string]::IsNullOrWhiteSpace($status)) {
        throw 'SENSOR_BUNDLE_SOURCE_NOT_CLEAN'
    }
    $commit = (& $git -C $projectRoot rev-parse HEAD) -join ''
    if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
        throw 'SENSOR_BUNDLE_COMMIT_INVALID'
    }
    return $commit
}

function Assert-PublishTree {
    param(
        [string]$Path,
        [string]$Executable
    )
    $root = [IO.Path]::GetFullPath($Path)
    $items = @(Get-ChildItem -LiteralPath $root -Force)
    if (
        $items.Count -lt 4 -or
        @($items | Where-Object {
            $_.PSIsContainer -or
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $_.Extension -notin @('.dll', '.exe', '.json')
        }).Count -ne 0 -or
        -not (Test-Path -LiteralPath (Join-Path $root $Executable) -PathType Leaf)
    ) {
        throw 'SENSOR_BUNDLE_PUBLISH_TREE_INVALID'
    }
}

if ($Command -eq 'plan') {
    Write-Json ([ordered]@{
        ok = $true
        command = 'plan'
        result = [ordered]@{
            runsElevated = $false
            buildsSensor = $true
            buildsIdentityStatusTool = $true
            buildsServiceSidTool = $true
            buildsAuditWitnessInstaller = $true
            buildsAuditWitnessChecker = $true
            emitsContentSealedBundle = $true
            installOrServiceMutation = $false
            telemetryEnabled = $false
            commandChannelEnabled = $false
        }
    })
    return
}

if (Test-IsAdministrator) {
    throw 'SENSOR_BUNDLE_UNELEVATED_HOST_REQUIRED'
}

$commit = Get-CleanCommit
$dotnet = Get-DotnetTool
$bundleId = [Guid]::NewGuid().ToString('N')
$outputRoot = Join-Path $bundleRoot $bundleId
$sensorRoot = Join-Path $outputRoot 'sensor'
$identityRoot = Join-Path $outputRoot 'identity-status'
$serviceSidRoot = Join-Path $outputRoot 'service-sid'
$auditWitnessInstallerRoot = Join-Path $outputRoot 'audit-witness-installer'
$auditWitnessCheckerRoot = Join-Path $outputRoot 'audit-witness-checker'
$created = $false
try {
    [void](New-Item -ItemType Directory -Path $sensorRoot -Force)
    [void](New-Item -ItemType Directory -Path $identityRoot -Force)
    [void](New-Item -ItemType Directory -Path $serviceSidRoot -Force)
    [void](New-Item -ItemType Directory -Path $auditWitnessInstallerRoot -Force)
    [void](New-Item -ItemType Directory -Path $auditWitnessCheckerRoot -Force)
    $created = $true

    $sensorProject = Join-Path $projectRoot `
        'apps\windows-sensor\src\WARRoom.WindowsSensor.csproj'
    & $dotnet publish $sensorProject --nologo -c Release `
        -r $runtimeIdentifier --self-contained true `
        "-p:WarRoomBuildRoot=$buildRoot" `
        "-p:PublishDir=$sensorRoot\" `
        '-p:DebugType=None' '-p:DebugSymbols=false' '-p:NuGetAudit=false' |
        Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "SENSOR_BUNDLE_SENSOR_PUBLISH_FAILED_$LASTEXITCODE"
    }

    $identityProject = Join-Path $projectRoot `
        'apps\windows-sensor\provisioner\WARRoom.WindowsSensor.Provisioner.csproj'
    & $dotnet publish $identityProject --nologo -c Release `
        -r $runtimeIdentifier --self-contained true `
        "-p:WarRoomBuildRoot=$buildRoot" `
        "-p:PublishDir=$identityRoot\" `
        '-p:DebugType=None' '-p:DebugSymbols=false' '-p:NuGetAudit=false' |
        Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "SENSOR_BUNDLE_IDENTITY_PUBLISH_FAILED_$LASTEXITCODE"
    }

    $serviceSidProject = Join-Path $projectRoot `
        'apps\windows-sensor\service-sid-tool\WARRoom.WindowsSensor.ServiceSidTool.csproj'
    & $dotnet publish $serviceSidProject --nologo -c Release `
        -r $runtimeIdentifier --self-contained true `
        "-p:WarRoomBuildRoot=$buildRoot" `
        "-p:PublishDir=$serviceSidRoot\" `
        '-p:DebugType=None' '-p:DebugSymbols=false' '-p:NuGetAudit=false' |
        Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "SENSOR_BUNDLE_SERVICE_SID_PUBLISH_FAILED_$LASTEXITCODE"
    }

    $auditWitnessInstallerProject = Join-Path $projectRoot `
        'apps\windows-sensor\audit-witness-installer\WARRoom.WindowsSensor.AuditWitnessInstaller.csproj'
    & $dotnet publish $auditWitnessInstallerProject --nologo -c Release `
        -r $runtimeIdentifier --self-contained true `
        "-p:WarRoomBuildRoot=$buildRoot" `
        "-p:PublishDir=$auditWitnessInstallerRoot\" `
        '-p:DebugType=None' '-p:DebugSymbols=false' '-p:NuGetAudit=false' |
        Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "SENSOR_BUNDLE_AUDIT_WITNESS_INSTALLER_PUBLISH_FAILED_$LASTEXITCODE"
    }

    $auditWitnessCheckerProject = Join-Path $projectRoot `
        'apps\windows-sensor\audit-witness-checker\WARRoom.WindowsSensor.AuditWitnessChecker.csproj'
    & $dotnet publish $auditWitnessCheckerProject --nologo -c Release `
        -r $runtimeIdentifier --self-contained true `
        "-p:WarRoomBuildRoot=$buildRoot" `
        "-p:PublishDir=$auditWitnessCheckerRoot\" `
        '-p:DebugType=None' '-p:DebugSymbols=false' '-p:NuGetAudit=false' |
        Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "SENSOR_BUNDLE_AUDIT_WITNESS_CHECKER_PUBLISH_FAILED_$LASTEXITCODE"
    }

    Assert-PublishTree -Path $sensorRoot -Executable 'WARRoom.WindowsSensor.exe'
    Assert-PublishTree -Path $identityRoot `
        -Executable 'WARRoom.WindowsSensor.Provisioner.exe'
    Assert-PublishTree -Path $serviceSidRoot `
        -Executable 'WARRoom.WindowsSensor.ServiceSidTool.exe'
    Assert-PublishTree -Path $auditWitnessInstallerRoot `
        -Executable 'WARRoom.WindowsSensor.AuditWitnessInstaller.exe'
    Assert-PublishTree -Path $auditWitnessCheckerRoot `
        -Executable 'WARRoom.WindowsSensor.AuditWitnessChecker.exe'

    $files = @(
        Get-ChildItem -LiteralPath $outputRoot -File -Recurse -Force |
            Sort-Object FullName |
            ForEach-Object {
                $relative = $_.FullName.Substring($outputRoot.Length + 1).
                    Replace('\', '/')
                if ($relative -notmatch '^(sensor|identity-status|service-sid|audit-witness-installer|audit-witness-checker)/[A-Za-z0-9_.-]+$') {
                    throw 'SENSOR_BUNDLE_RELATIVE_PATH_INVALID'
                }
                [ordered]@{
                    path = $relative
                    bytes = [long]$_.Length
                    sha256 = (Get-FileHash -LiteralPath $_.FullName `
                        -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            }
    )
    if ($files.Count -lt 8) {
        throw 'SENSOR_BUNDLE_FILE_COUNT_INVALID'
    }
    $manifest = [ordered]@{
        schemaVersion = 1
        commit = $commit
        runtimeIdentifier = $runtimeIdentifier
        deploymentMode = 'self-contained'
        generatedAt = [DateTime]::UtcNow.ToString('O')
        files = $files
    }
    $manifestPath = Join-Path $outputRoot 'package-manifest.json'
    [IO.File]::WriteAllText(
        $manifestPath,
        ($manifest | ConvertTo-Json -Depth 8),
        [Text.UTF8Encoding]::new($false)
    )
    $seal = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).
        Hash.ToLowerInvariant()
    Write-Json ([ordered]@{
        ok = $true
        command = 'build'
        result = [ordered]@{
            bundlePath = $outputRoot
            packageSealSha256 = $seal
            commit = $commit
            fileCount = $files.Count
            packageBytes = [long](($files | ForEach-Object {
                [long]$_['bytes']
            } | Measure-Object -Sum).Sum)
            elevated = $false
            installOrServiceMutation = $false
        }
    })
}
catch {
    if ($created -and (Test-Path -LiteralPath $outputRoot)) {
        Remove-Item -LiteralPath $outputRoot -Recurse -Force
    }
    throw
}
