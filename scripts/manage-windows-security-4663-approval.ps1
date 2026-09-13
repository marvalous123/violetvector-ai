[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateSet(
        'plan',
        'write',
        'check',
        'absent-check',
        'consume-exercise',
        'cleanup',
        'exercise',
        'service-consume-exercise',
        'startup-mode-cleanup'
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
    'apps\windows-sensor\security-4663-approval-tool\' +
    'WARRoom.WindowsSensor.Security4663ApprovalTool.csproj'
)
$readinessProject = Join-Path $root (
    'apps\windows-sensor\readiness\' +
    'WARRoom.WindowsSensor.Readiness.csproj'
)

function Build-NativeTool {
    param([string]$Project)
    & $dotnet build $Project --nologo -c Release `
        "-p:WarRoomBuildRoot=$buildRoot" '-p:NuGetAudit=false' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'SENSOR_C2E_SECURITY_4663_APPROVAL_TOOL_BUILD_FAILED'
    }
}

function Invoke-NativeJson {
    param([string]$Assembly, [string]$NativeCommand)
    $output = @(& $dotnet $Assembly $NativeCommand 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        $joined = $output -join "`n"
        $last = @($output | ForEach-Object {
            ([string]$_).Trim()
        } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Last 1)
        $publicError = 'SENSOR_C2E_SECURITY_4663_APPROVAL_NATIVE_FAILED'
        try {
            $errorJson = $joined | ConvertFrom-Json
            if ([string]$errorJson.error -match '^SENSOR_[A-Z0-9_]+$') {
                $publicError = [string]$errorJson.error
            }
        }
        catch {
            if ($last.Count -eq 1) {
                if ($last[0] -match '^SENSOR_[A-Z0-9_]+$') {
                    $publicError = $last[0]
                }
            }
        }
        throw $publicError
    }
    try {
        return (($output -join "`n") | ConvertFrom-Json)
    }
    catch {
        throw 'SENSOR_C2E_SECURITY_4663_APPROVAL_OUTPUT_INVALID'
    }
}

function Get-ServiceConsumeContext {
    $principal = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'SENSOR_ADMINISTRATOR_REQUIRED'
    }

    $git = (Get-Command git -ErrorAction Stop).Source
    $sourceCommit = (& $git -C $root rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $sourceCommit -notmatch '^[a-f0-9]{40}$') {
        throw 'SENSOR_C2E_SECURITY_4663_SOURCE_COMMIT_INVALID'
    }
    $sourceState = @(& $git -C $root status --porcelain=v1 `
        --untracked-files=all)
    if ($LASTEXITCODE -ne 0 -or $sourceState.Count -ne 0) {
        throw 'SENSOR_C2E_SECURITY_4663_SOURCE_NOT_CLEAN'
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
            throw 'SENSOR_NATIVE_PROGRAM_FILES_UNAVAILABLE'
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
    if ([string]::IsNullOrWhiteSpace($programFiles)) {
        throw 'SENSOR_NATIVE_PROGRAM_FILES_INVALID'
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
        throw 'SENSOR_C2E_SECURITY_4663_INSTALL_MISSING'
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
        throw 'SENSOR_C2E_SECURITY_4663_INSTALLED_COMMIT_MISMATCH'
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
        throw 'SENSOR_C2E_SECURITY_4663_SERVICE_CONTEXT_INVALID'
    }
    $serviceRegistry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64
    )
    try {
        $parameters = $serviceRegistry.OpenSubKey(
            'SYSTEM\CurrentControlSet\Services\WARRoomWindowsSensor\Parameters',
            $false
        )
        $parametersKeyExisted = $null -ne $parameters
        if ($null -ne $parameters) {
            try {
                if ($null -ne $parameters.GetValue(
                    'StartupMode',
                    $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                )) {
                    throw 'SENSOR_C2E_SECURITY_4663_STARTUP_MODE_PRESENT'
                }
            }
            finally {
                $parameters.Dispose()
            }
        }
    }
    finally {
        $serviceRegistry.Dispose()
    }
    [pscustomobject]@{
        sourceCommit = $sourceCommit
        executable = $executable
        expectedPath = $expectedPath
        parametersKeyExisted = $parametersKeyExisted
    }
}

function Set-ServiceConsumeStartupMode {
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
            throw 'SENSOR_C2E_SECURITY_4663_SERVICE_REGISTRY_MISSING'
        }
        try {
            $parameters = $serviceKey.OpenSubKey('Parameters', $true)
            if ($null -eq $parameters) {
                $parameters = $serviceKey.CreateSubKey(
                    'Parameters',
                    [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
                )
            }
            if ($null -eq $parameters) {
                throw 'SENSOR_C2E_SECURITY_4663_STARTUP_MODE_APPLY_FAILED'
            }
            try {
                if ($null -ne $parameters.GetValue('StartupMode', $null)) {
                    throw 'SENSOR_C2E_SECURITY_4663_STARTUP_MODE_PRESENT'
                }
                $parameters.SetValue(
                    'StartupMode',
                    '--security-4663-one-shot',
                    [Microsoft.Win32.RegistryValueKind]::String
                )
                if (
                    $parameters.GetValueKind('StartupMode') -ne
                        [Microsoft.Win32.RegistryValueKind]::String -or
                    [string]$parameters.GetValue('StartupMode', $null) -ne
                        '--security-4663-one-shot'
                ) {
                    throw 'SENSOR_C2E_SECURITY_4663_STARTUP_MODE_APPLY_FAILED'
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

function Remove-ServiceConsumeStartupMode {
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
            throw 'SENSOR_C2E_SECURITY_4663_SERVICE_REGISTRY_MISSING'
        }
        try {
            $parameters = $serviceKey.OpenSubKey('Parameters', $true)
            if ($null -eq $parameters) {
                throw 'SENSOR_C2E_SECURITY_4663_STARTUP_MODE_ROLLBACK_FAILED'
            }
            $deleteParameters = $false
            try {
                $value = $parameters.GetValue(
                    'StartupMode',
                    $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                )
                if (
                    $value -isnot [string] -or
                    [string]$value -ne '--security-4663-one-shot' -or
                    $parameters.GetValueKind('StartupMode') -ne
                        [Microsoft.Win32.RegistryValueKind]::String
                ) {
                    throw 'SENSOR_C2E_SECURITY_4663_STARTUP_MODE_ROLLBACK_FAILED'
                }
                $parameters.DeleteValue('StartupMode', $true)
                if ($null -ne $parameters.GetValue('StartupMode', $null)) {
                    throw 'SENSOR_C2E_SECURITY_4663_STARTUP_MODE_ROLLBACK_FAILED'
                }
                if (-not [bool]$Context.parametersKeyExisted) {
                    if (
                        $parameters.ValueCount -ne 0 -or
                        $parameters.SubKeyCount -ne 0
                    ) {
                        throw 'SENSOR_C2E_SECURITY_4663_STARTUP_MODE_ROOT_CHANGED'
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

function Remove-ServiceConsumeStartupModeForRecovery {
    $principal = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'SENSOR_ADMINISTRATOR_REQUIRED'
    }
    $machine = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64
    )
    try {
        $parameters = $machine.OpenSubKey(
            'SYSTEM\CurrentControlSet\Services\WARRoomWindowsSensor\Parameters',
            $true
        )
        if ($null -eq $parameters) {
            return $false
        }
        try {
            $value = $parameters.GetValue(
                'StartupMode',
                $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            )
            if ($null -eq $value) {
                return $false
            }
            if (
                $value -isnot [string] -or
                [string]$value -ne '--security-4663-one-shot' -or
                $parameters.GetValueKind('StartupMode') -ne
                    [Microsoft.Win32.RegistryValueKind]::String
            ) {
                throw 'SENSOR_C2E_SECURITY_4663_STARTUP_MODE_RECOVERY_REFUSED'
            }
            $parameters.DeleteValue('StartupMode', $true)
            if ($null -ne $parameters.GetValue('StartupMode', $null)) {
                throw 'SENSOR_C2E_SECURITY_4663_STARTUP_MODE_RECOVERY_FAILED'
            }
            return $true
        }
        finally {
            $parameters.Dispose()
        }
    }
    finally {
        $machine.Dispose()
    }
}

Build-NativeTool -Project $approvalProject
$approvalAssembly = Join-Path $buildRoot (
    'bin\WARRoom.WindowsSensor.Security4663ApprovalTool\Release\' +
    'net8.0-windows\WARRoom.WindowsSensor.Security4663ApprovalTool.dll'
)
if (-not (Test-Path -LiteralPath $approvalAssembly -PathType Leaf)) {
    throw 'SENSOR_C2E_SECURITY_4663_APPROVAL_TOOL_MISSING'
}

if ($Command -eq 'startup-mode-cleanup') {
    if ($WhatIfPreference) {
        Invoke-NativeJson -Assembly $approvalAssembly `
            -NativeCommand 'consume-proof-plan' | ConvertTo-Json -Depth 6
        return
    }
    if (-not $PSCmdlet.ShouldProcess(
        'WARRoomWindowsSensor exact StartupMode registry value',
        'Remove only the exact interrupted Gate C2e startup marker')) {
        return
    }
    $removed = Remove-ServiceConsumeStartupModeForRecovery
    [ordered]@{
        ok = $true
        command = 'startup-mode-cleanup'
        result = [ordered]@{
            exactMarkerRemoved = $removed
            serviceImagePathChanged = $false
            serviceStartModeChanged = $false
            machineIdentityChanged = $false
        }
    } | ConvertTo-Json -Depth 4
    return
}

if ($Command -eq 'plan') {
    Invoke-NativeJson -Assembly $approvalAssembly -NativeCommand 'plan' |
        ConvertTo-Json -Depth 6
    return
}

if ($Command -in @('write', 'consume-exercise', 'cleanup')) {
    $action = switch ($Command) {
        'write' { 'Create one protected five-minute signed approval' }
        'consume-exercise' { 'Atomically consume the exact protected approval' }
        'cleanup' { 'Remove only the exact protected approval for recovery' }
    }
    if ($WhatIfPreference) {
        Invoke-NativeJson -Assembly $approvalAssembly -NativeCommand 'plan' |
            ConvertTo-Json -Depth 6
        return
    }
    if (-not $PSCmdlet.ShouldProcess(
        'Gate C2e fixed Security 4663 approval path',
        $action)) {
        return
    }
    Invoke-NativeJson -Assembly $approvalAssembly `
        -NativeCommand $Command | ConvertTo-Json -Depth 6
    return
}

if ($Command -in @('check', 'absent-check')) {
    Invoke-NativeJson -Assembly $approvalAssembly -NativeCommand $Command |
        ConvertTo-Json -Depth 6
    return
}

if ($WhatIfPreference) {
    $planCommand = if ($Command -eq 'service-consume-exercise') {
        'consume-proof-plan'
    }
    else { 'plan' }
    Invoke-NativeJson -Assembly $approvalAssembly -NativeCommand $planCommand |
        ConvertTo-Json -Depth 6
    return
}
$action = if ($Command -eq 'service-consume-exercise') {
    'Run one exact LocalService approval-consume proof and always roll back'
}
else {
    'Run the no-event operator approval exercise and always roll back'
}
if (-not $PSCmdlet.ShouldProcess(
    'Gate C2d reversible readiness state and fixed Gate C2e approval path',
    $action)) {
    return
}

$serviceContext = if ($Command -eq 'service-consume-exercise') {
    Get-ServiceConsumeContext
}
else { $null }

Build-NativeTool -Project $readinessProject
$readinessAssembly = Join-Path $buildRoot (
    'bin\WARRoom.WindowsSensor.Readiness\Release\net8.0-windows\' +
    'WARRoom.WindowsSensor.Readiness.dll'
)
if (-not (Test-Path -LiteralPath $readinessAssembly -PathType Leaf)) {
    throw 'SENSOR_C2E_SECURITY_4663_READINESS_TOOL_MISSING'
}

$applied = $false
$written = $false
$checked = $false
$consumed = $false
$serviceStarted = $false
$serviceStopped = $false
$servicePathUnchanged = $false
$startupModeApplied = $false
$startupModeRestored = $false
$externalAbsenceChecked = $false
$localServiceAuthorityProven = $false
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
    if ($Command -eq 'service-consume-exercise') {
        Set-ServiceConsumeStartupMode -Context $serviceContext
        $startupModeApplied = $true
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
                throw 'SENSOR_C2E_SECURITY_4663_SERVICE_DID_NOT_STOP'
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
            [string]$service.PathName -ne $serviceContext.expectedPath -or
            [uint32]$service.ExitCode -ne 0 -or
            [uint32]$service.ServiceSpecificExitCode -ne 0
        ) {
            throw 'SENSOR_C2E_SECURITY_4663_SERVICE_RESULT_INVALID'
        }
        $servicePathUnchanged = $true
        Remove-ServiceConsumeStartupMode -Context $serviceContext
        $startupModeRestored = $true
        [void](Invoke-NativeJson -Assembly $approvalAssembly `
            -NativeCommand 'absent-check')
        $externalAbsenceChecked = $true
        $consumed = $true
        $localServiceAuthorityProven = $true
    }
    else {
        [void](Invoke-NativeJson -Assembly $approvalAssembly `
            -NativeCommand 'consume-exercise')
        $consumed = $true
    }
}
catch {
    $failure = $_.Exception.Message
}
finally {
    if ($applied) {
        if ($serviceStarted -and -not $serviceStopped) {
            try {
                $controller = [System.ServiceProcess.ServiceController]::new(
                    'WARRoomWindowsSensor'
                )
                try {
                    $controller.Refresh()
                    if ($controller.Status -ne
                        [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
                        $controller.Stop()
                        $controller.WaitForStatus(
                            [System.ServiceProcess.ServiceControllerStatus]::Stopped,
                            [TimeSpan]::FromSeconds(10)
                        )
                    }
                    $serviceStopped = $true
                }
                finally {
                    $controller.Dispose()
                }
            }
            catch {
                $failure =
                    'SENSOR_C2E_SECURITY_4663_SERVICE_RECOVERY_FAILED'
            }
        }
        if ($startupModeApplied -and -not $startupModeRestored) {
            try {
                Remove-ServiceConsumeStartupMode -Context $serviceContext
                $startupModeRestored = $true
            }
            catch {
                $failure =
                    'SENSOR_C2E_SECURITY_4663_STARTUP_MODE_RECOVERY_FAILED'
            }
        }
        try {
            [void](Invoke-NativeJson -Assembly $approvalAssembly `
                -NativeCommand 'cleanup')
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
            $failure = 'SENSOR_C2E_SECURITY_4663_APPROVAL_ROLLBACK_FAILED'
        }
    }
}

if ($null -ne $failure) {
    if ($failure -notmatch '^SENSOR_[A-Z0-9_]+$') {
        $failure = 'SENSOR_C2E_SECURITY_4663_APPROVAL_EXERCISE_FAILED'
    }
    throw $failure
}

[ordered]@{
    ok = $true
    command = $Command
    result = [ordered]@{
        checkpoint = 'gate-c2e-security-4663-one-shot'
        applied = $applied
        approvalWritten = $written
        externallyChecked = $checked
        externalAbsenceChecked = $externalAbsenceChecked
        operatorAtomicConsumeCompleted = (
            $consumed -and $Command -eq 'exercise'
        )
        localServiceAtomicConsumeCompleted = (
            $consumed -and $Command -eq 'service-consume-exercise'
        )
        localServiceAuthorityProven = $localServiceAuthorityProven
        eventContentRead = $false
        eventsRead = 0
        serviceStarted = $serviceStarted
        serviceStopped = $serviceStopped
        serviceConfigurationMutated = $startupModeApplied
        serviceConfigurationRestored = $startupModeRestored
        servicePathUnchanged = $servicePathUnchanged
        rollbackCompleted = $rolledBack
        retryEnabled = $false
        pollingEnabled = $false
        transportEnabled = $false
        inboundListenerEnabled = $false
        commandChannelEnabled = $false
        responseActionEnabled = $false
    }
} | ConvertTo-Json -Depth 5
