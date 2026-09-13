[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet(
        'plan',
        'status',
        'runtime-check',
        'package-check',
        'install',
        'source-readiness-check',
        'local-batch-check',
        'genuine-batch-check',
        'bounded-collector-check',
        'restart-check',
        'uninstall',
        'orphaned-install-cleanup',
        'orphaned-state-cleanup'
    )]
    [string]$Command = 'plan',
    [string]$PackageRoot,
    [string]$PackageSealSha256,
    [switch]$NativeHostConfirmFalse
)

$ErrorActionPreference = 'Stop'
$requiresNativeHost = (
    [Environment]::Is64BitOperatingSystem -and
    -not [Environment]::Is64BitProcess -and
    $Command -ne 'runtime-check'
)
if ($NativeHostConfirmFalse -and -not $requiresNativeHost) {
    if (
        -not [Environment]::Is64BitOperatingSystem -or
        -not [Environment]::Is64BitProcess
    ) {
        throw 'SENSOR_NATIVE_CONFIRMATION_RELAY_INVALID'
    }
    $ConfirmPreference = 'None'
}
if ($requiresNativeHost) {
    $nativePowerShell = Join-Path $env:SystemRoot `
        'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $nativePowerShell -PathType Leaf)) {
        throw 'SENSOR_NATIVE_POWERSHELL_HOST_UNAVAILABLE'
    }
    $nativeArguments = @(
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        $PSCommandPath,
        '-Command',
        $Command
    )
    if ($PSBoundParameters.ContainsKey('PackageRoot')) {
        $nativeArguments += @('-PackageRoot', $PackageRoot)
    }
    if ($PSBoundParameters.ContainsKey('PackageSealSha256')) {
        $nativeArguments += @('-PackageSealSha256', $PackageSealSha256)
    }
    if (
        $PSBoundParameters.ContainsKey('WhatIf') -and
        [bool]$PSBoundParameters['WhatIf']
    ) {
        $nativeArguments += '-WhatIf'
    }
    if (
        $NativeHostConfirmFalse -or
        (
            $PSBoundParameters.ContainsKey('Confirm') -and
            -not [bool]$PSBoundParameters['Confirm']
        )
    ) {
        $nativeArguments += '-NativeHostConfirmFalse'
    }
    & $nativePowerShell @nativeArguments
    if ($LASTEXITCODE -ne 0) {
        throw "SENSOR_NATIVE_POWERSHELL_HOST_FAILED_$LASTEXITCODE"
    }
    return
}
$projectRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$serviceName = 'WARRoomWindowsSensor'
$displayName = 'WAR-R00M Windows Sensor'
$expectedIdentity = 'NT AUTHORITY\LocalService'
$runtimeIdentifier = 'win-x64'
$runtimeProfile = 'self-contained-win-x64'
$deploymentMode = 'self-contained'
$legacyGateACommit = 'b1632a05b48e890fa3133cc3265c5f46394feb33'
$nativeRegistry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::LocalMachine,
    [Microsoft.Win32.RegistryView]::Registry64
)
try {
    $currentVersionRegistry = $nativeRegistry.OpenSubKey(
        'SOFTWARE\Microsoft\Windows\CurrentVersion',
        $false
    )
    if ($null -eq $currentVersionRegistry) {
        throw 'SENSOR_NATIVE_PROGRAM_FILES_UNAVAILABLE'
    }
    try {
        $nativeProgramFiles = [string]$currentVersionRegistry.GetValue(
            'ProgramFilesDir',
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
    }
    finally {
        $currentVersionRegistry.Dispose()
    }
}
finally {
    $nativeRegistry.Dispose()
}
if (
    [string]::IsNullOrWhiteSpace($nativeProgramFiles) -or
    $nativeProgramFiles -notmatch '^[A-Za-z]:\\'
) {
    throw 'SENSOR_NATIVE_PROGRAM_FILES_INVALID'
}
$nativeProgramFiles = [IO.Path]::GetFullPath($nativeProgramFiles)
$installRoot = [IO.Path]::GetFullPath(
    (Join-Path $nativeProgramFiles 'WAR-R00M\Windows Sensor')
)
$serviceExecutable = Join-Path $installRoot 'WARRoom.WindowsSensor.exe'
$nativeProgramData = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::CommonApplicationData
)
if (
    [string]::IsNullOrWhiteSpace($nativeProgramData) -or
    $nativeProgramData -notmatch '^[A-Za-z]:\\'
) {
    throw 'SENSOR_NATIVE_PROGRAM_DATA_INVALID'
}
$nativeProgramData = [IO.Path]::GetFullPath($nativeProgramData)
$stateRoot = [IO.Path]::GetFullPath(
    (Join-Path $nativeProgramData 'WAR-R00M\Windows Sensor')
)
$stagingParent = [IO.Path]::GetFullPath(
    (Join-Path $nativeProgramData 'WAR-R00M Windows Sensor Staging')
)
$localProofPath = Join-Path $stateRoot 'local-synthetic-batch-proof.json'
$genuineProofPath = Join-Path $stateRoot 'local-genuine-batch-proof.json'
$genuineSaltPath = Join-Path $stateRoot 'local-genuine-source-salt.bin'
$boundedProofPath = Join-Path $stateRoot 'local-bounded-collector-proof.json'
$endpointBindingPath = Join-Path $stateRoot 'endpoint-binding.json'
$capabilityProofPath = Join-Path $stateRoot 'local-capability-proof.json'
$loopbackDeliveryPath = Join-Path $stateRoot 'local-loopback-delivery.json'
$allowedLocalStateFiles = @(
    'local-synthetic-batch-proof.json',
    'local-genuine-batch-proof.json',
    'local-genuine-source-salt.bin',
    'local-bounded-collector-proof.json',
    'endpoint-binding.json',
    'local-capability-proof.json',
    'local-loopback-delivery.json'
)
$buildRoot = [IO.Path]::GetFullPath(
    (Join-Path $HOME '.codex-build\project15\windows-sensor')
)
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

function Get-ServiceRecord {
    return Get-CimInstance -ClassName Win32_Service `
        -Filter "Name='$serviceName'" `
        -ErrorAction SilentlyContinue
}

function Get-ServiceStatus {
    $service = Get-ServiceRecord
    if ($null -eq $service) {
        return [ordered]@{
            exists = $false
            name = $serviceName
            displayName = $displayName
            installRootExists = (Test-Path -LiteralPath $installRoot)
        }
    }

    $manifestExists = $null
    $manifestAccessible = $true
    try {
        $manifestExists = Test-Path -LiteralPath (
            Join-Path $installRoot 'install-manifest.json'
        ) -PathType Leaf -ErrorAction Stop
    }
    catch {
        if (
            $_.Exception -isnot [UnauthorizedAccessException] -and
            $_.FullyQualifiedErrorId -notlike
                'ItemExistsUnauthorizedAccessError*'
        ) {
            throw
        }
        $manifestAccessible = $false
    }

    return [ordered]@{
        exists = $true
        name = $service.Name
        displayName = $service.DisplayName
        state = $service.State
        startMode = $service.StartMode
        startIdentity = $service.StartName
        pathName = $service.PathName
        installRootExists = (Test-Path -LiteralPath $installRoot -PathType Container)
        manifestExists = $manifestExists
        manifestAccessible = $manifestAccessible
    }
}

function Get-ServiceCreateArguments {
    return @{
        Name = [string]$serviceName
        DisplayName = [string]$displayName
        PathName = [string](Get-NormalServicePathName)
        ServiceType = [byte]16
        ErrorControl = [byte]1
        StartMode = [string]'Manual'
        DesktopInteract = [bool]$false
        StartName = [string]$expectedIdentity
        StartPassword = [string]::Empty
    }
}

function Get-NormalServicePathName {
    return "`"$serviceExecutable`""
}

function Assert-ServiceCreateArgumentTypes {
    param([hashtable]$Arguments)
    if (
        $Arguments.ServiceType -isnot [byte] -or
        $Arguments.ErrorControl -isnot [byte] -or
        $Arguments.DesktopInteract -isnot [bool] -or
        $Arguments.Name -isnot [string] -or
        $Arguments.DisplayName -isnot [string] -or
        $Arguments.PathName -isnot [string] -or
        $Arguments.StartMode -isnot [string] -or
        $Arguments.StartName -isnot [string] -or
        $Arguments.StartPassword -isnot [string]
    ) {
        throw 'SENSOR_SERVICE_CREATE_ARGUMENT_TYPE_INVALID'
    }
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) {
        throw 'SENSOR_ADMINISTRATOR_REQUIRED'
    }
}

function Get-SupportedRuntimeStatus {
    $is64BitOperatingSystem = [Environment]::Is64BitOperatingSystem
    $is64BitProcess = [Environment]::Is64BitProcess
    $processorArchitectures = @(
        Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop |
            ForEach-Object { [int]$_.Architecture } |
            Sort-Object -Unique
    )
    $isX64OperatingSystem = (
        $processorArchitectures.Count -gt 0 -and
        @($processorArchitectures | Where-Object { $_ -ne 9 }).Count -eq 0
    )
    $processArchitecture = if ($is64BitProcess) {
        'X64'
    }
    else {
        'X86'
    }
    $operatingSystemArchitecture = if (
        $is64BitOperatingSystem -and
        $isX64OperatingSystem
    ) {
        'X64'
    }
    else {
        'Unsupported'
    }
    $supported = (
        $is64BitOperatingSystem -and
        $operatingSystemArchitecture -eq 'X64'
    )
    return [ordered]@{
        is64BitOperatingSystem = $is64BitOperatingSystem
        is64BitProcess = $is64BitProcess
        processArchitecture = $processArchitecture
        operatingSystemArchitecture = $operatingSystemArchitecture
        hostProcessArchitectureRequired = $false
        supported = $supported
    }
}

function Assert-SupportedRuntime {
    $status = Get-SupportedRuntimeStatus
    if (-not $status.supported) {
        throw 'SENSOR_RUNTIME_WIN_X64_REQUIRED'
    }
    return $status
}

function Assert-CleanSource {
    $status = (& git.exe -C $projectRoot status --porcelain) -join "`n"
    if ($LASTEXITCODE -ne 0 -or -not [string]::IsNullOrWhiteSpace($status)) {
        throw 'SENSOR_INSTALL_SOURCE_NOT_CLEAN'
    }

    $commit = (& git.exe -C $projectRoot rev-parse HEAD) -join ''
    if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
        throw 'SENSOR_INSTALL_SOURCE_COMMIT_INVALID'
    }
    return $commit
}

function Assert-IdentityStatus {
    $project = Join-Path $projectRoot `
        'apps\windows-sensor\provisioner\WARRoom.WindowsSensor.Provisioner.csproj'
    $lines = & $dotnet run --project $project -c Release `
        "-p:WarRoomBuildRoot=$buildRoot" `
        '-p:NuGetAudit=false' -- status
    if ($LASTEXITCODE -ne 0) {
        throw 'SENSOR_NATIVE_KEY_STATUS_INVALID'
    }

    try {
        $result = (($lines -join "`n") | ConvertFrom-Json)
    }
    catch {
        throw 'SENSOR_NATIVE_KEY_STATUS_INVALID'
    }
    if (
        -not $result.ok -or
        -not $result.status.exists -or
        -not $result.status.policyValid -or
        -not $result.status.aclVerified -or
        $result.status.provider -ne 'Microsoft Software Key Storage Provider' -or
        $result.status.profile -ne 'software-ksp-machine-v1' -or
        $result.status.publicKeyFingerprintSha256 -notmatch '^[0-9a-f]{64}$'
    ) {
        throw 'SENSOR_NATIVE_KEY_STATUS_INVALID'
    }
    return $result.status
}

function Invoke-LocalSyntheticBatchCheck {
    $project = Join-Path $projectRoot `
        'apps\windows-sensor\local-proof\WARRoom.WindowsSensor.LocalProof.csproj'
    $lines = & $dotnet run --project $project -c Release `
        "-p:WarRoomBuildRoot=$buildRoot" `
        '-p:NuGetAudit=false'
    if ($LASTEXITCODE -ne 0) {
        throw 'SENSOR_LOCAL_PROOF_CHECK_FAILED'
    }
    try {
        $result = (($lines -join "`n") | ConvertFrom-Json)
    }
    catch {
        throw 'SENSOR_LOCAL_PROOF_CHECK_INVALID'
    }
    if (
        -not $result.ok -or
        $result.command -ne 'local-synthetic-batch-check' -or
        $result.result.proofMode -ne 'local-synthetic-gate-b0' -or
        $result.result.certificateFingerprintSha256 -notmatch
            '^[0-9a-f]{64}$' -or
        $result.result.firstBatchHash -notmatch '^[0-9a-f]{64}$' -or
        $result.result.lastBatchHash -notmatch '^[0-9a-f]{64}$' -or
        $result.result.batchCount -ne 2 -or
        -not $result.result.syntheticOnly -or
        $result.result.eventReaderEnabled -or
        $result.result.networkTransportEnabled -or
        $result.result.inboundListenerEnabled -or
        $result.result.commandChannelEnabled -or
        $result.result.eventsRead -ne 0
    ) {
        throw 'SENSOR_LOCAL_PROOF_CHECK_INVALID'
    }
    return $result.result
}

function Invoke-LocalGenuineBatchCheck {
    $project = Join-Path $projectRoot `
        'apps\windows-sensor\genuine-proof\WARRoom.WindowsSensor.GenuineProof.csproj'
    $lines = & $dotnet run --project $project -c Release `
        "-p:WarRoomBuildRoot=$buildRoot" `
        '-p:NuGetAudit=false'
    if ($LASTEXITCODE -ne 0) {
        throw 'SENSOR_GENUINE_PROOF_CHECK_FAILED'
    }
    try {
        $result = (($lines -join "`n") | ConvertFrom-Json)
    }
    catch {
        throw 'SENSOR_GENUINE_PROOF_CHECK_INVALID'
    }
    if (
        -not $result.ok -or
        $result.command -ne 'local-genuine-batch-check' -or
        $result.result.proofMode -ne 'local-genuine-gate-b1' -or
        $result.result.status -notin @('verified', 'no-match') -or
        $result.result.certificateFingerprintSha256 -notmatch
            '^[0-9a-f]{64}$' -or
        $result.result.batchCount -notin @(0, 1) -or
        $result.result.factCount -notin @(0, 1) -or
        $result.result.eventsRead -notin @(0, 1) -or
        $result.result.rawEventContentRead -or
        -not $result.result.runtimeProofEventReaderEnabled -or
        $result.result.checkerEventReaderEnabled -or
        $result.result.networkTransportEnabled -or
        $result.result.inboundListenerEnabled -or
        $result.result.pollingEnabled -or
        $result.result.commandChannelEnabled -or
        (
            $result.result.machineProofComplete -and
            (
                $result.result.status -ne 'verified' -or
                -not $result.result.genuineEventRead -or
                $result.result.batchCount -ne 1 -or
                $result.result.factCount -ne 1 -or
                $result.result.eventsRead -ne 1 -or
                $result.result.batchHash -notmatch '^[0-9a-f]{64}$' -or
                $result.result.sourceRecordIdHash -notmatch '^[0-9a-f]{64}$'
            )
        ) -or
        (
            -not $result.result.machineProofComplete -and
            (
                $result.result.status -ne 'no-match' -or
                $result.result.genuineEventRead -or
                $result.result.batchCount -ne 0 -or
                $result.result.factCount -ne 0 -or
                $result.result.eventsRead -ne 0
            )
        )
    ) {
        throw 'SENSOR_GENUINE_PROOF_CHECK_INVALID'
    }
    return $result.result
}

function Invoke-LocalBoundedCollectorCheck {
    $project = Join-Path $projectRoot `
        'apps\windows-sensor\bounded-proof\WARRoom.WindowsSensor.BoundedProof.csproj'
    $lines = & $dotnet run --project $project -c Release `
        "-p:WarRoomBuildRoot=$buildRoot" `
        '-p:NuGetAudit=false'
    if ($LASTEXITCODE -ne 0) {
        throw 'SENSOR_C1_PROOF_CHECK_FAILED'
    }
    try {
        $result = (($lines -join "`n") | ConvertFrom-Json)
    }
    catch {
        throw 'SENSOR_C1_PROOF_CHECK_INVALID'
    }
    if (
        -not $result.ok -or
        $result.command -ne 'bounded-collector-check' -or
        $result.result.proofMode -ne 'local-bounded-gate-c1' -or
        $result.result.status -notin @('verified', 'pending') -or
        $result.result.certificateFingerprintSha256 -notmatch
            '^[0-9a-f]{64}$' -or
        $result.result.familiesQueried -notin @(0, 2) -or
        $result.result.eventsRead -notin @(0, 1, 2) -or
        $result.result.matchCount -notin @(0, 1, 2) -or
        $result.result.noMatchCount -notin @(0, 1, 2) -or
        $result.result.failureCount -notin @(0, 1, 2) -or
        $result.result.rawEventContentRead -or
        -not $result.result.runtimeProofEventReaderEnabled -or
        $result.result.checkerEventReaderEnabled -or
        $result.result.networkTransportEnabled -or
        $result.result.automaticRetryEnabled -or
        $result.result.pollingEnabled -or
        $result.result.inboundListenerEnabled -or
        $result.result.commandChannelEnabled -or
        $result.result.responseActionsEnabled -or
        $result.result.serviceMutated -or
        (
            $result.result.machineProofComplete -and
            (
                $result.result.status -ne 'verified' -or
                $result.result.familiesQueried -ne 2 -or
                ($result.result.matchCount +
                    $result.result.noMatchCount +
                    $result.result.failureCount) -ne 2 -or
                $result.result.eventsRead -ne $result.result.matchCount -or
                $result.result.proofHash -notmatch '^[0-9a-f]{64}$'
            )
        ) -or
        (
            -not $result.result.machineProofComplete -and
            (
                $result.result.status -ne 'pending' -or
                $result.result.familiesQueried -ne 0 -or
                $result.result.eventsRead -ne 0 -or
                $result.result.matchCount -ne 0 -or
                $result.result.noMatchCount -ne 0 -or
                $result.result.failureCount -ne 0
            )
        )
    ) {
        throw 'SENSOR_C1_PROOF_CHECK_INVALID'
    }
    return $result.result
}

function Set-ProtectedInstallAcl {
    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administratorsSid = [Security.Principal.SecurityIdentifier]::new(
        'S-1-5-32-544'
    )
    $localServiceSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-19')
    $inheritance = [Security.AccessControl.InheritanceFlags](
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    )
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administratorsSid)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $systemSid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        $propagation,
        $allow
    ))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $administratorsSid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        $propagation,
        $allow
    ))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $localServiceSid,
        [Security.AccessControl.FileSystemRights]::ReadAndExecute,
        $inheritance,
        $propagation,
        $allow
    ))
    Set-Acl -LiteralPath $installRoot -AclObject $acl
}

function Set-ProtectedFileAcl {
    param([string]$Path)
    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administratorsSid = [Security.Principal.SecurityIdentifier]::new(
        'S-1-5-32-544'
    )
    $localServiceSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-19')
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administratorsSid)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $systemSid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $allow
    ))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $administratorsSid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $allow
    ))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $localServiceSid,
        [Security.AccessControl.FileSystemRights]::ReadAndExecute,
        $allow
    ))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-ProtectedStateAcl {
    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administratorsSid = [Security.Principal.SecurityIdentifier]::new(
        'S-1-5-32-544'
    )
    $localServiceSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-19')
    $inheritance = [Security.AccessControl.InheritanceFlags](
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    )
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administratorsSid)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $systemSid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        $propagation,
        $allow
    ))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $administratorsSid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        $propagation,
        $allow
    ))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $localServiceSid,
        [Security.AccessControl.FileSystemRights]::ReadAndExecute,
        $inheritance,
        $propagation,
        $allow
    ))
    Set-Acl -LiteralPath $stateRoot -AclObject $acl
}

function Set-ProtectedLocalProofAcl {
    param([string]$Path = $localProofPath)
    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administratorsSid = [Security.Principal.SecurityIdentifier]::new(
        'S-1-5-32-544'
    )
    $localServiceSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-19')
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $serviceRights = (
        [Security.AccessControl.FileSystemRights]::Read -bor
        [Security.AccessControl.FileSystemRights]::WriteData
    )
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administratorsSid)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $systemSid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $allow
    ))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $administratorsSid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $allow
    ))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $localServiceSid,
        $serviceRights,
        $allow
    ))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-ProtectedGenuineSaltAcl {
    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administratorsSid = [Security.Principal.SecurityIdentifier]::new(
        'S-1-5-32-544'
    )
    $localServiceSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-19')
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administratorsSid)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $systemSid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $allow
    ))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $administratorsSid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $allow
    ))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $localServiceSid,
        [Security.AccessControl.FileSystemRights]::Read,
        $allow
    ))
    Set-Acl -LiteralPath $genuineSaltPath -AclObject $acl
}

function Set-ProtectedDescriptorAcl {
    param([string]$Path)
    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administratorsSid = [Security.Principal.SecurityIdentifier]::new(
        'S-1-5-32-544'
    )
    $localServiceSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-19')
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administratorsSid)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $systemSid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $allow
    ))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $administratorsSid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $allow
    ))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $localServiceSid,
        [Security.AccessControl.FileSystemRights]::Read,
        $allow
    ))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-ProtectedInstallAcl {
    $acl = Get-Acl -LiteralPath $installRoot
    $ownerSid = $acl.Owner
    try {
        $ownerSid = ([Security.Principal.NTAccount]$acl.Owner).Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    }
    catch {
        if ($ownerSid -notmatch '^S-\d-') {
            throw 'SENSOR_INSTALL_ACL_INVALID'
        }
    }
    if (
        $ownerSid -ne 'S-1-5-32-544' -or
        -not $acl.AreAccessRulesProtected
    ) {
        throw 'SENSOR_INSTALL_ACL_INVALID'
    }

    $rules = @($acl.GetAccessRules(
        $true,
        $false,
        [Security.Principal.SecurityIdentifier]
    ))
    if ($rules.Count -ne 3) {
        throw 'SENSOR_INSTALL_ACL_INVALID'
    }

    $bySid = @{}
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if (
            $rule.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow -or
            $rule.IsInherited -or
            $bySid.ContainsKey($sid)
        ) {
            throw 'SENSOR_INSTALL_ACL_INVALID'
        }
        $bySid[$sid] = $rule.FileSystemRights
    }

    foreach ($fullControlSid in @('S-1-5-18', 'S-1-5-32-544')) {
        if (
            -not $bySid.ContainsKey($fullControlSid) -or
            ($bySid[$fullControlSid] -band
                [Security.AccessControl.FileSystemRights]::FullControl) -ne
                [Security.AccessControl.FileSystemRights]::FullControl
        ) {
            throw 'SENSOR_INSTALL_ACL_INVALID'
        }
    }

    if (-not $bySid.ContainsKey('S-1-5-19')) {
        throw 'SENSOR_INSTALL_ACL_INVALID'
    }
    $localServiceRights = $bySid['S-1-5-19']
    $requiredRead = [Security.AccessControl.FileSystemRights]::ReadAndExecute
    $forbiddenWrite = (
        [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    )
    if (
        ($localServiceRights -band $requiredRead) -ne $requiredRead -or
        ($localServiceRights -band $forbiddenWrite) -ne 0
    ) {
        throw 'SENSOR_INSTALL_ACL_INVALID'
    }
}

function Assert-ProtectedFileAcl {
    param([string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $ownerSid = $acl.Owner
    try {
        $ownerSid = ([Security.Principal.NTAccount]$acl.Owner).Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    }
    catch {
        if ($ownerSid -notmatch '^S-\d-') {
            throw 'SENSOR_INSTALL_FILE_ACL_INVALID'
        }
    }
    if (
        $ownerSid -ne 'S-1-5-32-544' -or
        -not $acl.AreAccessRulesProtected
    ) {
        throw 'SENSOR_INSTALL_FILE_ACL_INVALID'
    }

    $rules = @($acl.GetAccessRules(
        $true,
        $false,
        [Security.Principal.SecurityIdentifier]
    ))
    if ($rules.Count -ne 3) {
        throw 'SENSOR_INSTALL_FILE_ACL_INVALID'
    }

    $bySid = @{}
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if (
            $rule.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow -or
            $rule.IsInherited -or
            $bySid.ContainsKey($sid)
        ) {
            throw 'SENSOR_INSTALL_FILE_ACL_INVALID'
        }
        $bySid[$sid] = $rule.FileSystemRights
    }

    foreach ($fullControlSid in @('S-1-5-18', 'S-1-5-32-544')) {
        if (
            -not $bySid.ContainsKey($fullControlSid) -or
            ($bySid[$fullControlSid] -band
                [Security.AccessControl.FileSystemRights]::FullControl) -ne
                [Security.AccessControl.FileSystemRights]::FullControl
        ) {
            throw 'SENSOR_INSTALL_FILE_ACL_INVALID'
        }
    }

    if (-not $bySid.ContainsKey('S-1-5-19')) {
        throw 'SENSOR_INSTALL_FILE_ACL_INVALID'
    }
    $localServiceRights = $bySid['S-1-5-19']
    $requiredRead = [Security.AccessControl.FileSystemRights]::ReadAndExecute
    $forbiddenWrite = (
        [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    )
    if (
        ($localServiceRights -band $requiredRead) -ne $requiredRead -or
        ($localServiceRights -band $forbiddenWrite) -ne 0
    ) {
        throw 'SENSOR_INSTALL_FILE_ACL_INVALID'
    }
}

function Assert-ProtectedStateAcl {
    if (-not (Test-Path -LiteralPath $stateRoot -PathType Container)) {
        throw 'SENSOR_LOCAL_STATE_ACL_INVALID'
    }
    $item = Get-Item -LiteralPath $stateRoot -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'SENSOR_LOCAL_STATE_ACL_INVALID'
    }
    $acl = Get-Acl -LiteralPath $stateRoot
    $ownerSid = $acl.Owner
    try {
        $ownerSid = ([Security.Principal.NTAccount]$acl.Owner).Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    }
    catch {
        if ($ownerSid -notmatch '^S-\d-') {
            throw 'SENSOR_LOCAL_STATE_ACL_INVALID'
        }
    }
    if (
        $ownerSid -ne 'S-1-5-32-544' -or
        -not $acl.AreAccessRulesProtected
    ) {
        throw 'SENSOR_LOCAL_STATE_ACL_INVALID'
    }
    $rules = @($acl.GetAccessRules(
        $true,
        $false,
        [Security.Principal.SecurityIdentifier]
    ))
    if ($rules.Count -ne 3) {
        throw 'SENSOR_LOCAL_STATE_ACL_INVALID'
    }
    $bySid = @{}
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if (
            $rule.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow -or
            $rule.IsInherited -or
            $bySid.ContainsKey($sid)
        ) {
            throw 'SENSOR_LOCAL_STATE_ACL_INVALID'
        }
        $bySid[$sid] = $rule.FileSystemRights
    }
    foreach ($fullControlSid in @('S-1-5-18', 'S-1-5-32-544')) {
        if (
            -not $bySid.ContainsKey($fullControlSid) -or
            ($bySid[$fullControlSid] -band
                [Security.AccessControl.FileSystemRights]::FullControl) -ne
                [Security.AccessControl.FileSystemRights]::FullControl
        ) {
            throw 'SENSOR_LOCAL_STATE_ACL_INVALID'
        }
    }
    if (-not $bySid.ContainsKey('S-1-5-19')) {
        throw 'SENSOR_LOCAL_STATE_ACL_INVALID'
    }
    $serviceRights = $bySid['S-1-5-19']
    $required = [Security.AccessControl.FileSystemRights]::ReadAndExecute
    $forbidden = (
        [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    )
    if (
        ($serviceRights -band $required) -ne $required -or
        ($serviceRights -band $forbidden) -ne 0
    ) {
        throw 'SENSOR_LOCAL_STATE_ACL_INVALID'
    }
}

function Assert-ProtectedLocalProofAcl {
    param([string]$Path = $localProofPath)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'SENSOR_LOCAL_PROOF_ACL_INVALID'
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'SENSOR_LOCAL_PROOF_ACL_INVALID'
    }
    $acl = Get-Acl -LiteralPath $Path
    $ownerSid = $acl.Owner
    try {
        $ownerSid = ([Security.Principal.NTAccount]$acl.Owner).Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    }
    catch {
        if ($ownerSid -notmatch '^S-\d-') {
            throw 'SENSOR_LOCAL_PROOF_ACL_INVALID'
        }
    }
    if (
        $ownerSid -ne 'S-1-5-32-544' -or
        -not $acl.AreAccessRulesProtected
    ) {
        throw 'SENSOR_LOCAL_PROOF_ACL_INVALID'
    }
    $rules = @($acl.GetAccessRules(
        $true,
        $false,
        [Security.Principal.SecurityIdentifier]
    ))
    if ($rules.Count -ne 3) {
        throw 'SENSOR_LOCAL_PROOF_ACL_INVALID'
    }
    $bySid = @{}
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if (
            $rule.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow -or
            $rule.IsInherited -or
            $bySid.ContainsKey($sid)
        ) {
            throw 'SENSOR_LOCAL_PROOF_ACL_INVALID'
        }
        $bySid[$sid] = $rule.FileSystemRights
    }
    foreach ($fullControlSid in @('S-1-5-18', 'S-1-5-32-544')) {
        if (
            -not $bySid.ContainsKey($fullControlSid) -or
            ($bySid[$fullControlSid] -band
                [Security.AccessControl.FileSystemRights]::FullControl) -ne
                [Security.AccessControl.FileSystemRights]::FullControl
        ) {
            throw 'SENSOR_LOCAL_PROOF_ACL_INVALID'
        }
    }
    if (-not $bySid.ContainsKey('S-1-5-19')) {
        throw 'SENSOR_LOCAL_PROOF_ACL_INVALID'
    }
    $serviceRights = $bySid['S-1-5-19']
    $required = (
        [Security.AccessControl.FileSystemRights]::Read -bor
        [Security.AccessControl.FileSystemRights]::WriteData
    )
    $forbidden = (
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    )
    if (
        ($serviceRights -band $required) -ne $required -or
        ($serviceRights -band $forbidden) -ne 0
    ) {
        throw 'SENSOR_LOCAL_PROOF_ACL_INVALID'
    }
}

function Assert-ProtectedGenuineSaltAcl {
    if (-not (Test-Path -LiteralPath $genuineSaltPath -PathType Leaf)) {
        throw 'SENSOR_GENUINE_SALT_ACL_INVALID'
    }
    $item = Get-Item -LiteralPath $genuineSaltPath -Force
    if (
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -ne 32
    ) {
        throw 'SENSOR_GENUINE_SALT_ACL_INVALID'
    }
    $acl = Get-Acl -LiteralPath $genuineSaltPath
    $ownerSid = $acl.Owner
    try {
        $ownerSid = ([Security.Principal.NTAccount]$acl.Owner).Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    }
    catch {
        if ($ownerSid -notmatch '^S-\d-') {
            throw 'SENSOR_GENUINE_SALT_ACL_INVALID'
        }
    }
    $rules = @($acl.GetAccessRules(
        $true,
        $false,
        [Security.Principal.SecurityIdentifier]
    ))
    if (
        $ownerSid -ne 'S-1-5-32-544' -or
        -not $acl.AreAccessRulesProtected -or
        $rules.Count -ne 3
    ) {
        throw 'SENSOR_GENUINE_SALT_ACL_INVALID'
    }
    $bySid = @{}
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if (
            $rule.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow -or
            $rule.IsInherited -or
            $bySid.ContainsKey($sid)
        ) {
            throw 'SENSOR_GENUINE_SALT_ACL_INVALID'
        }
        $bySid[$sid] = $rule.FileSystemRights
    }
    foreach ($fullControlSid in @('S-1-5-18', 'S-1-5-32-544')) {
        if (
            -not $bySid.ContainsKey($fullControlSid) -or
            ($bySid[$fullControlSid] -band
                [Security.AccessControl.FileSystemRights]::FullControl) -ne
                [Security.AccessControl.FileSystemRights]::FullControl
        ) {
            throw 'SENSOR_GENUINE_SALT_ACL_INVALID'
        }
    }
    if (-not $bySid.ContainsKey('S-1-5-19')) {
        throw 'SENSOR_GENUINE_SALT_ACL_INVALID'
    }
    $serviceRights = $bySid['S-1-5-19']
    $required = [Security.AccessControl.FileSystemRights]::Read
    $forbidden = (
        [Security.AccessControl.FileSystemRights]::ExecuteFile -bor
        [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    )
    if (
        ($serviceRights -band $required) -ne $required -or
        ($serviceRights -band $forbidden) -ne 0
    ) {
        throw 'SENSOR_GENUINE_SALT_ACL_INVALID'
    }
}

function Assert-ProtectedDescriptorAcl {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'SENSOR_BINDING_DESCRIPTOR_ACL_INVALID'
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -gt 32768) {
        throw 'SENSOR_BINDING_DESCRIPTOR_ACL_INVALID'
    }
    $acl = Get-Acl -LiteralPath $Path
    $ownerSid = ([Security.Principal.NTAccount]$acl.Owner).Translate(
        [Security.Principal.SecurityIdentifier]
    ).Value
    $rules = @($acl.GetAccessRules(
        $true, $false, [Security.Principal.SecurityIdentifier]
    ))
    if ($ownerSid -ne 'S-1-5-32-544' -or
        -not $acl.AreAccessRulesProtected -or $rules.Count -ne 3) {
        throw 'SENSOR_BINDING_DESCRIPTOR_ACL_INVALID'
    }
    $bySid = @{}
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne
            [Security.AccessControl.AccessControlType]::Allow -or
            $rule.IsInherited -or
            $bySid.ContainsKey($rule.IdentityReference.Value)) {
            throw 'SENSOR_BINDING_DESCRIPTOR_ACL_INVALID'
        }
        $bySid[$rule.IdentityReference.Value] = $rule.FileSystemRights
    }
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        if (-not $bySid.ContainsKey($sid) -or
            ($bySid[$sid] -band
                [Security.AccessControl.FileSystemRights]::FullControl) -ne
                [Security.AccessControl.FileSystemRights]::FullControl) {
            throw 'SENSOR_BINDING_DESCRIPTOR_ACL_INVALID'
        }
    }
    $required = [Security.AccessControl.FileSystemRights]::Read
    $forbidden = [Security.AccessControl.FileSystemRights]::ExecuteFile -bor
        [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    if (-not $bySid.ContainsKey('S-1-5-19') -or
        ($bySid['S-1-5-19'] -band $required) -ne $required -or
        ($bySid['S-1-5-19'] -band $forbidden) -ne 0) {
        throw 'SENSOR_BINDING_DESCRIPTOR_ACL_INVALID'
    }
}

function Assert-InstalledPackage {
    param([System.IO.FileInfo[]]$PublishedFiles)
    $requiredFiles = @(
        'WARRoom.WindowsSensor.exe',
        'WARRoom.WindowsSensor.dll',
        'WARRoom.WindowsSensor.deps.json',
        'WARRoom.WindowsSensor.runtimeconfig.json',
        'Microsoft.Extensions.Hosting.WindowsServices.dll',
        'WARRoom.WindowsSensor.Readiness.dll',
        'System.Diagnostics.EventLog.dll',
        'System.Diagnostics.EventLog.Messages.dll',
        'System.ServiceProcess.ServiceController.dll',
        'coreclr.dll',
        'hostfxr.dll',
        'hostpolicy.dll'
    )
    foreach ($required in $requiredFiles) {
        if (-not (Test-Path -LiteralPath (
            Join-Path $installRoot $required
        ) -PathType Leaf)) {
            throw "SENSOR_INSTALL_DEPENDENCY_MISSING_$required"
        }
    }

    $installedFiles = @(
        Get-ChildItem -LiteralPath $installRoot -File |
            Where-Object { $_.Name -ne 'install-manifest.json' } |
            Sort-Object Name
    )
    if ($installedFiles.Count -ne $PublishedFiles.Count) {
        throw 'SENSOR_INSTALL_FILE_SET_INVALID'
    }

    foreach ($source in $PublishedFiles) {
        $destination = Join-Path $installRoot $source.Name
        $installed = Get-Item -LiteralPath $destination -ErrorAction Stop
        if (
            $installed.Length -ne $source.Length -or
            (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne
                (Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash
        ) {
            throw "SENSOR_INSTALL_FILE_HASH_INVALID_$($source.Name)"
        }
        Assert-ProtectedFileAcl -Path $destination
    }
}

function Assert-ExactPropertySet {
    param(
        [object]$Value,
        [string[]]$Expected,
        [string]$ErrorCode
    )
    if ($null -eq $Value) {
        throw $ErrorCode
    }
    $actual = @($Value.PSObject.Properties.Name)
    if (
        $actual.Count -ne $Expected.Count -or
        @($actual | Where-Object { $_ -notin $Expected }).Count -ne 0
    ) {
        throw $ErrorCode
    }
}

function Convert-ManifestGeneratedAt {
    param([string]$Value)
    if (-not $Value.EndsWith('Z', [StringComparison]::Ordinal)) {
        throw 'SENSOR_MANIFEST_TIMESTAMP_UTC_SUFFIX_INVALID'
    }
    $parsed = [DateTime]::MinValue
    $parsedValid = [DateTime]::TryParseExact(
        $Value,
        'O',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$parsed
    )
    if (-not $parsedValid -or $parsed.Kind -ne [DateTimeKind]::Utc) {
        throw 'SENSOR_MANIFEST_TIMESTAMP_UTC_INVALID'
    }
    return $parsed
}

function Get-ManifestGeneratedAtText {
    param([string]$ManifestJson)
    $propertyPattern = '"generatedAt"\s*:'
    $valuePattern = (
        '"generatedAt"\s*:\s*"' +
        '(?<Value>[0-9]{4}-[0-9]{2}-[0-9]{2}T' +
        '[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}Z)"'
    )
    $options = [Text.RegularExpressions.RegexOptions]::CultureInvariant
    $properties = [Text.RegularExpressions.Regex]::Matches(
        $ManifestJson,
        $propertyPattern,
        $options
    )
    $values = [Text.RegularExpressions.Regex]::Matches(
        $ManifestJson,
        $valuePattern,
        $options
    )
    if ($properties.Count -ne 1 -or $values.Count -ne 1) {
        throw 'SENSOR_MANIFEST_TIMESTAMP_JSON_INVALID'
    }
    return $values[0].Groups['Value'].Value
}

function Assert-ManifestTimestampParser {
    $parsed = Convert-ManifestGeneratedAt `
        -Value '2026-07-30T15:58:08.6883706Z'
    if ($parsed.Kind -ne [DateTimeKind]::Utc) {
        throw 'SENSOR_MANIFEST_TIMESTAMP_UTC_INVALID'
    }
    try {
        [void](Convert-ManifestGeneratedAt `
            -Value '2026-07-30T16:58:08.6883706+01:00')
    }
    catch {
        if (
            $_.Exception.Message -eq
                'SENSOR_MANIFEST_TIMESTAMP_UTC_SUFFIX_INVALID'
        ) {
            return
        }
        throw
    }
    throw 'SENSOR_MANIFEST_TIMESTAMP_OFFSET_ACCEPTED'
}

function Assert-ManifestTimestampJsonParser {
    $valid = Get-ManifestGeneratedAtText -ManifestJson (
        '{"generatedAt":"2026-07-30T15:58:08.6883706Z"}'
    )
    if ($valid -ne '2026-07-30T15:58:08.6883706Z') {
        throw 'SENSOR_MANIFEST_TIMESTAMP_JSON_INVALID'
    }
    foreach ($invalid in @(
        '{"generatedAt":"2026-07-30T16:58:08.6883706+01:00"}',
        '{"generatedAt":"2026-07-30T15:58:08Z"}',
        '{"generatedAt":"2026-07-30T15:58:08.6883706Z","generatedAt":"2026-07-30T15:58:08.6883706Z"}'
    )) {
        try {
            [void](Get-ManifestGeneratedAtText -ManifestJson $invalid)
        }
        catch {
            if (
                $_.Exception.Message -eq
                    'SENSOR_MANIFEST_TIMESTAMP_JSON_INVALID'
            ) {
                continue
            }
            throw
        }
        throw 'SENSOR_MANIFEST_TIMESTAMP_JSON_WEAKNESS'
    }
}

function Read-ValidatedInstallManifest {
    $manifestPath = Join-Path $installRoot 'install-manifest.json'
    if (
        -not (Test-Path -LiteralPath $installRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $manifestPath -PathType Leaf)
    ) {
        throw 'SENSOR_INSTALLED_MANIFEST_MISSING'
    }
    $installItem = Get-Item -LiteralPath $installRoot -Force
    if (
        ($installItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw 'SENSOR_INSTALL_REPARSE_POINT_DENIED'
    }
    Assert-ProtectedInstallAcl
    Assert-ProtectedFileAcl -Path $manifestPath

    try {
        $manifestJson = Get-Content -Raw -LiteralPath $manifestPath
        $generatedAtText = Get-ManifestGeneratedAtText `
            -ManifestJson $manifestJson
        $manifest = $manifestJson | ConvertFrom-Json
    }
    catch {
        throw 'SENSOR_INSTALLED_MANIFEST_INVALID'
    }
    $manifestProperties = @(
        'schemaVersion',
        'commit',
        'serviceName',
        'startIdentity',
        'runtimeIdentifier',
        'deploymentMode',
        'runtimeProfile',
        'runtimeVersion',
        'packageBytes',
        'identityProfile',
        'identityFingerprintSha256',
        'generatedAt',
        'files'
    )
    if ($manifest.schemaVersion -eq 2) {
        $manifestProperties += 'bindingDescriptorSha256'
    }
    Assert-ExactPropertySet -Value $manifest -Expected $manifestProperties `
        -ErrorCode 'SENSOR_INSTALLED_MANIFEST_INVALID'

    $generatedAt = Convert-ManifestGeneratedAt -Value $generatedAtText
    $manifest.generatedAt = $generatedAtText
    if (
        $manifest.schemaVersion -notin @(1, 2) -or
        [string]$manifest.commit -notmatch '^[0-9a-f]{40}$' -or
        $manifest.serviceName -ne $serviceName -or
        $manifest.startIdentity -ne $expectedIdentity -or
        $manifest.runtimeIdentifier -ne $runtimeIdentifier -or
        $manifest.deploymentMode -ne $deploymentMode -or
        $manifest.runtimeProfile -ne $runtimeProfile -or
        [string]$manifest.runtimeVersion -notmatch '^8\.0\.\d+$' -or
        [long]$manifest.packageBytes -lt 1 -or
        $manifest.identityProfile -ne 'software-ksp-machine-v1' -or
        [string]$manifest.identityFingerprintSha256 -notmatch
            '^[0-9a-f]{64}$' -or
        $generatedAt.Kind -ne [DateTimeKind]::Utc
    ) {
        throw 'SENSOR_INSTALLED_MANIFEST_INVALID'
    }
    if ($manifest.schemaVersion -eq 2) {
        if (
            [string]$manifest.bindingDescriptorSha256 -notmatch
                '^[0-9a-f]{64}$' -or
            -not (Test-Path -LiteralPath $endpointBindingPath -PathType Leaf) -or
            (Get-FileHash -LiteralPath $endpointBindingPath -Algorithm SHA256).
                Hash.ToLowerInvariant() -ne
                [string]$manifest.bindingDescriptorSha256
        ) {
            throw 'SENSOR_BINDING_MANIFEST_HASH_INVALID'
        }
    }

    $manifestFiles = @($manifest.files)
    if ($manifestFiles.Count -lt 10 -or $manifestFiles.Count -gt 500) {
        throw 'SENSOR_INSTALLED_MANIFEST_INVALID'
    }
    $names = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    [long]$packageBytes = 0
    foreach ($file in $manifestFiles) {
        Assert-ExactPropertySet -Value $file -Expected @(
            'name',
            'bytes',
            'sha256'
        ) -ErrorCode 'SENSOR_INSTALLED_MANIFEST_INVALID'
        $name = [string]$file.name
        if (
            $name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' -or
            [IO.Path]::GetFileName($name) -ne $name -or
            $name -eq 'install-manifest.json' -or
            -not $names.Add($name) -or
            [long]$file.bytes -lt 0 -or
            [string]$file.sha256 -notmatch '^[0-9a-f]{64}$'
        ) {
            throw 'SENSOR_INSTALLED_MANIFEST_INVALID'
        }
        $packageBytes += [long]$file.bytes
    }
    if ($packageBytes -ne [long]$manifest.packageBytes) {
        throw 'SENSOR_INSTALLED_MANIFEST_INVALID'
    }

    $installedDirectories = @(
        Get-ChildItem -LiteralPath $installRoot -Directory -Force
    )
    $installedFiles = @(
        Get-ChildItem -LiteralPath $installRoot -File -Force |
            Sort-Object Name
    )
    $actualPayloadNames = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    if (
        $installedDirectories.Count -ne 0 -or
        $installedFiles.Count -ne ($manifestFiles.Count + 1)
    ) {
        throw 'SENSOR_INSTALLED_FILE_SET_INVALID'
    }
    foreach ($installed in $installedFiles) {
        if (
            ($installed.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0
        ) {
            throw 'SENSOR_INSTALLED_FILE_SET_INVALID'
        }
        if ([StringComparer]::OrdinalIgnoreCase.Equals(
            $installed.Name,
            'install-manifest.json'
        )) {
            if ($installed.Name -cne 'install-manifest.json') {
                throw 'SENSOR_INSTALLED_FILE_SET_INVALID'
            }
        }
        elseif (-not $actualPayloadNames.Add($installed.Name)) {
            throw 'SENSOR_INSTALLED_FILE_SET_INVALID'
        }
        Assert-ProtectedFileAcl -Path $installed.FullName
    }
    if (-not $actualPayloadNames.SetEquals($names)) {
        throw 'SENSOR_INSTALLED_FILE_SET_INVALID'
    }
    foreach ($file in $manifestFiles) {
        $path = Join-Path $installRoot ([string]$file.name)
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw 'SENSOR_INSTALLED_FILE_SET_INVALID'
        }
        $installed = Get-Item -LiteralPath $path -ErrorAction Stop
        if (
            $installed.Name -cne [string]$file.name -or
            $installed.Length -ne [long]$file.bytes -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).
                Hash.ToLowerInvariant() -ne [string]$file.sha256
        ) {
            throw "SENSOR_INSTALLED_FILE_HASH_INVALID_$($file.name)"
        }
    }
    return $manifest
}

function Assert-ServiceConfiguration {
    param([object]$Service)
    if ($null -eq $Service) {
        throw 'SENSOR_SERVICE_CONFIGURATION_INVALID'
    }
    $serviceRegistryPath = Join-Path (
        'HKLM:\SYSTEM\CurrentControlSet\Services'
    ) $serviceName
    $serviceRegistry = Get-Item -LiteralPath $serviceRegistryPath `
        -ErrorAction Stop
    $forbiddenServiceValues = @(
        'DependOnService',
        'DependOnGroup',
        'FailureActions',
        'FailureActionsOnNonCrashFailures'
    )
    $configuredServiceValues = @($serviceRegistry.GetValueNames())
    $controller = Get-Service -Name $serviceName -ErrorAction Stop
    $serviceDependencies = @($controller.ServicesDependedOn)
    $expectedPathName = Get-NormalServicePathName
    if ($Service.Name -ne $serviceName) {
        throw 'SENSOR_SERVICE_NAME_INVALID'
    }
    if ($Service.DisplayName -ne $displayName) {
        throw 'SENSOR_SERVICE_DISPLAY_NAME_INVALID'
    }
    if ($Service.StartName -ne $expectedIdentity) {
        throw 'SENSOR_SERVICE_IDENTITY_INVALID'
    }
    if ($Service.StartMode -ne 'Manual') {
        throw 'SENSOR_SERVICE_START_MODE_INVALID'
    }
    if ($Service.PathName -ne $expectedPathName) {
        throw 'SENSOR_SERVICE_PATH_CONFIGURATION_INVALID'
    }
    if ($Service.ServiceType -ne 'Own Process') {
        throw 'SENSOR_SERVICE_TYPE_INVALID'
    }
    if ($Service.DesktopInteract -ne $false) {
        throw 'SENSOR_SERVICE_DESKTOP_INTERACTION_INVALID'
    }
    if ($Service.ErrorControl -ne 'Normal') {
        throw 'SENSOR_SERVICE_ERROR_CONTROL_INVALID'
    }
    if ($Service.State -notin @('Running', 'Stopped')) {
        throw "SENSOR_SERVICE_TRANSITION_STATE_$($Service.State)"
    }
    if ($serviceDependencies.Count -ne 0) {
        throw 'SENSOR_SERVICE_DEPENDENCIES_INVALID'
    }
    if (
        @(
            $configuredServiceValues |
                Where-Object { $_ -in $forbiddenServiceValues }
        ).Count -ne 0
    ) {
        throw 'SENSOR_SERVICE_RECOVERY_CONFIGURATION_INVALID'
    }
}

function Assert-IdentityMatchesManifest {
    param([object]$Manifest)
    $identity = Assert-IdentityStatus
    if (
        $identity.publicKeyFingerprintSha256 -ne
            $Manifest.identityFingerprintSha256
    ) {
        throw 'SENSOR_INSTALLED_IDENTITY_MISMATCH'
    }
    return $identity
}

function Assert-InstalledServiceSourceMatches {
    param(
        [object]$Manifest,
        [string]$SourceCommit
    )
    $installedCommit = [string]$Manifest.commit
    & git.exe -C $projectRoot rev-parse --verify `
        "$installedCommit^{commit}" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'SENSOR_SOURCE_READINESS_INSTALLED_COMMIT_UNKNOWN'
    }
    & git.exe -C $projectRoot diff --quiet $installedCommit $SourceCommit `
        -- 'apps/windows-sensor'
    if ($LASTEXITCODE -eq 0) {
        return
    }
    if ($LASTEXITCODE -eq 1) {
        throw 'SENSOR_SOURCE_READINESS_SERVICE_SOURCE_MISMATCH'
    }
    throw 'SENSOR_SOURCE_READINESS_SERVICE_SOURCE_COMPARE_FAILED'
}

function Wait-ServiceDeleted {
    param([int]$Seconds = 20)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($null -eq (Get-ServiceRecord)) {
            return
        }
        Start-Sleep -Milliseconds 250
    }
    throw 'SENSOR_SERVICE_DELETE_TIMEOUT'
}

function Get-WindowsEventsFailClosed {
    param([hashtable]$Filter)
    try {
        return @(
            Get-WinEvent -FilterHashtable $Filter -ErrorAction Stop
        )
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            return @()
        }
        throw 'SENSOR_RESTART_EVENT_QUERY_FAILED'
    }
}

function Assert-NoSensorStartErrors {
    param([DateTime]$Since)
    $applicationErrors = @(
        Get-WindowsEventsFailClosed -Filter @{
            LogName = 'Application'
            ProviderName = @('Application Error', '.NET Runtime')
            Id = @(1000, 1026)
            Level = 2
            StartTime = $Since
        } |
            Where-Object {
                $_.Message -match 'WARRoom\.WindowsSensor'
            }
    )
    $serviceErrors = @(
        Get-WindowsEventsFailClosed -Filter @{
            LogName = 'System'
            ProviderName = 'Service Control Manager'
            Level = 2
            StartTime = $Since
        } |
            Where-Object {
                $_.Message -match 'WAR-R00M Windows Sensor'
            }
    )
    if ($applicationErrors.Count -gt 0 -or $serviceErrors.Count -gt 0) {
        throw 'SENSOR_RESTART_EVENT_ERROR'
    }
}

function Assert-PublishRuntimeProfile {
    param([string]$PublishRoot)
    $depsPath = Join-Path $PublishRoot 'WARRoom.WindowsSensor.deps.json'
    $runtimeConfigPath = Join-Path $PublishRoot `
        'WARRoom.WindowsSensor.runtimeconfig.json'
    try {
        $deps = Get-Content -Raw -LiteralPath $depsPath | ConvertFrom-Json
        $runtimeConfig = Get-Content -Raw -LiteralPath $runtimeConfigPath |
            ConvertFrom-Json
    }
    catch {
        throw 'SENSOR_PUBLISH_RUNTIME_PROFILE_INVALID'
    }

    $expectedTarget = ".NETCoreApp,Version=v8.0/$runtimeIdentifier"
    $includedFrameworks = @(
        $runtimeConfig.runtimeOptions.includedFrameworks
    )
    $coreFrameworks = @($includedFrameworks | Where-Object {
        $_.name -eq 'Microsoft.NETCore.App' -and
        $_.version -match '^8\.0\.'
    })
    if (
        $deps.runtimeTarget.name -ne $expectedTarget -or
        $includedFrameworks.Count -lt 1 -or
        $coreFrameworks.Count -ne 1 -or
        $null -ne $runtimeConfig.runtimeOptions.framework
    ) {
        throw 'SENSOR_PUBLISH_RUNTIME_PROFILE_INVALID'
    }
    return [string]$coreFrameworks[0].version
}

function Set-AdminOnlyDirectoryAcl {
    param([string]$Path)
    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administratorsSid = [Security.Principal.SecurityIdentifier]::new(
        'S-1-5-32-544'
    )
    $inheritance = [Security.AccessControl.InheritanceFlags](
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    )
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administratorsSid)
    foreach ($sid in @($systemSid, $administratorsSid)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        ))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-AdminOnlyFileAcl {
    param([string]$Path)
    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administratorsSid = [Security.Principal.SecurityIdentifier]::new(
        'S-1-5-32-544'
    )
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administratorsSid)
    foreach ($sid in @($systemSid, $administratorsSid)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        ))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-AdminOnlyAcl {
    param(
        [string]$Path,
        [switch]$File
    )
    $item = Get-Item -LiteralPath $Path -Force
    if (
        ($File -and $item.PSIsContainer) -or
        (-not $File -and -not $item.PSIsContainer) -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw 'SENSOR_STAGING_ITEM_INVALID'
    }
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.Owner
    try {
        $owner = ([Security.Principal.NTAccount]$owner).Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    }
    catch {
        if ($owner -notmatch '^S-\d-') {
            throw 'SENSOR_STAGING_ACL_INVALID'
        }
    }
    $rules = @($acl.GetAccessRules(
        $true,
        $false,
        [Security.Principal.SecurityIdentifier]
    ))
    $sids = @($rules | ForEach-Object { $_.IdentityReference.Value } | Sort-Object)
    if (
        $owner -ne 'S-1-5-32-544' -or
        -not $acl.AreAccessRulesProtected -or
        $rules.Count -ne 2 -or
        ($sids -join ',') -ne 'S-1-5-18,S-1-5-32-544' -or
        @($rules | Where-Object {
            $_.IsInherited -or
            $_.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow -or
            ($_.FileSystemRights -band
                [Security.AccessControl.FileSystemRights]::FullControl) -ne
                [Security.AccessControl.FileSystemRights]::FullControl
        }).Count -ne 0
    ) {
        throw 'SENSOR_STAGING_ACL_INVALID'
    }
}

function Read-SealedPackageManifest {
    param(
        [string]$Root,
        [string]$ExpectedSeal
    )
    if ($ExpectedSeal -cnotmatch '^[0-9a-f]{64}$') {
        throw 'SENSOR_PACKAGE_SEAL_INVALID'
    }
    if ([string]::IsNullOrWhiteSpace($Root)) {
        throw 'SENSOR_PACKAGE_ROOT_REQUIRED'
    }
    $resolvedRoot = [IO.Path]::GetFullPath($Root)
    $allowedRoot = [IO.Path]::GetFullPath(
        (Join-Path $HOME '.codex-build\project15\windows-sensor\sealed-packages')
    ).TrimEnd('\') + '\'
    if (-not $resolvedRoot.StartsWith(
        $allowedRoot,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'SENSOR_PACKAGE_ROOT_INVALID'
    }
    $rootItem = Get-Item -LiteralPath $resolvedRoot -Force
    if (
        -not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw 'SENSOR_PACKAGE_ROOT_INVALID'
    }
    $manifestPath = Join-Path $resolvedRoot 'package-manifest.json'
    $manifestItem = Get-Item -LiteralPath $manifestPath -Force
    if (
        $manifestItem.PSIsContainer -or
        ($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $manifestItem.Length -lt 100 -or
        $manifestItem.Length -gt 1048576
    ) {
        throw 'SENSOR_PACKAGE_MANIFEST_INVALID'
    }
    $manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $actualSeal = ([BitConverter]::ToString(
            $hasher.ComputeHash($manifestBytes)
        )).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
    }
    if ($actualSeal -cne $ExpectedSeal) {
        throw 'SENSOR_PACKAGE_SEAL_MISMATCH'
    }
    try {
        $manifest = ([Text.UTF8Encoding]::new($false, $true)).GetString(
            $manifestBytes
        ) | ConvertFrom-Json
    }
    catch {
        throw 'SENSOR_PACKAGE_MANIFEST_INVALID'
    }
    $fields = @($manifest.PSObject.Properties.Name | Sort-Object)
    if (
        ($fields -join ',') -ne
            'commit,deploymentMode,files,generatedAt,runtimeIdentifier,schemaVersion' -or
        $manifest.schemaVersion -ne 1 -or
        $manifest.commit -cnotmatch '^[0-9a-f]{40}$' -or
        $manifest.runtimeIdentifier -ne $runtimeIdentifier -or
        $manifest.deploymentMode -ne $deploymentMode -or
        @($manifest.files).Count -lt 8
    ) {
        throw 'SENSOR_PACKAGE_MANIFEST_INVALID'
    }
    $seen = @{}
    foreach ($file in @($manifest.files)) {
        $fileFields = @($file.PSObject.Properties.Name | Sort-Object)
        if (
            ($fileFields -join ',') -ne 'bytes,path,sha256' -or
            $file.path -cnotmatch '^(sensor|identity-status|service-sid|audit-witness-installer|audit-witness-checker)/[A-Za-z0-9_.-]+$' -or
            $file.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [long]$file.bytes -lt 1 -or
            $seen.ContainsKey([string]$file.path)
        ) {
            throw 'SENSOR_PACKAGE_FILE_MANIFEST_INVALID'
        }
        $seen[[string]$file.path] = $true
    }
    foreach ($required in @(
        'sensor/WARRoom.WindowsSensor.exe',
        'identity-status/WARRoom.WindowsSensor.Provisioner.exe',
        'service-sid/WARRoom.WindowsSensor.ServiceSidTool.exe',
        'audit-witness-installer/WARRoom.WindowsSensor.AuditWitnessInstaller.exe',
        'audit-witness-checker/WARRoom.WindowsSensor.AuditWitnessChecker.exe'
    )) {
        if (-not $seen.ContainsKey($required)) {
            throw 'SENSOR_PACKAGE_REQUIRED_FILE_MISSING'
        }
    }
    $actualFiles = @(
        Get-ChildItem -LiteralPath $resolvedRoot -File -Recurse -Force |
            Where-Object { $_.FullName -ne $manifestPath }
    )
    if ($actualFiles.Count -ne @($manifest.files).Count) {
        throw 'SENSOR_PACKAGE_FILE_SET_INVALID'
    }
    return [pscustomobject]@{
        Root = $resolvedRoot
        Seal = $actualSeal
        Manifest = $manifest
        ManifestBytes = $manifestBytes
    }
}

function Copy-ToProtectedPackageStage {
    param([pscustomobject]$Package)
    if (Test-Path -LiteralPath $stagingParent) {
        $existingStageParent = Get-Item -LiteralPath $stagingParent -Force
        if (
            -not $existingStageParent.PSIsContainer -or
            ($existingStageParent.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0
        ) {
            throw 'SENSOR_PACKAGE_STAGING_PARENT_INVALID'
        }
    }
    else {
        [void](New-Item -ItemType Directory -Path $stagingParent -Force)
        $createdStageParent = Get-Item -LiteralPath $stagingParent -Force
        if (
            -not $createdStageParent.PSIsContainer -or
            ($createdStageParent.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0
        ) {
            throw 'SENSOR_PACKAGE_STAGING_PARENT_INVALID'
        }
    }
    Set-AdminOnlyDirectoryAcl -Path $stagingParent
    Assert-AdminOnlyAcl -Path $stagingParent
    $stageRoot = Join-Path $stagingParent $Package.Seal
    if (Test-Path -LiteralPath $stageRoot) {
        throw 'SENSOR_PACKAGE_STAGE_ALREADY_EXISTS'
    }
    [void](New-Item -ItemType Directory -Path $stageRoot -Force)
    Set-AdminOnlyDirectoryAcl -Path $stageRoot
    Assert-AdminOnlyAcl -Path $stageRoot
    foreach ($directoryName in @(
        'sensor',
        'identity-status',
        'service-sid',
        'audit-witness-installer',
        'audit-witness-checker'
    )) {
        $directory = Join-Path $stageRoot $directoryName
        [void](New-Item -ItemType Directory -Path $directory)
        Set-AdminOnlyDirectoryAcl -Path $directory
        Assert-AdminOnlyAcl -Path $directory
    }
    foreach ($file in @($Package.Manifest.files)) {
        $relative = ([string]$file.path).Replace('/', '\')
        $source = Join-Path $Package.Root $relative
        $sourceItem = Get-Item -LiteralPath $source -Force
        if (
            $sourceItem.PSIsContainer -or
            ($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        ) {
            throw 'SENSOR_PACKAGE_SOURCE_FILE_INVALID'
        }
        $destination = Join-Path $stageRoot $relative
        Copy-Item -LiteralPath $source -Destination $destination
        Set-AdminOnlyFileAcl -Path $destination
        Assert-AdminOnlyAcl -Path $destination -File
        $destinationItem = Get-Item -LiteralPath $destination -Force
        $hash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).
            Hash.ToLowerInvariant()
        if (
            $destinationItem.Length -ne [long]$file.bytes -or
            $hash -cne [string]$file.sha256
        ) {
            throw 'SENSOR_PACKAGE_STAGE_HASH_MISMATCH'
        }
    }
    $stageManifest = Join-Path $stageRoot 'package-manifest.json'
    [IO.File]::WriteAllBytes($stageManifest, $Package.ManifestBytes)
    Set-AdminOnlyFileAcl -Path $stageManifest
    Assert-AdminOnlyAcl -Path $stageManifest -File
    return $stageRoot
}

function Remove-ProtectedPackageStage {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return
    }
    $resolved = [IO.Path]::GetFullPath($Path)
    $allowed = $stagingParent.TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($allowed, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'SENSOR_PACKAGE_STAGE_CLEANUP_PATH_INVALID'
    }
    Assert-AdminOnlyAcl -Path $resolved
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

function Get-ProtectedPackageIdentityStatus {
    param([string]$StageRoot)
    $tool = Join-Path $StageRoot `
        'identity-status\WARRoom.WindowsSensor.Provisioner.exe'
    Assert-AdminOnlyAcl -Path $tool -File
    $lines = & $tool status
    if ($LASTEXITCODE -ne 0) {
        throw 'SENSOR_NATIVE_KEY_STATUS_INVALID'
    }
    try {
        $result = (($lines -join "`n") | ConvertFrom-Json)
    }
    catch {
        throw 'SENSOR_NATIVE_KEY_STATUS_INVALID'
    }
    if (
        -not $result.ok -or
        -not $result.status.exists -or
        -not $result.status.policyValid -or
        -not $result.status.aclVerified -or
        $result.status.provider -ne 'Microsoft Software Key Storage Provider' -or
        $result.status.profile -ne 'software-ksp-machine-v1' -or
        $result.status.publicKeyFingerprintSha256 -notmatch '^[0-9a-f]{64}$'
    ) {
        throw 'SENSOR_NATIVE_KEY_STATUS_INVALID'
    }
    return $result.status
}

function Invoke-ProtectedServiceSidTool {
    param(
        [string]$StageRoot,
        [ValidateSet(
            'status',
            'apply-unrestricted',
            'restore-none',
            'restore-restricted'
        )]
        [string]$ToolCommand
    )
    $tool = Join-Path $StageRoot `
        'service-sid\WARRoom.WindowsSensor.ServiceSidTool.exe'
    Assert-AdminOnlyAcl -Path $tool -File
    $lines = & $tool $ToolCommand
    if ($LASTEXITCODE -ne 0) {
        throw 'SENSOR_SERVICE_SID_TOOL_FAILED'
    }
    try {
        $result = (($lines -join "`n") | ConvertFrom-Json)
    }
    catch {
        throw 'SENSOR_SERVICE_SID_TOOL_RESULT_INVALID'
    }
    if (
        -not $result.ok -or
        $result.command -cne $ToolCommand -or
        $result.result.serviceName -cne $serviceName -or
        $result.result.scmLogonAccount -cne $expectedIdentity -or
        [uint64]$result.result.previousSidType -notin @(0, 1, 3) -or
        [uint64]$result.result.currentSidType -notin @(0, 1, 3) -or
        $result.result.independentlyReadBack -cne $true -or
        $result.result.telemetryEnabled -cne $false -or
        $result.result.transportEnabled -cne $false -or
        $result.result.commandChannelEnabled -cne $false
    ) {
        throw 'SENSOR_SERVICE_SID_TOOL_RESULT_INVALID'
    }
    return $result.result
}

function Invoke-ProtectedAuditWitnessInstaller {
    param([string]$StageRoot)
    $tool = Join-Path $StageRoot `
        'audit-witness-installer\WARRoom.WindowsSensor.AuditWitnessInstaller.exe'
    Assert-AdminOnlyAcl -Path $tool -File
    $lines = & $tool install
    if ($LASTEXITCODE -ne 0) {
        throw 'SENSOR_AUDIT_WITNESS_INSTALLER_FAILED'
    }
    try {
        $result = (($lines -join "`n") | ConvertFrom-Json)
    }
    catch {
        throw 'SENSOR_AUDIT_WITNESS_INSTALLER_RESULT_INVALID'
    }
    $status = $result.result.status
    if (
        -not $result.ok -or
        $result.command -cne 'install' -or
        $status.baseRootPath -cne 'C:\ProgramData\Project15 Audit Head' -or
        $status.rootPath -cne 'C:\ProgramData\Project15 Audit Head\Witness' -or
        $status.filePath -cne 'C:\ProgramData\Project15 Audit Head\Witness\audit-witness-v1.log' -or
        $status.claim -cne 'historical-rewrite-detection-only' -or
        [long]$status.fileLength -lt 0 -or
        [long]$status.fileLength -gt 1048576 -or
        [int]$status.hardLinkCount -ne 1 -or
        $status.baseRootAclVerified -cne $true -or
        $status.rootAclVerified -cne $true -or
        $status.fileAclVerified -cne $true -or
        $status.fileIdentityVerified -cne $true -or
        $status.runtimeWiringEnabled -cne $false -or
        $status.telemetryEnabled -cne $false -or
        $status.transportEnabled -cne $false -or
        $status.commandChannelEnabled -cne $false -or
        $result.result.independentlyChecked -cne $true
    ) {
        throw 'SENSOR_AUDIT_WITNESS_INSTALLER_RESULT_INVALID'
    }
    return $result.result
}

function Invoke-ProtectedAuditWitnessChecker {
    param([string]$StageRoot)
    $tool = Join-Path $StageRoot `
        'audit-witness-checker\WARRoom.WindowsSensor.AuditWitnessChecker.exe'
    Assert-AdminOnlyAcl -Path $tool -File
    $lines = & $tool check
    if ($LASTEXITCODE -ne 0) {
        throw 'SENSOR_AUDIT_WITNESS_CHECKER_FAILED'
    }
    try {
        $result = (($lines -join "`n") | ConvertFrom-Json)
    }
    catch {
        throw 'SENSOR_AUDIT_WITNESS_CHECKER_RESULT_INVALID'
    }
    $status = $result.result
    if (
        -not $result.ok -or
        $result.command -cne 'check' -or
        $status.baseRootPath -cne 'C:\ProgramData\Project15 Audit Head' -or
        $status.rootPath -cne 'C:\ProgramData\Project15 Audit Head\Witness' -or
        $status.filePath -cne 'C:\ProgramData\Project15 Audit Head\Witness\audit-witness-v1.log' -or
        $status.claim -cne 'historical-rewrite-detection-only' -or
        [long]$status.fileLength -lt 0 -or
        [long]$status.fileLength -gt 1048576 -or
        [int]$status.hardLinkCount -ne 1 -or
        $status.baseRootAclVerified -cne $true -or
        $status.rootAclVerified -cne $true -or
        $status.fileAclVerified -cne $true -or
        $status.fileIdentityVerified -cne $true -or
        $status.runtimeWiringEnabled -cne $false -or
        $status.telemetryEnabled -cne $false -or
        $status.transportEnabled -cne $false -or
        $status.commandChannelEnabled -cne $false
    ) {
        throw 'SENSOR_AUDIT_WITNESS_CHECKER_RESULT_INVALID'
    }
    return $status
}

function New-ValidatedPublishPackage {
    param([string]$PublishRoot)
    [void](New-Item -ItemType Directory -Path $PublishRoot -Force)
    $sensorProject = Join-Path $projectRoot `
        'apps\windows-sensor\src\WARRoom.WindowsSensor.csproj'
    & $dotnet publish $sensorProject --nologo -c Release `
        -r $runtimeIdentifier --self-contained true `
        "-p:WarRoomBuildRoot=$buildRoot" `
        "-p:PublishDir=$PublishRoot\" `
        '-p:DebugType=None' `
        '-p:DebugSymbols=false' `
        '-p:NuGetAudit=false' | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "SENSOR_SERVICE_PUBLISH_FAILED_$LASTEXITCODE"
    }

    $publishedFiles = @(
        Get-ChildItem -LiteralPath $PublishRoot -File -Force |
            Sort-Object Name
    )
    $publishedDirectories = @(
        Get-ChildItem -LiteralPath $PublishRoot -Directory -Force
    )
    if (
        $publishedFiles.Count -lt 4 -or
        $publishedDirectories.Count -ne 0 -or
        -not (Test-Path -LiteralPath (
            Join-Path $PublishRoot 'WARRoom.WindowsSensor.exe'
        ) -PathType Leaf) -or
        @($publishedFiles | Where-Object {
            $_.Extension -notin @('.dll', '.exe', '.json') -or
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        }).Count -gt 0
    ) {
        throw 'SENSOR_SERVICE_PUBLISH_CONTENT_INVALID'
    }

    $runtimeVersion = Assert-PublishRuntimeProfile -PublishRoot $PublishRoot
    foreach ($required in @(
        'WARRoom.WindowsSensor.exe',
        'WARRoom.WindowsSensor.dll',
        'WARRoom.WindowsSensor.deps.json',
        'WARRoom.WindowsSensor.runtimeconfig.json',
        'Microsoft.Extensions.Hosting.WindowsServices.dll',
        'WARRoom.WindowsSensor.Readiness.dll',
        'System.Diagnostics.EventLog.dll',
        'System.Diagnostics.EventLog.Messages.dll',
        'System.ServiceProcess.ServiceController.dll',
        'coreclr.dll',
        'hostfxr.dll',
        'hostpolicy.dll'
    )) {
        if (-not (Test-Path -LiteralPath (
            Join-Path $PublishRoot $required
        ) -PathType Leaf)) {
            throw "SENSOR_PUBLISH_DEPENDENCY_MISSING_$required"
        }
    }

    return [pscustomobject]@{
        Files = [System.IO.FileInfo[]]$publishedFiles
        RuntimeVersion = $runtimeVersion
        PackageBytes = [long](
            ($publishedFiles | Measure-Object -Property Length -Sum).Sum
        )
    }
}

function Remove-CreatedInstallRoot {
    if (-not (Test-Path -LiteralPath $installRoot)) {
        return
    }
    $expected = [IO.Path]::GetFullPath(
        (Join-Path $nativeProgramFiles 'WAR-R00M\Windows Sensor')
    )
    if (-not $installRoot.Equals(
        $expected,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'SENSOR_INSTALL_CLEANUP_PATH_INVALID'
    }
    Remove-Item -LiteralPath $installRoot -Recurse -Force
}

function Remove-CreatedStateRoot {
    if (-not (Test-Path -LiteralPath $stateRoot)) {
        return
    }
    $expected = [IO.Path]::GetFullPath(
        (Join-Path $nativeProgramData 'WAR-R00M\Windows Sensor')
    )
    if (-not $stateRoot.Equals(
        $expected,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'SENSOR_LOCAL_STATE_CLEANUP_PATH_INVALID'
    }
    $rootItem = Get-Item -LiteralPath $stateRoot -Force
    if (
        -not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw 'SENSOR_LOCAL_STATE_CLEANUP_PATH_INVALID'
    }
    $children = @(Get-ChildItem -LiteralPath $stateRoot -Force)
    foreach ($child in $children) {
        if (
            $child.PSIsContainer -or
            $child.Name -notin $allowedLocalStateFiles -or
            ($child.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0
        ) {
            throw 'SENSOR_LOCAL_STATE_CLEANUP_CONTENT_INVALID'
        }
    }
    foreach ($path in @(
        $localProofPath,
        $genuineProofPath,
        $genuineSaltPath,
        $boundedProofPath,
        $endpointBindingPath,
        $capabilityProofPath,
        $loopbackDeliveryPath
    )) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Remove-Item -LiteralPath $path -Force
        }
    }
    Remove-Item -LiteralPath $stateRoot -Force
}

function Assert-InstalledStateLayout {
    $children = @(Get-ChildItem -LiteralPath $stateRoot -Force)
    if (@($children | Where-Object {
        $_.PSIsContainer -or
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    }).Count -ne 0) {
        throw 'SENSOR_LOCAL_STATE_LAYOUT_INVALID'
    }
    $names = @($children.Name | Sort-Object)
    $gateB0 = @('local-synthetic-batch-proof.json')
    $gateB1 = @(
        'local-genuine-batch-proof.json',
        'local-genuine-source-salt.bin',
        'local-synthetic-batch-proof.json'
    )
    $gateC0b = @(
        'endpoint-binding.json',
        'local-capability-proof.json',
        'local-genuine-batch-proof.json',
        'local-genuine-source-salt.bin',
        'local-synthetic-batch-proof.json'
    ) | Sort-Object
    $gateC0c = @(
        'endpoint-binding.json',
        'local-capability-proof.json',
        'local-genuine-batch-proof.json',
        'local-genuine-source-salt.bin',
        'local-loopback-delivery.json',
        'local-synthetic-batch-proof.json'
    ) | Sort-Object
    $gateC1 = @($allowedLocalStateFiles | Sort-Object)
    if (($names -join ',') -eq ($gateB0 -join ',')) {
        Assert-ProtectedLocalProofAcl
        return 'gate-b0'
    }
    if (($names -join ',') -eq ($gateB1 -join ',')) {
        Assert-ProtectedLocalProofAcl
        Assert-ProtectedLocalProofAcl -Path $genuineProofPath
        Assert-ProtectedGenuineSaltAcl
        return 'gate-b1'
    }
    if (($names -join ',') -eq ($gateC0b -join ',')) {
        Assert-ProtectedDescriptorAcl -Path $endpointBindingPath
        Assert-ProtectedLocalProofAcl -Path $capabilityProofPath
        Assert-ProtectedLocalProofAcl
        Assert-ProtectedLocalProofAcl -Path $genuineProofPath
        Assert-ProtectedGenuineSaltAcl
        return 'gate-c0b'
    }
    if (($names -join ',') -eq ($gateC0c -join ',')) {
        Assert-ProtectedDescriptorAcl -Path $endpointBindingPath
        Assert-ProtectedLocalProofAcl -Path $capabilityProofPath
        Assert-ProtectedLocalProofAcl -Path $loopbackDeliveryPath
        Assert-ProtectedLocalProofAcl
        Assert-ProtectedLocalProofAcl -Path $genuineProofPath
        Assert-ProtectedGenuineSaltAcl
        return 'gate-c0c'
    }
    if (($names -join ',') -eq ($gateC1 -join ',')) {
        Assert-ProtectedDescriptorAcl -Path $endpointBindingPath
        Assert-ProtectedLocalProofAcl -Path $capabilityProofPath
        Assert-ProtectedLocalProofAcl -Path $loopbackDeliveryPath
        Assert-ProtectedLocalProofAcl -Path $boundedProofPath
        Assert-ProtectedLocalProofAcl
        Assert-ProtectedLocalProofAcl -Path $genuineProofPath
        Assert-ProtectedGenuineSaltAcl
        return 'gate-c1'
    }
    throw 'SENSOR_LOCAL_STATE_LAYOUT_INVALID'
}

function Remove-PublishRoot {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $resolved = [IO.Path]::GetFullPath($Path)
    $allowed = [IO.Path]::GetFullPath((Join-Path $buildRoot 'install-publish'))
    $allowedPrefix = $allowed.TrimEnd('\') + '\'
    if (-not $resolved.StartsWith(
        $allowedPrefix,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'SENSOR_PUBLISH_CLEANUP_PATH_INVALID'
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

function Remove-CreatedService {
    $service = Get-ServiceRecord
    if ($null -eq $service) {
        return
    }
    if ($service.State -ne 'Stopped') {
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    }
    $result = Invoke-CimMethod -InputObject $service -MethodName Delete
    if ($result.ReturnValue -ne 0) {
        throw "SENSOR_SERVICE_CLEANUP_FAILED_$($result.ReturnValue)"
    }
}

function Wait-ServiceState {
    param(
        [System.ServiceProcess.ServiceControllerStatus]$State,
        [int]$Seconds = 20
    )
    $controller = Get-Service -Name $serviceName -ErrorAction Stop
    try {
        $controller.WaitForStatus($State, [TimeSpan]::FromSeconds($Seconds))
    }
    catch [System.ServiceProcess.TimeoutException] {
        $controller.Refresh()
        throw "SENSOR_SERVICE_STATE_TIMEOUT_EXPECTED_$($State)_ACTUAL_$($controller.Status)"
    }
    $controller.Refresh()
    if ($controller.Status -ne $State) {
        throw "SENSOR_SERVICE_STATE_INVALID_$State"
    }
    $expectedCimState = [string]$State
    $cimDeadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $service = Get-ServiceRecord
        if (
            $null -ne $service -and
            $service.State -eq $expectedCimState
        ) {
            return
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $cimDeadline)
    throw "SENSOR_SERVICE_CIM_STATE_INVALID_$expectedCimState"
}

function Write-Json {
    param([object]$Value)
    $Value | ConvertTo-Json -Depth 8
}

$serviceCreateArguments = Get-ServiceCreateArguments
Assert-ServiceCreateArgumentTypes -Arguments $serviceCreateArguments

if ($Command -eq 'plan' -or ($Command -eq 'install' -and $WhatIfPreference)) {
    Write-Json ([ordered]@{
        ok = $true
        command = 'plan'
        plan = [ordered]@{
            serviceName = $serviceName
            displayName = $displayName
            startIdentity = $expectedIdentity
            startMode = 'Manual'
            runtimeIdentifier = $runtimeIdentifier
            deploymentMode = $deploymentMode
            runtimeProfile = $runtimeProfile
            installRoot = $installRoot
            localStateRoot = $stateRoot
            localProofPath = $localProofPath
            genuineProofPath = $genuineProofPath
            genuineSaltPath = $genuineSaltPath
            boundedProofPath = $boundedProofPath
            endpointBindingPath = $endpointBindingPath
            capabilityProofPath = $capabilityProofPath
            loopbackDeliveryPath = $loopbackDeliveryPath
            genuineSaltBytes = 32
            genuineMaximumProofBytes = 32768
            boundedMaximumProofBytes = 32768
            genuineSaltReadableByLocalService = $true
            genuineSaltWritableByLocalService = $false
            genuineSaltIncludedInOutput = $false
            requiresElevation = $true
            requiresSealedPackage = $true
            packageBuiltUnelevated = $true
            buildToolchainRunsElevated = $false
            sourceTreeExecutableRunsElevated = $false
            protectedStagingRoot = $stagingParent
            installsProtectedAuditWitnessFileFromSealedTool = $true
            independentlyChecksAuditWitnessAclAndHandle = $true
            auditWitnessPath = 'C:\ProgramData\Project15 Audit Head\Witness\audit-witness-v1.log'
            auditWitnessClaim = 'historical-rewrite-detection-only'
            auditWitnessRuntimeWiringEnabled = $false
            configuresFixedServiceSidFromSealedTool = $true
            serviceSidType = 'SERVICE_SID_TYPE_UNRESTRICTED'
            serviceSidConfiguredBeforeResourceAcls = $true
            serviceSidIndependentReadbackRequired = $true
            serviceSidRollbackRequiredOnFailure = $true
            acceptsCallerServiceSid = $false
            replacesExistingService = $false
            deletesMachineIdentity = $false
            syntheticBatchCount = 2
            maximumGenuineBatchCount = 1
            maximumGenuineFactCount = 1
            genuineLog = 'System'
            genuineProvider = 'Service Control Manager'
            genuineEventId = 7045
            genuineLevel = 4
            genuineNewestFirst = $true
            genuineMaximumRecords = 1
            genuineAllowedFields = @(
                'providerName',
                'eventId',
                'level',
                'timeCreatedUtc',
                'recordId'
            )
            rawEventContentRead = $false
            oneShotEventReaderEnabled = $true
            boundedOneShotCollectorEnabled = $true
            boundedMaximumFamilies = 2
            boundedMaximumEventsRead = 2
            continuousCollectorEnabled = $false
            oneShotLoopbackTransportRegistered = $true
            automaticRetryEnabled = $false
            remoteTransportEnabled = $false
            networkTransportEnabled = $false
            inboundListenerEnabled = $false
            collectorEnabled = $false
            telemetryEnabled = $false
            commandChannelEnabled = $false
        }
    })
    return
}

if ($Command -eq 'restart-check' -and $WhatIfPreference) {
    Write-Json ([ordered]@{
        ok = $true
        command = 'restart-check-plan'
        plan = [ordered]@{
            serviceName = $serviceName
            startIdentity = $expectedIdentity
            requiresElevation = $true
            requiresBootAfterInstall = $true
            requiresExactManifestAndHashes = $true
            startsOnlyExactService = $true
            changesStartMode = $false
            deletesInstalledFiles = $false
            deletesMachineIdentity = $false
            collectorEnabled = $false
            telemetryEnabled = $false
            commandChannelEnabled = $false
        }
    })
    return
}

if ($Command -eq 'source-readiness-check' -and $WhatIfPreference) {
    Write-Json ([ordered]@{
        ok = $true
        command = 'source-readiness-check-plan'
        plan = [ordered]@{
            serviceName = $serviceName
            startIdentity = $expectedIdentity
            requiresElevation = $true
            requiresExactManifestAndMatchingServiceSource = $true
            startsOnlyExactService = $true
            changesServicePath = $false
            normalStartupIncludesFixedGateA = $true
            allowedLogs = @('System', 'Application')
            gateAEventsRead = 0
            maximumNormalStartupEventsRead = 3
            genuineEventReaderMayRunIfProofEmpty = $true
            boundedCollectorMayRunIfProofEmpty = $true
            rawEventContentRead = $false
            collectorEnabled = $false
            telemetryEnabled = $false
            commandChannelEnabled = $false
        }
    })
    return
}

if ($Command -eq 'local-batch-check' -and $WhatIfPreference) {
    Write-Json ([ordered]@{
        ok = $true
        command = 'local-batch-check-plan'
        plan = [ordered]@{
            serviceName = $serviceName
            startIdentity = $expectedIdentity
            requiresElevation = $true
            requiresExactManifestAndMatchingServiceSource = $true
            readsOnlyFixedProofFile = $true
            validatesRealMachineKeySignature = $true
            validatesTwoBatchHashChain = $true
            mutatesService = $false
            syntheticBatchCount = 2
            eventsRead = 0
            eventReaderEnabled = $false
            networkTransportEnabled = $false
            inboundListenerEnabled = $false
            commandChannelEnabled = $false
        }
    })
    return
}

if ($Command -eq 'genuine-batch-check' -and $WhatIfPreference) {
    Write-Json ([ordered]@{
        ok = $true
        command = 'genuine-batch-check-plan'
        plan = [ordered]@{
            serviceName = $serviceName
            startIdentity = $expectedIdentity
            requiresElevation = $true
            requiresExactManifestAndMatchingServiceSource = $true
            proofPath = $genuineProofPath
            saltPath = $genuineSaltPath
            readsOnlyFixedProofFile = $true
            validatesFixedSaltAclAndSize = $true
            saltBytes = 32
            maximumProofBytes = 32768
            saltReadableByLocalService = $true
            saltWritableByLocalService = $false
            saltIncludedInOutput = $false
            queriesWindowsEventLog = $false
            validatesRealMachineKeySignature = $true
            maximumBatchCount = 1
            maximumFactCount = 1
            maximumEventsRead = 1
            mutatesService = $false
            rawEventContentRead = $false
            runtimeProofEventReaderEnabled = $true
            checkerEventReaderEnabled = $false
            networkTransportEnabled = $false
            inboundListenerEnabled = $false
            pollingEnabled = $false
            commandChannelEnabled = $false
        }
    })
    return
}

if ($Command -eq 'bounded-collector-check' -and $WhatIfPreference) {
    Write-Json ([ordered]@{
        ok = $true
        command = 'bounded-collector-check-plan'
        plan = [ordered]@{
            serviceName = $serviceName
            startIdentity = $expectedIdentity
            requiresElevation = $true
            requiresExactManifestAndMatchingServiceSource = $true
            proofPath = $boundedProofPath
            saltPath = $genuineSaltPath
            readsOnlyFixedProofAndManifest = $true
            queriesWindowsEventLog = $false
            validatesRealMachineKeySignature = $true
            maximumProofBytes = 32768
            maximumFamiliesQueried = 2
            maximumEventsRead = 2
            mutatesService = $false
            rawEventContentRead = $false
            runtimeProofEventReaderEnabled = $true
            checkerEventReaderEnabled = $false
            lossState = 'unknown'
            continuityState = 'unknown'
            networkTransportEnabled = $false
            automaticRetryEnabled = $false
            pollingEnabled = $false
            inboundListenerEnabled = $false
            commandChannelEnabled = $false
            responseActionsEnabled = $false
        }
    })
    return
}

if ($Command -eq 'uninstall' -and $WhatIfPreference) {
    Write-Json ([ordered]@{
        ok = $true
        command = 'uninstall-plan'
        plan = [ordered]@{
            serviceName = $serviceName
            installRoot = $installRoot
            localStateRoot = $stateRoot
            requiresElevation = $true
            requiresExactManifestAndHashes = $true
            requiresSealedPackage = $true
            buildToolchainRunsElevated = $false
            sourceTreeExecutableRunsElevated = $false
            removesOnlyExactService = $true
            removesOnlyExactInstallRoot = $true
            removesOnlyExactLocalStateRoot = $true
            allowedLocalStateFiles = $allowedLocalStateFiles
            supportedLocalStateProfiles = @(
                'gate-b0', 'gate-b1', 'gate-c0b', 'gate-c0c', 'gate-c1'
            )
            allowsOnlyRecordedGateACommitWithoutLocalState =
                $legacyGateACommit
            deletesMachineIdentity = $false
            preservesMachineIdentityByDefault = $true
            collectorEnabled = $false
            telemetryEnabled = $false
            commandChannelEnabled = $false
        }
    })
    return
}

if ($Command -eq 'orphaned-state-cleanup' -and $WhatIfPreference) {
    Write-Json ([ordered]@{
        ok = $true
        command = 'orphaned-state-cleanup-plan'
        plan = [ordered]@{
            serviceName = $serviceName
            installRoot = $installRoot
            localStateRoot = $stateRoot
            requiresElevation = $true
            requiresCleanSource = $true
            requiresServiceAbsent = $true
            requiresInstallRootAbsent = $true
            requiresExactProtectedStateLayout = $true
            allowedLocalStateFiles = $allowedLocalStateFiles
            removesOnlyExactLocalStateRoot = $true
            deletesMachineIdentity = $false
            networkTransportEnabled = $false
            collectorEnabled = $false
            telemetryEnabled = $false
            commandChannelEnabled = $false
        }
    })
    return
}

if ($Command -eq 'orphaned-install-cleanup' -and $WhatIfPreference) {
    Write-Json ([ordered]@{
        ok = $true
        command = 'orphaned-install-cleanup-plan'
        plan = [ordered]@{
            serviceName = $serviceName
            installRoot = $installRoot
            localStateRoot = $stateRoot
            requiresElevation = $true
            requiresCleanSource = $true
            requiresServiceAbsent = $true
            requiresExactManifestAndHashes = $true
            requiresExactProtectedStateLayout = $true
            removesOnlyExactInstallRoot = $true
            removesOnlyExactLocalStateRoot = $true
            deletesMachineIdentity = $false
            networkTransportEnabled = $false
            collectorEnabled = $false
            telemetryEnabled = $false
            commandChannelEnabled = $false
        }
    })
    return
}

if ($Command -eq 'orphaned-install-cleanup') {
    Assert-Administrator
    $sourceCommit = Assert-CleanSource
    if ($null -ne (Get-ServiceRecord)) {
        throw 'SENSOR_ORPHANED_INSTALL_SERVICE_PRESENT'
    }
    if (-not (Test-Path -LiteralPath $installRoot -PathType Container)) {
        throw 'SENSOR_ORPHANED_INSTALL_ROOT_REQUIRED'
    }
    $manifest = Read-ValidatedInstallManifest
    $identityBefore = Assert-IdentityMatchesManifest -Manifest $manifest
    $localStatePresent = Test-Path -LiteralPath $stateRoot -PathType Container
    $stateProfile = 'legacy-gate-a'
    if ($localStatePresent) {
        Assert-ProtectedStateAcl
        $stateProfile = Assert-InstalledStateLayout
    }
    elseif ($manifest.commit -ne $legacyGateACommit) {
        throw 'SENSOR_LOCAL_STATE_REQUIRED'
    }
    if (-not $PSCmdlet.ShouldProcess(
        $serviceName,
        'Resume only the interrupted verified uninstall; remove exact install and protected state roots while preserving machine identity'
    )) {
        return
    }
    Remove-CreatedInstallRoot
    if ($localStatePresent) {
        Remove-CreatedStateRoot
    }
    if (
        $null -ne (Get-ServiceRecord) -or
        (Test-Path -LiteralPath $installRoot) -or
        (Test-Path -LiteralPath $stateRoot)
    ) {
        throw 'SENSOR_ORPHANED_INSTALL_CLEANUP_INCOMPLETE'
    }
    $identityAfter = Assert-IdentityStatus
    if (
        $identityAfter.publicKeyFingerprintSha256 -ne
            $identityBefore.publicKeyFingerprintSha256
    ) {
        throw 'SENSOR_ORPHANED_INSTALL_IDENTITY_CHANGED'
    }
    Write-Json ([ordered]@{
        ok = $true
        command = 'orphaned-install-cleanup'
        result = [ordered]@{
            serviceAbsent = $true
            installRootRemoved = $true
            localStateRootRemoved = $localStatePresent
            localStateProfile = $stateProfile
            sourceCommit = $sourceCommit
            interruptedInstallCommit = $manifest.commit
            machineIdentityPreserved = $true
            identityFingerprintSha256 =
                $identityAfter.publicKeyFingerprintSha256
            networkTransportEnabled = $false
            collectorEnabled = $false
            telemetryEnabled = $false
            commandChannelEnabled = $false
        }
    })
    return
}

if ($Command -eq 'orphaned-state-cleanup') {
    Assert-Administrator
    $sourceCommit = Assert-CleanSource
    if ($null -ne (Get-ServiceRecord) -or
        (Test-Path -LiteralPath $installRoot)) {
        throw 'SENSOR_ORPHANED_STATE_PRECONDITION_INVALID'
    }
    $identityBefore = Assert-IdentityStatus
    if (-not (Test-Path -LiteralPath $stateRoot -PathType Container)) {
        Write-Json ([ordered]@{
            ok = $true
            command = 'orphaned-state-cleanup'
            result = [ordered]@{
                serviceAbsent = $true
                installRootAbsent = $true
                localStateRootRemoved = $false
                alreadyAbsent = $true
                sourceCommit = $sourceCommit
                machineIdentityPreserved = $true
                identityFingerprintSha256 =
                    $identityBefore.publicKeyFingerprintSha256
                networkTransportEnabled = $false
                collectorEnabled = $false
                telemetryEnabled = $false
                commandChannelEnabled = $false
            }
        })
        return
    }
    Assert-ProtectedStateAcl
    $stateProfile = Assert-InstalledStateLayout
    if (-not $PSCmdlet.ShouldProcess(
        $stateRoot,
        'Remove only the exact protected orphaned sensor state after service and install-root absence'
    )) {
        return
    }
    Remove-CreatedStateRoot
    if (Test-Path -LiteralPath $stateRoot) {
        throw 'SENSOR_ORPHANED_STATE_CLEANUP_INCOMPLETE'
    }
    $identityAfter = Assert-IdentityStatus
    if ($identityAfter.publicKeyFingerprintSha256 -ne
        $identityBefore.publicKeyFingerprintSha256) {
        throw 'SENSOR_ORPHANED_STATE_IDENTITY_CHANGED'
    }
    Write-Json ([ordered]@{
        ok = $true
        command = 'orphaned-state-cleanup'
        result = [ordered]@{
            serviceAbsent = $true
            installRootAbsent = $true
            localStateRootRemoved = $true
            alreadyAbsent = $false
            localStateProfile = $stateProfile
            sourceCommit = $sourceCommit
            machineIdentityPreserved = $true
            identityFingerprintSha256 =
                $identityAfter.publicKeyFingerprintSha256
            networkTransportEnabled = $false
            collectorEnabled = $false
            telemetryEnabled = $false
            commandChannelEnabled = $false
        }
    })
    return
}

if ($Command -eq 'status') {
    Write-Json ([ordered]@{
        ok = $true
        command = 'status'
        status = (Get-ServiceStatus)
    })
    return
}

if ($Command -eq 'runtime-check') {
    $runtime = Assert-SupportedRuntime
    Write-Json ([ordered]@{
        ok = $true
        command = 'runtime-check'
        result = $runtime
    })
    return
}

if ($Command -eq 'package-check') {
    [void](Assert-SupportedRuntime)
    Assert-ManifestTimestampParser
    Assert-ManifestTimestampJsonParser
    $packageCheckParent = Join-Path $buildRoot 'install-publish'
    $packageCheckRoot = Join-Path $packageCheckParent (
        [Guid]::NewGuid().ToString('N')
    )
    try {
        $packageCheck = New-ValidatedPublishPackage `
            -PublishRoot $packageCheckRoot
        Write-Json ([ordered]@{
            ok = $true
            command = 'package-check'
            result = [ordered]@{
                runtimeIdentifier = $runtimeIdentifier
                deploymentMode = $deploymentMode
                runtimeProfile = $runtimeProfile
                runtimeVersion = $packageCheck.RuntimeVersion
                fileCount = @($packageCheck.Files).Count
                packageBytes = $packageCheck.PackageBytes
                pdbIncluded = $false
                nestedDirectories = 0
            }
        })
    }
    finally {
        Remove-PublishRoot -Path $packageCheckRoot
    }
    return
}

if ($Command -eq 'restart-check') {
    Assert-Administrator
    $sourceCommit = Assert-CleanSource
    $record = Get-ServiceRecord
    Assert-ServiceConfiguration -Service $record
    $manifest = Read-ValidatedInstallManifest
    $identity = Assert-IdentityMatchesManifest -Manifest $manifest
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
    $bootTime = $operatingSystem.LastBootUpTime.ToUniversalTime()
    $installedAt = [DateTimeOffset]::Parse(
        [string]$manifest.generatedAt,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind
    ).UtcDateTime
    if ($bootTime -le $installedAt) {
        throw 'SENSOR_RESTART_NOT_OBSERVED'
    }
    if ($record.State -ne 'Stopped') {
        throw 'SENSOR_RESTART_EXPECTED_STOPPED_SERVICE'
    }
    if (-not $PSCmdlet.ShouldProcess(
        $serviceName,
        'Start the exact normal service after a verified machine reboot'
    )) {
        return
    }

    $startedAt = [DateTime]::UtcNow
    Start-Service -Name $serviceName
    Wait-ServiceState -State Running
    Start-Sleep -Seconds 3
    Wait-ServiceState -State Running
    $running = Get-ServiceRecord
    Assert-ServiceConfiguration -Service $running
    if (
        $running.State -ne 'Running' -or
        $running.ExitCode -ne 0 -or
        $running.ServiceSpecificExitCode -ne 0
    ) {
        throw 'SENSOR_RESTART_SERVICE_UNSTABLE'
    }
    Assert-NoSensorStartErrors -Since $startedAt

    Write-Json ([ordered]@{
        ok = $true
        command = 'restart-check'
        result = [ordered]@{
            serviceName = $serviceName
            state = 'Running'
            startMode = 'Manual'
            startIdentity = $expectedIdentity
            bootTimeUtc = $bootTime.ToString('O')
            installedAtUtc = $installedAt.ToString('O')
            restartObserved = $true
            serviceStartVerified = $true
            identityProfile = $identity.profile
            identityFingerprintSha256 =
                $identity.publicKeyFingerprintSha256
            installedCommit = $manifest.commit
            validationCommit = $sourceCommit
            deletesMachineIdentity = $false
            collectorEnabled = $false
            telemetryEnabled = $false
            commandChannelEnabled = $false
        }
    })
    return
}

if ($Command -eq 'source-readiness-check') {
    Assert-Administrator
    $sourceCommit = Assert-CleanSource
    $record = Get-ServiceRecord
    Assert-ServiceConfiguration -Service $record
    $manifest = Read-ValidatedInstallManifest
    $identity = Assert-IdentityMatchesManifest -Manifest $manifest
    Assert-InstalledServiceSourceMatches -Manifest $manifest `
        -SourceCommit $sourceCommit
    if (-not $PSCmdlet.ShouldProcess(
        $serviceName,
        'Restart the exact normal service and validate its fixed LocalService System/Application metadata startup gate'
    )) {
        return
    }

    if ($record.State -ne 'Stopped') {
        Stop-Service -Name $serviceName
        Wait-ServiceState -State Stopped
    }
    $stopped = Get-ServiceRecord
    Assert-ServiceConfiguration -Service $stopped
    Start-Service -Name $serviceName
    Wait-ServiceState -State Running
    Start-Sleep -Seconds 3
    Wait-ServiceState -State Running
    $running = Get-ServiceRecord
    Assert-ServiceConfiguration -Service $running
    if (
        $running.ExitCode -ne 0 -or
        $running.ServiceSpecificExitCode -ne 0
    ) {
        throw 'SENSOR_SOURCE_READINESS_SERVICE_UNSTABLE'
    }

    Write-Json ([ordered]@{
        ok = $true
        command = 'source-readiness-check'
        result = [ordered]@{
            serviceName = $serviceName
            startIdentity = $expectedIdentity
            serviceIdentityValidated = $true
            installedCommit = $manifest.commit
            validationCommit = $sourceCommit
            installedServiceSourceCommit = $manifest.commit
            allowedLogs = @('System', 'Application')
            gateAEventsRead = 0
            maximumNormalStartupEventsRead = 1
            genuineEventReaderMayRunIfProofEmpty = $true
            rawEventContentRead = $false
            collectorEnabled = $false
            telemetryEnabled = $false
            commandChannelEnabled = $false
            servicePathChanged = $false
            normalStartupGateValidated = $true
            identityProfile = $identity.profile
            identityFingerprintSha256 =
                $identity.publicKeyFingerprintSha256
        }
    })
    return
}

if ($Command -eq 'local-batch-check') {
    Assert-Administrator
    $sourceCommit = Assert-CleanSource
    $record = Get-ServiceRecord
    Assert-ServiceConfiguration -Service $record
    $manifest = Read-ValidatedInstallManifest
    $identity = Assert-IdentityMatchesManifest -Manifest $manifest
    Assert-InstalledServiceSourceMatches -Manifest $manifest `
        -SourceCommit $sourceCommit
    Assert-ProtectedStateAcl
    Assert-ProtectedLocalProofAcl
    $proof = Invoke-LocalSyntheticBatchCheck
    if (
        $proof.certificateFingerprintSha256 -ne
            $identity.publicKeyFingerprintSha256
    ) {
        throw 'SENSOR_LOCAL_PROOF_IDENTITY_MISMATCH'
    }

    Write-Json ([ordered]@{
        ok = $true
        command = 'local-batch-check'
        result = [ordered]@{
            serviceName = $serviceName
            startIdentity = $expectedIdentity
            installedCommit = $manifest.commit
            validationCommit = $sourceCommit
            proofMode = $proof.proofMode
            generatedAtUtc = $proof.generatedAtUtc
            identityFingerprintSha256 =
                $proof.certificateFingerprintSha256
            batchCount = $proof.batchCount
            firstBatchHash = $proof.firstBatchHash
            lastBatchHash = $proof.lastBatchHash
            signatureVerified = $true
            continuityVerified = $true
            syntheticOnly = $true
            eventsRead = 0
            eventReaderEnabled = $false
            networkTransportEnabled = $false
            inboundListenerEnabled = $false
            commandChannelEnabled = $false
            serviceMutated = $false
        }
    })
    return
}

if ($Command -eq 'genuine-batch-check') {
    Assert-Administrator
    $sourceCommit = Assert-CleanSource
    $record = Get-ServiceRecord
    Assert-ServiceConfiguration -Service $record
    $manifest = Read-ValidatedInstallManifest
    $identity = Assert-IdentityMatchesManifest -Manifest $manifest
    Assert-InstalledServiceSourceMatches -Manifest $manifest `
        -SourceCommit $sourceCommit
    Assert-ProtectedStateAcl
    $stateProfile = Assert-InstalledStateLayout
    if ($stateProfile -ne 'gate-b1') {
        throw 'SENSOR_GENUINE_STATE_REQUIRED'
    }
    $proof = Invoke-LocalGenuineBatchCheck
    if (
        $proof.certificateFingerprintSha256 -ne
            $identity.publicKeyFingerprintSha256 -or
        (
            $proof.machineProofComplete -and
            $proof.manifestGeneratedAtUtc -ne $manifest.generatedAt
        )
    ) {
        throw 'SENSOR_GENUINE_PROOF_BINDING_MISMATCH'
    }

    Write-Json ([ordered]@{
        ok = $true
        command = 'genuine-batch-check'
        result = [ordered]@{
            serviceName = $serviceName
            startIdentity = $expectedIdentity
            installedCommit = $manifest.commit
            validationCommit = $sourceCommit
            proofMode = $proof.proofMode
            status = $proof.status
            machineProofComplete = $proof.machineProofComplete
            identityFingerprintSha256 =
                $proof.certificateFingerprintSha256
            generatedAtUtc = $proof.generatedAtUtc
            manifestGeneratedAtUtc = $proof.manifestGeneratedAtUtc
            occurredAtUtc = $proof.occurredAtUtc
            sourceRecordIdHash = $proof.sourceRecordIdHash
            batchHash = $proof.batchHash
            batchCount = $proof.batchCount
            factCount = $proof.factCount
            eventsRead = $proof.eventsRead
            genuineEventRead = $proof.genuineEventRead
            rawEventContentRead = $false
            runtimeProofEventReaderEnabled = $true
            checkerEventReaderEnabled = $false
            networkTransportEnabled = $false
            inboundListenerEnabled = $false
            pollingEnabled = $false
            commandChannelEnabled = $false
            serviceMutated = $false
        }
    })
    return
}

if ($Command -eq 'bounded-collector-check') {
    Assert-Administrator
    $sourceCommit = Assert-CleanSource
    $record = Get-ServiceRecord
    Assert-ServiceConfiguration -Service $record
    $manifest = Read-ValidatedInstallManifest
    $identity = Assert-IdentityMatchesManifest -Manifest $manifest
    Assert-InstalledServiceSourceMatches -Manifest $manifest `
        -SourceCommit $sourceCommit
    Assert-ProtectedStateAcl
    $stateProfile = Assert-InstalledStateLayout
    if ($stateProfile -ne 'gate-c1') {
        throw 'SENSOR_C1_STATE_REQUIRED'
    }
    $proof = Invoke-LocalBoundedCollectorCheck
    if (
        $proof.certificateFingerprintSha256 -ne
            $identity.publicKeyFingerprintSha256 -or
        (
            $proof.machineProofComplete -and
            $proof.manifestGeneratedAtUtc -ne $manifest.generatedAt
        )
    ) {
        throw 'SENSOR_C1_PROOF_BINDING_MISMATCH'
    }

    Write-Json ([ordered]@{
        ok = $true
        command = 'bounded-collector-check'
        result = [ordered]@{
            serviceName = $serviceName
            startIdentity = $expectedIdentity
            installedCommit = $manifest.commit
            validationCommit = $sourceCommit
            proofMode = $proof.proofMode
            status = $proof.status
            machineProofComplete = $proof.machineProofComplete
            identityFingerprintSha256 =
                $proof.certificateFingerprintSha256
            generatedAtUtc = $proof.generatedAtUtc
            manifestGeneratedAtUtc = $proof.manifestGeneratedAtUtc
            proofHash = $proof.proofHash
            familiesQueried = $proof.familiesQueried
            eventsRead = $proof.eventsRead
            matchCount = $proof.matchCount
            noMatchCount = $proof.noMatchCount
            failureCount = $proof.failureCount
            rawEventContentRead = $false
            runtimeProofEventReaderEnabled = $true
            checkerEventReaderEnabled = $false
            lossState = 'unknown'
            continuityState = 'unknown'
            networkTransportEnabled = $false
            automaticRetryEnabled = $false
            pollingEnabled = $false
            inboundListenerEnabled = $false
            commandChannelEnabled = $false
            responseActionsEnabled = $false
            serviceMutated = $false
        }
    })
    return
}

if ($Command -eq 'uninstall') {
    Assert-Administrator
    $record = Get-ServiceRecord
    Assert-ServiceConfiguration -Service $record
    $manifest = Read-ValidatedInstallManifest
    $localStatePresent = Test-Path -LiteralPath $stateRoot -PathType Container
    $stateProfile = 'legacy-gate-a'
    if ($localStatePresent) {
        Assert-ProtectedStateAcl
        $stateProfile = Assert-InstalledStateLayout
    }
    elseif ($manifest.commit -ne $legacyGateACommit) {
        throw 'SENSOR_LOCAL_STATE_REQUIRED'
    }
    if (-not $PSCmdlet.ShouldProcess(
        $serviceName,
        'Remove only the exact service and verified install directory; preserve the machine identity'
    )) {
        return
    }
    $sealedPackage = Read-SealedPackageManifest -Root $PackageRoot `
        -ExpectedSeal $PackageSealSha256
    $sourceCommit = [string]$sealedPackage.Manifest.commit
    $uninstallStageRoot = $null
    try {
        $uninstallStageRoot = Copy-ToProtectedPackageStage `
            -Package $sealedPackage
        $identityBefore = Get-ProtectedPackageIdentityStatus `
            -StageRoot $uninstallStageRoot
        if (
            $identityBefore.publicKeyFingerprintSha256 -ne
                $manifest.identityFingerprintSha256
        ) {
            throw 'SENSOR_IDENTITY_MANIFEST_MISMATCH'
        }

        if ($record.State -ne 'Stopped') {
            Stop-Service -Name $serviceName
            Wait-ServiceState -State Stopped
        }
        $stopped = Get-ServiceRecord
        Assert-ServiceConfiguration -Service $stopped
        $deleteResult = Invoke-CimMethod -InputObject $stopped -MethodName Delete
        if ($deleteResult.ReturnValue -ne 0) {
            throw "SENSOR_SERVICE_DELETE_FAILED_$($deleteResult.ReturnValue)"
        }
        Wait-ServiceDeleted
        Remove-CreatedInstallRoot
        if ($localStatePresent) {
            Remove-CreatedStateRoot
        }
        if (
            $null -ne (Get-ServiceRecord) -or
            (Test-Path -LiteralPath $installRoot) -or
            (Test-Path -LiteralPath $stateRoot)
        ) {
            throw 'SENSOR_UNINSTALL_INCOMPLETE'
        }
        $identityAfter = Get-ProtectedPackageIdentityStatus `
            -StageRoot $uninstallStageRoot
        if (
            $identityAfter.publicKeyFingerprintSha256 -ne
                $identityBefore.publicKeyFingerprintSha256
        ) {
            throw 'SENSOR_UNINSTALL_IDENTITY_CHANGED'
        }

        Write-Json ([ordered]@{
            ok = $true
            command = 'uninstall'
            result = [ordered]@{
                serviceName = $serviceName
                serviceRemoved = $true
                installRootRemoved = $true
                localStateRootRemoved = $localStatePresent
                localStateProfile = $stateProfile
                legacyGateAStateAbsent = (-not $localStatePresent)
                machineIdentityPreserved = $true
                identityProfile = $identityAfter.profile
                identityFingerprintSha256 =
                    $identityAfter.publicKeyFingerprintSha256
                installedCommit = $manifest.commit
                uninstallCommit = $sourceCommit
                packageSealSha256 = $sealedPackage.Seal
                auditWitnessProtectedFilePreserved = $true
                collectorEnabled = $false
                telemetryEnabled = $false
                commandChannelEnabled = $false
            }
        })
    }
    finally {
        Remove-ProtectedPackageStage -Path $uninstallStageRoot
    }
    return
}

if (-not $PSCmdlet.ShouldProcess(
    $serviceName,
    'Install and start the exact sealed one-shot bounded-metadata LocalService package'
)) {
    return
}

Assert-Administrator
[void](Assert-SupportedRuntime)
if ($null -ne (Get-ServiceRecord)) {
    throw 'SENSOR_SERVICE_ALREADY_EXISTS'
}
if (Test-Path -LiteralPath $installRoot) {
    throw 'SENSOR_INSTALL_ROOT_ALREADY_EXISTS'
}
if (Test-Path -LiteralPath $stateRoot) {
    throw 'SENSOR_LOCAL_STATE_ROOT_ALREADY_EXISTS'
}

$sealedPackage = Read-SealedPackageManifest -Root $PackageRoot `
    -ExpectedSeal $PackageSealSha256
$commit = [string]$sealedPackage.Manifest.commit
$stageRoot = $null
$installCreated = $false
$stateCreated = $false
$serviceCreated = $false
$serviceSidChanged = $false
$serviceSidPrevious = $null
try {
    $stageRoot = Copy-ToProtectedPackageStage -Package $sealedPackage
    $identityStatus = Get-ProtectedPackageIdentityStatus -StageRoot $stageRoot
    $auditWitnessInstall = Invoke-ProtectedAuditWitnessInstaller `
        -StageRoot $stageRoot
    $auditWitnessCheck = Invoke-ProtectedAuditWitnessChecker `
        -StageRoot $stageRoot
    if (
        $auditWitnessInstall.status.fileIdentity -cne
            $auditWitnessCheck.fileIdentity -or
        [long]$auditWitnessInstall.status.fileLength -ne
            [long]$auditWitnessCheck.fileLength
    ) {
        throw 'SENSOR_AUDIT_WITNESS_INDEPENDENT_CHECK_MISMATCH'
    }
    $protectedSensorRoot = Join-Path $stageRoot 'sensor'
    $runtimeVersion = Assert-PublishRuntimeProfile `
        -PublishRoot $protectedSensorRoot
    $publishedFiles = [System.IO.FileInfo[]]@(
        Get-ChildItem -LiteralPath $protectedSensorRoot -File -Force |
            Sort-Object Name
    )
    $packageBytes = [long](
        ($publishedFiles | Measure-Object -Property Length -Sum).Sum
    )

    [void](New-Item -ItemType Directory -Path $installRoot)
    $installCreated = $true
    $installItem = Get-Item -LiteralPath $installRoot -Force
    if (
        ($installItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw 'SENSOR_INSTALL_REPARSE_POINT_DENIED'
    }
    Set-ProtectedInstallAcl
    Assert-ProtectedInstallAcl

    foreach ($file in $publishedFiles) {
        $destination = Join-Path $installRoot $file.Name
        Copy-Item -LiteralPath $file.FullName -Destination $destination
        Set-ProtectedFileAcl -Path $destination
    }
    Assert-InstalledPackage -PublishedFiles $publishedFiles

    $manifestFiles = @(
        Get-ChildItem -LiteralPath $installRoot -File |
            Sort-Object Name |
            ForEach-Object {
                [ordered]@{
                    name = $_.Name
                    bytes = $_.Length
                    sha256 = (
                        Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
                    ).Hash.ToLowerInvariant()
                }
            }
    )
    $manifest = [ordered]@{
        schemaVersion = 2
        commit = $commit
        serviceName = $serviceName
        startIdentity = $expectedIdentity
        runtimeIdentifier = $runtimeIdentifier
        deploymentMode = $deploymentMode
        runtimeProfile = $runtimeProfile
        runtimeVersion = $runtimeVersion
        packageBytes = $packageBytes
        identityProfile = $identityStatus.profile
        identityFingerprintSha256 =
            $identityStatus.publicKeyFingerprintSha256
        bindingDescriptorSha256 =
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        generatedAt = [DateTime]::UtcNow.ToString('O')
        files = $manifestFiles
    }
    $manifestJson = $manifest | ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText(
        (Join-Path $installRoot 'install-manifest.json'),
        $manifestJson,
        [Text.UTF8Encoding]::new($false)
    )
    Set-ProtectedFileAcl -Path (
        Join-Path $installRoot 'install-manifest.json'
    )
    Assert-ProtectedFileAcl -Path (
        Join-Path $installRoot 'install-manifest.json'
    )
    Assert-ProtectedInstallAcl

    $createResult = Invoke-CimMethod -ClassName Win32_Service `
        -MethodName Create `
        -Arguments $serviceCreateArguments
    if ($createResult.ReturnValue -ne 0) {
        throw "SENSOR_SERVICE_CREATE_FAILED_$($createResult.ReturnValue)"
    }
    $serviceCreated = $true

    $record = Get-ServiceRecord
    if (
        $null -eq $record -or
        $record.StartName -ne $expectedIdentity -or
        $record.StartMode -ne 'Manual' -or
        $record.PathName -ne "`"$serviceExecutable`""
    ) {
        throw 'SENSOR_SERVICE_CONFIGURATION_INVALID'
    }

    $serviceSidApply = Invoke-ProtectedServiceSidTool `
        -StageRoot $stageRoot `
        -ToolCommand 'apply-unrestricted'
    $serviceSidPrevious = [uint32]$serviceSidApply.previousSidType
    $serviceSidChanged = [bool]$serviceSidApply.changed
    if (
        [uint32]$serviceSidApply.currentSidType -ne 1 -or
        (
            $serviceSidChanged -and
            $serviceSidPrevious -notin @([uint32]0, [uint32]3)
        ) -or
        (
            -not $serviceSidChanged -and
            $serviceSidPrevious -ne [uint32]1
        )
    ) {
        throw 'SENSOR_SERVICE_SID_APPLY_RESULT_INVALID'
    }

    $stateParent = Split-Path -Parent $stateRoot
    if (Test-Path -LiteralPath $stateParent) {
        $stateParentItem = Get-Item -LiteralPath $stateParent -Force
        if (
            -not $stateParentItem.PSIsContainer -or
            ($stateParentItem.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0
        ) {
            throw 'SENSOR_LOCAL_STATE_PARENT_INVALID'
        }
    }
    [void](New-Item -ItemType Directory -Path $stateRoot -Force)
    $stateCreated = $true
    $stateItem = Get-Item -LiteralPath $stateRoot -Force
    if (
        -not $stateItem.PSIsContainer -or
        ($stateItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw 'SENSOR_LOCAL_STATE_REPARSE_POINT_DENIED'
    }
    Set-ProtectedStateAcl
    [IO.File]::WriteAllBytes($localProofPath, [byte[]]@())
    Set-ProtectedLocalProofAcl
    [IO.File]::WriteAllBytes($genuineProofPath, [byte[]]@())
    Set-ProtectedLocalProofAcl -Path $genuineProofPath
    [IO.File]::WriteAllBytes($boundedProofPath, [byte[]]@())
    Set-ProtectedLocalProofAcl -Path $boundedProofPath
    $salt = [byte[]]::new(32)
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $random.GetBytes($salt)
        [IO.File]::WriteAllBytes($genuineSaltPath, $salt)
    }
    finally {
        $random.Dispose()
        [Array]::Clear($salt, 0, $salt.Length)
    }
    Set-ProtectedGenuineSaltAcl
    [IO.File]::WriteAllBytes($endpointBindingPath, [byte[]]@())
    Set-ProtectedDescriptorAcl -Path $endpointBindingPath
    [IO.File]::WriteAllBytes($capabilityProofPath, [byte[]]@())
    Set-ProtectedLocalProofAcl -Path $capabilityProofPath
    [IO.File]::WriteAllBytes($loopbackDeliveryPath, [byte[]]@())
    Set-ProtectedLocalProofAcl -Path $loopbackDeliveryPath
    Assert-ProtectedStateAcl
    Assert-ProtectedLocalProofAcl
    Assert-ProtectedLocalProofAcl -Path $genuineProofPath
    Assert-ProtectedLocalProofAcl -Path $boundedProofPath
    Assert-ProtectedGenuineSaltAcl
    Assert-ProtectedDescriptorAcl -Path $endpointBindingPath
    Assert-ProtectedLocalProofAcl -Path $capabilityProofPath
    Assert-ProtectedLocalProofAcl -Path $loopbackDeliveryPath

    Start-Service -Name $serviceName
    Wait-ServiceState -State Running
    Start-Sleep -Seconds 2
    Wait-ServiceState -State Running
    Stop-Service -Name $serviceName
    Wait-ServiceState -State Stopped
    Start-Service -Name $serviceName
    Wait-ServiceState -State Running
    Start-Sleep -Seconds 2
    Wait-ServiceState -State Running
    Assert-ProtectedStateAcl
    Assert-ProtectedLocalProofAcl
    Assert-ProtectedLocalProofAcl -Path $genuineProofPath
    Assert-ProtectedLocalProofAcl -Path $boundedProofPath
    Assert-ProtectedGenuineSaltAcl
    Assert-ProtectedDescriptorAcl -Path $endpointBindingPath
    Assert-ProtectedLocalProofAcl -Path $capabilityProofPath
    Assert-ProtectedLocalProofAcl -Path $loopbackDeliveryPath
    Write-Json ([ordered]@{
        ok = $true
        command = 'install'
        result = [ordered]@{
            serviceName = $serviceName
            displayName = $displayName
            state = 'Running'
            startMode = 'Manual'
            startIdentity = $expectedIdentity
            runtimeIdentifier = $runtimeIdentifier
            deploymentMode = $deploymentMode
            runtimeProfile = $runtimeProfile
            runtimeVersion = $runtimeVersion
            packageBytes = $packageBytes
            installRoot = $installRoot
            localStateRoot = $stateRoot
            commit = $commit
            fileCount = $manifestFiles.Count
            identityProfile = $identityStatus.profile
            identityFingerprintSha256 =
                $identityStatus.publicKeyFingerprintSha256
            aclVerified = $true
            serviceRestartVerified = $true
            serviceSidType = 'SERVICE_SID_TYPE_UNRESTRICTED'
            serviceSidReadBackVerified = $true
            privateExportBlocked = $true
            packageSealSha256 = $sealedPackage.Seal
            protectedStagingVerified = $true
            auditWitnessProtectedFileInstalled = $true
            auditWitnessIndependentCheckVerified = $true
            auditWitnessExistingHistoryPreserved =
                [bool]$auditWitnessInstall.existingHistoryPreserved
            auditWitnessFileLength = [long]$auditWitnessCheck.fileLength
            auditWitnessFileIdentity = $auditWitnessCheck.fileIdentity
            auditWitnessClaim = $auditWitnessCheck.claim
            auditWitnessRuntimeWiringEnabled = $false
            syntheticBatchProofVerified = $false
            genuineMachineProofComplete = $false
            boundedMachineProofComplete = $false
            rawEventContentRead = $false
            eventReaderEnabled = $true
            continuousCollectorEnabled = $false
            oneShotLoopbackTransportRegistered = $true
            automaticRetryEnabled = $false
            remoteTransportEnabled = $false
            networkTransportEnabled = $false
            inboundListenerEnabled = $false
            pollingEnabled = $false
            boundedOneShotCollectorEnabled = $true
            collectorEnabled = $false
            telemetryEnabled = $false
            commandChannelEnabled = $false
        }
    })
}
catch {
    $failure = $_
    $serviceSidRollbackFailure = $null
    if ($serviceCreated -and $serviceSidChanged) {
        try {
            $rollbackCommand = switch ([uint32]$serviceSidPrevious) {
                0 { 'restore-none' }
                3 { 'restore-restricted' }
                default { throw 'SENSOR_SERVICE_SID_ROLLBACK_TYPE_INVALID' }
            }
            $serviceSidRollback = Invoke-ProtectedServiceSidTool `
                -StageRoot $stageRoot `
                -ToolCommand $rollbackCommand
            if (
                [uint32]$serviceSidRollback.currentSidType -ne
                    [uint32]$serviceSidPrevious
            ) {
                throw 'SENSOR_SERVICE_SID_ROLLBACK_RESULT_INVALID'
            }
        }
        catch {
            $serviceSidRollbackFailure = $_
        }
    }
    if ($serviceCreated) {
        Remove-CreatedService
    }
    if ($installCreated) {
        Remove-CreatedInstallRoot
    }
    if ($stateCreated) {
        Remove-CreatedStateRoot
    }
    if ($null -ne $serviceSidRollbackFailure) {
        throw $serviceSidRollbackFailure
    }
    throw $failure
}
finally {
    Remove-ProtectedPackageStage -Path $stageRoot
}
