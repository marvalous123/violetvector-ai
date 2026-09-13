[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateSet(
        'plan', 'install-pending', 'finalize', 'check-pending', 'check-final',
        'deliver-once', 'check-delivery')]
    [string]$Command
)

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$serviceName = 'WARRoomWindowsSensor'
$expectedIdentity = 'NT AUTHORITY\LocalService'
$nativeRegistry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::LocalMachine,
    [Microsoft.Win32.RegistryView]::Registry64)
try {
    $versionKey = $nativeRegistry.OpenSubKey(
        'SOFTWARE\Microsoft\Windows\CurrentVersion', $false)
    if ($null -eq $versionKey) { throw 'SENSOR_NATIVE_PROGRAM_FILES_UNAVAILABLE' }
    try {
        $nativeProgramFiles = [string]$versionKey.GetValue(
            'ProgramFilesDir', $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    }
    finally { $versionKey.Dispose() }
}
finally { $nativeRegistry.Dispose() }
if ([string]::IsNullOrWhiteSpace($nativeProgramFiles) -or
    $nativeProgramFiles -notmatch '^[A-Za-z]:\\') {
    throw 'SENSOR_NATIVE_PROGRAM_FILES_INVALID'
}
$installRoot = Join-Path ([IO.Path]::GetFullPath($nativeProgramFiles)) `
    'WAR-R00M\Windows Sensor'
$nativeProgramData = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::CommonApplicationData)
if ([string]::IsNullOrWhiteSpace($nativeProgramData) -or
    $nativeProgramData -notmatch '^[A-Za-z]:\\') {
    throw 'SENSOR_NATIVE_PROGRAM_DATA_INVALID'
}
$stateRoot = Join-Path ([IO.Path]::GetFullPath($nativeProgramData)) `
    'WAR-R00M\Windows Sensor'
$manifestPath = Join-Path $installRoot 'install-manifest.json'
$bindingPath = Join-Path $stateRoot 'endpoint-binding.json'
$proofPath = Join-Path $stateRoot 'local-capability-proof.json'
$deliveryPath = Join-Path $stateRoot 'local-loopback-delivery.json'
$toolProject = Join-Path $projectRoot `
    'apps\windows-sensor\binding-tool\WARRoom.WindowsSensor.BindingTool.csproj'
$buildRoot = Join-Path $HOME '.codex-build\project15\windows-sensor'
$portableDotnet = Join-Path $HOME '.codex-build\toolchains\dotnet8\dotnet.exe'
$dotnet = if ($env:WAR_ROOM_DOTNET) { $env:WAR_ROOM_DOTNET }
elseif (Test-Path -LiteralPath $portableDotnet -PathType Leaf) { $portableDotnet }
else { (Get-Command dotnet -ErrorAction Stop).Source }

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )) {
            throw 'SENSOR_ADMINISTRATOR_REQUIRED'
        }
    }
    finally { $identity.Dispose() }
}

function Assert-RegularFixedFile {
    param([string]$Path, [long]$MaximumBytes)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'SENSOR_BINDING_STATE_FILE_INVALID'
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -gt $MaximumBytes
    ) { throw 'SENSOR_BINDING_STATE_FILE_INVALID' }
}

function Set-ExactBindingAcl {
    param(
        [string]$Path,
        [bool]$ProofWritable,
        [bool]$ReadExecute = $false
    )
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $service = [Security.Principal.SecurityIdentifier]::new('S-1-5-19')
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($admins)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $system, [Security.AccessControl.FileSystemRights]::FullControl, $allow))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $admins, [Security.AccessControl.FileSystemRights]::FullControl, $allow))
    $serviceRights = if ($ProofWritable) {
        [Security.AccessControl.FileSystemRights]::Read -bor
        [Security.AccessControl.FileSystemRights]::WriteData
    }
    elseif ($ReadExecute) {
        [Security.AccessControl.FileSystemRights]::ReadAndExecute
    }
    else { [Security.AccessControl.FileSystemRights]::Read }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $service, $serviceRights, $allow))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-ExactBindingAcl {
    param(
        [string]$Path,
        [bool]$ProofWritable,
        [bool]$ReadExecute = $false
    )
    $maximumBytes = if ($ReadExecute) { 1048576 } else { 32768 }
    Assert-RegularFixedFile -Path $Path -MaximumBytes $maximumBytes
    $acl = Get-Acl -LiteralPath $Path
    $owner = ([Security.Principal.NTAccount]$acl.Owner).Translate(
        [Security.Principal.SecurityIdentifier]).Value
    $rules = @($acl.GetAccessRules(
        $true, $false, [Security.Principal.SecurityIdentifier]))
    if ($owner -ne 'S-1-5-32-544' -or -not $acl.AreAccessRulesProtected -or
        $rules.Count -ne 3 -or @($rules | Where-Object { $_.IsInherited }).Count) {
        throw 'SENSOR_BINDING_ACL_INVALID'
    }
    $bySid = @{}
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne
            [Security.AccessControl.AccessControlType]::Allow -or
            $bySid.ContainsKey($rule.IdentityReference.Value)) {
            throw 'SENSOR_BINDING_ACL_INVALID'
        }
        $bySid[$rule.IdentityReference.Value] = $rule.FileSystemRights
    }
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        if (-not $bySid.ContainsKey($sid) -or
            ($bySid[$sid] -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
                [Security.AccessControl.FileSystemRights]::FullControl) {
            throw 'SENSOR_BINDING_ACL_INVALID'
        }
    }
    $required = if ($ProofWritable) {
        [Security.AccessControl.FileSystemRights]::Read -bor
        [Security.AccessControl.FileSystemRights]::WriteData
    }
    elseif ($ReadExecute) {
        [Security.AccessControl.FileSystemRights]::ReadAndExecute
    }
    else { [Security.AccessControl.FileSystemRights]::Read }
    $forbidden = [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    if (-not $ProofWritable -and -not $ReadExecute) {
        $forbidden = $forbidden -bor
            [Security.AccessControl.FileSystemRights]::ExecuteFile -bor
            [Security.AccessControl.FileSystemRights]::Write
    }
    if (-not $bySid.ContainsKey('S-1-5-19') -or
        ($bySid['S-1-5-19'] -band $required) -ne $required -or
        ($bySid['S-1-5-19'] -band $forbidden) -ne 0) {
        throw 'SENSOR_BINDING_ACL_INVALID'
    }
}

function Get-ExactManifestGeneratedAt {
    param([string]$Json)
    $pattern = '"generatedAt"\s*:\s*"(?<value>[0-9]{4}-[0-9]{2}-[0-9]{2}T' +
        '[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}Z)"'
    $properties = [Text.RegularExpressions.Regex]::Matches(
        $Json, '"generatedAt"\s*:',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    $matches = [Text.RegularExpressions.Regex]::Matches(
        $Json, $pattern,
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if ($properties.Count -ne 1 -or $matches.Count -ne 1) {
        throw 'SENSOR_MANIFEST_TIMESTAMP_JSON_INVALID'
    }
    return $matches[0].Groups['value'].Value
}

function Read-ValidatedContext {
    foreach ($root in @($installRoot, $stateRoot)) {
        if (-not (Test-Path -LiteralPath $root -PathType Container) -or
            ((Get-Item -LiteralPath $root -Force).Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'SENSOR_BINDING_FIXED_ROOT_INVALID'
        }
    }
    Assert-RegularFixedFile -Path $manifestPath -MaximumBytes 1048576
    Assert-RegularFixedFile -Path $bindingPath -MaximumBytes 32768
    Assert-RegularFixedFile -Path $proofPath -MaximumBytes 32768
    $service = Get-CimInstance -ClassName Win32_Service `
        -Filter "Name='$serviceName'" -ErrorAction Stop
    $expectedPath = '"' + (Join-Path $installRoot 'WARRoom.WindowsSensor.exe') + '"'
    if ($service.StartName -ne $expectedIdentity -or
        $service.StartMode -ne 'Manual' -or $service.PathName -ne $expectedPath) {
        throw 'SENSOR_SERVICE_CONFIGURATION_INVALID'
    }
    $sourceStatus = (& git.exe -C $projectRoot status --porcelain) -join "`n"
    $sourceCommit = (& git.exe -C $projectRoot rev-parse HEAD) -join ''
    if ($LASTEXITCODE -ne 0 -or -not [string]::IsNullOrWhiteSpace($sourceStatus) -or
        $sourceCommit -notmatch '^[a-f0-9]{40}$') {
        throw 'SENSOR_BINDING_SOURCE_NOT_CLEAN'
    }
    $manifestJson = Get-Content -Raw -LiteralPath $manifestPath
    $generatedAt = Get-ExactManifestGeneratedAt -Json $manifestJson
    $manifest = $manifestJson | ConvertFrom-Json
    $manifest.generatedAt = $generatedAt
    $expectedManifestProperties = @(
        'schemaVersion', 'commit', 'serviceName', 'startIdentity',
        'runtimeIdentifier', 'deploymentMode', 'runtimeProfile',
        'runtimeVersion', 'packageBytes', 'identityProfile',
        'identityFingerprintSha256', 'bindingDescriptorSha256',
        'generatedAt', 'files'
    )
    $actualManifestProperties = @($manifest.PSObject.Properties.Name)
    if ($manifest.schemaVersion -ne 2 -or $manifest.commit -ne $sourceCommit -or
        $actualManifestProperties.Count -ne $expectedManifestProperties.Count -or
        @($actualManifestProperties | Where-Object {
            $_ -notin $expectedManifestProperties
        }).Count -ne 0 -or
        [string]$manifest.bindingDescriptorSha256 -notmatch '^[a-f0-9]{64}$' -or
        (Get-FileHash -LiteralPath $bindingPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne
            $manifest.bindingDescriptorSha256) {
        throw 'SENSOR_BINDING_MANIFEST_INVALID'
    }
    Assert-ExactBindingAcl -Path $bindingPath -ProofWritable $false
    Assert-ExactBindingAcl -Path $proofPath -ProofWritable $true
    Assert-ExactBindingAcl -Path $manifestPath -ProofWritable $false `
        -ReadExecute $true
    return [pscustomobject]@{ Service = $service; Manifest = $manifest }
}

function Invoke-BindingTool {
    param([string]$ToolCommand, [string]$InputJson)
    $buildArguments = @(
        'build', $toolProject, '--nologo', '-c', 'Release',
        "-p:WarRoomBuildRoot=$buildRoot", '-p:NuGetAudit=false'
    )
    & $dotnet @buildArguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'SENSOR_BINDING_TOOL_BUILD_FAILED' }
    $toolAssembly = Join-Path $buildRoot (
        'bin\WARRoom.WindowsSensor.BindingTool\Release\net8.0-windows\' +
        'WARRoom.WindowsSensor.BindingTool.dll'
    )
    Assert-RegularFixedFile -Path $toolAssembly -MaximumBytes 1048576
    $arguments = @($toolAssembly, $ToolCommand)
    $lines = if ($null -eq $InputJson) {
        & $dotnet @arguments
    }
    else { $InputJson | & $dotnet @arguments }
    if ($LASTEXITCODE -ne 0) { throw 'SENSOR_BINDING_TOOL_FAILED' }
    try { return (($lines -join "`n") | ConvertFrom-Json) }
    catch { throw 'SENSOR_BINDING_TOOL_OUTPUT_INVALID' }
}

function Read-BoundedStandardInput {
    $inputJson = [Console]::In.ReadToEnd()
    if ([Text.Encoding]::UTF8.GetByteCount($inputJson) -gt 32768 -or
        [string]::IsNullOrWhiteSpace($inputJson)) {
        throw 'SENSOR_BINDING_INPUT_INVALID'
    }
    return $inputJson
}

function Get-Sha256Hex {
    param([byte[]]$Bytes)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $sha256.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally { $sha256.Dispose() }
}

function Write-DescriptorAndManifest {
    param([object]$ToolResult)
    if (-not $ToolResult.ok -or
        [string]$ToolResult.descriptorSha256 -notmatch '^[a-f0-9]{64}$') {
        throw 'SENSOR_BINDING_TOOL_OUTPUT_INVALID'
    }
    try { $bytes = [Convert]::FromBase64String($ToolResult.descriptorBase64) }
    catch { throw 'SENSOR_BINDING_TOOL_OUTPUT_INVALID' }
    if ($bytes.Length -lt 1 -or $bytes.Length -gt 32768 -or
        (Get-Sha256Hex -Bytes $bytes) -ne $ToolResult.descriptorSha256) {
        throw 'SENSOR_BINDING_TOOL_OUTPUT_INVALID'
    }
    $oldBinding = [IO.File]::ReadAllBytes($bindingPath)
    $oldManifest = [IO.File]::ReadAllBytes($manifestPath)
    try {
        [IO.File]::WriteAllBytes($bindingPath, $bytes)
        Set-ExactBindingAcl -Path $bindingPath -ProofWritable $false
        $oldManifestJson = [Text.Encoding]::UTF8.GetString($oldManifest)
        $generatedAt = Get-ExactManifestGeneratedAt -Json $oldManifestJson
        $manifest = $oldManifestJson | ConvertFrom-Json
        $manifest.generatedAt = $generatedAt
        $manifest.bindingDescriptorSha256 = [string]$ToolResult.descriptorSha256
        [IO.File]::WriteAllText(
            $manifestPath,
            ($manifest | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))
        Set-ExactBindingAcl -Path $manifestPath -ProofWritable $false `
            -ReadExecute $true
        if ((Get-FileHash -LiteralPath $bindingPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ne $manifest.bindingDescriptorSha256) {
            throw 'SENSOR_BINDING_MANIFEST_WRITE_INVALID'
        }
    }
    catch {
        [IO.File]::WriteAllBytes($bindingPath, $oldBinding)
        [IO.File]::WriteAllBytes($manifestPath, $oldManifest)
        Set-ExactBindingAcl -Path $bindingPath -ProofWritable $false
        Set-ExactBindingAcl -Path $manifestPath -ProofWritable $false `
            -ReadExecute $true
        throw
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
        [Array]::Clear($oldBinding, 0, $oldBinding.Length)
        [Array]::Clear($oldManifest, 0, $oldManifest.Length)
    }
}

$timestampProbe = Get-ExactManifestGeneratedAt -Json `
    '{"generatedAt":"2026-08-03T12:00:00.0000000Z"}'
if ($timestampProbe -ne '2026-08-03T12:00:00.0000000Z') {
    throw 'SENSOR_MANIFEST_TIMESTAMP_JSON_INVALID'
}
$sha256Probe = Get-Sha256Hex -Bytes `
    ([Text.Encoding]::UTF8.GetBytes('WAR-R00M.C0b.SHA256.Probe.v1'))
if ($sha256Probe -ne
    'f7d02befbfd638c20ef0923fae762caf0db8b3ef5b23972ec5b8d62f6227d7c1') {
    throw 'SENSOR_BINDING_SHA256_RUNTIME_INVALID'
}

if ($Command -eq 'plan' -or
    ($WhatIfPreference -and $Command -in @('install-pending', 'finalize'))) {
    [ordered]@{
        ok = $true
        command = 'plan'
        plan = [ordered]@{
            fixedBindingPath = $bindingPath
            fixedCapabilityProofPath = $proofPath
            fixedDeliveryReceiptPath = $deliveryPath
            maximumInputBytes = 32768
            requiresElevation = $true
            requiresCleanMatchingInstalledCommit = $true
            oneNormalServiceStart = ($Command -eq 'install-pending')
            maximumEventReads = if ($Command -eq 'install-pending') { 1 } else { 0 }
            changesServiceConfiguration = $false
            networkTransportEnabled = $false
            collectorEnabled = $false
            telemetryEnabled = $false
            commandChannelEnabled = $false
        }
    } | ConvertTo-Json -Depth 5
    return
}

if ($WhatIfPreference -and $Command -eq 'deliver-once') {
    [ordered]@{
        ok = $true
        command = 'deliver-once-plan'
        plan = [ordered]@{
            fixedDestination =
                'http://127.0.0.1:4315/api/endpoints/facts'
            fixedDeliveryReceiptPath = $deliveryPath
            requiresElevation = $true
            requiresCleanMatchingInstalledCommit = $true
            requiresFreshFinalBinding = $true
            requiresEmptyProtectedReceipt = $true
            oneNormalServiceStart = $true
            maximumNetworkAttempts = 1
            maximumEventReads = 0
            automaticRetryEnabled = $false
            remoteTransportEnabled = $false
            inboundListenerEnabled = $false
            pollingEnabled = $false
            commandChannelEnabled = $false
        }
    } | ConvertTo-Json -Depth 5
    return
}

Assert-Administrator
$context = Read-ValidatedContext

if ($Command -in @('check-pending', 'check-final', 'check-delivery')) {
    $result = Invoke-BindingTool -ToolCommand $Command -InputJson $null
    Write-Output ($result | ConvertTo-Json -Depth 6)
    return
}


if ($Command -eq 'deliver-once') {
    if ($context.Service.State -ne 'Stopped') {
        throw 'SENSOR_DELIVERY_SERVICE_STATE_INVALID'
    }
    Assert-RegularFixedFile -Path $deliveryPath -MaximumBytes 8192
    Assert-ExactBindingAcl -Path $deliveryPath -ProofWritable $true
    if ((Get-Item -LiteralPath $deliveryPath -Force).Length -ne 0) {
        throw 'SENSOR_DELIVERY_RECEIPT_ALREADY_EXISTS'
    }
    [void](Invoke-BindingTool -ToolCommand 'check-final' -InputJson $null)
    if (-not $PSCmdlet.ShouldProcess(
        $serviceName,
        'Perform one exact Gate C0c loopback fact delivery attempt'
    )) { return }
    $started = $false
    try {
        Start-Service -Name $serviceName -ErrorAction Stop
        $started = $true
        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        do {
            Start-Sleep -Milliseconds 100
            $deliveryLength = (Get-Item -LiteralPath $deliveryPath -Force).Length
            $deliveryState = $null
            if ($deliveryLength -gt 0 -and $deliveryLength -le 8192) {
                try {
                    $deliveryState = [string](
                        (Get-Content -Raw -LiteralPath $deliveryPath |
                            ConvertFrom-Json).state
                    )
                }
                catch { $deliveryState = $null }
            }
        } while ($deliveryState -notin @('accepted', 'failed') -and
            [DateTime]::UtcNow -lt $deadline)
    }
    finally {
        if ($started -and
            (Get-Service -Name $serviceName -ErrorAction Stop).Status -ne
                [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            Stop-Service -Name $serviceName -ErrorAction Stop
        }
    }
    if ($deliveryLength -lt 1 -or $deliveryLength -gt 8192 -or
        $deliveryState -notin @('accepted', 'failed')) {
        throw 'SENSOR_DELIVERY_RECEIPT_NOT_WRITTEN'
    }
    Assert-ExactBindingAcl -Path $deliveryPath -ProofWritable $true
    $checked = Invoke-BindingTool -ToolCommand 'check-delivery' -InputJson $null
    Write-Output ($checked | ConvertTo-Json -Depth 6)
    return
}

$inputJson = Read-BoundedStandardInput
if (-not $PSCmdlet.ShouldProcess(
    $serviceName,
    "Write the exact protected Gate C0b $Command descriptor"
)) { return }

if ($context.Service.State -ne 'Stopped') {
    Stop-Service -Name $serviceName -ErrorAction Stop
}

if ($Command -eq 'install-pending') {
    $result = Invoke-BindingTool -ToolCommand 'create-pending' -InputJson $inputJson
    Write-DescriptorAndManifest -ToolResult $result
    [IO.File]::WriteAllBytes($proofPath, [byte[]]@())
    Set-ExactBindingAcl -Path $proofPath -ProofWritable $true
    $started = $false
    try {
        Start-Service -Name $serviceName
        $started = $true
        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        do {
            Start-Sleep -Milliseconds 100
            $proofLength = (Get-Item -LiteralPath $proofPath -Force).Length
        } while ($proofLength -eq 0 -and [DateTime]::UtcNow -lt $deadline)
    }
    finally {
        if ($started -and
            (Get-Service -Name $serviceName -ErrorAction Stop).Status -ne
                [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            Stop-Service -Name $serviceName -ErrorAction Stop
        }
    }
    if ($proofLength -lt 1 -or $proofLength -gt 32768) {
        throw 'SENSOR_CAPABILITY_PROOF_NOT_WRITTEN'
    }
    Assert-ExactBindingAcl -Path $proofPath -ProofWritable $true
    $checked = Invoke-BindingTool -ToolCommand 'check-pending' -InputJson $null
    Write-Output ($checked | ConvertTo-Json -Depth 6)
    return
}

$result = Invoke-BindingTool -ToolCommand 'finalize' -InputJson $inputJson
Write-DescriptorAndManifest -ToolResult $result
$checked = Invoke-BindingTool -ToolCommand 'check-final' -InputJson $null
Write-Output ($checked | ConvertTo-Json -Depth 6)
