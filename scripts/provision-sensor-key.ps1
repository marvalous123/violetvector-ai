[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$KeyRoot = (Join-Path $env:ProgramData 'WAR-R00M\Sensor'),
    [string]$RuntimeDataRoot = (Join-Path $HOME '.war-room-project15')
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$resolvedProjectRoot = [IO.Path]::GetFullPath($projectRoot)
$resolvedRuntimeRoot = [IO.Path]::GetFullPath($RuntimeDataRoot)
$resolvedKeyRoot = [IO.Path]::GetFullPath($KeyRoot)
$allowedKeyRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'WAR-R00M'))

function Test-PathInside {
    param([string]$Child, [string]$Parent)
    $parentWithSeparator = $Parent.TrimEnd('\') + '\'
    return $Child.Equals($Parent, [StringComparison]::OrdinalIgnoreCase) -or
        $Child.StartsWith($parentWithSeparator, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-NoReparseComponents {
    param([string]$Path, [string]$StopAt)
    $current = [IO.DirectoryInfo]::new($Path)
    while ($null -ne $current -and (Test-PathInside -Child $current.FullName -Parent $StopAt)) {
        if (Test-Path -LiteralPath $current.FullName) {
            $item = Get-Item -LiteralPath $current.FullName -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Reparse-point directories are forbidden in the sensor key path: $($current.FullName)"
            }
        }
        if ($current.FullName.Equals($StopAt, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $current = $current.Parent
    }
}

if (
    -not (Test-PathInside -Child $resolvedKeyRoot -Parent $allowedKeyRoot) -or
    (Test-PathInside -Child $resolvedKeyRoot -Parent $resolvedProjectRoot) -or
    (Test-PathInside -Child $resolvedKeyRoot -Parent $resolvedRuntimeRoot)
) {
    throw 'Sensor key root must remain under ProgramData\WAR-R00M and outside the repository and runtime data.'
}
Assert-NoReparseComponents -Path $resolvedKeyRoot -StopAt $allowedKeyRoot

$privateKeyPath = Join-Path $resolvedKeyRoot 'identity-ed25519.pk8'
$descriptorPath = Join-Path $resolvedKeyRoot 'identity-public.json'
$tsxEntrypoint = Join-Path $resolvedProjectRoot 'node_modules\tsx\dist\cli.mjs'
if (-not (Test-Path -LiteralPath $tsxEntrypoint -PathType Leaf)) {
    throw 'The reviewed local tsx runtime is missing. Run the project setup before provisioning.'
}
if (-not $PSCmdlet.ShouldProcess($resolvedKeyRoot, 'Provision protected WAR-R00M sensor identity')) {
    return
}

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator elevation is required to provision the LocalService sensor identity.'
}

$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$administratorsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$localServiceSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-19')
$inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$propagation = [Security.AccessControl.PropagationFlags]::None
$allow = [Security.AccessControl.AccessControlType]::Allow

if (-not (Test-Path -LiteralPath $resolvedKeyRoot)) {
    [void](New-Item -ItemType Directory -Path $resolvedKeyRoot)
}
Assert-NoReparseComponents -Path $resolvedKeyRoot -StopAt $allowedKeyRoot
$directoryAcl = [Security.AccessControl.DirectorySecurity]::new()
$directoryAcl.SetAccessRuleProtection($true, $false)
$directoryAcl.SetOwner($administratorsSid)
$directoryAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    $systemSid,
    [Security.AccessControl.FileSystemRights]::FullControl,
    $inheritance,
    $propagation,
    $allow
))
$directoryAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    $administratorsSid,
    [Security.AccessControl.FileSystemRights]::FullControl,
    $inheritance,
    $propagation,
    $allow
))
$directoryAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    $localServiceSid,
    [Security.AccessControl.FileSystemRights]::ReadAndExecute,
    $inheritance,
    $propagation,
    $allow
))
Set-Acl -LiteralPath $resolvedKeyRoot -AclObject $directoryAcl

Push-Location $resolvedProjectRoot
try {
    & node.exe $tsxEntrypoint apps/sensor/src/provision-windows-key.ts `
        generate `
        $privateKeyPath `
        $descriptorPath `
        $resolvedProjectRoot `
        $resolvedRuntimeRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Sensor key generation failed with exit code $LASTEXITCODE"
    }

    foreach ($protectedFile in @($privateKeyPath, $descriptorPath)) {
        $fileAcl = [Security.AccessControl.FileSecurity]::new()
        $fileAcl.SetAccessRuleProtection($true, $false)
        $fileAcl.SetOwner($administratorsSid)
        $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $systemSid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $allow
        ))
        $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $administratorsSid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $allow
        ))
        $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $localServiceSid,
            [Security.AccessControl.FileSystemRights]::Read,
            $allow
        ))
        Set-Acl -LiteralPath $protectedFile -AclObject $fileAcl
    }

    & node.exe $tsxEntrypoint apps/sensor/src/provision-windows-key.ts `
        verify `
        $privateKeyPath `
        $descriptorPath `
        $resolvedProjectRoot `
        $resolvedRuntimeRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Sensor key protection verification failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}
