[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$BackupRoot,

    [Parameter(Mandatory)]
    [string]$DestinationRoot
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$resolvedBackupRoot = [IO.Path]::GetFullPath($BackupRoot)
$resolvedDestinationRoot = [IO.Path]::GetFullPath($DestinationRoot)

Push-Location $root
try {
    & npx.cmd tsx apps/api/scripts/restore-local.ts $resolvedBackupRoot $resolvedDestinationRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Restore failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}
