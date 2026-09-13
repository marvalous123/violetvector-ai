[CmdletBinding()]
param(
    [string]$DataRoot = (Join-Path $HOME '.war-room-project15'),
    [string]$OutputRoot = (Join-Path $HOME 'WAR-R00M Backups')
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$resolvedDataRoot = [IO.Path]::GetFullPath($DataRoot)
$resolvedOutputRoot = [IO.Path]::GetFullPath($OutputRoot)

Push-Location $root
try {
    & npx.cmd tsx apps/api/scripts/backup-local.ts $resolvedDataRoot $resolvedOutputRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Backup failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}
