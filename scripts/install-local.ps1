[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$DataRoot = (Join-Path $HOME '.war-room-project15'),
    [switch]$SkipDependencies
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$resolvedDataRoot = [IO.Path]::GetFullPath($DataRoot)
$evidenceRoot = Join-Path $resolvedDataRoot 'evidence'

if (-not (Get-Command node.exe -ErrorAction SilentlyContinue)) {
    throw 'Node.js 24.12 or newer is required.'
}
$nodeVersion = [version]((& node.exe -p 'process.versions.node').Trim())
if ($nodeVersion -lt [version]'24.12.0') {
    throw "Node.js 24.12 or newer is required; found version $nodeVersion."
}
if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) {
    throw 'npm is required.'
}

Push-Location $root
try {
    if ($PSCmdlet.ShouldProcess($resolvedDataRoot, 'Create protected WAR-R00M runtime directories')) {
        New-Item -ItemType Directory -Force -Path $resolvedDataRoot, $evidenceRoot | Out-Null
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        & icacls.exe $resolvedDataRoot '/inheritance:r' '/grant:r' "$identity`:(OI)(CI)F" '/grant:r' '*S-1-5-18:(OI)(CI)F' | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Runtime ACL protection failed with exit code $LASTEXITCODE"
        }
    }
    if (-not $SkipDependencies -and $PSCmdlet.ShouldProcess($root, 'Install locked dependencies')) {
        & npm.cmd ci
        if ($LASTEXITCODE -ne 0) {
            throw "npm ci failed with exit code $LASTEXITCODE"
        }
    }
    if ($PSCmdlet.ShouldProcess($root, 'Build WAR-R00M production assets')) {
        & npm.cmd run build
        if ($LASTEXITCODE -ne 0) {
            throw "Build failed with exit code $LASTEXITCODE"
        }
    }
    Write-Host "WAR-R00M local setup is ready." -ForegroundColor Green
    Write-Host "Runtime data: $resolvedDataRoot"
    Write-Host "Start with: .\scripts\start-local.ps1"
}
finally {
    Pop-Location
}
