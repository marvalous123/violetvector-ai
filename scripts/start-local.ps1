[CmdletBinding()]
param(
    [int]$Port = 4315
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$userProfileRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
$buildRoot = Join-Path $userProfileRoot '.codex-build\project15\web'
$dataRoot = Join-Path $userProfileRoot '.war-room-project15'
$previousBootstrap = $env:WAR_ROOM_OPERATOR_BOOTSTRAP
$generatedBootstrap = $false
$secretBytes = $null

Push-Location $root
try {
    & npm.cmd run build
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed with exit code $LASTEXITCODE"
    }

    $env:WAR_ROOM_WEB_ROOT = $buildRoot
    $env:WAR_ROOM_DATA_ROOT = $dataRoot
    $env:WAR_ROOM_PORT = $Port.ToString()
    if ([string]::IsNullOrWhiteSpace($env:WAR_ROOM_OPERATOR_BOOTSTRAP)) {
        $secretBytes = [byte[]]::new(32)
        $random = [Security.Cryptography.RandomNumberGenerator]::Create()
        try {
            $random.GetBytes($secretBytes)
        }
        finally {
            $random.Dispose()
        }
        $env:WAR_ROOM_OPERATOR_BOOTSTRAP = [Convert]::ToBase64String($secretBytes).
            TrimEnd('=').
            Replace('+', '-').
            Replace('/', '_')
        $generatedBootstrap = $true
    }
    Write-Host "Starting WAR-R00M at http://127.0.0.1:$Port" -ForegroundColor Green
    if ($generatedBootstrap) {
        Write-Host "WAR-R00M bootstrap secret: $env:WAR_ROOM_OPERATOR_BOOTSTRAP" -ForegroundColor Yellow
        Write-Host 'The generated secret exists only in this process environment and is cleared when WAR-R00M stops.'
    }
    else {
        Write-Host 'Using the deliberately preconfigured WAR_ROOM_OPERATOR_BOOTSTRAP value; it is not printed.'
    }
    & npm.cmd start -w '@war-room/api'
}
finally {
    if ($generatedBootstrap) {
        Remove-Item Env:WAR_ROOM_OPERATOR_BOOTSTRAP -ErrorAction SilentlyContinue
    }
    elseif ($null -ne $previousBootstrap) {
        $env:WAR_ROOM_OPERATOR_BOOTSTRAP = $previousBootstrap
    }
    if ($null -ne $secretBytes) {
        [Array]::Clear($secretBytes, 0, $secretBytes.Length)
    }
    Pop-Location
}
