[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)][int]$Port = 4315,
    [switch]$NoBrowser,
    [switch]$PrepareOnly,
    [switch]$Plan
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$profileRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
$hasher = [Security.Cryptography.SHA256]::Create()
try {
    $checkoutHash = [BitConverter]::ToString($hasher.ComputeHash(
        [Text.Encoding]::UTF8.GetBytes($root.ToLowerInvariant())
    )).Replace('-', '').Substring(0, 16).ToLowerInvariant()
}
finally { $hasher.Dispose() }
$previewBase = Join-Path $profileRoot '.violetvector-preview'
$previewRoot = Join-Path $previewBase $checkoutHash
$webRoot = Join-Path $previewRoot 'web'
$dataRoot = Join-Path $previewRoot 'runtime'

if ($Plan) {
    [ordered]@{
        product = 'VioletVector AI'
        mode = 'synthetic-demo'
        requiredNode = '24.12.0'
        nativeSensorRequired = $false
        mcpwnEnabled = $false
        redmiExecutionEnabled = $false
        address = "http://127.0.0.1:$Port"
        webRoot = $webRoot
        dataRoot = $dataRoot
    } | ConvertTo-Json
    return
}

if (-not (Get-Command node.exe -ErrorAction SilentlyContinue)) {
    throw 'Install Node.js 24.12 or newer (including npm), then double-click the demo launcher again.'
}
$versionOutput = & node.exe -p 'process.versions.node'
if ($LASTEXITCODE -ne 0 -or [version]($versionOutput.Trim()) -lt [version]'24.12.0') {
    throw 'Node.js 24.12 or newer is required. Update Node, then retry the demo launcher.'
}
if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) {
    throw 'npm is missing. Reinstall Node.js with its npm component, then retry.'
}
if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw 'Run the demo as an ordinary user, not as Administrator.'
}
if (-not $PrepareOnly) {
    $portProbe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse('127.0.0.1'), $Port)
    try { $portProbe.Start() }
    catch { throw "Port $Port is already occupied. Stop the earlier console or run .\scripts\start-demo.ps1 -Port 4316." }
    finally { $portProbe.Stop() }
}

# Never replace files through a junction or share the maintainer runtime.
foreach ($path in @($previewBase, $previewRoot, $webRoot, $dataRoot)) {
    if ((Test-Path -LiteralPath $path) -and
        ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Demo folders must not be junctions or symbolic links: $path"
    }
}
New-Item -ItemType Directory -Force -Path $webRoot, $dataRoot | Out-Null
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe $previewRoot '/inheritance:r' '/grant:r' "$identity`:(OI)(CI)F" '/grant:r' '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Unable to protect the demo data folder. No server was started.' }

$savedEnvironment = @{}
$browserJob = $null
$secretBytes = $null
Push-Location $root
try {
    $lockHasher = [Security.Cryptography.SHA256]::Create()
    try {
        $lockHash = [BitConverter]::ToString($lockHasher.ComputeHash(
            [IO.File]::ReadAllBytes((Join-Path $root 'package-lock.json'))
        )).Replace('-', '')
    }
    finally { $lockHasher.Dispose() }
    $stamp = Join-Path $root 'node_modules\.violetvector-demo-lock'
    $dependenciesReady = (Test-Path -LiteralPath $stamp) -and
        ([IO.File]::ReadAllText($stamp) -eq $lockHash) -and
        (Test-Path -LiteralPath (Join-Path $root 'node_modules\.bin\tsx.cmd')) -and
        (Test-Path -LiteralPath (Join-Path $root 'node_modules\.bin\vite.cmd'))
    if (-not $dependenciesReady) {
        Write-Host 'First setup: downloading locked application dependencies. This needs internet access.'
        & npm.cmd ci
        if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed. Check your internet connection and retry.' }
        [IO.File]::WriteAllText($stamp, $lockHash)
    }

    Write-Host 'Preparing the demo interface (no .NET, WSL, Docker or sensor build)...'
    & npm.cmd run typecheck -w '@war-room/web'
    if ($LASTEXITCODE -ne 0) { throw 'Interface validation failed. No server was started.' }
    & npm.cmd exec -w '@war-room/web' -- vite build --outDir $webRoot --emptyOutDir
    if ($LASTEXITCODE -ne 0) { throw 'Interface build failed. No server was started.' }
    if ($PrepareOnly) {
        Write-Host 'VioletVector AI demo setup passed. Run the launcher to open the console.' -ForegroundColor Green
        return
    }

    # Ignore inherited live-adapter and bootstrap settings for this demo process.
    $settings = @{
        WAR_ROOM_WEB_ROOT = $webRoot
        WAR_ROOM_DATA_ROOT = $dataRoot
        WAR_ROOM_PORT = $Port.ToString()
        WAR_ROOM_MCPWN_VERSION_ENABLED = '0'
        WAR_ROOM_REDMI_EXECUTION_ENABLED = '0'
    }
    $secretBytes = [byte[]]::new(32)
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($secretBytes) } finally { $random.Dispose() }
    $settings.WAR_ROOM_OPERATOR_BOOTSTRAP = [Convert]::ToBase64String($secretBytes).
        TrimEnd('=').Replace('+', '-').Replace('/', '_')
    foreach ($name in $settings.Keys) {
        $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        [Environment]::SetEnvironmentVariable($name, $settings[$name], 'Process')
    }
    Write-Host "VioletVector AI demo: http://127.0.0.1:$Port" -ForegroundColor Green
    Write-Host "One-time bootstrap secret: $($settings.WAR_ROOM_OPERATOR_BOOTSTRAP)" -ForegroundColor Yellow
    Write-Host 'Enter your name and this secret. On Missions, click Create guided demo.'
    Write-Host 'Then open the finding and report. Synthetic data only; live tool adapters are disabled.'
    Write-Host 'Keep this window open. Press Ctrl+C to stop. Never share the secret.'
    if (-not $NoBrowser) {
        try { $browserJob = Start-Job -ArgumentList $Port -ScriptBlock {
            param($DemoPort)
            $url = "http://127.0.0.1:$DemoPort"
            for ($attempt = 0; $attempt -lt 60; $attempt++) {
                try {
                    $health = Invoke-RestMethod "$url/api/health" -TimeoutSec 1
                    if ($health.executionEnabled -eq $false) {
                        Start-Process -FilePath $url
                        return
                    }
                } catch { }
                Start-Sleep -Milliseconds 500
            }
        } }
        catch { Write-Warning 'Automatic browser opening is unavailable. Open the localhost URL printed above.' }
    }
    & npm.cmd start -w '@war-room/api'
    if ($LASTEXITCODE -ne 0) {
        throw "Demo server stopped unexpectedly. If port $Port is occupied, run .\scripts\start-demo.ps1 -Port 4316."
    }
}
finally {
    if ($null -ne $browserJob) {
        Stop-Job $browserJob -ErrorAction SilentlyContinue
        Remove-Job $browserJob -Force -ErrorAction SilentlyContinue
    }
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
    }
    if ($null -ne $secretBytes) { [Array]::Clear($secretBytes, 0, $secretBytes.Length) }
    Pop-Location
}
