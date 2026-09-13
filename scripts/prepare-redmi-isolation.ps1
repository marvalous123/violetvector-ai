[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$Distro = 'kali-linux'
$Target = '192.168.42.129'
$Network = 'war-room-redmi-isolated'
$Bridge = 'wr15-redmi'
$Subnet = '172.30.15.0/28'
$Image = 'sha256:dca1d57e32c7818f6eadba39bcac1e31c6abfb57a2ae08b84b0062a8ab4dbde3'

function Invoke-Wsl {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments,
        [switch]$AllowFailure,
        [switch]$Root
    )

    $prefix = @('--distribution', $Distro)
    if ($Root) {
        $prefix += @('--user', 'root')
    }
    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & wsl.exe @prefix --exec @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorAction
    }
    if ($exitCode -ne 0 -and -not $AllowFailure) {
        throw "WSL command failed ($exitCode): $($Arguments -join ' ')`n$($output -join [Environment]::NewLine)"
    }
    return [pscustomobject]@{ ExitCode = $exitCode; Output = ($output -join "`n").Trim() }
}

$networkResult = Invoke-Wsl -Arguments @('docker', 'network', 'inspect', $Network)
$networkRecord = @($networkResult.Output | ConvertFrom-Json)[0]
$containerCount = @($networkRecord.Containers.PSObject.Properties).Count
if (
    [string]$networkRecord.Id -notmatch '^[a-f0-9]{64}$' -or
    [string]$networkRecord.Options.'com.docker.network.bridge.name' -ne $Bridge -or
    [string]$networkRecord.IPAM.Config[0].Subnet -ne $Subnet -or
    $containerCount -ne 0
) {
    throw 'ISOLATION_NETWORK_MISMATCH'
}

$route = (Invoke-Wsl -Arguments @('ip', '-4', 'route', 'get', $Target)).Output
if ($route -notmatch '^192\.168\.42\.129 dev (eth[0-9]+) src (192\.168\.42\.([0-9]{1,3}))(?:\s|$)') {
    throw 'ISOLATION_ROUTE_MISMATCH'
}
$interfaceName = $Matches[1]
$sourceAddress = $Matches[2]
$sourceOctet = [int]$Matches[3]
if ($sourceOctet -lt 1 -or $sourceOctet -gt 254 -or $sourceOctet -eq 129) {
    throw 'ISOLATION_ROUTE_MISMATCH'
}

$address = (Invoke-Wsl -Arguments @('ip', '-4', '-o', 'addr', 'show', 'dev', $interfaceName, 'scope', 'global')).Output
$escapedSource = [regex]::Escape($sourceAddress)
if ($address -notmatch "\binet $escapedSource/24\b") {
    throw 'ISOLATION_ROUTE_MISMATCH'
}

Invoke-Wsl -Root -AllowFailure -Arguments @('/usr/sbin/iptables', '-N', 'WAR_ROOM_REDMI') | Out-Null
Invoke-Wsl -Root -Arguments @('/usr/sbin/iptables', '-F', 'WAR_ROOM_REDMI') | Out-Null
while ($true) {
    $jump = Invoke-Wsl -Root -AllowFailure -Arguments @(
        '/usr/sbin/iptables', '-C', 'DOCKER-USER', '-i', $Bridge, '-j', 'WAR_ROOM_REDMI'
    )
    if ($jump.ExitCode -ne 0) {
        break
    }
    Invoke-Wsl -Root -Arguments @(
        '/usr/sbin/iptables', '-D', 'DOCKER-USER', '-i', $Bridge, '-j', 'WAR_ROOM_REDMI'
    ) | Out-Null
}
Invoke-Wsl -Root -Arguments @(
    '/usr/sbin/iptables', '-I', 'DOCKER-USER', '1', '-i', $Bridge, '-j', 'WAR_ROOM_REDMI'
) | Out-Null
Invoke-Wsl -Root -Arguments @(
    '/usr/sbin/iptables', '-A', 'WAR_ROOM_REDMI',
    '-d', "$Target/32", '-o', $interfaceName, '-p', 'tcp', '-j', 'ACCEPT'
) | Out-Null
Invoke-Wsl -Root -Arguments @('/usr/sbin/iptables', '-A', 'WAR_ROOM_REDMI', '-j', 'DROP') | Out-Null

$dockerUserRules = (Invoke-Wsl -Root -Arguments @('/usr/sbin/iptables', '-S', 'DOCKER-USER')).Output
$dockerRuleLines = @($dockerUserRules -split "`r?`n" | Where-Object { $_ -like '-A *' })
$expectedJump = "-A DOCKER-USER -i $Bridge -j WAR_ROOM_REDMI"
$bridgeRules = @($dockerRuleLines | Where-Object { $_ -match "(?:-i|-o) $([regex]::Escape($Bridge))(?:\s|$)" })
if ($dockerRuleLines.Count -lt 1 -or $dockerRuleLines[0] -ne $expectedJump -or $bridgeRules.Count -ne 1 -or $bridgeRules[0] -ne $expectedJump) {
    throw 'ISOLATION_FIREWALL_MISMATCH'
}
$redmiRules = (Invoke-Wsl -Root -Arguments @('/usr/sbin/iptables', '-S', 'WAR_ROOM_REDMI')).Output
$redmiRuleLines = @($redmiRules -split "`r?`n" | Where-Object { $_ -like '-A *' })
$expectedRedmiRules = @(
    "-A WAR_ROOM_REDMI -d $Target/32 -o $interfaceName -p tcp -j ACCEPT",
    '-A WAR_ROOM_REDMI -j DROP'
)
if ($redmiRuleLines.Count -ne 2 -or $redmiRuleLines[0] -ne $expectedRedmiRules[0] -or $redmiRuleLines[1] -ne $expectedRedmiRules[1]) {
    throw 'ISOLATION_FIREWALL_MISMATCH'
}

$imageId = (Invoke-Wsl -Arguments @('docker', 'image', 'inspect', $Image, '--format', '{{.Id}}')).Output
if ($imageId -ne $Image) {
    throw 'ISOLATION_IMAGE_MISMATCH'
}

[pscustomobject]@{
    Target = $Target
    Source = $sourceAddress
    Interface = $interfaceName
    DockerNetwork = $Network
    Bridge = $Bridge
    Image = $imageId
    Firewall = 'exact target TCP allow, then drop'
}
