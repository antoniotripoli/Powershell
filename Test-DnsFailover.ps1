<#
Test-DnsFailover-Auto.ps1
Reports DNS failover behaviour using Event ID 3011 sequence per iteration.
#>

[CmdletBinding()]
param(
    [IPAddress[]] $DnsServers          = @("8.8.8.8","1.1.1.1","8.8.4.4"),
    [string]      $Hostname            = "www.microsoft.com",
    [int]         $IterationsPerStage  = 2,
    [int]         $DelaySeconds        = 2,
    [string]      $CsvPath             = "$env:TEMP\DnsFailover_Auto.csv"
)

function Test-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { throw "Run this script as Administrator." }
}

function Enable-DnsClientOperationalLog { wevtutil set-log Microsoft-Windows-DNS-Client/Operational /e:true | Out-Null }
function Clear-DnsClientOperationalLog  { wevtutil clear-log Microsoft-Windows-DNS-Client/Operational | Out-Null }
function Disable-DnsClientOperationalLog{ wevtutil set-log Microsoft-Windows-DNS-Client/Operational /e:false | Out-Null }

function Get-3011Sequence {
    param([datetime]$Start,[datetime]$End,[int]$ClientPid,[string]$HostName)

    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-DNS-Client/Operational'
        Id        = 3011
        StartTime = $Start
        EndTime   = $End
    }

    $hostEsc = [Regex]::Escape($HostName)
    $seq = @()

    foreach ($ev in $events) {
        $msg = $ev.Message
        if (-not $msg) { continue }
        if ($msg -notmatch "client PID\s+$ClientPid") { continue }
        if ($msg -notmatch "for name\s+$hostEsc") { continue }
        if ($msg -notmatch 'type\s+1') { continue }
        if ($msg -notmatch 'response status\s+0') { continue }

        if ($msg -match 'DNS Server\s+(?<ip>\d{1,3}(?:\.\d{1,3}){3})') {
            $seq += [pscustomobject]@{ Time=$ev.TimeCreated; IP=$Matches['ip'] }
        }
    }

    return ($seq | Sort-Object Time | Select-Object -ExpandProperty IP)
}

function Block-DnsServer {
    param([string]$ServerIP)
    Write-Host "Blocking DNS $ServerIP..." -ForegroundColor Yellow
    New-NetFirewallRule -DisplayName "BlockDNS_${ServerIP}_UDP" -Direction Outbound -Action Block `
        -RemoteAddress $ServerIP -Protocol UDP -RemotePort 53 | Out-Null
    New-NetFirewallRule -DisplayName "BlockDNS_${ServerIP}_TCP" -Direction Outbound -Action Block `
        -RemoteAddress $ServerIP -Protocol TCP -RemotePort 53 | Out-Null
    Start-Sleep -Seconds 1
}

function Unblock-DnsServer {
    param([string]$ServerIP)
    Get-NetFirewallRule -DisplayName "BlockDNS_${ServerIP}_UDP","BlockDNS_${ServerIP}_TCP" -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule | Out-Null
    Start-Sleep -Seconds 1
}

function Unblock-AllDns {
    Get-NetFirewallRule -DisplayName "BlockDNS_*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule | Out-Null
}

function Run-Queries {
    param([int]$Stage,[ref]$Results,[string]$HostName,[int]$IterCount,[int]$DelaySec)
    foreach ($i in 1..$IterCount) {
        Clear-DnsClientCache
        $start = Get-Date
        $sw    = [System.Diagnostics.Stopwatch]::StartNew()
        $status = "Success"
        $ips = ""
        try {
            $ans = Resolve-DnsName -Name $HostName -DnsOnly -NoHostsFile -ErrorAction Stop
            $ips = ($ans | Where-Object {$_.IPAddress} | Select-Object -ExpandProperty IPAddress) -join ", "
        } catch {
            $status = "Failed"
        }
        $sw.Stop(); $end = Get-Date

        # Get sequence of DNS servers that responded (3011 events)
        $seq = Get-3011Sequence -Start $start.AddSeconds(-30) -End $end.AddSeconds(30) -ClientPid $PID -HostName $HostName
        $sequenceText = if ($seq.Count -gt 0) { $seq -join " -> " } else { "none" }

        $row = [pscustomobject]@{
            Stage=$Stage;Iteration=$i;QueriedHost=$HostName;
            ResponseSequence=$sequenceText;
            IPAddresses=$ips;DurationMs=$sw.ElapsedMilliseconds;Status=$status;
            StartTime=$start;EndTime=$end
        }
        [void]$Results.Value.Add($row)

        Write-Host "[S$Stage-Q$i] $status in $($sw.ElapsedMilliseconds) ms | Sequence: $sequenceText"
        Start-Sleep -Seconds $DelaySec
    }
}

# ---------------------- MAIN ----------------------------
Test-Admin
Enable-DnsClientOperationalLog
Clear-DnsClientOperationalLog

$results = New-Object System.Collections.Generic.List[pscustomobject]

try {
    Write-Host "`nStage 0: All DNS servers allowed..." -ForegroundColor Cyan
    Run-Queries 0 ([ref]$results) $Hostname $IterationsPerStage $DelaySeconds

    Block-DnsServer $DnsServers[0]
    Write-Host "`nStage 1: Blocked $($DnsServers[0])..." -ForegroundColor Cyan
    Run-Queries 1 ([ref]$results) $Hostname $IterationsPerStage $DelaySeconds

    Block-DnsServer $DnsServers[1]
    Write-Host "`nStage 2: Blocked $($DnsServers[1])    Write-Host "`nStage 2: Blocked $($DnsServers[1])regroundColor Cyan
    Run-Queries 2 ([ref]$results) $Hostname $IterationsPerStage $DelaySeconds

    if ($DnsServers.Count -ge 3) {
        Unblock-DnsServer $DnsServers[0]
        Unblock-DnsServer $DnsServers[1]
        Block-DnsServer   $DnsServers[2]
        Write-Host "`nStage 3: Unblocked $($DnsServers[0]), $($DnsServers[1]); Blocked $($DnsServers[2])..." -ForegroundColor Cyan
        Run-Queries 3 ([ref]$results) $Hostname $IterationsPerStage $DelaySeconds
    }

    Unblock-AllDns

    Write-Host "`nVerification (IPv4-only):" -ForegroundColor Cyan
    foreach ($dns in $DnsServers) {
        try {
            $ans4 = Resolve-DnsName -Name $Hostname -Server $dns -DnsOnly -Type A -ErrorAction Stop
            Write-Host "  Server $dns responded (IPv4: $($ans4.IPAddress -join ', '))" -ForegroundColor Green
        } catch {
            Write-Host "  Server $dns unreachable" -ForegroundColor Red
        }
    }
} finally {
    Disable-DnsClientOperationalLog
}

# ---------------------- Output ----------------------
$results | Export-Csv -Path $CsvPath -NoTypeInformation
Write-Host "`nResults saved to $CsvPath"

Write-Host "`n=== DNS Failover Summary ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize