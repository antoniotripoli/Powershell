<#
.SYNOPSIS
    Retrieve DNS global and conditional forwarder timeouts from one or more servers.

.DESCRIPTION
    Queries DNS server settings for Global Forwarder Timeout, Recursion Timeout,
    and per-conditional-forwarder timeouts. By default it targets all domain
    controllers in the current AD domain. You can also provide an explicit list
    of servers or run against the local computer.

.PARAMETER AllDomainControllers
    When present (default), retrieves the list of domain controllers via
    Get-ADDomainController and queries each one.

.PARAMETER Servers
    An array of server hostnames to query. If omitted and AllDomainControllers is
    not set, the local computer is used.

.PARAMETER Credential
    Optional PSCredential to use for remote connections.

.PARAMETER OutputPath
    CSV output path. Default: C:\Temp\DNS_Timeouts.csv

.EXAMPLE
    .\Get_DNS_Timeouts_DC.ps1

    Runs against all domain controllers and writes C:\Temp\DNS_Timeouts.csv
#>

[CmdletBinding()]
param(
    [switch]
    $AllDomainControllers = $true,

    [string[]]
    $Servers,

    [System.Management.Automation.PSCredential]
    $Credential,

    [string]
    $OutputPath = 'C:\Temp\DNS_Timeouts.csv'
)

function Get-DnsTimeoutsFromServer {
    param(
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $sb = {
        try {
            # Ensure DnsServer module commands are available
            if (-not (Get-Command -Name Get-DnsServerForwarder -ErrorAction SilentlyContinue)) {
                throw 'DnsServer module or cmdlets not available on this server.'
            }

            $GlobalTimeout = (Get-DnsServerForwarder -ErrorAction Stop).Timeout
            $RecursionTimeout = (Get-DnsServerRecursion -ErrorAction Stop).Timeout

            # Prefer the dedicated conditional forwarder cmdlet; fallback to zones of type Forwarder
            $CFs = Get-DnsServerConditionalForwarderZone -ErrorAction SilentlyContinue
            if (-not $CFs) {
                $CFs = Get-DnsServerZone | Where-Object { $_.ZoneType -eq 'Forwarder' } -ErrorAction SilentlyContinue
            }

            if ($CFs -and $CFs.Count -gt 0) {
                foreach ($CF in $CFs) {
                    [PSCustomObject]@{
                        Server                 = $env:COMPUTERNAME
                        GlobalForwarderTimeout = $GlobalTimeout
                        RecursionTimeout       = $RecursionTimeout
                        ZoneName               = ($CF.PSObject.Properties.Name -contains 'ZoneName') ? $CF.ZoneName : $CF.Name
                        ForwarderTimeout       = ($CF.PSObject.Properties.Name -contains 'ForwarderTimeout') ? $CF.ForwarderTimeout : $CF.Timeout
                        Error                  = $null
                    }
                }
            }
            else {
                [PSCustomObject]@{
                    Server                 = $env:COMPUTERNAME
                    GlobalForwarderTimeout = $GlobalTimeout
                    RecursionTimeout       = $RecursionTimeout
                    ZoneName               = '<No Conditional Forwarders>'
                    ForwarderTimeout       = $null
                    Error                  = $null
                }
            }
        }
        catch {
            [PSCustomObject]@{
                Server                 = $env:COMPUTERNAME
                GlobalForwarderTimeout = $null
                RecursionTimeout       = $null
                ZoneName               = $null
                ForwarderTimeout       = $null
                Error                  = $_.Exception.Message
            }
        }
    }

    if ($Credential) {
        Invoke-Command -ComputerName $Server -Credential $Credential -ScriptBlock $sb -ErrorAction Stop
    }
    else {
        Invoke-Command -ComputerName $Server -ScriptBlock $sb -ErrorAction Stop
    }
}

# Determine target servers
if ($AllDomainControllers) {
    try {
        if (-not (Get-Command -Name Get-ADDomainController -ErrorAction SilentlyContinue)) {
            Throw 'ActiveDirectory module is not available. Install RSAT/AD PowerShell or run on a domain-joined system with the module.'
        }

        $DnsServers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
    }
    catch {
        Write-Error "Failed to enumerate domain controllers: $_"
        return
    }
}
elseif ($Servers -and $Servers.Count -gt 0) {
    $DnsServers = $Servers
}
else {
    $DnsServers = @($env:COMPUTERNAME)
}

# Collect results
$AllResults = @()
foreach ($Server in $DnsServers) {
    try {
        $res = Get-DnsTimeoutsFromServer -Server $Server -Credential $Credential
        if ($res) { $AllResults += $res }
    }
    catch {
        $AllResults += [PSCustomObject]@{
            Server                 = $Server
            GlobalForwarderTimeout = $null
            RecursionTimeout       = $null
            ZoneName               = $null
            ForwarderTimeout       = $null
            Error                  = $_.Exception.Message
        }
    }
}

# Ensure output directory exists
$dir = Split-Path -Path $OutputPath -Parent
if (-not (Test-Path -Path $dir)) {
    try { New-Item -ItemType Directory -Path $dir -Force | Out-Null } catch {}
}

# Export results
$AllResults |
    Select-Object Server,GlobalForwarderTimeout,RecursionTimeout,ZoneName,ForwarderTimeout,Error |
    Export-Csv -Path $OutputPath -NoTypeInformation -Force

Write-Output "Wrote results for $($AllResults | Select-Object -ExpandProperty Server | Sort-Object -Unique | Measure-Object).Count servers to '$OutputPath'"
