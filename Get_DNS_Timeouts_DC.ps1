$DnsServers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName

$Results = foreach ($Server in $DnsServers)
{
    Invoke-Command -ComputerName $Server -ScriptBlock {

        $GlobalTimeout    = (Get-DnsServerForwarder).Timeout
        $RecursionTimeout = (Get-DnsServerRecursion).Timeout

        $CFs = Get-DnsServerZone | Where-Object {$_.ZoneType -eq 'Forwarder'}

        if ($CFs)
        {
            foreach ($CF in $CFs)
            {
                [PSCustomObject]@{
                    Server                 = $env:COMPUTERNAME
                    GlobalForwarderTimeout = $GlobalTimeout
                    RecursionTimeout       = $RecursionTimeout
                    ZoneName               = $CF.ZoneName
                    ForwarderTimeout       = $CF.ForwarderTimeout
                }
            }
        }
        else
        {
            [PSCustomObject]@{
                Server                 = $env:COMPUTERNAME
                GlobalForwarderTimeout = $GlobalTimeout
                RecursionTimeout       = $RecursionTimeout
                ZoneName               = "<No Conditional Forwarders>"
                ForwarderTimeout       = $null
            }
        }
    }
}

$Results |
Select-Object Server,GlobalForwarderTimeout,RecursionTimeout,ZoneName,ForwarderTimeout |
Export-Csv C:\Temp\DNS_Timeouts.csv -NoTypeInformation